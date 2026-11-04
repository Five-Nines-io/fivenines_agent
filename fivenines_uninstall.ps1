# Fivenines Monitoring Agent - Windows uninstall bootstrap
#
# Removes the agent cleanly: uninstalls the MSI, deletes the local
# fivenines-agent service account, and cleans up the config + logs dir.
# Parallels fivenines_uninstall.sh for Linux.
#
# Usage (run as Administrator):
#   .\fivenines_uninstall.ps1                 # full cleanup
#   .\fivenines_uninstall.ps1 -KeepAccount    # leave the local account behind
#                                              # (use if you pre-staged the
#                                              # account in config management)
#
# What this script does:
#   1. Verifies it's running elevated.
#   2. Finds the installed product via the ARP registry.
#   3. Runs msiexec /x to uninstall (which also unregisters the service and
#      removes %ProgramFiles%\fivenines-agent + the config + log dirs).
#   4. Unless -KeepAccount, removes the local fivenines-agent user.
#   5. Removes the SeServiceLogonRight grant for that SID (it lingers in the
#      LSA after the user is deleted - tidy up so secedit /export is clean)
#      and its read access to the WMI Storage namespace (an ACE naming a
#      deleted account broke the next install's WMI delegation).
#
# On a domain controller the account is a DOMAIN account (a DC has no local
# ones), which other DCs may run the agent as. It is deleted only when this
# DC's installer created it with a random password nobody else knows; an
# account whose password the operator set is kept, and only this DC's
# SeServiceLogonRight grant is removed.

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$KeepAccount,

    # Defaults to a new private directory under %TEMP%
    # (New-PrivateWorkDirectory below). A path given here is used as is: pick
    # a directory only administrators can write to.
    [string]$LogFile = ""
)

$ErrorActionPreference = "Stop"

# A new directory for the downloaded MSI, its extracted copy and the install
# log, always under %SystemRoot%\Temp, whatever the session. No user may
# rename or delete there what someone else created: an administrator's own
# %TEMP% would let their unelevated processes replace the directory through
# its parent, and run as SYSTEM (an RMM tool, Intune, a scheduled task)
# %TEMP% is that directory anyway. Owned by Administrators, open to SYSTEM
# and Administrators, read-only to the user running the script (who reads a
# failed run's log unelevated, where the Administrators group does not
# apply). The ACL is set in the call that creates the directory, so it never
# exists with the inherited one (Windows PowerShell 5.1's .NET Framework has
# a Directory.CreateDirectory overload taking it; PowerShell 7's .NET moved
# it to FileSystemAclExtensions), and checked after: a file system without
# ACLs drops it silently.
function New-PrivateWorkDirectory {
    param([string]$Prefix)

    $admins = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetOwner($admins)
    $security.SetAccessRuleProtection($true, $false)
    $expected = @("S-1-5-18", "S-1-5-32-544")
    foreach ($sid in $expected) {  # SYSTEM, Administrators
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($sid)),
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)))
    }
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($user.Value -ne "S-1-5-18") {
        $expected += $user.Value
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $user,
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)))
    }
    $path = Join-Path (Join-Path $env:SystemRoot "Temp") ("{0}-{1}" -f $Prefix, [guid]::NewGuid())
    if (Test-Path -LiteralPath $path) { throw "$path already exists" }
    if ($PSVersionTable.PSEdition -eq "Core") {
        [System.IO.FileSystemAclExtensions]::CreateDirectory($security, $path) | Out-Null
    } else {
        [System.IO.Directory]::CreateDirectory($path, $security) | Out-Null
    }
    $acl = Get-Acl -LiteralPath $path
    $granted = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
        ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    if (-not $acl.AreAccessRulesProtected -or
        $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $admins.Value -or
        ($granted -join ",") -ne ((@($expected) | Sort-Object -Unique) -join ",")) {
        throw "$path did not keep its access control list (does its file system support ACLs?)"
    }
    return $path
}

# Removes the work directories earlier runs of these scripts left under
# %SystemRoot%\Temp, so a scheduled run does not leave one MSI copy per run.
# Only directories it can tell are its own: a fivenines-setup-, -update- or
# -uninstall-<guid> name, owned by Administrators (no other user can create
# one so owned) with a protected ACL, not a link, and at least $MinAgeMinutes
# old (a run still in progress keeps its own). Kept: $Keep (this run's), and
# the installed product's recorded install source, from which Windows
# Installer reads the MSI to repair it (its cached copy keeps no embedded
# cabinet).
function Remove-EarlierWorkDirectories {
    param([string]$Keep, [int]$MinAgeMinutes = 60)

    $keepPaths = @($Keep.TrimEnd('\'))
    $product = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "Fivenines Monitoring Agent" } |
        Select-Object -First 1
    if ($product -and $product.InstallSource) { $keepPaths += ([string]$product.InstallSource).TrimEnd('\') }
    $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-$MinAgeMinutes)
    $parent = Join-Path $env:SystemRoot "Temp"
    $candidates = @(Get-ChildItem -LiteralPath $parent -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^fivenines-(setup|update|uninstall)-[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' })
    foreach ($dir in $candidates) {
        if ($keepPaths -contains $dir.FullName.TrimEnd('\')) { continue }
        if (([int]$dir.Attributes -band 0x400) -ne 0) { continue }  # a junction or a link: never followed
        if ($dir.CreationTimeUtc -gt $cutoff) { continue }
        try {
            $acl = Get-Acl -LiteralPath $dir.FullName
            if (-not $acl.AreAccessRulesProtected) { continue }
            if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne "S-1-5-32-544") { continue }
            Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            continue
        }
    }
}

$WorkDir = New-PrivateWorkDirectory "fivenines-uninstall"
if (-not $LogFile) { $LogFile = Join-Path $WorkDir "fivenines-uninstall.log" }

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run from an elevated PowerShell session (Run as administrator)."
    exit 1
}

# Find the installed product. Same lookup as fivenines_update.ps1.
$installed = Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "Fivenines Monitoring Agent" } |
    Select-Object -First 1

if (-not $installed) {
    Write-Host "Fivenines agent is not installed. Nothing to uninstall."
} else {
    $productCode = $installed.PSChildName
    Write-Host ("Uninstalling {0} ({1})..." -f $installed.DisplayName, $productCode)
    $msiArgs = @("/x", $productCode, "/qb", "/l*v", "`"$LogFile`"")
    $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Error "msiexec /x failed with exit code $($proc.ExitCode). See $LogFile."
        exit $proc.ExitCode
    }
}

if ($KeepAccount) {
    Write-Host "-KeepAccount set; leaving fivenines-agent local account in place."
    Remove-EarlierWorkDirectories -Keep $WorkDir
    Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 0
}

# Same tag as CreateServiceAccount.ps1, which writes it on an account the
# installer created on a domain controller (windows.yml keeps the two equal).
$DC_MANAGED_PREFIX = "Fivenines agent, managed on "
$MSI_MANAGED_DESCRIPTION = "Fivenines monitoring agent service account"

# Whether the uninstall deletes the account. On a member server, always (it
# is local to the machine; -KeepAccount keeps it). On a domain controller,
# where it is a domain account other DCs may run the agent as, only when
# this DC's installer created it (its own tag) or when a release before
# domain-controller support left it (MSI_MANAGED_DESCRIPTION): those
# releases failed on every DC before configuring the service, so no DC runs
# the agent as such an account, and CreateServiceAccount.ps1 adopts it the
# same way. Pure, so CI checks it case by case.
function Test-UninstallDeletesAccount {
    param([bool]$IsDomainController, [string]$Description, [string]$ComputerName)

    if (-not $IsDomainController) { return $true }
    return ($Description -eq ($DC_MANAGED_PREFIX + $ComputerName)) -or ($Description -eq $MSI_MANAGED_DESCRIPTION)
}

# Kept identical in CreateServiceAccount.ps1 (windows.yml checks it).
# The WinNT entry of this machine's user NAME, or $null when there is none.
# [ADSI]::Exists() does not answer that for WinNT: it raises NERR_UserNotFound
# instead of returning false. [ADSI] binds lazily and reading a property does
# not bind it either (a missing user reads as one with no SID), so
# RefreshCache() -- IADs::GetInfo -- is what finds out. .NET members go
# through psbase: PowerShell's ADSI adapter hides them.
function Get-WinNTUser {
    param([string]$Name)

    $entry = [ADSI]("WinNT://{0}/{1},user" -f $env:COMPUTERNAME, $Name)
    try {
        $entry.psbase.RefreshCache()
    } catch {
        # NERR_UserNotFound (2221, 0x800708AD), ERROR_NO_SUCH_USER (1317,
        # 0x80070525), from the COMException that PowerShell's invocation
        # exceptions wrap (the innermost one).
        $hresult = $_.Exception.GetBaseException().HResult
        if ($hresult -eq -2147022675 -or $hresult -eq -2147023579) { return $null }
        throw
    }
    if ($null -eq $entry.psbase.Properties["objectSid"].Value) {
        throw ("WinNT user '{0}' was read but carries no objectSid" -f $Name)
    }
    return $entry
}

# (Kept identical in DelegateWmiStorageNamespace.ps1; windows.yml checks it.)
# Read and write a WMI namespace's security descriptor in binary form
# (__SystemSecurity GetSD/SetSD), with the args-array calling convention of
# Microsoft's own namespace-security sample: the out parameter comes back in
# the array, and SetSD takes the bytes as its one argument.
function Get-WmiNamespaceSD {
    param([string]$Namespace)

    $security = Get-WmiObject -Namespace $Namespace -Class __SystemSecurity
    $out = @($null)
    $rv = $security.PsBase.InvokeMethod("GetSD", $out)
    if ($rv -ne 0) { throw ("GetSD on {0} failed: {1}" -f $Namespace, $rv) }
    return [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$out[0], 0)
}

function Set-WmiNamespaceSD {
    param([string]$Namespace, [System.Security.AccessControl.RawSecurityDescriptor]$Descriptor)

    # Raw .NET arrays: New-Object would hand back a PSObject-wrapped byte[],
    # which InvokeMethod cannot cast to System.Array.
    $bytes = [byte[]]::new($Descriptor.BinaryLength)
    $Descriptor.GetBinaryForm($bytes, 0)
    $arguments = [object[]]::new(1)
    $arguments[0] = $bytes
    $security = Get-WmiObject -Namespace $Namespace -Class __SystemSecurity
    $rv = $security.PsBase.InvokeMethod("SetSD", $arguments)
    if ($rv -ne 0) { throw ("SetSD on {0} failed: {1}" -f $Namespace, $rv) }
}

# Remove every explicit allow ACE naming this SID from the WMI Storage
# namespace, which DelegateWmiStorageNamespace.ps1 granted. A deny ACE stays:
# it was set by someone else, and on a domain controller that keeps the
# account, it may still be meant to hold. Binary GetSD/SetSD, as there:
# GetSecurityDescriptor fails outright once an ACE names a deleted account.
function Remove-WmiStorageGrant {
    param([string]$Sid)

    $namespace = "root\Microsoft\Windows\Storage"
    $sd = Get-WmiNamespaceSD $namespace
    $sidObject = [System.Security.Principal.SecurityIdentifier]$Sid
    $allowed = [System.Security.AccessControl.AceQualifier]::AccessAllowed
    $removed = 0
    for ($i = $sd.DiscretionaryAcl.Count - 1; $i -ge 0; $i--) {
        $ace = $sd.DiscretionaryAcl[$i]
        if ($ace -is [System.Security.AccessControl.QualifiedAce] -and
            $ace.AceQualifier -eq $allowed -and
            $ace.SecurityIdentifier -eq $sidObject -and
            -not $ace.IsInherited) {
            $sd.DiscretionaryAcl.RemoveAce($i)
            $removed++
        }
    }
    if ($removed -eq 0) { return }
    Set-WmiNamespaceSD $namespace $sd
    Write-Host ("Removed {0} WMI Storage namespace grant(s) for {1}." -f $removed, $Sid)
}

# Capture the SID before deleting the account so we can clean up the
# SeServiceLogonRight grant secedit left behind. The account goes through the
# ADSI WinNT provider, as in CreateServiceAccount.ps1: the LocalAccounts
# cmdlets find no account at all on a domain controller.
$entry = Get-WinNTUser "fivenines-agent"
if ($entry) {
    $sid = ([System.Security.Principal.SecurityIdentifier]::new(
        [byte[]]$entry.psbase.Properties["objectSid"].Value, 0)).Value
    $description = [string]$entry.psbase.Properties["Description"].Value
    # This machine's grant goes whether or not the account does: the agent
    # it was for is gone from here. A failure must not stop the uninstall.
    try {
        Remove-WmiStorageGrant $sid
    } catch {
        Write-Warning ("Could not remove the WMI Storage namespace grant for {0}: {1}" -f $sid, $_)
    }

    # DomainRole 4 = backup DC, 5 = primary DC.
    $isDomainController = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    if (Test-UninstallDeletesAccount -IsDomainController $isDomainController -Description $description -ComputerName $env:COMPUTERNAME) {
        Write-Host "Removing account fivenines-agent (SID $sid)..."
        ([ADSI]("WinNT://{0},computer" -f $env:COMPUTERNAME)).Delete("user", "fivenines-agent")
    } else {
        Write-Host ("Keeping domain account fivenines-agent (Description={0}): other domain controllers may run the agent as it. Delete it in Active Directory once none does." -f $description)
    }

    # Strip the account's SeServiceLogonRight entry from this machine's
    # security policy. secedit /export shows it as a dangling *S-1-5-21-...
    # after the user is gone, which is cosmetic but ugly; on a domain
    # controller that keeps the account, the service it was granted for is
    # gone from this DC.
    $tmpCfg = Join-Path $env:TEMP "fnuninstall_secpolicy.cfg"
    $tmpDb  = Join-Path $env:TEMP "fnuninstall_secpolicy.sdb"
    try {
        secedit /export /cfg $tmpCfg /areas USER_RIGHTS /quiet | Out-Null
        $content = Get-Content $tmpCfg
        $changed = $false
        for ($i = 0; $i -lt $content.Length; $i++) {
            if ($content[$i] -match '^SeServiceLogonRight\s*=') {
                $original = $content[$i]
                # Match either ',*<sid>' (in the middle / end of the list)
                # or '= *<sid>,' (start of list) or '= *<sid>' (only entry).
                $updated = $original -replace [regex]::Escape(",*$sid"), ""
                $updated = $updated -replace [regex]::Escape("*$sid,"), ""
                $updated = $updated -replace [regex]::Escape("*$sid"), ""
                if ($updated -ne $original) {
                    $content[$i] = $updated
                    $changed = $true
                }
                break
            }
        }
        if ($changed) {
            $content | Set-Content -Encoding ascii $tmpCfg
            secedit /configure /db $tmpDb /cfg $tmpCfg /areas USER_RIGHTS /quiet | Out-Null
            Write-Host "Cleaned up orphaned SeServiceLogonRight grant."
        }
    } finally {
        Remove-Item $tmpCfg, $tmpDb -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "fivenines-agent local account already gone; nothing to remove."
}

# The run succeeded: the product is gone, so the work directories earlier
# runs left go (their MSI no longer backs a repair), and this run's too (the
# log, unless -LogFile named another path); a failed run exits before this
# line and keeps it, for the log. Only SYSTEM and Administrators can write in
# them, so the recursive removal meets nothing another user planted.
Remove-EarlierWorkDirectories -Keep $WorkDir
Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Uninstall complete."
