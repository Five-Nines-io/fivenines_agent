# Fivenines Monitoring Agent - Windows update bootstrap
#
# Downloads the latest MSI and runs it. Windows Installer's MajorUpgrade
# machinery handles the rest: the old service is stopped + removed, files
# are replaced, the new service is registered, and CreateServiceAccount.ps1
# detects the existing MSI-managed account and rotates its password
# automatically (no operator credentials needed). The TOKEN file is
# recreated by the post-install CA using the value the agent already
# negotiated with the API (per-host token swap on first contact).
#
# Usage (run as Administrator):
#   .\fivenines_update.ps1
#
# One-liner:
#   iwr https://releases.fivenines.io/latest/fivenines_update.ps1 -OutFile update.ps1
#   .\update.ps1
#
# If the agent is NOT already installed, this script refuses and tells the
# operator to use fivenines_setup.ps1 instead - update has no way to obtain
# a TOKEN from thin air.
#
# Domain controllers: an account the installer created on THIS DC with a
# random password is rotated like on any server. One whose password the
# operator set (shared by several DCs) is never rotated, so pass it:
#   .\fivenines_update.ps1 -ServiceAccountPassword (Read-Host -AsSecureString "fivenines-agent password")

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$MsiUrl = "https://releases.fivenines.io/latest/fivenines-agent-windows-amd64.msi",

    # Both default to a new private directory under %TEMP%
    # (New-PrivateWorkDirectory below). A path given here is used as is: pick
    # a directory only administrators can write to.
    [string]$MsiPath = "",

    [string]$LogFile = "",

    # The service account's password, when it is not one the MSI may rotate
    # (see the domain controller note above).
    [System.Security.SecureString]$ServiceAccountPassword
)

$ErrorActionPreference = "Stop"

# A new directory under %TEMP% that only SYSTEM and Administrators can write
# to (the user running the script can read it),
# for the downloaded MSI, its extracted copy and the install log; kept after
# the run, for the log. Run as SYSTEM (an RMM tool, Intune, a scheduled task),
# %TEMP% is C:\Windows\Temp, where any local user can create a file, and a
# file a user created stays theirs to rewrite. The directory is created with
# its ACL in one call, so it never exists with the inherited one (Windows
# PowerShell 5.1's .NET Framework has a Directory.CreateDirectory overload
# taking the ACL; PowerShell 7's .NET moved it to FileSystemAclExtensions).
# A run that succeeds removes it; a failed one keeps it, for the log.
function New-PrivateWorkDirectory {
    param([string]$Prefix)

    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {  # SYSTEM, Administrators
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($sid)),
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)))
    }
    # The user running the script reads what it leaves (the log of a failed
    # run) from a session that is not elevated too, where the Administrators
    # group does not apply: read-only, nothing to rewrite the MSI with.
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($user.Value -ne "S-1-5-18") {
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $user,
            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)))
    }
    $path = Join-Path $env:TEMP ("{0}-{1}" -f $Prefix, [guid]::NewGuid())
    if (Test-Path -LiteralPath $path) { throw "$path already exists" }
    if ($PSVersionTable.PSEdition -eq "Core") {
        [System.IO.FileSystemAclExtensions]::CreateDirectory($security, $path) | Out-Null
    } else {
        [System.IO.Directory]::CreateDirectory($path, $security) | Out-Null
    }
    return $path
}

$WorkDir = New-PrivateWorkDirectory "fivenines-update"
if (-not $MsiPath) { $MsiPath = Join-Path $WorkDir "fivenines-agent-windows-amd64.msi" }
if (-not $LogFile) { $LogFile = Join-Path $WorkDir "fivenines-update.log" }

# A relative -MsiPath, resolved once against PowerShell's current location:
# the ProductCode read (COM) resolves one against the process's working
# directory instead, usually System32, where it found no MSI (or another
# one), so the password went unapplied.
$MsiPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($MsiPath)

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "This script must be run from an elevated PowerShell session (Run as administrator)."
    exit 1
}

# SERVICEACCOUNTPASSWORD as msiexec takes it. The MSI embeds the value in
# the custom action's command line between double quotes, so a '"' in it, or
# a trailing '\' (which escapes the closing quote), would split the command
# line, and powershell.exe -File reads a value starting with '-' as a
# parameter name: refused here rather than failing the install with 1603.
function ConvertTo-MsiPasswordArgument {
    param([Parameter(Mandatory=$true)][System.Security.SecureString]$Password)

    $plain = (New-Object System.Management.Automation.PSCredential("x", $Password)).GetNetworkCredential().Password
    if ([string]::IsNullOrEmpty($plain)) {
        throw "-ServiceAccountPassword is empty."
    }
    # PowerShell takes an en, em or horizontal-bar dash (U+2013..U+2015) for
    # '-' too.
    if ($plain.Contains('"') -or $plain.EndsWith('\') -or ($plain[0] -in @([char]'-', [char]0x2013, [char]0x2014, [char]0x2015))) {
        throw "-ServiceAccountPassword cannot contain a double quote, end with a backslash or start with a dash (the MSI passes it on a quoted powershell.exe -File command line, which reads a leading dash as a parameter name). Set a password without them on the account first."
    }
    return "SERVICEACCOUNTPASSWORD=`"$plain`""
}


# The ProductCode of an MSI file, read from its Property table (read-only).
# Equal to the installed agent's, msiexec /i only runs the MSI in maintenance
# mode, which never reaches the account step.
function Get-MsiProductCode {
    param([string]$MsiPath)

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $installer, @($MsiPath, 0))
    $view = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $database, @("SELECT Value FROM Property WHERE Property = 'ProductCode'"))
    try {
        [void]$view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null)
        $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
        if (-not $record) { return $null }
        return $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 1)
    } finally {
        [void]$view.GetType().InvokeMember("Close", "InvokeMethod", $null, $view, $null)
        foreach ($com in @($view, $database, $installer)) {
            [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($com)
        }
    }
}

# Resolve an account name, as the installed service's StartName spells it, to
# its SID. A "." or <ComputerName> prefix is dropped and the bare name looked
# up instead: on a domain controller the account the MSI created is a DOMAIN
# account (a DC has no local ones), and the MSI's default "<DCNAME>\name" is
# not how the domain names it, while a bare name is looked up in the
# machine's own account database on every role (the local SAM on a member
# server, the domain on a DC).
# Kept identical in SetTokenFileAcl.ps1, DelegateWmiStorageNamespace.ps1,
# fivenines_setup.ps1 and fivenines_update.ps1 (windows.yml checks it).
function Resolve-ServiceAccountSid {
    param([Parameter(Mandatory=$true)][string]$Account)

    $name = $Account
    if ($name.Contains('\')) {
        $parts = $name.Split('\', 2)
        if ($parts[0] -eq '.' -or $parts[0] -eq $env:COMPUTERNAME) {
            $name = $parts[1]
        }
    }
    $ntAccount = New-Object System.Security.Principal.NTAccount($name)
    return $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
}

# What the preflight makes of the plan the MSI's account step printed
# ({action, message, sid, checked}). Pure (no system calls), so CI checks it
# case by case. $Installed is what msiexec would find: "none" (or not looked
# for: only a password needs it), "same" (this very version: msiexec would
# only run a maintenance pass, which never reaches the account) or "other"
# (an upgrade, which removes the installed agent before the installer uses
# the account). $ServiceSid is the SID the installed service's StartName
# ($ServiceAccount) resolves to, empty when it does not. Returns
# @{ Action; Message }:
#   Action   Refuse | Install (run msiexec) | InPlace (run the step here)
#   Message  the refusal, or a warning to print for Install and InPlace
function Get-PreflightVerdict {
    param(
        $Plan,
        [bool]$HasPassword,
        [string]$Installed,
        [string]$AccountName,
        [string]$ServiceAccount,
        [string]$ServiceSid
    )

    if ($Plan.action -eq "Refuse") {
        return @{ Action = "Refuse"; Message = ("Nothing was changed: {0}" -f $Plan.message) }
    }

    # A password for an existing account that LogonUser could not answer for
    # (Add-Type blocked, an error the account step does not name, or an MSI
    # too old to say) is used as given, on an upgrade too: the account step
    # applies it (sc.exe takes any password) and the install completes, so a
    # wrong one leaves a service that does not start, which running the
    # script again with the right password repairs in place. Refusing it
    # would only block the update.
    $warning = $null
    if ($HasPassword -and $Plan.action -eq "UseProvided" -and $Plan.checked -ne $true) {
        $warning = "The -ServiceAccountPassword given could not be checked against account '{0}': it is used as given, and if it is wrong the service does not start; run this script again with the right password to fix that." -f $AccountName
    }
    if ($Installed -ne "same") {
        return @{ Action = "Install"; Message = $warning }
    }

    # In place, the step may only update the account the installed service
    # already runs as: run alone, it would move the service to another
    # account, or create one, without the rest of the install (that
    # account's WMI Storage access).
    $why = $null
    if ($Plan.action -notin @("Rotate", "UseProvided")) {
        $why = "the MSI's account step would {0} account '{1}' rather than update it" -f "$($Plan.action)".ToLower(), $AccountName
    } elseif (-not $Plan.sid) {
        $why = "the MSI's account step does not say which account '{0}' is" -f $AccountName
    } elseif (-not $ServiceAccount) {
        $why = "the installed agent has no fivenines-agent service"
    } elseif ($ServiceSid -ne $Plan.sid) {
        $why = "the installed service runs as '{0}', not as account '{1}'" -f $ServiceAccount, $AccountName
    }
    if ($why) {
        return @{ Action = "Refuse"; Message = (
            "Nothing was changed: {0}, so -ServiceAccountPassword cannot be applied to the installed agent in place. To run the agent as '{1}' with that password, reinstall it: fivenines_uninstall.ps1 -KeepAccount, then fivenines_setup.ps1 -Token <token> -ServiceAccountPassword <password>." -f $why, $AccountName) }
    }
    return @{ Action = "InPlace"; Message = $warning }
}

# The account step of the MSI about to be installed, run before msiexec: the
# MSI's own CreateServiceAccount.ps1, extracted by an administrative install
# (which runs no custom action). Its -PlanOnly run reads the account and
# checks a supplied password, changing nothing, and a refusal stops here:
# inside the MSI it comes too late on an upgrade, after Windows Installer has
# removed the running agent. With a password and this very version already
# installed, msiexec would only run in maintenance mode, which never reaches
# the account, so the step itself applies the password (as this elevated
# session) and the service is restarted with it, but only to the account the
# service already runs as; returns $true then, as there is nothing left for
# msiexec to do. Get-PreflightVerdict decides. With a password and an agent
# installed, an MSI whose ProductCode cannot be read is refused (it may be
# this very version). An MSI too old for -PlanOnly, or whose account step
# cannot be run, leaves the decision to the installer, except over this very
# version.
function Invoke-AccountPreflight {
    param([string]$MsiPath, [System.Security.SecureString]$Password, [string]$WorkDir)

    $plain = if ($Password) {
        (New-Object System.Management.Automation.PSCredential("x", $Password)).GetNetworkCredential().Password
    } else { "" }
    $account = "fivenines-agent"
    $installed = "none"
    if ($plain) {
        $agent = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match "Fivenines Monitoring Agent" } |
            Select-Object -First 1
        if ($agent) {
            # Unread, this could be the installed version, which msiexec
            # would report done without applying the password.
            $productCode = $null
            $why = "it has none"
            try {
                $productCode = Get-MsiProductCode $MsiPath
            } catch {
                $why = "$_"
            }
            if (-not $productCode) {
                throw ("Nothing was changed: could not read the MSI's ProductCode ({0}), so whether it is the version already installed, to which msiexec would not apply -ServiceAccountPassword, is not known." -f $why)
            }
            $installed = if ($agent.PSChildName -eq $productCode) { "same" } else { "other" }
        }
    }
    # $WorkDir is already unique: a short name keeps the extracted payload's
    # deepest path under MAX_PATH, which msiexec /a cannot exceed.
    $image = Join-Path $WorkDir "plan"
    try {
        $plan = $null
        $planScript = $null
        try {
            $extract = Start-Process msiexec.exe -ArgumentList @("/a", "`"$MsiPath`"", "/qn", "TARGETDIR=`"$image`"") -Wait -PassThru
            if ($extract.ExitCode -ne 0) {
                throw ("extracting the MSI failed (msiexec /a exit {0})" -f $extract.ExitCode)
            }
            $planScript = Get-ChildItem -LiteralPath $image -Recurse -File -Filter "CreateServiceAccount.ps1" | Select-Object -First 1
            if (-not $planScript) { throw "the MSI carries no CreateServiceAccount.ps1" }
            if (-not (Select-String -LiteralPath $planScript.FullName -SimpleMatch '[switch]$PlanOnly' -Quiet)) {
                throw "the MSI's CreateServiceAccount.ps1 has no -PlanOnly"
            }
            $arguments = @{ ServiceAccount = "$env:COMPUTERNAME\$account" }
            if ($plain) { $arguments.Password = $plain }
            $line = @(& $planScript.FullName @arguments -PlanOnly) | Where-Object { "$_" -like "FIVENINES_PLAN *" } | Select-Object -Last 1
            if (-not $line) { throw "CreateServiceAccount.ps1 -PlanOnly printed no plan" }
            $plan = "$line".Substring("FIVENINES_PLAN ".Length) | ConvertFrom-Json
        } catch {
            if ($installed -eq "same") {
                throw ("Could not run the MSI's account step ({0}), so -ServiceAccountPassword cannot be applied to the installed agent. Nothing was changed." -f $_)
            }
            Write-Warning ("Could not check the service account before installing ({0}); the installer still checks it." -f $_)
            return $false
        }
        # Who the installed service logs on as, for the in-place step.
        $serviceAccount = ""
        $serviceSid = ""
        if ($installed -eq "same") {
            $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='fivenines-agent'"
            if ($service) {
                $serviceAccount = [string]$service.StartName
                try {
                    $serviceSid = (Resolve-ServiceAccountSid $serviceAccount).Value
                } catch {
                    $serviceSid = ""
                }
            }
        }
        $verdict = Get-PreflightVerdict -Plan $plan -HasPassword ([bool]$plain) -Installed $installed `
            -AccountName $account -ServiceAccount $serviceAccount -ServiceSid $serviceSid
        if ($verdict.Action -eq "Refuse") { throw $verdict.Message }
        if ($verdict.Message) { Write-Warning $verdict.Message }
        if ($verdict.Action -ne "InPlace") { return $false }
        Write-Host "This version is already installed: applying the service account password to it..."
        & $planScript.FullName @arguments | Out-Host
        Restart-Service -Name "fivenines-agent" -ErrorAction Stop
        return $true
    } finally {
        Remove-Item -LiteralPath $image -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$passwordArgument = $null
if ($ServiceAccountPassword) {
    try {
        $passwordArgument = ConvertTo-MsiPasswordArgument $ServiceAccountPassword
    } catch {
        Write-Error $_
        exit 1
    }
}

# Detect the currently-installed Fivenines product via the ARP registry.
# We don't use Get-WmiObject Win32_Product because it triggers a costly
# MSI consistency check on every installed product.
$installed = Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "Fivenines Monitoring Agent" } |
    Select-Object -First 1

if (-not $installed) {
    Write-Error "Fivenines agent is not currently installed. Use fivenines_setup.ps1 -Token <token> for a fresh install."
    exit 1
}

Write-Host ("Currently installed: {0} {1}" -f $installed.DisplayName, $installed.DisplayVersion)

# Make sure the existing TOKEN file is still in place before we kick off
# the upgrade. The MSI's RemoveFolder cleans it up during the uninstall
# half of the major upgrade, but our post-install CA recreates it from
# the TOKEN MSI property - which we don't have here. So we read the
# existing TOKEN and feed it back into msiexec.
$tokenPath = Join-Path $env:ProgramData "fivenines_agent\TOKEN"
if (-not (Test-Path $tokenPath)) {
    Write-Error ("Expected TOKEN file at {0} is missing. Did a previous uninstall leave the config dir behind? Run fivenines_setup.ps1 -Token <token> to install cleanly." -f $tokenPath)
    exit 1
}
$token = (Get-Content $tokenPath -Raw).Trim()
if ([string]::IsNullOrWhiteSpace($token)) {
    Write-Error "TOKEN file is empty."
    exit 1
}

Write-Host "Downloading $MsiUrl..."
try {
    Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing
} catch {
    Write-Error "Download failed: $_"
    exit 1
}
Unblock-File -Path $MsiPath

$applied = $false
try {
    $applied = Invoke-AccountPreflight -MsiPath $MsiPath -Password $ServiceAccountPassword -WorkDir $WorkDir
} catch {
    Write-Error $_
    exit 1
}

if (-not $applied) {
    Write-Host "Running upgrade (log: $LogFile)..."
    $msiArgs = @(
        "/i", "`"$MsiPath`"",
        "TOKEN=$token",
        "/qb",
        "/l*v", "`"$LogFile`""
    )
    if ($passwordArgument) {
        $msiArgs += $passwordArgument
    }
    $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Error "msiexec failed with exit code $($proc.ExitCode). See $LogFile."
        exit $proc.ExitCode
    }
}

# After a MajorUpgrade the MSI's StartAgentService CA has already kicked
# the new service via sc.exe start. Pause briefly so SCM has settled, then
# Start-Service as an idempotent safety net (no-op if already Running, or
# kicks it if the MSI's start was lost to a race with reconfiguration).
Start-Sleep -Seconds 2
Start-Service -Name "fivenines-agent" -ErrorAction Stop
Start-Sleep -Seconds 3
$svc = Get-Service -Name "fivenines-agent"
Write-Host ("Service status: {0}" -f $svc.Status)
if ($svc.Status -ne "Running") {
    Write-Warning "Service did not reach Running state after upgrade. Check the WinSW log at C:\ProgramData\fivenines_agent\logs\."
    exit 1
}

# Re-read the installed version so the operator sees what they got.
$updated = Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -match "Fivenines Monitoring Agent" } |
    Select-Object -First 1
if ($updated) {
    Write-Host ("Updated to: {0}" -f $updated.DisplayVersion)
}

# The run succeeded: what its work directory holds goes (the MSI, and the
# log unless -LogFile named another path), so a scheduled run (an RMM tool, a
# task) leaves no MSI copy behind in %TEMP%; a failed run exits before this
# line and keeps it, for the log. The empty directory stays: Windows
# Installer recorded it as the product's install source, and removed, its
# path under C:\Windows\Temp could be recreated by any local user. Only SYSTEM
# and Administrators can write in it, so the removal meets nothing planted.
Get-ChildItem -LiteralPath $WorkDir -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
