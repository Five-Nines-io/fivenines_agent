# Provision the agent's dedicated service account and flip the just-registered
# Windows service to run as it.
#
# Invoked by the MSI as a deferred custom action AFTER InstallServices and
# BEFORE WriteTokenAcl/DelegateWmi (which both look up the account's SID).
# When InstallServices runs, the service is registered with LocalSystem as a
# placeholder; this script switches it to the dedicated low-priv account.
#
# Behavior (the decision itself is Get-AccountPlan, below):
#   * If the account does not exist and no Password is supplied, we generate
#     a cryptographically strong random password (32 characters, over 180
#     bits) and create the account with it.
#   * If the account exists AND has the MSI-managed Description tag we set
#     on creation, this is an upgrade / reinstall: generate a fresh random
#     password and update the existing account via Set-LocalUser. The old
#     password lived only in the LSA secret of the just-removed service;
#     the new ServiceInstall about to run receives our new password via
#     sc.exe config. Operator workflow: no SERVICEACCOUNTPASSWORD needed.
#   * If the account exists with a DIFFERENT Description (or none), it
#     was created by something outside the MSI - Ansible, Chef, or a
#     hand-rolled provisioning step. Require Password explicitly so we
#     don't silently clobber operator-managed credentials.
#   * On a DOMAIN CONTROLLER there are no local accounts: New-LocalUser
#     creates a DOMAIN account, which every DC of the domain sees and may run
#     the agent as. Rotating its password from one DC would stop the agent on
#     the others, so a DC rotates only an account its own installer created
#     with a random password; see the Description tags below.
#   * Membership in 'Performance Monitor Users' is required for the PDH-based
#     handle-count metric (files.py win32pdh path); 'Users' is required so the
#     account inherits the default Read+Execute ACE on %ProgramFiles% and can
#     load python311.dll out of the install dir. Both are joined by their
#     well-known SID, never by name: the names are translated with the OS
#     install language, so the English names failed the install (1603) on
#     every non-English Windows.
#   * SeServiceLogonRight is required by SCM for any non-built-in account.

param(
    [Parameter(Mandatory=$true)][string]$ServiceAccount,
    [string]$Password = ""
)

$ErrorActionPreference = "Stop"

# Resolve the qualified ServiceAccount to a bare local-account name.
# [ComputerName]\name and .\name both refer to the local machine; anything
# else is a domain account, which this MSI does not try to provision. On a
# domain controller the bare name then names a domain account, since the
# domain is the only account database a DC has: leave SERVICEACCOUNT unset
# (or use .\name) there rather than spelling the domain.
$bareName = $ServiceAccount
if ($bareName.Contains('\')) {
    $parts = $bareName.Split('\', 2)
    $prefix = $parts[0]
    if ($prefix -ne $env:COMPUTERNAME -and $prefix -ne '.') {
        throw ("Account '{0}' is not a local-machine account (prefix '{1}' != COMPUTERNAME '{2}'). The MSI only provisions local accounts; domain accounts must be pre-staged by the deployer." -f $ServiceAccount, $prefix, $env:COMPUTERNAME)
    }
    $bareName = $parts[1]
}

# BUILTIN groups the account joins, by well-known SID (see the header).
$PERFORMANCE_MONITOR_USERS_SID = "S-1-5-32-558"
$USERS_SID = "S-1-5-32-545"

# The account's Description records who manages its password, which decides
# whether a later install may rotate it (Get-AccountPlan). 48 characters at
# most: New-LocalUser refuses a longer one.
#   * MSI_MANAGED_DESCRIPTION: created by this installer on a member server or
#     a workgroup machine, where the account is local to the machine. Every
#     release before domain-controller support also wrote it on a DC.
#   * DC_MANAGED_PREFIX + <computer name>: created by the installer on that
#     domain controller with a random password nobody else knows. Only that DC
#     rotates it.
#   * DC_OPERATOR_DESCRIPTION: a domain account whose password the operator
#     supplied (SERVICEACCOUNTPASSWORD), so several DCs can share it. No
#     install ever rotates it.
# DC_MANAGED_PREFIX is repeated in fivenines_uninstall.ps1, which deletes the
# account only when this DC manages it (windows.yml keeps the two equal).
$MSI_MANAGED_DESCRIPTION = "Fivenines monitoring agent service account"
$DC_MANAGED_PREFIX = "Fivenines agent, managed on "
$DC_OPERATOR_DESCRIPTION = "Fivenines agent, operator-managed password"

# Uniform index in [0, Bound) from a CSPRNG. Bound is never above 64 here, so
# one byte is enough; the rejection loop keeps (byte % Bound) from
# over-weighting the first (256 % Bound) values. .NET Framework has no
# RandomNumberGenerator.GetInt32, and this custom action runs under
# powershell.exe (5.1), so the sampling is hand-rolled rather than borrowed.
function Get-RandomIndex {
    param(
        [int]$Bound,
        [System.Security.Cryptography.RandomNumberGenerator]$Rng
    )

    $limit = 256 - (256 % $Bound)
    $buf = New-Object byte[] 1
    do {
        $Rng.GetBytes($buf)
    } while ($buf[0] -ge $limit)
    return [int]($buf[0] % $Bound)
}

function Get-RandomChar {
    param(
        [string]$Alphabet,
        [System.Security.Cryptography.RandomNumberGenerator]$Rng
    )

    return $Alphabet[(Get-RandomIndex $Alphabet.Length $Rng)]
}

function New-RandomPassword {
    # URL-safe alphabet - sc.exe is fine with [A-Za-z0-9_-], but the standard
    # base64 '/' and '+' characters can trip up command-line parsing in tools
    # that see the password later (e.g. log scrapers).
    #
    # Every character class is drawn EXPLICITLY rather than left to chance.
    # Windows' complexity policy wants at least three of {upper, lower, digit,
    # non-alphanumeric}, and a purely random 32-character draw over this
    # 64-symbol alphabet contains neither a digit nor a '-'/'_' about once in
    # 770 tries ((52/64)^32). When that happened New-LocalUser threw
    # InvalidPasswordException, this custom action returned 1603 and the whole
    # MSI rolled back: a rare but real failed install on a customer machine,
    # not merely a flaky CI run. It stayed hidden because the E2E smoke job
    # was gated behind a test job that was itself failing.
    $upper   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $lower   = 'abcdefghijklmnopqrstuvwxyz'
    $digit   = '0123456789'
    $special = '-_'
    $all     = $upper + $lower + $digit + $special

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        # One guaranteed character per class, then fill to 32. Pinning four
        # positions costs almost nothing against a 64-symbol alphabet: this is
        # still well over 180 bits, against 192 for a wholly free draw.
        $chars = @(
            (Get-RandomChar $upper $rng),
            (Get-RandomChar $lower $rng),
            (Get-RandomChar $digit $rng),
            (Get-RandomChar $special $rng)
        )
        while ($chars.Count -lt 32) {
            $chars += (Get-RandomChar $all $rng)
        }

        # Fisher-Yates with the same CSPRNG, so the four guaranteed characters
        # do not always sit in the first four positions in a fixed class order.
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = Get-RandomIndex ($i + 1) $rng
            $tmp = $chars[$i]
            $chars[$i] = $chars[$j]
            $chars[$j] = $tmp
        }

        return (-join $chars)
    } finally {
        $rng.Dispose()
    }
}

# Decide what to do with the service account. Pure (no system calls), so CI
# can exercise the domain-controller rules on a runner that is not one.
# Returns @{ Action; Description; Message }:
#   Action       Create | Rotate | UseProvided | Refuse
#   Description  the tag to write, or $null to leave the account's as it is
#   Message      the error to raise, for Refuse
function Get-AccountPlan {
    param(
        [bool]$IsDomainController,
        [bool]$Exists,
        [string]$Description,
        [bool]$HasPassword,
        [string]$AccountName,
        [string]$ComputerName
    )

    $ownTag = $DC_MANAGED_PREFIX + $ComputerName

    if (-not $Exists) {
        if (-not $IsDomainController) {
            return @{ Action = "Create"; Description = $MSI_MANAGED_DESCRIPTION; Message = $null }
        }
        if ($HasPassword) {
            return @{ Action = "Create"; Description = $DC_OPERATOR_DESCRIPTION; Message = $null }
        }
        return @{ Action = "Create"; Description = $ownTag; Message = $null }
    }

    if (-not $IsDomainController) {
        if ($HasPassword) {
            return @{ Action = "UseProvided"; Description = $null; Message = $null }
        }
        if ($Description -eq $MSI_MANAGED_DESCRIPTION) {
            return @{ Action = "Rotate"; Description = $null; Message = $null }
        }
        return @{ Action = "Refuse"; Description = $null; Message = (
            "Local account '{0}' exists but is not MSI-managed (Description={1}). Re-run with SERVICEACCOUNTPASSWORD=<the account's actual password> so the service can be registered correctly without changing the existing credentials." -f $AccountName, $Description) }
    }

    # Domain controller, existing (domain) account.
    $installerManaged = ($Description -eq $MSI_MANAGED_DESCRIPTION) -or ($Description -like "$DC_MANAGED_PREFIX*")
    if ($HasPassword) {
        # The operator knows the password now, so other DCs may share the
        # account: retag it so that no installer, the one that created it
        # included, rotates it under them.
        $retag = if ($installerManaged) { $DC_OPERATOR_DESCRIPTION } else { $null }
        return @{ Action = "UseProvided"; Description = $retag; Message = $null }
    }
    if ($Description -eq $ownTag) {
        return @{ Action = "Rotate"; Description = $null; Message = $null }
    }
    if ($Description -eq $MSI_MANAGED_DESCRIPTION) {
        # Left by a release before domain-controller support, which rotated
        # it on every install whatever the DC: adopting it here is what that
        # release would have done, and it is what lets an install that
        # failed half-way on a DC (the account was created, nothing else)
        # be retried without a password.
        return @{ Action = "Rotate"; Description = $ownTag; Message = $null }
    }
    if ($Description -like "$DC_MANAGED_PREFIX*") {
        $owner = $Description.Substring($DC_MANAGED_PREFIX.Length)
        return @{ Action = "Refuse"; Description = $null; Message = (
            "Domain account '{0}' was created by the fivenines installer on domain controller {1}, with a random password only that DC knows; changing it from here would stop the agent there. To run the agent on several domain controllers as this account, reset its password in Active Directory to a value you keep, then install on each of them, {1} included, with SERVICEACCOUNTPASSWORD=<that value> (fivenines_setup.ps1 -ServiceAccountPassword)." -f $AccountName, $owner) }
    }
    return @{ Action = "Refuse"; Description = $null; Message = (
        "Domain account '{0}' exists (Description={1}) and this installer will not change its password: on a domain controller it is a domain account, which other domain controllers may run the agent as. Re-run with SERVICEACCOUNTPASSWORD=<the account's current password> (fivenines_setup.ps1 or fivenines_update.ps1 -ServiceAccountPassword)." -f $AccountName, $Description) }
}

# DomainRole 4 = backup DC, 5 = primary DC.
$isDomainController = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
$accountKind = if ($isDomainController) { "domain" } else { "local" }

$existing = Get-LocalUser -Name $bareName -ErrorAction SilentlyContinue
$existingDescription = if ($existing) { [string]$existing.Description } else { "" }
$plan = Get-AccountPlan `
    -IsDomainController $isDomainController `
    -Exists ([bool]$existing) `
    -Description $existingDescription `
    -HasPassword (-not [string]::IsNullOrEmpty($Password)) `
    -AccountName $bareName `
    -ComputerName $env:COMPUTERNAME

if ($plan.Action -eq "Refuse") {
    throw $plan.Message
} elseif ($plan.Action -eq "Rotate") {
    # The old password is gone with the old service (see the header).
    $Password = New-RandomPassword
    $securePwd = ConvertTo-SecureString $Password -AsPlainText -Force
    Set-LocalUser -Name $bareName -Password $securePwd -ErrorAction Stop
    Write-Host ("Rotated password on MSI-managed {0} account '{1}' (upgrade path)." -f $accountKind, $bareName)
} elseif ($plan.Action -eq "UseProvided") {
    Write-Host ("Account '{0}' already exists; using provided password." -f $bareName)
} else {
    if ([string]::IsNullOrEmpty($Password)) {
        $Password = New-RandomPassword
    }
    $securePwd = ConvertTo-SecureString $Password -AsPlainText -Force
    New-LocalUser -Name $bareName `
        -Password $securePwd `
        -PasswordNeverExpires `
        -UserMayNotChangePassword `
        -AccountNeverExpires `
        -Description $plan.Description `
        -ErrorAction Stop | Out-Null
    if ($isDomainController) {
        Write-Host ("Created domain account '{0}' (a domain controller has no local accounts)." -f $bareName)
    } else {
        Write-Host ("Created local account '{0}'." -f $bareName)
    }
}
if ($plan.Description -and $plan.Action -ne "Create") {
    Set-LocalUser -Name $bareName -Description $plan.Description -ErrorAction Stop
    Write-Host ("Tagged account '{0}': {1}." -f $bareName, $plan.Description)
}

$account = Get-LocalUser -Name $bareName -ErrorAction Stop
$sid = $account.SID.Value

# Idempotent group memberships, by SID (see the header). A re-run or an
# upgrade finds the account already a member: MemberExistsException is
# matched by type, since its message is translated too.
foreach ($groupSid in @($PERFORMANCE_MONITOR_USERS_SID, $USERS_SID)) {
    $group = Get-LocalGroup -SID $groupSid -ErrorAction Stop
    try {
        Add-LocalGroupMember -Group $group -Member $account -ErrorAction Stop
        Write-Host ("Added '{0}' to '{1}' ({2})." -f $bareName, $group.Name, $groupSid)
    } catch [Microsoft.PowerShell.Commands.MemberExistsException] {
        Write-Host ("'{0}' already in '{1}' ({2}) (ok)." -f $bareName, $group.Name, $groupSid)
    }
}

# Grant SeServiceLogonRight via secedit. Without this, SCM refuses to start
# any service under a non-built-in account ("Cannot start service ... on
# computer '.'.") and emits no Event Log entry. On a domain controller this
# is the DC's own policy, which the Default Domain Controllers Policy leaves
# undefined; a GPO that does define "Log on as a service" for the DCs
# replaces it at the next refresh and must list the account itself.
$tmpCfg = Join-Path $env:TEMP "fnsetup_secpolicy.cfg"
$tmpDb  = Join-Path $env:TEMP "fnsetup_secpolicy.sdb"
try {
    secedit /export /cfg $tmpCfg /areas USER_RIGHTS /quiet | Out-Null
    $content = Get-Content $tmpCfg
    $found = $false
    for ($i = 0; $i -lt $content.Length; $i++) {
        if ($content[$i] -match '^SeServiceLogonRight\s*=') {
            if ($content[$i] -notmatch [regex]::Escape("*$sid")) {
                $content[$i] = $content[$i].TrimEnd() + ",*$sid"
            }
            $found = $true
            break
        }
    }
    if (-not $found) {
        $appended = @()
        foreach ($line in $content) {
            $appended += $line
            if ($line -match '^\[Privilege Rights\]') {
                $appended += "SeServiceLogonRight = *$sid"
            }
        }
        $content = $appended
    }
    $content | Set-Content -Encoding ascii $tmpCfg
    secedit /configure /db $tmpDb /cfg $tmpCfg /areas USER_RIGHTS /quiet | Out-Null
    Write-Host ("Granted SeServiceLogonRight to '{0}'." -f $bareName)
} finally {
    Remove-Item $tmpCfg, $tmpDb -ErrorAction SilentlyContinue
}

# Grant the service account FullControl on the config + log dirs. The MSI
# created these dirs with only Administrators + SYSTEM via util:PermissionEx
# (because [SERVICEACCOUNT] couldn't be resolved at InstallFiles time); now
# that the account exists, give it the access it needs to read the config
# and write rolling log files. /T applies recursively so anything WinSW or
# the agent later creates inherits the grant.
$programData = if ($env:ProgramData) { $env:ProgramData } else { Join-Path $env:SystemDrive "ProgramData" }
$dirs = @(
    (Join-Path $programData "fivenines_agent"),
    (Join-Path $programData "fivenines_agent\logs")
)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        Write-Warning ("Expected directory {0} not present; skipping ACL grant." -f $d)
        continue
    }
    $icaclsOut = & icacls.exe $d /grant "*$($sid):(OI)(CI)F" /T /C 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("icacls /grant failed for {0} (exit {1}): {2}" -f $d, $LASTEXITCODE, ($icaclsOut -join "`n"))
    }
    Write-Host ("Granted FullControl on {0} to '{1}'." -f $d, $bareName)
}

# Switch the service from the LocalSystem placeholder (set by InstallServices)
# to the dedicated account. sc.exe's argument syntax requires the literal
# tokens 'obj=' and 'password=' as separate args with the equals sign attached.
# The account is named as its SID translates back: <ComputerName>\name on a
# member server, <DOMAIN>\name on a domain controller, whose account domain
# is the domain rather than the DC's own name (the MSI's default
# SERVICEACCOUNT spells the latter).
$qualified = $account.SID.Translate([System.Security.Principal.NTAccount]).Value
$scArgs = @("config", "fivenines-agent", "obj=", $qualified, "password=", $Password)
$scOut = & sc.exe @scArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    throw ("sc.exe config failed (exit {0}): {1}" -f $LASTEXITCODE, ($scOut -join "`n"))
}
Write-Host ("Configured service 'fivenines-agent' to run as '{0}'." -f $qualified)
