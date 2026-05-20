# Provision the agent's dedicated service account and flip the just-registered
# Windows service to run as it.
#
# Invoked by the MSI as a deferred custom action AFTER InstallServices and
# BEFORE WriteTokenAcl/DelegateWmi (which both look up the account's SID).
# When InstallServices runs, the service is registered with LocalSystem as a
# placeholder; this script switches it to the dedicated low-priv account.
#
# Behavior:
#   * If the account does not exist and no Password is supplied, we generate
#     a cryptographically strong random password (24 bytes / ~192 bits, URL-
#     safe base64) and create the account with it.
#   * If the account exists, Password is required - we have no way to read
#     an existing account's password, and registering the service with the
#     wrong one would silently break Start-Service. Tools that pre-provision
#     accounts (Ansible/Chef/etc.) should pass SERVICEACCOUNTPASSWORD on the
#     msiexec command line; everyone else just lets the MSI do the work.
#   * Membership in 'Performance Monitor Users' is required for the PDH-based
#     handle-count metric (files.py win32pdh path); 'Users' is required so the
#     account inherits the default Read+Execute ACE on %ProgramFiles% and can
#     load python311.dll out of the install dir.
#   * SeServiceLogonRight is required by SCM for any non-built-in account.

param(
    [Parameter(Mandatory=$true)][string]$ServiceAccount,
    [string]$Password = ""
)

$ErrorActionPreference = "Stop"

# Resolve the qualified ServiceAccount to a bare local-account name.
# [ComputerName]\name and .\name both refer to the local machine; anything
# else is a domain account, which this MSI does not try to provision.
$bareName = $ServiceAccount
if ($bareName.Contains('\')) {
    $parts = $bareName.Split('\', 2)
    $prefix = $parts[0]
    if ($prefix -ne $env:COMPUTERNAME -and $prefix -ne '.') {
        throw ("Account '{0}' is not a local-machine account (prefix '{1}' != COMPUTERNAME '{2}'). The MSI only provisions local accounts; domain accounts must be pre-staged by the deployer." -f $ServiceAccount, $prefix, $env:COMPUTERNAME)
    }
    $bareName = $parts[1]
}

$exists = $null -ne (Get-LocalUser -Name $bareName -ErrorAction SilentlyContinue)

if ($exists) {
    if ([string]::IsNullOrEmpty($Password)) {
        throw ("Local account '{0}' already exists but SERVICEACCOUNTPASSWORD was not passed to msiexec. Re-run with SERVICEACCOUNTPASSWORD=<the account's actual password> so the service can be registered correctly." -f $bareName)
    }
    Write-Host ("Account '{0}' already exists; using provided password." -f $bareName)
} else {
    if ([string]::IsNullOrEmpty($Password)) {
        $bytes = New-Object byte[] 24
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $rng.GetBytes($bytes)
        } finally {
            $rng.Dispose()
        }
        # URL-safe base64 - sc.exe is fine with [A-Za-z0-9_-], but the standard
        # '/' and '+' characters can trip up command-line parsing in tools that
        # see the password later (e.g. log scrapers).
        $Password = [System.Convert]::ToBase64String($bytes).Replace('/', '_').Replace('+', '-').Replace('=', '')
    }
    $securePwd = ConvertTo-SecureString $Password -AsPlainText -Force
    New-LocalUser -Name $bareName `
        -Password $securePwd `
        -PasswordNeverExpires `
        -UserMayNotChangePassword `
        -AccountNeverExpires `
        -Description "Fivenines monitoring agent service account" `
        -ErrorAction Stop | Out-Null
    Write-Host ("Created local account '{0}'." -f $bareName)
}

# Idempotent group memberships.
$groups = @("Performance Monitor Users", "Users")
foreach ($g in $groups) {
    try {
        Add-LocalGroupMember -Group $g -Member $bareName -ErrorAction Stop
        Write-Host ("Added '{0}' to '{1}'." -f $bareName, $g)
    } catch {
        # The exact exception type for 'already a member' varies by Windows
        # build; fall back to string matching so the install is idempotent
        # across re-runs and partial-rollback recovery.
        if ($_.Exception.Message -match "already a member") {
            Write-Host ("'{0}' already in '{1}' (ok)." -f $bareName, $g)
        } else {
            throw
        }
    }
}

# Grant SeServiceLogonRight via secedit. Without this, SCM refuses to start
# any service under a non-built-in account ("Cannot start service ... on
# computer '.'.") and emits no Event Log entry.
$sid = (New-Object System.Security.Principal.NTAccount($bareName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
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
    $icaclsOut = & icacls.exe $d /grant "$($bareName):(OI)(CI)F" /T /C 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("icacls /grant failed for {0} (exit {1}): {2}" -f $d, $LASTEXITCODE, ($icaclsOut -join "`n"))
    }
    Write-Host ("Granted FullControl on {0} to '{1}'." -f $d, $bareName)
}

# Switch the service from the LocalSystem placeholder (set by InstallServices)
# to the dedicated account. sc.exe's argument syntax requires the literal
# tokens 'obj=' and 'password=' as separate args with the equals sign attached.
$qualified = if ($ServiceAccount.Contains('\')) { $ServiceAccount } else { ".\$bareName" }
$scArgs = @("config", "fivenines-agent", "obj=", $qualified, "password=", $Password)
$scOut = & sc.exe @scArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    throw ("sc.exe config failed (exit {0}): {1}" -f $LASTEXITCODE, ($scOut -join "`n"))
}
Write-Host ("Configured service 'fivenines-agent' to run as '{0}'." -f $qualified)
