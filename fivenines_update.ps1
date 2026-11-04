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

    [string]$MsiPath = (Join-Path $env:TEMP "fivenines-agent-windows-amd64.msi"),

    [string]$LogFile = (Join-Path $env:TEMP "fivenines-update.log"),

    # The service account's password, when it is not one the MSI may rotate
    # (see the domain controller note above).
    [System.Security.SecureString]$ServiceAccountPassword
)

$ErrorActionPreference = "Stop"

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
# line: refused here rather than failing the install with 1603.
function ConvertTo-MsiPasswordArgument {
    param([Parameter(Mandatory=$true)][System.Security.SecureString]$Password)

    $plain = (New-Object System.Management.Automation.PSCredential("x", $Password)).GetNetworkCredential().Password
    if ([string]::IsNullOrEmpty($plain)) {
        throw "-ServiceAccountPassword is empty."
    }
    if ($plain.Contains('"') -or $plain.EndsWith('\')) {
        throw "-ServiceAccountPassword cannot contain a double quote or end with a backslash (the MSI passes it on a quoted command line). Set a password without them on the account first."
    }
    return "SERVICEACCOUNTPASSWORD=`"$plain`""
}

# The account decision the MSI will make, made before msiexec runs: the
# MSI's own CreateServiceAccount.ps1, extracted by an administrative install
# (which runs no custom action), in -PlanOnly mode reads the account and,
# for an existing one, checks the password, changing nothing. Returns its
# {action, message}, or $null for an MSI too old to have -PlanOnly. Inside
# the MSI a refusal comes too late on an upgrade: Windows Installer has
# already removed the running agent, and a failed install does not put it
# back.
function Get-MsiAccountPlan {
    param([string]$MsiPath, [string]$Password)

    $image = Join-Path $env:TEMP ("fivenines-plan-" + [guid]::NewGuid())
    try {
        $extract = Start-Process msiexec.exe -ArgumentList @("/a", "`"$MsiPath`"", "/qn", "TARGETDIR=`"$image`"") -Wait -PassThru
        if ($extract.ExitCode -ne 0) {
            throw ("extracting the MSI failed (msiexec /a exit {0})" -f $extract.ExitCode)
        }
        $planScript = Get-ChildItem -LiteralPath $image -Recurse -File -Filter "CreateServiceAccount.ps1" | Select-Object -First 1
        if (-not $planScript) { throw "the MSI carries no CreateServiceAccount.ps1" }
        if (-not (Select-String -LiteralPath $planScript.FullName -SimpleMatch '[switch]$PlanOnly' -Quiet)) { return $null }
        $arguments = @{ ServiceAccount = "$env:COMPUTERNAME\fivenines-agent"; PlanOnly = $true }
        if ($Password) { $arguments.Password = $Password }
        $line = @(& $planScript.FullName @arguments) | Where-Object { "$_" -like "FIVENINES_PLAN *" } | Select-Object -Last 1
        if (-not $line) { throw "CreateServiceAccount.ps1 -PlanOnly printed no plan" }
        return ("$line".Substring("FIVENINES_PLAN ".Length) | ConvertFrom-Json)
    } finally {
        Remove-Item -LiteralPath $image -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Refuse before msiexec what the MSI would refuse, then, with a password,
# remove an installed agent first (its account is kept): installing the
# same version again is a maintenance run of the MSI, which never reaches
# the account, so the password would silently not be applied.
function Invoke-AccountPreflight {
    param([string]$MsiPath, [System.Security.SecureString]$Password, [string]$LogFile)

    $plain = if ($Password) {
        (New-Object System.Management.Automation.PSCredential("x", $Password)).GetNetworkCredential().Password
    } else { "" }
    $plan = $null
    try {
        $plan = Get-MsiAccountPlan -MsiPath $MsiPath -Password $plain
    } catch {
        Write-Warning ("Could not check the service account before installing ({0}); the installer still checks it." -f $_)
    }
    if ($plan -and $plan.action -eq "Refuse") {
        throw ("Nothing was changed: {0}" -f $plan.message)
    }
    if (-not $Password) { return }
    $agent = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "Fivenines Monitoring Agent" } |
        Select-Object -First 1
    if (-not $agent) { return }
    Write-Host ("Removing {0} {1} to apply the service account password (the account is kept)..." -f $agent.DisplayName, $agent.DisplayVersion)
    $removeLog = [System.IO.Path]::ChangeExtension($LogFile, ".remove.log")
    $remove = Start-Process msiexec.exe -ArgumentList @("/x", $agent.PSChildName, "/qb", "/l*v", "`"$removeLog`"") -Wait -PassThru
    if ($remove.ExitCode -ne 0) {
        throw ("removing the installed agent failed (msiexec /x exit {0}, log {1})" -f $remove.ExitCode, $removeLog)
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

try {
    Invoke-AccountPreflight -MsiPath $MsiPath -Password $ServiceAccountPassword -LogFile $LogFile
} catch {
    Write-Error $_
    exit 1
}

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
