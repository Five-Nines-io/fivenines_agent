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
