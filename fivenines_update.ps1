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

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$MsiUrl = "https://releases.fivenines.io/latest/fivenines-agent-windows-amd64.msi",

    [string]$MsiPath = (Join-Path $env:TEMP "fivenines-agent-windows-amd64.msi"),

    [string]$LogFile = (Join-Path $env:TEMP "fivenines-update.log")
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
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "msiexec failed with exit code $($proc.ExitCode). See $LogFile."
    exit $proc.ExitCode
}

# After a MajorUpgrade the service is registered but not started. Start it
# explicitly so the operator can verify the update without an extra step.
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
