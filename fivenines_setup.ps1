# Fivenines Monitoring Agent - Windows installer bootstrap
#
# Downloads the latest MSI and installs the agent under a dedicated low-priv
# local service account. Parallels fivenines_setup.sh for Linux.
#
# Usage:
#   .\fivenines_setup.ps1 -Token <enrollment-token>
#
# One-liner (run as Administrator):
#   iwr https://releases.fivenines.io/latest/fivenines_setup.ps1 -OutFile setup.ps1
#   .\setup.ps1 -Token <enrollment-token>
#
# What this script does (each step is idempotent enough to re-run on failure):
#   1. Verifies it's running elevated.
#   2. Downloads fivenines-agent-windows-amd64.msi from the configured URL
#      (defaults to https://releases.fivenines.io/latest/...).
#   3. Strips Mark-of-the-Web so SmartScreen does not block the silent install.
#   4. Runs msiexec with TOKEN and a verbose log file. The MSI itself handles
#      service-account creation, password generation, group membership, the
#      SeServiceLogonRight grant, WMI Storage namespace delegation, and
#      writing TOKEN under a restrictive ACL.
#   5. Starts the service and reports its status.

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Token,

    [string]$MsiUrl = "https://releases.fivenines.io/latest/fivenines-agent-windows-amd64.msi",

    [string]$MsiPath = (Join-Path $env:TEMP "fivenines-agent-windows-amd64.msi"),

    [string]$LogFile = (Join-Path $env:TEMP "fivenines-setup.log")
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

Write-Host "Downloading $MsiUrl..."
try {
    Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing
} catch {
    Write-Error "Download failed: $_"
    exit 1
}

# Mark-of-the-Web is what makes SmartScreen / Defender silently refuse a
# /qn install of a downloaded MSI. Stripping it is safe here: the operator
# explicitly ran the installer, and Trusted Signing will eventually replace
# this dance once the MSI is signed.
Unblock-File -Path $MsiPath

Write-Host "Installing (log: $LogFile)..."
$msiArgs = @(
    "/i", "`"$MsiPath`"",
    "TOKEN=$Token",
    "/qb",
    "/l*v", "`"$LogFile`""
)
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "msiexec failed with exit code $($proc.ExitCode). See $LogFile."
    exit $proc.ExitCode
}

Write-Host "Starting service..."
# Brief pause so the MSI's StartAgentService custom action (sc.exe start)
# has fully settled in the SCM before we issue Start-Service here. Without
# it, Start-Service can race the still-completing service reconfiguration
# from CreateServiceAccount.ps1 and throw "service cannot accept control
# messages at this time". Start-Service is idempotent against a service
# already transitioning to Running, so this redundant call is safe.
Start-Sleep -Seconds 2
Start-Service -Name "fivenines-agent" -ErrorAction Stop
Start-Sleep -Seconds 3

$svc = Get-Service -Name "fivenines-agent"
Write-Host ("Service status: {0}" -f $svc.Status)
if ($svc.Status -ne "Running") {
    Write-Warning "Service did not reach Running state. Check the WinSW log at C:\ProgramData\fivenines_agent\logs\."
    exit 1
}

Write-Host "Done. The agent will appear on the fivenines.io dashboard shortly."
