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

# The account step of the MSI about to be installed, run before msiexec: the
# MSI's own CreateServiceAccount.ps1, extracted by an administrative install
# (which runs no custom action). Its -PlanOnly run reads the account and
# checks a supplied password, changing nothing, and a refusal stops here:
# inside the MSI it comes too late on an upgrade, after Windows Installer has
# removed the running agent. With a password and this very version already
# installed, msiexec would only run in maintenance mode, which never reaches
# the account, so the step itself applies the password (as this elevated
# session) and the service is restarted with it; returns $true then, as
# there is nothing left for msiexec to do. An MSI too old for -PlanOnly, or
# one that cannot be read, leaves the decision to the installer.
function Invoke-AccountPreflight {
    param([string]$MsiPath, [System.Security.SecureString]$Password)

    $plain = if ($Password) {
        (New-Object System.Management.Automation.PSCredential("x", $Password)).GetNetworkCredential().Password
    } else { "" }
    $sameProduct = $false
    if ($plain) {
        $agent = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match "Fivenines Monitoring Agent" } |
            Select-Object -First 1
        try {
            $sameProduct = [bool]($agent -and ($agent.PSChildName -eq (Get-MsiProductCode $MsiPath)))
        } catch {
            Write-Warning ("Could not read the MSI's ProductCode ({0}); installing it as usual." -f $_)
        }
    }
    $image = Join-Path $env:TEMP ("fivenines-plan-" + [guid]::NewGuid())
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
            $arguments = @{ ServiceAccount = "$env:COMPUTERNAME\fivenines-agent" }
            if ($plain) { $arguments.Password = $plain }
            $line = @(& $planScript.FullName @arguments -PlanOnly) | Where-Object { "$_" -like "FIVENINES_PLAN *" } | Select-Object -Last 1
            if (-not $line) { throw "CreateServiceAccount.ps1 -PlanOnly printed no plan" }
            $plan = "$line".Substring("FIVENINES_PLAN ".Length) | ConvertFrom-Json
        } catch {
            if ($sameProduct) {
                throw ("Could not run the MSI's account step ({0}), so -ServiceAccountPassword cannot be applied to the installed agent. Nothing was changed." -f $_)
            }
            Write-Warning ("Could not check the service account before installing ({0}); the installer still checks it." -f $_)
            return $false
        }
        if ($plan.action -eq "Refuse") {
            throw ("Nothing was changed: {0}" -f $plan.message)
        }
        if (-not $sameProduct) { return $false }
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
    $applied = Invoke-AccountPreflight -MsiPath $MsiPath -Password $ServiceAccountPassword
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
