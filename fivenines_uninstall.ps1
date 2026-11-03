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
#      LSA after the user is deleted - tidy up so secedit /export is clean).
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

    [string]$LogFile = (Join-Path $env:TEMP "fivenines-uninstall.log")
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
    exit 0
}

# Same tag as CreateServiceAccount.ps1, which writes it on an account the
# installer created on a domain controller (windows.yml keeps the two equal).
$DC_MANAGED_PREFIX = "Fivenines agent, managed on "

# Capture the SID before deleting the account so we can clean up the
# SeServiceLogonRight grant secedit left behind.
$user = Get-LocalUser -Name "fivenines-agent" -ErrorAction SilentlyContinue
if ($user) {
    $sid = $user.SID.Value
    # DomainRole 4 = backup DC, 5 = primary DC.
    $isDomainController = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    if ((-not $isDomainController) -or ($user.Description -eq ($DC_MANAGED_PREFIX + $env:COMPUTERNAME))) {
        Write-Host "Removing account fivenines-agent (SID $sid)..."
        Remove-LocalUser -Name "fivenines-agent" -ErrorAction Stop
    } else {
        Write-Host ("Keeping domain account fivenines-agent (Description={0}): other domain controllers may run the agent as it. Delete it in Active Directory once none does." -f $user.Description)
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

Write-Host "Uninstall complete."
