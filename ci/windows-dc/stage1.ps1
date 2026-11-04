# Domain-controller E2E, stage 1: first logon of the freshly installed VM, as
# the local Administrator (autounattend). Copies the payload to C:\fn, logs
# the language facts the installer must cope with, registers stage2.ps1 to
# run as SYSTEM at the next boot, and promotes the machine to the first DC of
# a new forest (KUEPFER / kuepfer.test), which reboots it.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here "common.ps1")

try {
    New-Item -ItemType Directory -Force -Path "C:\fn", "C:\fn\logs" | Out-Null
    Copy-Item -Path (Join-Path $here "*") -Destination "C:\fn" -Recurse -Force

    $os = Get-CimInstance Win32_OperatingSystem
    Log ("stage1: {0} {1}, UI {2}, system locale {3}" -f $os.Caption, $os.Version, (Get-UICulture).Name, (Get-WinSystemLocale).Name)
    foreach ($sid in @("S-1-5-32-558", "S-1-5-32-545", "S-1-5-32-544", "S-1-5-18")) {
        $name = ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value
        Log ("  {0} is named '{1}'" -f $sid, $name)
    }

    $system = ([System.Security.Principal.SecurityIdentifier]"S-1-5-18").Translate([System.Security.Principal.NTAccount]).Value
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\fn\stage2.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $system -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "fivenines-dc-stage2" -Action $action -Trigger $trigger -Principal $principal | Out-Null

    Log "stage1: installing the AD DS role"
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null

    Log "stage1: promoting to the first domain controller of kuepfer.test (KUEPFER)"
    $dsrm = ConvertTo-SecureString (Get-Content "C:\fn\password.txt" -Raw).Trim() -AsPlainText -Force
    Install-ADDSForest -DomainName "kuepfer.test" -DomainNetbiosName "KUEPFER" -InstallDns `
        -SafeModeAdministratorPassword $dsrm -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null

    Log "stage1: promoted, rebooting into the domain controller"
    Restart-Computer -Force
} catch {
    Log ("FN-RESULT: FAIL stage1: {0} {1}" -f $_, $_.InvocationInfo.PositionMessage)
    Stop-Computer -Force
}
