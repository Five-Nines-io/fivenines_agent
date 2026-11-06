# Domain-controller E2E, stage 2: runs as SYSTEM at the first boot after the
# promotion (like the MSI's own custom actions), plays every account
# scenario a domain controller meets, reports each check on COM1, ends with
# one "FN-RESULT: PASS" or "FN-RESULT: FAIL" line and powers the VM off.
#
# Accounts are changed through the ADSI WinNT provider (as SYSTEM, like the
# installer) and checked through the AD cmdlets, an independent path.

$ErrorActionPreference = "Stop"
. "C:\fn\common.ps1"

if (Test-Path "C:\fn\stage2.started") {
    Log "stage2: already ran once, not twice"
    Stop-Computer -Force
    exit 0
}
New-Item -ItemType File -Path "C:\fn\stage2.started" | Out-Null

$NewMsi = "C:\fn\new.msi"
$OldMsi = "C:\fn\old.msi"
$Account = "fivenines-agent"
$Domain = "KUEPFER"
$Legacy = "Fivenines monitoring agent service account"
$Own = "Fivenines agent, managed on " + $env:COMPUTERNAME
$OtherDc = "Fivenines agent, managed on DC2"
$Operator = "Fivenines agent, operator-managed password"

$script:failures = New-Object System.Collections.Generic.List[string]

function Check {
    param([bool]$Condition, [string]$What)

    if ($Condition) {
        Log "ok   $What"
    } else {
        Log "FAIL $What"
        $script:failures.Add($What)
    }
}

function Invoke-Msi {
    param([string]$Name, [string[]]$Arguments)

    # 1601 (the Windows Installer service could not be reached) and 1618
    # (another installation is running) are the service settling after the
    # previous run, not a result: retry them.
    $log = "C:\fn\logs\$Name.log"
    $script:InstallStartedAt = Get-Date
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        $p = Start-Process msiexec.exe -ArgumentList ($Arguments + @("/qn", "/l*v", "`"$log`"")) -Wait -PassThru
        Log ("msiexec {0}: exit {1}" -f $Name, $p.ExitCode)
        if ($p.ExitCode -ne 1601 -and $p.ExitCode -ne 1618) { break }
        Start-Sleep -Seconds 20
    }
    return @{ ExitCode = $p.ExitCode; Log = $log; Token = $null }
}

function Install-Agent {
    param([string]$Name, [string]$Msi = $NewMsi, [string]$Password = "")

    $token = "ci-dc-token-" + (Get-Random)
    $arguments = @("/i", "`"$Msi`"", "TOKEN=$token")
    if ($Password) { $arguments += "SERVICEACCOUNTPASSWORD=`"$Password`"" }
    $r = Invoke-Msi $Name $arguments
    $r.Token = $token
    # This MSI's verbose log carries neither secret (v1.22.0's did).
    if ($Msi -eq $NewMsi) { Check-NoSecrets $r.Log $Name $token $Password }
    return $r
}

function Check-NoSecrets {
    param([string]$LogPath, [string]$Label, [string]$Token, [string]$Password)

    if (-not (Test-Path $LogPath)) { return }
    $text = [System.IO.File]::ReadAllText($LogPath)
    Check (-not $text.Contains($Token)) "$Label the TOKEN value is not in the MSI log"
    if ($Password) { Check (-not $text.Contains($Password)) "$Label the password is not in the MSI log" }
}

function Test-AgentInstalled {
    return [bool](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "Fivenines Monitoring Agent" })
}

# fivenines_update.ps1 from the payload, bounded; $null on success.
function Invoke-UpdateScript {
    param([string]$Name, [string]$Password = "")

    return Invoke-Bootstrap -Arguments @($Name, $Password) -Script {
        param($Name, $Password)
        $arguments = @{ MsiUrl = "file:///C:/fn/new.msi"; MsiPath = "C:\fn\downloaded-update.msi"; LogFile = "C:\fn\logs\$Name.log" }
        if ($Password) { $arguments.ServiceAccountPassword = ConvertTo-SecureString $Password -AsPlainText -Force }
        $global:LASTEXITCODE = 0
        & "C:\fn\fivenines_update.ps1" @arguments
        "EXIT:$LASTEXITCODE"
    }
}

function Uninstall-Agent {
    param([string]$Name)

    return Invoke-Msi $Name @("/x", "`"$NewMsi`"")
}

# The custom actions' own output (WixQuietExec lines), never their command
# lines, which carry TOKEN and SERVICEACCOUNTPASSWORD.
function Get-CustomActionLines {
    param([string]$LogPath)

    if (-not (Test-Path $LogPath)) { return @() }
    return @(Get-Content $LogPath | Where-Object { $_ -match "WixQuietExec" -and $_ -notmatch "powershell\.exe" })
}

# The errors an MSI log recorded (a bootstrap script's msiexec runs with no
# window in this session 0 task: the log is the only place they show).
function Show-MsiErrors {
    param([string]$LogPath)

    if (-not (Test-Path $LogPath)) { Log "  (no MSI log at $LogPath)"; return }
    Get-Content $LogPath | Where-Object { $_ -match "Error \d{4}|Fehler \d{4}|Return value 3|WixQuietExec:.*(Exception|Error)" } |
        Select-Object -Last 15 | ForEach-Object { Log ("  | " + $_.Trim()) }
}

function Show-CustomActionOutput {
    param([string]$LogPath)

    foreach ($line in (Get-CustomActionLines $LogPath | Select-Object -Last 30)) {
        Log ("  | " + $line.Trim())
    }
}

# PowerShell wraps a long error over several log lines: compare with every
# whitespace removed.
function Test-CustomActionSaid {
    param([string]$LogPath, [string]$Text)

    $joined = (Get-CustomActionLines $LogPath | ForEach-Object { $_ -replace "^.*?WixQuietExec:\s*", "" }) -join ""
    return ($joined -replace "\s", "").Contains(($Text -replace "\s", ""))
}

# The installer's own helpers, as they ship.
$uninstallSource = Get-Content "C:\fn\fivenines_uninstall.ps1" -Raw
foreach ($fn in @("Get-WinNTUser", "Get-WmiNamespaceSD")) {
    Invoke-Expression ([regex]::Match($uninstallSource, "(?ms)^function $fn \{.*?^\}").Value)
}

function Get-AccountEntry {
    return Get-WinNTUser $Account
}

function Set-AccountDescription {
    param([string]$Description)

    $e = Get-AccountEntry
    $e.Put("Description", $Description)
    $e.SetInfo()
}

function Get-AdAccount {
    return Get-ADUser -Filter "SamAccountName -eq '$Account'" -Properties Description, userAccountControl
}

function New-TestPassword {
    $chars = [char[]]"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "Fn9-" + (-join (1..20 | ForEach-Object { $chars | Get-Random }))
}

function Wait-AgentRunning {
    for ($i = 0; $i -lt 30; $i++) {
        $s = Get-Service -Name "fivenines-agent" -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq "Running") { return $true }
        if ($i -eq 10 -and $s) { Start-Service -Name "fivenines-agent" -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 3
    }
    Log "  service status: $((Get-Service -Name 'fivenines-agent' -ErrorAction SilentlyContinue).Status)"
    Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Service Control Manager" } -MaxEvents 6 -ErrorAction SilentlyContinue |
        ForEach-Object { Log ("  | SCM {0}: {1}" -f $_.Id, ($_.Message -replace "\s+", " ")) }
    Get-ChildItem (Join-Path $env:ProgramData "fivenines_agent\logs") -File -ErrorAction SilentlyContinue | ForEach-Object {
        Get-Content $_.FullName -Tail 8 -ErrorAction SilentlyContinue | ForEach-Object { Log ("  | log: " + $_) }
    }
    return $false
}

# Run one of the bootstrap scripts (fivenines_setup.ps1, fivenines_uninstall.ps1)
# in a job, bounded: in this SYSTEM task's session 0 their msiexec runs /qn,
# so nothing waits for a click, but a hung msiexec, or the Windows Installer
# service still busy through the retries, must not hold the stage. Returns
# $null on success, else why it failed.
function Invoke-Bootstrap {
    param([scriptblock]$Script, [object[]]$Arguments = @(), [int]$TimeoutSeconds = 600)

    $script:InstallStartedAt = Get-Date
    $job = Start-Job -ScriptBlock $Script -ArgumentList $Arguments
    if (-not (Wait-Job $job -Timeout $TimeoutSeconds)) {
        Stop-Job $job
        Get-Process -Name msiexec -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        return "timed out after $TimeoutSeconds s (a hung msiexec?)"
    }
    try {
        $output = @(Receive-Job $job -ErrorAction Stop)
    } catch {
        return "failed: $_"
    }
    foreach ($line in $output) { Log ("  | " + $line) }
    if ($job.State -ne "Completed") { return "job $($job.State)" }
    if (-not ($output -contains "EXIT:0")) { return "exit code: $(@($output | Where-Object { "$_" -like 'EXIT:*' }) -join ',')" }
    return $null
}

function Test-Installed {
    param([string]$Label, [string]$Description)

    $user = Get-AdAccount
    Check ($null -ne $user) "$Label the domain account exists"
    if (-not $user) { return }
    Check ($user.Description -eq $Description) "$Label account tagged '$Description' (is '$($user.Description)')"
    Check (($user.userAccountControl -band 0x10000) -ne 0) "$Label password never expires"
    $sid = $user.SID.Value

    $svc = Get-CimInstance Win32_Service -Filter "Name='fivenines-agent'"
    Check ($svc.StartName -eq "$Domain\$Account") "$Label service logs on as $Domain\$Account (is '$($svc.StartName)')"
    Check (Wait-AgentRunning) "$Label service reaches Running"
    # Running is no proof of health now that the SCM restarts the service: the
    # agent must keep one process for 20s, with no unexpected termination of
    # the service (SCM events 7031/7034) since the last msiexec or bootstrap.
    $first = (Get-CimInstance Win32_Service -Filter "Name='fivenines-agent'").ProcessId
    Start-Sleep -Seconds 20
    $stops = @(Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Service Control Manager"; Id = 7031, 7034; StartTime = $script:InstallStartedAt } -ErrorAction SilentlyContinue |
               Where-Object { @("Fivenines Monitoring Agent", "fivenines-agent") -contains $_.Properties[0].Value })
    $same = (Get-CimInstance Win32_Service -Filter "Name='fivenines-agent'").ProcessId -eq $first
    Check ($same -and $stops.Count -eq 0) "$Label agent keeps running on one process (unexpected stops since the install: $($stops.Count))"
    $key = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\fivenines-agent"
    Check ($key.Start -eq 2 -and $key.DelayedAutostart -eq 1) "$Label service is Automatic (Delayed Start) (Start=$($key.Start) DelayedAutostart=$($key.DelayedAutostart))"
    # SERVICE_FAILURE_ACTIONS as the SCM stores it: five DWORDs (reset period,
    # two pointer slots, the action count, a pointer slot), then (type, delay
    # in ms) per action, type 1 = restart; sc.exe qfailure is localized.
    $bin = $key.FailureActions
    $actions = if (-not $bin) { "none" } else {
        "reset={0} {1}" -f [BitConverter]::ToUInt32($bin, 0), ((0..([BitConverter]::ToUInt32($bin, 12) - 1) |
            ForEach-Object { "{0}/{1}" -f [BitConverter]::ToUInt32($bin, 20 + 8 * $_), [BitConverter]::ToUInt32($bin, 24 + 8 * $_) }) -join " ")
    }
    Check ($actions -eq "reset=3600 1/10000 1/30000 1/60000") "$Label service restarts on failure (FailureActions: $actions)"

    foreach ($group in @("S-1-5-32-558", "S-1-5-32-545")) {
        $members = @(Get-ADGroupMember -Identity $group | ForEach-Object { $_.SID.Value })
        Check ($members -contains $sid) "$Label account is a member of $group"
    }

    $acl = Get-Acl (Join-Path $env:ProgramData "fivenines_agent\TOKEN")
    $granted = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
                 ForEach-Object { $_.IdentityReference.Value })
    foreach ($want in @($sid, "S-1-5-32-544", "S-1-5-18")) {
        Check ($granted -contains $want) "$Label TOKEN ACL grants $want"
    }

    $grants = @(Get-WmiStorageAces | Where-Object { $_.SecurityIdentifier.Value -eq $sid })
    Check ($grants.Count -eq 1) "$Label WMI Storage namespace grants the account exactly once (ACEs: $($grants.Count))"
}

# The WMI Storage namespace's ACEs, read in binary like the installer does
# (GetSecurityDescriptor fails once an ACE names a deleted account).
function Get-WmiStorageAces {
    $sd = Get-WmiNamespaceSD "root\Microsoft\Windows\Storage"
    return @($sd.DiscretionaryAcl | Where-Object { $_ -is [System.Security.AccessControl.KnownAce] })
}

try {
    Log "stage2: waiting for Active Directory"
    $deadline = (Get-Date).AddMinutes(25)
    while ($true) {
        try {
            Get-ADDomain | Out-Null
            break
        } catch {
            if ((Get-Date) -gt $deadline) { throw "Active Directory did not come up: $_" }
            Start-Sleep -Seconds 15
        }
    }
    $role = (Get-CimInstance Win32_ComputerSystem).DomainRole
    Check ($role -eq 5) "the VM is the primary domain controller (DomainRole $role)"

    # The finding the fix rests on: the LocalAccounts cmdlets see nothing here.
    foreach ($probe in @(
        @("Get-LocalGroup -SID S-1-5-32-558", { Get-LocalGroup -SID "S-1-5-32-558" -ErrorAction Stop }),
        @("Get-LocalUser -Name Administrator", { Get-LocalUser -Name "Administrator" -ErrorAction Stop })
    )) {
        try {
            $found = & $probe[1]
            Log ("INFO {0} on a DC: found '{1}'" -f $probe[0], $found.Name)
        } catch {
            Log ("INFO {0} on a DC: {1}" -f $probe[0], $_.Exception.Message)
        }
    }

    Log "== S1: v1.22.0 on this DC, the failure the trial reported"
    $r = Install-Agent "s1-v1.22.0" -Msi $OldMsi
    Check ($r.ExitCode -eq 1603) "v1.22.0 fails with 1603"
    Show-CustomActionOutput $r.Log
    Check ((Get-AdAccount).Description -eq $Legacy) "v1.22.0 left the account behind with its old tag"

    Log "== S2: this MSI over the account v1.22.0 left (the trial's retry)"
    $r = Install-Agent "s2-retry"
    Check ($r.ExitCode -eq 0) "S2 install exits 0"
    if ($r.ExitCode -ne 0) { Show-CustomActionOutput $r.Log }
    Test-Installed "S2" $Own

    Log "== S3: reinstall, the account tagged for this DC is rotated"
    Check ((Uninstall-Agent "s3-uninstall").ExitCode -eq 0) "S3 uninstall exits 0"
    $r = Install-Agent "s3-reinstall"
    Check ($r.ExitCode -eq 0) "S3 install exits 0"
    if ($r.ExitCode -ne 0) { Show-CustomActionOutput $r.Log }
    Test-Installed "S3" $Own

    Log "== S4: an account another DC's installer created is refused"
    Check ((Uninstall-Agent "s4-uninstall").ExitCode -eq 0) "S4 uninstall exits 0"
    Set-AccountDescription $OtherDc
    $r = Install-Agent "s4-other-dc"
    Check ($r.ExitCode -eq 1603) "S4 install fails with 1603"
    Check (Test-CustomActionSaid $r.Log "created by the fivenines installer on domain controller DC2") "S4 the log says why"
    Check ((Get-AdAccount).Description -eq $OtherDc) "S4 the account is untouched"
    Check ($null -eq (Get-Service -Name "fivenines-agent" -ErrorAction SilentlyContinue)) "S4 no service left after the rollback"

    Log "== S5: the operator's password, through fivenines_setup.ps1 -ServiceAccountPassword"
    $password = New-TestPassword
    (Get-AccountEntry).SetPassword($password)
    # The script ends with 'exit 1' when the service does not run, and
    # throws (Write-Error under Stop) on any other failure.
    $setupToken = "ci-dc-token-" + (Get-Random)
    $setupFailed = Invoke-Bootstrap -Arguments @($password, $setupToken) -Script {
        param($Password, $Token)
        $secure = ConvertTo-SecureString $Password -AsPlainText -Force
        $global:LASTEXITCODE = 0
        & "C:\fn\fivenines_setup.ps1" -Token $Token -MsiUrl "file:///C:/fn/new.msi" `
            -MsiPath "C:\fn\downloaded.msi" -LogFile "C:\fn\logs\s5-setup.log" -ServiceAccountPassword $secure
        "EXIT:$LASTEXITCODE"
    }
    Check ($null -eq $setupFailed) "S5 fivenines_setup.ps1 succeeds ($setupFailed)"
    if ($setupFailed) { Show-CustomActionOutput "C:\fn\logs\s5-setup.log"; Show-MsiErrors "C:\fn\logs\s5-setup.log" }
    Check-NoSecrets "C:\fn\logs\s5-setup.log" "S5" $setupToken $password
    Test-Installed "S5" $Operator

    Log "== S6: an operator-managed account needs its password"
    Check ((Uninstall-Agent "s6-uninstall").ExitCode -eq 0) "S6 uninstall exits 0"
    $r = Install-Agent "s6-no-password"
    Check ($r.ExitCode -eq 1603) "S6 install without the password fails with 1603"
    Check (Test-CustomActionSaid $r.Log "SERVICEACCOUNTPASSWORD=<the account's current password>") "S6 the log says why"
    $r = Install-Agent "s6-wrong-password" -Password ("Fn9-wrong-" + (Get-Random))
    Check ($r.ExitCode -eq 1603) "S6 install with a wrong password fails with 1603"
    Check (Test-CustomActionSaid $r.Log "does not log domain account 'fivenines-agent' on") "S6 the log says the password is wrong"
    Check ((Get-AdAccount).Description -eq $Operator) "S6 a wrong password changes no tag"
    $r = Install-Agent "s6-password" -Password $password
    Check ($r.ExitCode -eq 0) "S6 install with the password exits 0"
    if ($r.ExitCode -ne 0) { Show-CustomActionOutput $r.Log }
    Test-Installed "S6" $Operator

    Log "== S10: fivenines_update.ps1 without the password, on an operator-managed account"
    $failed = Invoke-UpdateScript "s10-update-no-password"
    Check ("$failed" -match "Nothing was changed") "S10 the update is refused ($failed)"
    Check (-not (Test-Path "C:\fn\logs\s10-update-no-password.log")) "S10 refused before msiexec ran"
    Check (Test-AgentInstalled) "S10 the agent is still installed"
    Check (Wait-AgentRunning) "S10 the service still runs"

    Log "== S11: fivenines_update.ps1 with a wrong password"
    $failed = Invoke-UpdateScript "s11-update-wrong" ("Fn9-wrong-" + (Get-Random))
    Check ("$failed" -match "does not log") "S11 the update is refused: wrong password ($failed)"
    Check (-not (Test-Path "C:\fn\logs\s11-update-wrong.log")) "S11 refused before msiexec ran"
    Check (Test-AgentInstalled) "S11 the agent is still installed"
    Check ((Get-AdAccount).Description -eq $Operator) "S11 no tag changed"

    Log "== S12: a new password, applied by fivenines_update.ps1 to the installed version"
    $password = New-TestPassword
    (Get-AccountEntry).SetPassword($password)
    $agentToken = (Get-Content (Join-Path $env:ProgramData "fivenines_agent\TOKEN") -Raw).Trim()
    $failed = Invoke-UpdateScript "s12-update-new-password" $password
    Check ($null -eq $failed) "S12 fivenines_update.ps1 succeeds ($failed)"
    if ($failed) { Show-MsiErrors "C:\fn\logs\s12-update-new-password.log" }
    Check (-not (Test-Path "C:\fn\logs\s12-update-new-password.log")) "S12 applied without an msiexec run"
    Restart-Service -Name "fivenines-agent" -ErrorAction SilentlyContinue
    Test-Installed "S12" $Operator

    Log "== S7: fivenines_uninstall.ps1 keeps a shared account"
    $failed = Invoke-Bootstrap -Arguments @("C:\fn\logs\s7-uninstall.log") -Script {
        param($LogFile)
        $global:LASTEXITCODE = 0
        & "C:\fn\fivenines_uninstall.ps1" -LogFile $LogFile
        "EXIT:$LASTEXITCODE"
    }
    Check ($null -eq $failed) "S7 fivenines_uninstall.ps1 succeeds ($failed)"
    if ($failed) { Show-MsiErrors "C:\fn\logs\s7-uninstall.log" }
    Check ($null -eq (Get-Service -Name "fivenines-agent" -ErrorAction SilentlyContinue)) "S7 the service is gone"
    Check ((Get-AdAccount).Description -eq $Operator) "S7 the shared account is kept"

    Log "== S8: fivenines_uninstall.ps1 deletes this DC's own account"
    Set-AccountDescription $Own
    $r = Install-Agent "s8-install"
    Check ($r.ExitCode -eq 0) "S8 install exits 0"
    # An uninstall a second after the install finds the service still
    # starting, which msiexec cannot stop yet: let it come up, as on a real
    # host.
    Check (Wait-AgentRunning) "S8 service reaches Running"
    $deletedSid = (Get-AdAccount).SID.Value
    $failed = Invoke-Bootstrap -Arguments @("C:\fn\logs\s8-uninstall.log") -Script {
        param($LogFile)
        $global:LASTEXITCODE = 0
        & "C:\fn\fivenines_uninstall.ps1" -LogFile $LogFile
        "EXIT:$LASTEXITCODE"
    }
    Check ($null -eq $failed) "S8 fivenines_uninstall.ps1 succeeds ($failed)"
    if ($failed) { Show-MsiErrors "C:\fn\logs\s8-uninstall.log" }
    Check ($null -eq (Get-AdAccount)) "S8 the account is deleted"
    Check (@(Get-WmiStorageAces | Where-Object { $_.SecurityIdentifier.Value -eq $deletedSid }).Count -eq 0) "S8 no WMI grant left for the deleted account"

    Log "== S8b: an account deleted by hand leaves its WMI grant behind; the next install must cope"
    $r = Install-Agent "s8b-install"
    Check ($r.ExitCode -eq 0) "S8b install exits 0"
    Check (Wait-AgentRunning) "S8b service reaches Running"
    Check ((Uninstall-Agent "s8b-uninstall").ExitCode -eq 0) "S8b uninstall exits 0"
    ([ADSI]("WinNT://{0},computer" -f $env:COMPUTERNAME)).Delete("user", $Account)
    Check ($null -eq (Get-AdAccount)) "S8b the account is deleted by hand"

    Log "== S9: a fresh install on a DC with no account yet"
    $r = Install-Agent "s9-fresh"
    Check ($r.ExitCode -eq 0) "S9 install exits 0"
    if ($r.ExitCode -ne 0) { Show-CustomActionOutput $r.Log }
    Test-Installed "S9" $Own
} catch {
    $script:failures.Add("stage2 aborted")
    Log ("FAIL stage2 aborted: {0} {1}" -f $_, $_.InvocationInfo.PositionMessage)
}

if ($script:failures.Count -gt 0) {
    Log ("FN-RESULT: FAIL ({0}): {1}" -f $script:failures.Count, ($script:failures -join " | "))
} else {
    Log "FN-RESULT: PASS"
}
Stop-Computer -Force
