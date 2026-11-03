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
$AccountPath = "WinNT://{0}/{1},user" -f $env:COMPUTERNAME, $Account
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

    $log = "C:\fn\logs\$Name.log"
    $p = Start-Process msiexec.exe -ArgumentList ($Arguments + @("/qn", "/l*v", "`"$log`"")) -Wait -PassThru
    Log ("msiexec {0}: exit {1}" -f $Name, $p.ExitCode)
    return @{ ExitCode = $p.ExitCode; Log = $log; Token = $null }
}

function Install-Agent {
    param([string]$Name, [string]$Msi = $NewMsi, [string]$Password = "")

    $token = "ci-dc-token-" + (Get-Random)
    $arguments = @("/i", "`"$Msi`"", "TOKEN=$token")
    if ($Password) { $arguments += "SERVICEACCOUNTPASSWORD=`"$Password`"" }
    $r = Invoke-Msi $Name $arguments
    $r.Token = $token
    return $r
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

function Report-TokenInLog {
    param($Result)

    $hit = Select-String -Path $Result.Log -SimpleMatch $Result.Token -Quiet
    Log ("INFO the TOKEN value appears in the verbose MSI log: {0}" -f [bool]$hit)
}

function Get-AccountEntry {
    if ([ADSI]::Exists($AccountPath)) { return [ADSI]$AccountPath }
    return $null
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

    $sd = (Invoke-WmiMethod -Namespace "root\Microsoft\Windows\Storage" -Path "__SystemSecurity=@" -Name GetSecurityDescriptor).Descriptor
    Check (@($sd.DACL | ForEach-Object { $_.Trustee.SIDString }) -contains $sid) "$Label WMI Storage namespace grants the account"
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
    Report-TokenInLog $r
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
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    # The script ends with 'exit 1' when the service does not run, and
    # throws (Write-Error under Stop) on any other failure.
    $setupFailed = $null
    $global:LASTEXITCODE = 0
    try {
        & "C:\fn\fivenines_setup.ps1" -Token ("ci-dc-token-" + (Get-Random)) -MsiUrl "file:///C:/fn/new.msi" `
            -MsiPath "C:\fn\downloaded.msi" -LogFile "C:\fn\logs\s5-setup.log" -ServiceAccountPassword $secure
        if ($LASTEXITCODE -ne 0) { $setupFailed = "exit $LASTEXITCODE" }
    } catch {
        $setupFailed = $_
    }
    Check ($null -eq $setupFailed) "S5 fivenines_setup.ps1 succeeds ($setupFailed)"
    if ($setupFailed) { Show-CustomActionOutput "C:\fn\logs\s5-setup.log" }
    Test-Installed "S5" $Operator

    Log "== S6: an operator-managed account needs its password"
    Check ((Uninstall-Agent "s6-uninstall").ExitCode -eq 0) "S6 uninstall exits 0"
    $r = Install-Agent "s6-no-password"
    Check ($r.ExitCode -eq 1603) "S6 install without the password fails with 1603"
    Check (Test-CustomActionSaid $r.Log "SERVICEACCOUNTPASSWORD=<the account's current password>") "S6 the log says why"
    $r = Install-Agent "s6-password" -Password $password
    Check ($r.ExitCode -eq 0) "S6 install with the password exits 0"
    if ($r.ExitCode -ne 0) { Show-CustomActionOutput $r.Log }
    Test-Installed "S6" $Operator

    Log "== S7: fivenines_uninstall.ps1 keeps a shared account"
    & "C:\fn\fivenines_uninstall.ps1" -LogFile "C:\fn\logs\s7-uninstall.log"
    Check ($null -eq (Get-Service -Name "fivenines-agent" -ErrorAction SilentlyContinue)) "S7 the service is gone"
    Check ((Get-AdAccount).Description -eq $Operator) "S7 the shared account is kept"

    Log "== S8: fivenines_uninstall.ps1 deletes this DC's own account"
    Set-AccountDescription $Own
    $r = Install-Agent "s8-install"
    Check ($r.ExitCode -eq 0) "S8 install exits 0"
    & "C:\fn\fivenines_uninstall.ps1" -LogFile "C:\fn\logs\s8-uninstall.log"
    Check ($null -eq (Get-AdAccount)) "S8 the account is deleted"

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
