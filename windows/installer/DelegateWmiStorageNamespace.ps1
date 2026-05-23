# Grant the agent's service account read access to the WMI Storage namespace.
#
# Per D12 the service runs as a dedicated low-privilege account in the
# Performance Monitor Users group. That group covers perf counters but does
# NOT cover the root\Microsoft\Windows\Storage WMI namespace where
# MSFT_PhysicalDisk lives (codex finding T1 in the eng review). Without this
# delegation the disk_health collector probes false on a low-priv install
# and the headline feature silently degrades.
#
# This script reads the current namespace security descriptor, builds an
# ACE granting WBEM_ENABLE | WBEM_METHOD_EXECUTE | WBEM_REMOTE_ENABLE to the
# service account's SID, appends it to the DACL, and writes the SD back.
# The ACE has CONTAINER_INHERIT set so sub-namespaces inherit the grant.

param(
    [Parameter(Mandatory=$true)][string]$ServiceAccount
)

$ErrorActionPreference = "Stop"

$Namespace = "root\Microsoft\Windows\Storage"

# Resolve the service account to a SID. Translate raises if the account
# does not exist - fail loudly here rather than silently writing a broken ACE.
# Normalize ".\name" -> "name": NTAccount can't always resolve the dot-prefix
# even though MSI uses it as the local-machine convention.
$accountName = $ServiceAccount
if ($accountName.StartsWith('.\')) {
    $accountName = $accountName.Substring(2)
}
$ntAccount = New-Object System.Security.Principal.NTAccount($accountName)
$sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
Write-Host ("Service account {0} (resolved as {1}) -> SID {2}" -f $ServiceAccount, $accountName, $sid)

# Read the current namespace security descriptor.
# __SystemSecurity is a singleton; "__SystemSecurity=@" is the canonical
# WMI path for the singleton instance (Invoke-WmiMethod can't be given the
# class itself - it needs the instance).
$secPath = "__SystemSecurity=@"
$getResult = Invoke-WmiMethod `
    -Namespace $Namespace `
    -Path $secPath `
    -Name GetSecurityDescriptor `
    -ErrorAction Stop
if ($getResult.ReturnValue -ne 0) {
    throw ("GetSecurityDescriptor failed: ReturnValue={0}" -f $getResult.ReturnValue)
}
$sd = $getResult.Descriptor

# Build a new ACE granting the service account read access.
$WBEM_ENABLE         = 0x1
$WBEM_METHOD_EXECUTE = 0x2
$WBEM_REMOTE_ENABLE  = 0x20
$ACCESS_ALLOWED      = 0
$CONTAINER_INHERIT   = 0x2

# [wmiclass] needs "<namespace>:<class>" - the namespace already contains
# the necessary backslashes and PowerShell double-quoted strings keep them
# literal.
$aceClass = [wmiclass]"$($Namespace):__ACE"
$ace = $aceClass.CreateInstance()
$ace.AccessMask = $WBEM_ENABLE -bor $WBEM_METHOD_EXECUTE -bor $WBEM_REMOTE_ENABLE
$ace.AceType    = $ACCESS_ALLOWED
$ace.AceFlags   = $CONTAINER_INHERIT

$trusteeClass = [wmiclass]"$($Namespace):__Trustee"
$trustee = $trusteeClass.CreateInstance()
$trustee.Name = $accountName
$trustee.SidString = $sid
$ace.Trustee = $trustee

# Append to the DACL and write back.
$dacl = @($sd.DACL) + $ace
$sd.DACL = $dacl

$setResult = Invoke-WmiMethod `
    -Namespace $Namespace `
    -Path $secPath `
    -Name SetSecurityDescriptor `
    -ArgumentList $sd `
    -ErrorAction Stop
if ($setResult.ReturnValue -ne 0) {
    throw ("SetSecurityDescriptor failed: ReturnValue={0}" -f $setResult.ReturnValue)
}

Write-Host ("Granted {0} read access to WMI namespace {1}" -f $ServiceAccount, $Namespace)
