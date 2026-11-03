# Grant the agent's service account read access to the WMI Storage namespace.
#
# Per D12 the service runs as a dedicated low-privilege account in the
# Performance Monitor Users group. That group covers perf counters but does
# NOT cover the root\Microsoft\Windows\Storage WMI namespace where
# MSFT_PhysicalDisk lives (codex finding T1 in the eng review). Without this
# delegation the disk_health collector probes false on a low-priv install
# and the headline feature silently degrades.
#
# This script reads the current namespace security descriptor, adds an ACE
# granting WBEM_ENABLE | WBEM_METHOD_EXECUTE | WBEM_REMOTE_ENABLE to the
# service account's SID unless one already does (a reinstall keeps the
# account), and writes the SD back. The ACE has CONTAINER_INHERIT set so
# sub-namespaces inherit the grant.

param(
    [Parameter(Mandatory=$true)][string]$ServiceAccount
)

$ErrorActionPreference = "Stop"

$Namespace = "root\Microsoft\Windows\Storage"

# Resolve the MSI's SERVICEACCOUNT to its SID. A "." or <ComputerName> prefix
# is dropped and the bare name looked up instead: on a domain controller the
# account the MSI created is a DOMAIN account (a DC has no local ones), and
# the MSI's default "<DCNAME>\name" is not how the domain names it, while a
# bare name is looked up in the machine's own account database on every
# role (the local SAM on a member server, the domain on a DC).
# Kept identical in SetTokenFileAcl.ps1 and DelegateWmiStorageNamespace.ps1
# (windows.yml checks it).
function Resolve-ServiceAccountSid {
    param([Parameter(Mandatory=$true)][string]$Account)

    $name = $Account
    if ($name.Contains('\')) {
        $parts = $name.Split('\', 2)
        if ($parts[0] -eq '.' -or $parts[0] -eq $env:COMPUTERNAME) {
            $name = $parts[1]
        }
    }
    $ntAccount = New-Object System.Security.Principal.NTAccount($name)
    return $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
}

# Resolve the service account to a SID. Translate raises if the account
# does not exist - fail loudly here rather than silently writing a broken ACE.
$sid = (Resolve-ServiceAccountSid $ServiceAccount).Value
Write-Host ("Service account {0} -> SID {1}" -f $ServiceAccount, $sid)

# The descriptor is read and written in binary form (GetSD/SetSD), never as
# the object GetSecurityDescriptor returns: that one resolves every ACE's
# trustee to a name, and fails ("unexpected error") once an ACE names an
# account that no longer exists -- which an uninstall that deleted the
# account used to leave behind, so the next install failed with 1603.
# (Kept identical in fivenines_uninstall.ps1; windows.yml checks it.)
# Read and write a WMI namespace's security descriptor in binary form
# (__SystemSecurity GetSD/SetSD), with the args-array calling convention of
# Microsoft's own namespace-security sample: the out parameter comes back in
# the array, and SetSD takes the bytes as its one argument (setting them on a
# GetMethodParameters object raised InvalidCastException).
function Get-WmiNamespaceSD {
    param([string]$Namespace)

    $security = Get-WmiObject -Namespace $Namespace -Class __SystemSecurity
    $out = @($null)
    $rv = $security.PsBase.InvokeMethod("GetSD", $out)
    if ($rv -ne 0) { throw ("GetSD on {0} failed: {1}" -f $Namespace, $rv) }
    return [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$out[0], 0)
}

function Set-WmiNamespaceSD {
    param([string]$Namespace, [System.Security.AccessControl.RawSecurityDescriptor]$Descriptor)

    $bytes = New-Object byte[] $Descriptor.BinaryLength
    $Descriptor.GetBinaryForm($bytes, 0)
    $security = Get-WmiObject -Namespace $Namespace -Class __SystemSecurity
    $rv = $security.PsBase.InvokeMethod("SetSD", (, $bytes))
    if ($rv -ne 0) { throw ("SetSD on {0} failed: {1}" -f $Namespace, $rv) }
}

$sd = Get-WmiNamespaceSD $Namespace
if ($null -eq $sd.DiscretionaryAcl) {
    throw ("WMI namespace {0} has no DACL" -f $Namespace)
}

$WBEM_ENABLE         = 0x1
$WBEM_METHOD_EXECUTE = 0x2
$WBEM_REMOTE_ENABLE  = 0x20
$mask = $WBEM_ENABLE -bor $WBEM_METHOD_EXECUTE -bor $WBEM_REMOTE_ENABLE
$sidObject = [System.Security.Principal.SecurityIdentifier]$sid
$allowed = [System.Security.AccessControl.AceQualifier]::AccessAllowed
$inherited = [System.Security.AccessControl.AceFlags]::Inherited

$alreadyGranted = $false
foreach ($existingAce in $sd.DiscretionaryAcl) {
    if ($existingAce -is [System.Security.AccessControl.CommonAce] -and
        $existingAce.AceQualifier -eq $allowed -and
        $existingAce.SecurityIdentifier -eq $sidObject -and
        ($existingAce.AccessMask -band $mask) -eq $mask) {
        $alreadyGranted = $true
    }
}

if ($alreadyGranted) {
    Write-Host ("{0} already has read access to WMI namespace {1}" -f $ServiceAccount, $Namespace)
    exit 0
}

# Explicit ACEs go before inherited ones (the canonical order).
$position = $sd.DiscretionaryAcl.Count
for ($i = 0; $i -lt $sd.DiscretionaryAcl.Count; $i++) {
    if (($sd.DiscretionaryAcl[$i].AceFlags -band $inherited) -ne 0) {
        $position = $i
        break
    }
}
$ace = [System.Security.AccessControl.CommonAce]::new(
    [System.Security.AccessControl.AceFlags]::ContainerInherit, $allowed, $mask, $sidObject, $false, $null)
$sd.DiscretionaryAcl.InsertAce($position, $ace)

Set-WmiNamespaceSD $Namespace $sd

Write-Host ("Granted {0} read access to WMI namespace {1}" -f $ServiceAccount, $Namespace)
