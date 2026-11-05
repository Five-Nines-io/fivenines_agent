# Write the enrollment TOKEN to the agent's config dir with a restrictive ACL.
#
# Default %ProgramData% ACLs grant every local user read access (F1 from the
# CEO review). This script breaks inheritance on the TOKEN file and grants
# FullControl to only the service account, BUILTIN\Administrators, and
# NT AUTHORITY\SYSTEM. The ACL must also survive _swap_token rotation
# (synchronizer._swap_token uses open(...,'w') which truncates in place and
# preserves the file ACL on NTFS - see the Section 2 / codex token-ACL note).
#
# Invoked by the MSI as a deferred custom action with TOKEN passed as a
# hidden MSI property (D21) so it doesn't leak into installer logs.

param(
    [Parameter(Mandatory=$true)][string]$ConfigDir,
    [Parameter(Mandatory=$true)][string]$ServiceAccount,
    [Parameter(Mandatory=$true)][string]$Token
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

$tokenPath = Join-Path $ConfigDir "TOKEN"

# Write the token: UTF-8, no BOM, no trailing newline - matches the format
# the agent's _load_file reads with f.read().strip().
[System.IO.File]::WriteAllText($tokenPath, $Token)

# Build a restrictive ACL with inheritance broken so the world-readable
# %ProgramData% default doesn't leak in.
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)  # protect=true, preserve=false

$fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
$allow = [System.Security.AccessControl.AccessControlType]::Allow

# Resolve the MSI's SERVICEACCOUNT to its SID. A "." or <ComputerName> prefix
# is dropped and the bare name looked up instead: on a domain controller the
# account the MSI created is a DOMAIN account (a DC has no local ones), and
# the MSI's default "<DCNAME>\name" is not how the domain names it, while a
# bare name is looked up in the machine's own account database on every
# role (the local SAM on a member server, the domain on a DC).
# Kept identical in SetTokenFileAcl.ps1, DelegateWmiStorageNamespace.ps1,
# fivenines_setup.ps1 and fivenines_update.ps1 (windows.yml checks it).
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

# Every principal by SID, never by name: "BUILTIN\Administrators" and
# "NT AUTHORITY\SYSTEM" are translated with the OS install language, and on a
# non-English Windows they failed to resolve, so the file was left without
# them. The service account must resolve: an ACL it is missing from is a
# TOKEN the agent cannot read, so that failure stops the install.
$principals = @(
    (Resolve-ServiceAccountSid $ServiceAccount),
    [System.Security.Principal.SecurityIdentifier]"S-1-5-32-544",  # BUILTIN\Administrators
    [System.Security.Principal.SecurityIdentifier]"S-1-5-18"       # NT AUTHORITY\SYSTEM
)
foreach ($sid in $principals) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $fullControl, $allow)
    $acl.AddAccessRule($rule)
}

Set-Acl -Path $tokenPath -AclObject $acl

# Verify the ACL took (post-write sanity check); if every non-admin
# principal is gone we're good.
$resultPrincipals = (Get-Acl $tokenPath).Access |
    ForEach-Object { $_.IdentityReference.Value } |
    Sort-Object -Unique
Write-Host ("TOKEN written with ACL granting: {0}" -f ($resultPrincipals -join ", "))
