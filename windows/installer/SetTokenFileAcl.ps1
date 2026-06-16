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

function Resolve-LocalAccount {
    param([string]$Name)
    # ".\name" is the MSI convention but System.Security.Principal.NTAccount
    # rejects the dot-prefix on some Windows configurations - normalize to the
    # bare username so NTAccount falls back to the local machine.
    if ($Name.StartsWith('.\')) { return $Name.Substring(2) }
    return $Name
}

$principals = @($ServiceAccount, "BUILTIN\Administrators", "NT AUTHORITY\SYSTEM")
foreach ($id in $principals) {
    $normalized = Resolve-LocalAccount $id
    try {
        $sid = New-Object System.Security.Principal.NTAccount($normalized)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $fullControl, $allow)
        $acl.AddAccessRule($rule)
    } catch {
        Write-Warning ("Could not grant FullControl to {0} (resolved as {1}): {2}" -f $id, $normalized, $_)
    }
}

Set-Acl -Path $tokenPath -AclObject $acl

# Verify the ACL took (post-write sanity check); if every non-admin
# principal is gone we're good.
$resultPrincipals = (Get-Acl $tokenPath).Access |
    ForEach-Object { $_.IdentityReference.Value } |
    Sort-Object -Unique
Write-Host ("TOKEN written with ACL granting: {0}" -f ($resultPrincipals -join ", "))
