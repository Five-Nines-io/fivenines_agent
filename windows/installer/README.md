# MSI installer

This directory builds the Windows MSI installer for the fivenines agent.

- Install location: `%ProgramFiles%\fivenines-agent\` (admin-write-only).
- Config dir: `%ProgramData%\fivenines_agent\` with a restrictive ACL.
- Service: registered as `fivenines-agent` (Automatic Delayed Start) running
  as a dedicated low-privilege local account (a domain account on a domain
  controller, see "Domain controllers" below) in the Performance Monitor Users
  group (D12). WMI Storage-namespace read access is delegated to that account
  by `DelegateWmiStorageNamespace.ps1` (D19) so disk-health works.
- Token: passed via the **hidden** `TOKEN` MSI property (D21). Written to
  `%ProgramData%\fivenines_agent\TOKEN` with `SetTokenFileAcl.ps1` so only
  the service account, Administrators, and SYSTEM have access (F1).

## Files

- `Product.wxs` - WiX 4 source. Components, service registration, ACL
  components, and the security custom-action hookups.
- `CreateServiceAccount.ps1` - deferred custom action: creates (or rotates)
  the service account, joins its groups, grants SeServiceLogonRight and the
  config-dir ACL, and flips the service to it.
- `SetTokenFileAcl.ps1` - deferred custom action: writes TOKEN with a
  restrictive ACL, inheritance broken.
- `DelegateWmiStorageNamespace.ps1` - deferred custom action: grants the
  service account read access to `root\Microsoft\Windows\Storage` so the
  disk-health collector can query `MSFT_PhysicalDisk` without admin.

## Rules the custom actions keep

- **No principal by name.** Group and built-in account names are translated
  with the OS install language, so `Performance Monitor Users`, `Users`,
  `BUILTIN\Administrators` and `NT AUTHORITY\SYSTEM` are looked up by their
  well-known SID (S-1-5-32-558, -545, -544, S-1-5-18), errors are matched by
  HRESULT rather than message, and WiX's `util:PermissionEx` uses the names it
  maps to a SID itself (`Administrators`, `LocalSystem`). A lookup by English
  name fails on a non-English Windows.
- **No LocalAccounts cmdlets for the account.** `Get-LocalUser`,
  `Get-LocalGroup`, `Set-LocalUser` and `Add-LocalGroupMember` enumerate SAM one
  entry at a time and drop any reply carrying more than one, which is what a
  domain controller's directory-backed SAM sends: on a DC they find nothing
  (only `New-LocalUser` works, so v1.22.0 created the account, then failed with
  "Group Performance Monitor Users was not found" on an English DC). The account
  and its groups go through the ADSI WinNT provider (`WinNT://<ComputerName>`,
  the NetUser*/NetLocalGroup* APIs), which is the local SAM on a member server
  and the domain on a DC.
- **No secret in the log.** TOKEN and SERVICEACCOUNTPASSWORD are hidden
  properties, and so are the CreateServiceAccount and WriteTokenAcl
  properties the SetProperty actions copy them into, with `HideTarget` on
  both custom actions: otherwise the verbose log (which the bootstrap scripts
  always write) printed them three times each. The E2E and the DC runs search
  every log for the values.
- **Decide before msiexec.** `CreateServiceAccount.ps1 -PlanOnly` reads the
  account, checks a supplied password and prints the plan without changing
  anything. `fivenines_setup.ps1` and `fivenines_update.ps1` run it from the
  MSI they downloaded (an administrative install extracts it and runs no
  custom action) and stop on a refusal, because inside the MSI a refusal comes
  after Windows Installer has removed the running agent on an upgrade. With
  `-ServiceAccountPassword` and the same ProductCode installed, msiexec would
  only run a maintenance pass, which never reaches the account: the scripts
  run that account step themselves and restart the service, removing nothing,
  but only for a Rotate or UseProvided plan whose account (the plan's `sid`)
  is the one the service's StartName resolves to. Run alone, the step would
  otherwise move the service to another account, or create one without its
  WMI grant: they refuse and point to a reinstall. With a password and an
  agent installed, an unreadable ProductCode is a refusal too (it may be
  this very version). The decision is `Get-PreflightVerdict`, pure, tested
  case by case in `windows.yml`. A password is checked with a LogonUser
  network logon (no SMB session): wrong, locked, disabled, password expired,
  must-change and account expired are refused by name, and 1385 (the host
  denies the account network logon) counts as checked, since Windows checks
  the logon type only once the credentials were accepted. Anything else
  leaves it unchecked (`checked: false` in the plan): the scripts warn and
  use it as given, since the account step applies any password and a wrong
  one leaves a service that does not start, which a rerun with the right
  password repairs in place. The scripts run the step in their own process,
  for the plan and in place alike, with `TEMP` and `TMP` pointed at their
  private work directory: it compiles C# with Add-Type, which writes the
  source and the assembly it then loads in `%TEMP%`, and an administrator's
  own `%TEMP%` is writable by their unelevated processes.
- **The agent directories through handles.** The account step gives the
  account FullControl on `%ProgramData%\fivenines_agent` and its `logs`
  (`Grant-AgentDirectory`, through the `FiveninesAgentDirectory` type it
  compiles with Add-Type), as SYSTEM, in directories the account can write
  to. A grant already there is kept (read by path: a directory moved behind
  a junction that already has it is left as it is; a read that fails counts
  as no grant). Otherwise every directory from the one below `%ProgramData%`
  down to the target is opened without following a link at it, with the
  right to list it, and shared for reading only, so none can be renamed,
  deleted or replaced meanwhile (Windows applies a share mode only to a
  handle holding a data right such as listing); a junction, a symbolic link
  or anything that is not a directory (a hard link to a file) is refused, and
  so is a target whose last handle's final path is not its own under
  `%ProgramData%` as that resolves (a share mode does not keep a directory
  from being turned into a junction). `-PlanOnly` refuses the same, before
  msiexec (a check it cannot run, Add-Type blocked, is left to the account
  step); the ACE is written through the last handle. No `/T` and no walk of
  its own: Windows propagates the inheritable ACE to the existing children
  that inherit it.
- **The WMI namespace ACL in binary.** `DelegateWmiStorageNamespace.ps1` reads
  and writes `root\Microsoft\Windows\Storage`'s descriptor with
  `__SystemSecurity` `GetSD`/`SetSD` and `RawSecurityDescriptor`, never
  `GetSecurityDescriptor`: that one resolves every ACE's trustee to a name and
  fails ("unexpected error") once an ACE names a deleted account, which failed
  a reinstall after `fivenines_uninstall.ps1` (or a hand-deleted account) with
  1603. A grant already present is not added again (only an allow ACE that
  applies to the namespace itself counts: not an inherit-only one), and the
  uninstall script removes the account's allow ACEs, keeping deny ACEs. Two
  Windows PowerShell 5.1 traps met on the way: `-band` on a byte-based enum
  such as `AceFlags` raises "Specified cast is not valid" (use `IsInherited`,
  or cast to `[int]` first), and `InvokeMethod` cannot take `New-Object`'s
  PSObject-wrapped `byte[]` (use `[byte[]]::new`).
- **Domain controllers.** On a DC the account is a domain account, the BUILTIN
  groups are the domain's, and the account's qualified name is `<DOMAIN>\name`,
  not the `[ComputerName]\name` the MSI defaults to, so every script resolves it
  by SID (`Resolve-ServiceAccountSid`) and `sc.exe` gets the name the SID
  translates back to. Whether a DC may rotate the password is `Get-AccountPlan`
  in `CreateServiceAccount.ps1`, tracked by the account's Description (the
  user-facing rules are in the main README, "Domain controllers"). No GitHub
  runner can become a DC (promotion needs a reboot), so `windows.yml` tests
  `Get-AccountPlan` case by case on every run, and its on-request
  `smoke-msi-domain-controller` job (`gh workflow run windows.yml --ref <branch>
  -f domain_controller=true`, about an hour) installs Windows Server 2019 in
  English and German in QEMU/KVM, promotes it, reproduces v1.22.0's failure
  and plays every account scenario (`ci/windows-dc/`).

## Build prerequisites

- Windows Server 2019+ or Windows 10/11 build host.
- WiX Toolset v4.0+ (`dotnet tool install --global wix`).
- `WixToolset.UI.wixext` and `WixToolset.Util.wixext` extensions
  (`wix extension add -g WixToolset.Util.wixext`).
- The agent binary built by `py2exe_windows.ps1` (T10).
- The WinSW exe (pinned at v2.12.0; downloaded by the build script).

## Build (manual)

```powershell
# Assume the agent binary and WinSW exe are staged.
$AgentBinarySource  = "..\..\dist\windows\fivenines-agent-windows-amd64\fivenines-agent-windows-amd64.exe"
$WinSwSource        = "..\..\dist\windows\WinSW.NET4.exe"
$WinSwConfigSource  = "..\winsw\fivenines-agent.xml"

wix build .\Product.wxs `
    -ext WixToolset.Util.wixext `
    -d AgentBinarySource="$AgentBinarySource" `
    -d WinSwSource="$WinSwSource" `
    -d WinSwConfigSource="$WinSwConfigSource" `
    -arch x64 `
    -o fivenines-agent.msi
```

The Windows CI runner (T14) automates this end-to-end.

## Silent install (for GPO / Intune)

The MSI accepts `TOKEN` and (optionally) `SERVICEACCOUNT`/`SERVICEACCOUNTPASSWORD`
as properties:

```cmd
msiexec /i fivenines-agent.msi TOKEN=xxxxx /qn /norestart
```

`TOKEN` is in `MsiHiddenProperties`, so it does **not** appear in the
installer log. Process command lines and deployment-tool history still see
it briefly - acceptable for an enrollment-only secret since the backend
swaps it for a per-host token on first sync via `synchronizer._swap_token`.
Cross-platform enrollment hardening is tracked separately (declined as a
TODO in the eng review).

## Uninstall

```cmd
msiexec /x {ProductCode} /qn
```

Or via Programs and Features. Uninstall stops + deregisters the service,
removes the install dir, the config dir, and the logs.

## What's verified vs what needs Windows-side polish

This MSI is built blind on macOS (the eng review acknowledged Windows code
is CI-verified, not locally-verified). What's solid:

- The two PowerShell custom-action scripts (real, runnable on any Windows
  host - they're standard PowerShell against WMI/ACL APIs).
- The component layout, file installation, and uninstall removal.
- The TOKEN-as-hidden-property pattern.
- The MajorUpgrade element for in-place upgrades.

What needs verification on the windows-latest runner (T14):

- Exact WiX 4 + Util extension property syntax for the deferred
  CustomAction CustomActionData passing (the `[#FileId]` token resolution
  inside a `SetProperty` value is the typical bind-time wrinkle).
- The service-account creation pre-install (currently the MSI assumes
  `SERVICEACCOUNT` already exists; the e2e smoke job should add a step
  that creates it via `net user` + adds to `Performance Monitor Users` if
  not present, then passes credentials to the MSI).
- That `util:PermissionEx` actually breaks the parent inheritance on the
  config dir as written (some WiX versions need a separate
  `RemovePermissionEx` first).
- WinSW v2.12.0 SHA256 pin in the build script.

These are not blockers for landing the scaffold - they're the verification
list for the first windows-latest build.
