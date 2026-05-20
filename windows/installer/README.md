# MSI installer

This directory builds the Windows MSI installer for the fivenines agent.
Implements the install contract from `docs/windows-server-support-plan.md`:

- Install location: `%ProgramFiles%\fivenines-agent\` (admin-write-only).
- Config dir: `%ProgramData%\fivenines_agent\` with a restrictive ACL.
- Service: registered as `fivenines-agent` (Automatic Delayed Start) running
  as a dedicated low-privilege local account in the Performance Monitor Users
  group (D12). WMI Storage-namespace read access is delegated to that account
  by `DelegateWmiStorageNamespace.ps1` (D19) so disk-health works.
- Token: passed via the **hidden** `TOKEN` MSI property (D21). Written to
  `%ProgramData%\fivenines_agent\TOKEN` with `SetTokenFileAcl.ps1` so only
  the service account, Administrators, and SYSTEM have access (F1).

## Files

- `Product.wxs` - WiX 4 source. Components, service registration, ACL
  components, and the two security custom-action hookups.
- `SetTokenFileAcl.ps1` - deferred custom action: writes TOKEN with a
  restrictive ACL, inheritance broken.
- `DelegateWmiStorageNamespace.ps1` - deferred custom action: grants the
  service account read access to `root\Microsoft\Windows\Storage` so the
  disk-health collector can query `MSFT_PhysicalDisk` without admin.

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
