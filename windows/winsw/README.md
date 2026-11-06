# WinSW integration

The fivenines agent runs as a Windows Service via [WinSW](https://github.com/winsw/winsw)
(D16). WinSW is a small .NET wrapper that registers our console binary with
the Windows Service Control Manager (SCM) and handles:

- **stdout/stderr capture** to a rotating log file under
  `%ProgramData%\fivenines_agent\logs\` (the agent itself just writes to
  stdout as it does on Linux).
- **Lifecycle events** (Service started / stopped / failed) to the Windows
  Event Log automatically. Admins see agent health in `services.msc` and
  Event Viewer with zero extra config.
- **Restart on failure** with the backoff schedule defined in
  `fivenines-agent.xml`.
- **Automatic start at boot** with a short delay so the network and WMI
  service are up before the agent's first capability probe runs.

WinSW applies those last two (`<onfailure>`, `<resetfailure>`, `<startmode>`,
`<delayedAutoStart>`) only when its own `install` command registers the
service. The MSI never runs it (below), so it sets the same delayed start and
restart schedule itself; keep the two in step.

## What this directory contains

- `fivenines-agent.xml` - the WinSW service definition.

The WinSW executable (`WinSW.NET4.exe`) itself is **not committed** - the
Windows build script downloads it during CI and the MSI installer (T13)
bundles it alongside our frozen agent binary.

## Version pin

The build pins WinSW **v2.12.0** (or newer 2.x). v2.x targets .NET Framework
4 which ships in-box on Windows Server 2019, 2022, 2025 and Windows 10/11.
WinSW v3 requires .NET Core / .NET 6 self-contained which we may move to in
Phase 2.

Download URL pattern (used by the build / installer):
`https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW.NET4.exe`

## How the MSI uses this (T13)

The MSI's `Component` for the service:

1. Copies `WinSW.NET4.exe` to `Program Files\fivenines-agent\fivenines-agent-service.exe`
   (renamed so the registered service binary path is stable - WinSW reads its
   config from the XML next to itself).
2. Copies `fivenines-agent.xml` next to the renamed WinSW exe, as
   `fivenines-agent-service.xml`.
3. Copies the actual agent binary (`fivenines-agent-windows-amd64.exe`)
   alongside, because `%BASE%\fivenines-agent-windows-amd64.exe` in the XML
   resolves relative to the WinSW exe's directory.
4. Registers the service with the SCM through its own `ServiceInstall`
   (`windows/installer/Product.wxs`), not WinSW's `install` command, then
   sets the delayed start and the restart schedule (10s, 30s, 60s, the count
   reset after an hour) with `sc.exe config` and `sc.exe failure` custom
   actions (Windows Installer's own `MsiServiceConfigFailureActions` is
   documented as not working):
   up to 1.23.0 neither existed, so MSI installs started with the plain
   automatic services and a crashed agent stayed stopped.
5. Configures the service account (D12 - dedicated low-priv +
   `Performance Monitor Users`) and delegates WMI Storage namespace access
   (D19) via custom actions.
6. On uninstall, removes the service through its `ServiceControl`.

## Local install / debug (manual, without MSI)

For developers iterating on Windows:

```powershell
# From the build output directory
.\fivenines-agent.exe install     # register with SCM
.\fivenines-agent.exe start       # start the service
.\fivenines-agent.exe status      # check status
.\fivenines-agent.exe stop        # stop
.\fivenines-agent.exe uninstall   # deregister
```

The agent's `--dry-run` mode is still available as a console app:

```powershell
.\fivenines-agent-windows-amd64.exe --dry-run
```

`--dry-run` runs outside the service context and prints metrics JSON to
stdout - the primary hands-on debug path on Windows just as on Linux.
