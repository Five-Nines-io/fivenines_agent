# Install the fivenines agent on Windows

Supports **Windows Server 2019 / 2022 / 2025** and **Windows 10 / 11** (64-bit).

The agent runs as a Windows Service under a dedicated low-privilege local
account (`fivenines-agent`), provisioned automatically by the installer.
There is nothing to set up by hand — no IIS, no .NET install, no manual
service-account creation.

## Quickest install (recommended)

Open **PowerShell as Administrator** and run:

```powershell
iwr https://releases.fivenines.io/latest/fivenines_setup.ps1 -OutFile setup.ps1
.\setup.ps1 -Token <your-enrollment-token>
```

Replace `<your-enrollment-token>` with the token shown on your
[hosts page](https://app.fivenines.io/hosts/new). The token format is a
UUID, like `29cf9c5b-69a1-43b6-926e-600c6ec8a316`.

That's it. The script downloads the latest MSI, installs the agent,
starts the service, and the host appears on your dashboard within a
minute.

### What the install does

For full transparency, the installer:

1. Creates a local user `fivenines-agent` with a randomly-generated
   password (never displayed, never persisted in plain text).
2. Joins it to **Performance Monitor Users** and **Users**.
3. Grants it the `Log on as a service` right.
4. Installs the agent binary to `C:\Program Files\fivenines-agent\`.
5. Registers a Windows Service named `fivenines-agent` running under
   that local account.
6. Writes your enrollment token to `C:\ProgramData\fivenines_agent\TOKEN`
   with an ACL restricted to Administrators, SYSTEM, and the service
   account (no other user can read it).
7. Grants the service account read access to the WMI Storage namespace
   so disk health monitoring works.

The service writes its logs to
`C:\ProgramData\fivenines_agent\logs\fivenines-agent-service.wrapper.log`.

## Alternative: install directly from the MSI

If you can't run PowerShell scripts (corporate policy, GUI-only host,
etc.), you can install the MSI directly.

1. Download the installer from:

   <https://releases.fivenines.io/latest/fivenines-agent-windows-amd64.msi>

2. Right-click the file → **Properties** → check **Unblock** at the
   bottom → **OK**. (This removes the "downloaded from internet" tag and
   prevents Windows Installer from refusing to run.)

3. Double-click the MSI to install.

> ### About the SmartScreen warning
>
> Windows may show a screen titled **"Windows protected your PC"** when
> you run the installer. This is expected for the moment — our MSI is
> not code-signed yet (we're in the process of obtaining a Microsoft
> Trusted Signing certificate; signed installers will ship in a
> subsequent release).
>
> To proceed: click **More info** → **Run anyway**. The installer is
> the same one published on this page and verified by our automated
> build pipeline.

4. After the install, you must provide the enrollment token. Open
   **PowerShell as Administrator** and run:

   ```powershell
   Set-Content -Path "C:\ProgramData\fivenines_agent\TOKEN" `
               -Value "<your-enrollment-token>" `
               -Encoding ASCII
   Start-Service fivenines-agent
   ```

5. The host appears on your dashboard within a minute.

## Updating the agent

To upgrade to the latest version:

```powershell
iwr https://releases.fivenines.io/latest/fivenines_update.ps1 -OutFile update.ps1
.\update.ps1
```

The script detects the installed version, downloads the new MSI, and
runs the upgrade in place. Your existing token, service account, and
configuration are preserved. Windows Installer's MajorUpgrade machinery
handles stopping the old service, replacing the files, and starting the
new service.

## Uninstalling

```powershell
iwr https://releases.fivenines.io/latest/fivenines_uninstall.ps1 -OutFile uninstall.ps1
.\uninstall.ps1
```

This removes the agent binary, the service, the local
`fivenines-agent` account, the config directory, and the
SeServiceLogonRight grant. Pass `-KeepAccount` if your config-management
tooling created the service account and should retain ownership of it.

## Configuration

The agent reads optional environment variables from
`C:\ProgramData\fivenines_agent\.env`. To override the API endpoint
(typically only useful for sandbox / lab deployments):

```powershell
Set-Content -Path "C:\ProgramData\fivenines_agent\.env" `
            -Value "API_URL=lab.example.com" `
            -Encoding ASCII
Restart-Service fivenines-agent
```

Most installations never need to touch this — the default
(`api.fivenines.io`) is correct.

## Troubleshooting

### The host doesn't appear on the dashboard

Check the service is running:

```powershell
Get-Service fivenines-agent
```

Status should be **Running**. If it's **Stopped**, start it:

```powershell
Start-Service fivenines-agent
```

Then check the wrapper log for errors:

```powershell
Get-Content "C:\ProgramData\fivenines_agent\logs\fivenines-agent-service.wrapper.log" -Tail 30
Get-Content "C:\ProgramData\fivenines_agent\logs\fivenines-agent-service.err.log" -Tail 30
```

### The service won't start

Common cause: the local account's password is wrong (after an MSI
upgrade that hit a corner case, or a manual password change).

Reinstall from scratch:

```powershell
iwr https://releases.fivenines.io/latest/fivenines_uninstall.ps1 -OutFile uninstall.ps1
.\uninstall.ps1
iwr https://releases.fivenines.io/latest/fivenines_setup.ps1 -OutFile setup.ps1
.\setup.ps1 -Token <your-enrollment-token>
```

### Verify which version is installed

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
    Where-Object { $_.DisplayName -match "Fivenines" } |
    Select-Object DisplayName, DisplayVersion
```

### Verify the agent is talking to fivenines

```powershell
$pid = (Get-Process fivenines-agent-windows-amd64 -ErrorAction SilentlyContinue).Id
if ($pid) {
    Get-NetTCPConnection -OwningProcess $pid |
        Where-Object { $_.RemotePort -eq 443 } |
        Select-Object RemoteAddress, State
}
```

You should see at least one connection to a fivenines.io IP in
`Established` or `TimeWait` state shortly after each collection tick
(default every 60 seconds).

## FAQ

### Does the agent need to run as Administrator?

No. The MSI runs as Administrator during install (to provision the
service account, set ACLs, register the service), but the agent
itself runs as the dedicated low-privilege `fivenines-agent` account.
It cannot escalate, modify the registry's HKLM, or read other users'
files.

### What does the agent collect on Windows?

CPU / memory / disk / network / processes / open ports / connected
listeners — same as the Linux agent — plus Windows-specific signals:

- **Disk health** via the WMI Storage namespace
  (`MSFT_PhysicalDisk` + `MSFT_StorageReliabilityCounter`).
- **Installed software inventory** from the registry's Uninstall keys
  (parallels dpkg/rpm on Linux for the security scanner).
- **Kernel handle counts** (Windows equivalent of Linux's file
  descriptor counters).

Some Linux-only metrics are not collected on Windows because they have
no native equivalent (e.g. `load_average`, RAID status via `mdadm`,
`fail2ban` events).

### How do I deploy the agent to many hosts at once?

The MSI supports unattended install. From your config-management tool
(Ansible, Chef, Group Policy, MECM/Intune):

```powershell
msiexec /i fivenines-agent-windows-amd64.msi `
        TOKEN=<your-enrollment-token> `
        /qn
```

`/qn` is fully silent (no UI). The dedicated service account, ACLs,
and service registration all happen automatically. Pass the same token
to every host in the fleet — each one gets its own per-host token
back from the API on first contact.
