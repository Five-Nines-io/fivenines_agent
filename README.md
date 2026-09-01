# fivenines agent

This agent collects server metrics from the monitored host and sends it to the [fivenines](https://fivenines.io) API.

Runs on **Linux** (glibc + musl, amd64 + arm64), **Windows** (Server 2019+,
Windows 10/11), **Synology DSM 7** and **UNRAID**.

## Contents

- [Installation](#installation)
  - [Standard Installation (Linux)](#standard-installation-linux)
  - [User-Level Installation (No Sudo/Root Access)](#user-level-installation-no-sudoroot-access)
  - [Windows Installation](#windows-installation)
  - [Alpine Linux (OpenRC)](#alpine-linux-openrc)
  - [UNRAID](#unraid)
  - [Synology Installation (DSM 7+)](#synology-installation-dsm-7)
  - [Cloning VMs or building golden images](#cloning-vms-or-building-golden-images)
- [Update](#update) / [Remove](#remove) / [Debug](#debug)
- [Permissions](#permissions)
- **Host and platform monitoring**
  - [Docker Monitoring](#docker-monitoring) (container states + image vulnerability scanning)
  - [Proxmox VE Monitoring](#proxmox-ve-monitoring)
  - [systemd Unit Monitoring](#systemd-unit-monitoring)
  - [Log Monitoring](#log-monitoring)
  - [ZFS Pool Health](#zfs-pool-health)
  - [Ceph Cluster Monitoring](#ceph-cluster-monitoring)
  - [Ubuntu Pro Entitlement](#ubuntu-pro-entitlement)
- **Network and devices**
  - [SNMP Network Device Monitoring](#snmp-network-device-monitoring)
  - [MQTT Broker Monitoring](#mqtt-broker-monitoring)
  - [VPN Monitoring (WireGuard + Tailscale)](#vpn-monitoring-wireguard--tailscale)
- **Applications**
  - [AI Inference Serving (vLLM and SGLang)](#ai-inference-serving-vllm-and-sglang)
  - [Application Integrations](#application-integrations): [Apache](#apache),
    [Caddy](#caddy), [Nginx](#nginx), [HAProxy](#haproxy), [PHP-FPM](#php-fpm),
    [PostgreSQL](#postgresql), [MySQL / MariaDB](#mysql--mariadb),
    [Redis / Valkey](#redis--valkey), [Memcached](#memcached),
    [RabbitMQ](#rabbitmq), [Prometheus / VictoriaMetrics](#prometheus--victoriametrics)
- [Contribute](#contribute) / [Contact](#contact)

## Installation

### Standard Installation (Linux)

Requires sudo/root access for initial setup. The agent runs as a dedicated `fivenines` user with limited permissions.

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN
```

One script covers every Linux init system: it detects **systemd**, **OpenRC**
(Alpine) and **UNRAID** and installs the matching service integration, and it
detects glibc vs musl and downloads the matching binary. See
[Alpine Linux (OpenRC)](#alpine-linux-openrc) and [UNRAID](#unraid) for the
platform-specific notes.

### User-Level Installation (No Sudo/Root Access)

For environments where you don't have sudo/root access (shared hosting, managed VPS, etc.):

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_setup_user.sh && bash fivenines_setup_user.sh TOKEN
```

This installs to `~/.local/fivenines` and creates helper scripts:

```bash
~/.local/fivenines/start.sh    # Start the agent
~/.local/fivenines/stop.sh     # Stop the agent
~/.local/fivenines/status.sh   # Check status and recent logs
~/.local/fivenines/logs.sh     # Follow log output
~/.local/fivenines/refresh.sh  # Refresh capabilities (after permission changes)
```

To auto-start on reboot, add to crontab (`crontab -e`):
```
@reboot ~/.local/fivenines/start.sh
```

> **Note:** User-level installation has limited monitoring capabilities. Features requiring sudo (SMART, RAID) won't be available. See [Permissions](#permissions) section.

### Windows Installation

Supported: **Windows Server 2019, 2022 and 2025** and **Windows 10 / 11**, x64
only. Windows Server 2016 is **not supported** -- it is not in the build or test
matrix and no release artifact is validated against it.

The agent ships as an MSI that does the whole install in one step: the frozen
agent binary, a [WinSW](https://github.com/winsw/winsw) wrapper registered with
the Service Control Manager, a dedicated low-privilege service account, and the
ACLs and WMI delegation that account needs.

From an **elevated** PowerShell session:

```powershell
iwr https://releases.fivenines.io/latest/fivenines_setup.ps1 -OutFile setup.ps1
.\setup.ps1 -Token TOKEN
```

> **The MSI is not code-signed yet.** SmartScreen will warn on a manual
> double-click ("Windows protected your PC" -> **More info** -> **Run anyway**),
> and a downloaded MSI carries Mark-of-the-Web, which makes a silent `/qn`
> install fail with no obvious error. `fivenines_setup.ps1` handles this for you
> by calling `Unblock-File` before `msiexec`; if you deploy the MSI yourself, run
> `Unblock-File .\fivenines-agent-windows-amd64.msi` (or use **Unblock** in the
> file's Properties dialog) first. Authenticode signing via Azure Trusted Signing
> is tracked in [#63](https://github.com/Five-Nines-io/fivenines_agent/issues/63).

#### Silent install (GPO / SCCM / Intune)

Download `fivenines-agent-windows-amd64.msi` from
[releases.fivenines.io/latest](https://releases.fivenines.io/latest/fivenines-agent-windows-amd64.msi)
or from a tagged [GitHub release](https://github.com/Five-Nines-io/fivenines_agent/releases),
then:

```cmd
msiexec /i fivenines-agent-windows-amd64.msi TOKEN=xxxxx /qn /norestart
```

| MSI property | Purpose |
|---|---|
| `TOKEN` | Enrollment token (required). |
| `SERVICEACCOUNT` | Use an existing **local** account instead of the MSI-managed one. Domain accounts must be pre-staged by the deployer. |
| `SERVICEACCOUNTPASSWORD` | Required when `SERVICEACCOUNT` names an account the MSI did not create, so operator-managed credentials are never silently rotated. |

`TOKEN` is declared in `MsiHiddenProperties`, so it does **not** land in the
installer log. It is still briefly visible on the process command line and in
your deployment tool's history -- acceptable for an enrollment-only secret,
which the backend swaps for a per-host token on the agent's first sync.

- **GPO**: assign the MSI per-machine (Computer Configuration -> Software
  Installation). Per-user assignment will not work; the service is machine-scoped.
- **SCCM / Intune**: use the `msiexec` line above as the install command and
  `msiexec /x {ProductCode} /qn` as the uninstall command. Detect on the
  `fivenines-agent` service or on `%ProgramFiles%\fivenines-agent\`.
- Unblock the MSI on the distribution point (or repackage it) so
  Mark-of-the-Web does not block the silent install on clients.

Upgrades are in-place: the MSI carries a `MajorUpgrade` element, so installing a
newer MSI over an older one stops and re-registers the service and rotates the
MSI-managed service-account password automatically -- no operator credentials
needed.

#### Update and uninstall

```powershell
# Update to the latest release (refuses if the agent is not already installed)
iwr https://releases.fivenines.io/latest/fivenines_update.ps1 -OutFile update.ps1
.\update.ps1

# Uninstall: removes the MSI, the service, the local service account,
# its SeServiceLogonRight grant, and the config + log directories.
# Pass -KeepAccount to leave a pre-staged account in place.
iwr https://releases.fivenines.io/latest/fivenines_uninstall.ps1 -OutFile uninstall.ps1
.\uninstall.ps1
```

#### Security model

The Windows install is least-privilege by construction -- the agent never runs
as `LocalSystem` and never as an administrator:

- **Dedicated local service account.** The MSI creates a local account --
  `<ComputerName>\fivenines-agent` unless you override `SERVICEACCOUNT` -- with a
  cryptographically random 192-bit password that is never displayed and never
  written to the install log; only the SCM's LSA secret holds it. Its only group
  memberships are `Users` (to read the install directory) and **Performance
  Monitor Users** (for the PDH handle-count metric), and it is granted exactly
  one privilege: `SeServiceLogonRight`, which the SCM requires to start a service
  under a non-built-in account. Re-installs rotate the password. If the account
  already exists and was **not** created by the MSI, the install stops and asks
  for `SERVICEACCOUNTPASSWORD` instead of clobbering credentials your
  config-management system may own.
- **Scoped WMI delegation.** Disk health reads
  `root\Microsoft\Windows\Storage`, which is admin-only by default. Rather than
  making the account an administrator, the installer delegates read access to
  **that one namespace**. No other WMI namespace becomes reachable.
- **Restrictive ACLs.** `%ProgramData%\fivenines_agent\` holds `TOKEN` and
  `MACHINE_ID`; it is created with inheritance broken and access limited to the
  service account, `Administrators` and `SYSTEM`. The install directory
  `%ProgramFiles%\fivenines-agent\` is admin-write-only.
- **Outbound HTTPS only.** The agent opens outbound TLS connections to the
  fivenines API and never listens on a port. No inbound firewall rule is needed,
  and the installer creates none.

#### Windows-specific collectors

Core metrics (CPU, memory, disk I/O, network, partitions, ports, processes) and
every HTTP-based application integration behave the same as on Linux. Three
things differ:

- **Disk health** (the Windows counterpart to SMART) reads `MSFT_PhysicalDisk`
  from the WMI Storage namespace for the drive inventory -- friendly name, media
  type, bus type, size, serial, health and operational status -- and merges in
  `MSFT_StorageReliabilityCounter` for temperature, power-on hours, read/write
  error counts and SSD wear. It runs as a short-lived `Get-CimInstance`
  subprocess with a hard 5s timeout, so a wedged WMI service cannot stall a
  collection tick.
- **Software inventory** enumerates the `Uninstall` registry keys under
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` **and** the 32-bit
  `WOW6432Node` view, so 32-bit applications on a 64-bit host are not missed.
  This feeds the same vulnerability scanner as the Linux package inventory.
- **No load average**, and **handle count instead of file handles**. Windows has
  no load-average equivalent and psutil's emulation reads zero on an idle system,
  so the metric is omitted rather than faked. Likewise there is no
  `/proc/sys/fs/file-nr` equivalent, so Windows reports a total kernel
  `handle_count` under its own key rather than a used/limit pair the backend
  would otherwise conflate with the Linux metric.

Linux-only collectors (SMART via smartctl, mdadm RAID, ZFS, Ceph, fail2ban,
QEMU/libvirt, Proxmox, systemd, journald logs, WireGuard) are absent from the
Windows capability set entirely -- the agent sends a Windows-shaped payload
rather than Linux keys marked unavailable.

#### Service management and logs

The service is registered as `fivenines-agent`, Automatic with delayed start so
the network stack and WMI service are up before the first capability probe:

```powershell
Get-Service fivenines-agent
Restart-Service fivenines-agent
```

Lifecycle events (started / stopped / failed) go to the Windows Event Log, so
the agent is visible in `services.msc` and Event Viewer with no extra setup.
Captured stdout/stderr lands in `%ProgramData%\fivenines_agent\logs\`, rotated at
10 MB with 5 generations kept. On failure the wrapper restarts the agent after
10s, 30s and 60s, resetting the counter after an hour of clean running.

### Alpine Linux (OpenRC)

Use the [standard installer](#standard-installation-linux) -- it detects musl and
OpenRC, downloads the Alpine build, installs `/etc/init.d/fivenines-agent`, and
runs `rc-update add fivenines-agent default`:

Run it as root -- Alpine ships neither `sudo` nor `bash` by default:

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_setup.sh && sh fivenines_setup.sh TOKEN
```

```bash
rc-service fivenines-agent status
rc-service fivenines-agent restart
```

> **Alpine 3.19 or newer is required.** The musl binary uses `pwritev2`, which
> Alpine 3.18 and older do not provide. CI builds and tests the Alpine amd64 and
> arm64 binaries on Alpine 3.21.

Under OpenRC the agent cannot be granted ambient capabilities the way the systemd
unit does, so WireGuard peer health is unavailable unless the agent runs as root.

### UNRAID

Use the [standard installer](#standard-installation-linux) -- it detects UNRAID
(`/etc/unraid-version`) and installs to the flash drive rather than to `/opt`,
because UNRAID's root filesystem lives in RAM and is rebuilt on every boot:

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_setup.sh && bash fivenines_setup.sh TOKEN
```

What it does differently:

- Installs the agent under `/boot/config/custom/fivenines_agent/` on the flash
  drive, and symlinks the binary to `/usr/local/bin/fivenines_agent`.
- Installs a boot script at
  `/boot/config/custom/fivenines_agent/fivenines_boot` and appends it to
  `/boot/config/go`, so the agent starts automatically on every boot.
- **Persists the machine identity to flash.** `/etc` is a ramdisk on UNRAID, so
  `TOKEN` and `MACHINE_ID` are copied from flash into `/etc/fivenines_agent` at
  boot and copied back whenever the agent changes them. Without this, every
  reboot would look like a brand-new machine to the backend and enroll a
  duplicate host. Requires agent version **1.14.5+**.

### Synology Installation (DSM 7+)

For Synology NAS devices running DSM 7 and higher, the agent is distributed as a native `.spk` application.

1. Download the appropriate `.spk` package for your architecture (x86_64 or ARM64) from the releases page.
2. Open **Package Center** in DSM and click **Manual Install**.
3. Upload the `.spk` file and follow the wizard.
4. When prompted by the UI, paste your Fivenines API token. the agent will automatically configure itself and start.

> **Note:** To comply with Synology DSM 7's strict security policies, the agent runs as a dedicated low-privilege system user (`sc-fivenines-agent`), not as `root`. Because it cannot use `sudo`, deep system hardware telemetry (like SMART disk health, RAID mapping, and raw `sysfs` temperature sensors) may be gracefully disabled depending on your NAS model permissions. QEMU and Proxmox metrics are also excluded from the Synology build.

### Cloning VMs or building golden images

The agent keeps two per-machine files in its config directory
(`/etc/fivenines_agent` by default): the per-host `TOKEN` and `MACHINE_ID`, a
stable identifier the backend uses to recognize a machine across
re-enrollments. If the agent is installed **and started** before a VM template
or golden image is captured, both files are baked into the image and every
clone inherits them, so the backend treats all the clones as one host and
merges their metrics.

The reliable approach is to install and enroll the agent **after** cloning
(via cloud-init, a provisioning script, or by hand), so each machine gets its
own identity.

If the agent must be present in the image, remove its per-machine state before
capturing the template so each clone regenerates it on first start:

```bash
sudo rm -f /etc/fivenines_agent/TOKEN /etc/fivenines_agent/MACHINE_ID
```

Use `~/.config/fivenines_agent` for a user-level install or
`/boot/config/custom/fivenines_agent` on UNRAID. Each clone then needs the
agent re-enrolled with a fresh token.

## Update

### Standard Update (with sudo/root)

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_update.sh && sudo bash fivenines_update.sh
```

### User-Level Update (no sudo/root)

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_update_user.sh && bash fivenines_update_user.sh
```

### Windows Update

From an elevated PowerShell session (see [Windows Installation](#windows-installation)):

```powershell
iwr https://releases.fivenines.io/latest/fivenines_update.ps1 -OutFile update.ps1
.\update.ps1
```

## Remove

### Standard Removal (with sudo/root)

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_uninstall.sh && sudo bash fivenines_uninstall.sh
```

### User-Level Removal (no sudo/root)

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_uninstall_user.sh && bash fivenines_uninstall_user.sh
```

### Windows Removal

From an elevated PowerShell session:

```powershell
iwr https://releases.fivenines.io/latest/fivenines_uninstall.ps1 -OutFile uninstall.ps1
.\uninstall.ps1                 # add -KeepAccount to keep a pre-staged service account
```

## Debug

If you need to debug the agent collected data, you can run the following command:

```bash
# Standard installation
sudo -u fivenines /opt/fivenines/fivenines_agent --dry-run

# User-level installation
~/.local/fivenines/fivenines-agent-linux-*/fivenines-agent-linux-* --dry-run

# UNRAID
/usr/local/bin/fivenines_agent --dry-run
```

On Windows, run the agent binary directly as a console app (the service itself
stays untouched):

```powershell
& "$env:ProgramFiles\fivenines-agent\fivenines-agent-windows-amd64.exe" --dry-run
```

## Permissions

The agent runs as the `fivenines` user and automatically detects available monitoring capabilities at startup. Most metrics work without any special permissions.

> This section describes the **Linux** permission model. On Windows the
> installer provisions everything the agent needs (a dedicated low-privilege
> service account, a scoped WMI Storage delegation, and restrictive ACLs) with
> no manual steps -- see [Security model](#security-model).

### Full Monitoring (Recommended)

For full monitoring capabilities, add the following to `/etc/sudoers.d/fivenines`:

```
fivenines ALL=(ALL) NOPASSWD: /usr/sbin/smartctl
fivenines ALL=(ALL) NOPASSWD: /sbin/mdadm
```

### Limited Monitoring (No Sudo)

The agent works without sudo, but these features will be unavailable (this is also the default behavior for the Synology DSM 7 `sc-fivenines-agent` package):

| Feature | Requirement |
|---------|-------------|
| SMART disk health | `sudo smartctl` |
| RAID array status | `sudo mdadm` |
| Fail2ban status | `sudo fail2ban-client` |
| Docker containers | `docker` group membership |
| QEMU/KVM VMs | `libvirt` group membership |
| ZFS pools | ZFS delegation or permissions |
| NVIDIA GPU metrics | NVIDIA driver + pynvml library |
| SNMP device polling | `net-snmp` tools (`snmpget`, `snmpbulkwalk`) |
| systemd unit metrics | `systemd` init system (`systemctl`; `journalctl` only for failure journal tails) |
| systemd failure journal tails | journal read access: the bundled service unit grants `SupplementaryGroups=systemd-journal`; for user installs add your user to the `systemd-journal` group (tails degrade to empty without it) |
| Log monitoring (journald capture + signals) | journal read access (`systemd-journal` group) |
| WireGuard peer health | root or `CAP_NET_ADMIN` (the bundled systemd unit grants `AmbientCapabilities=CAP_NET_ADMIN`) |
| Tailscale node state | `tailscale` CLI on `PATH` + a reachable `tailscaled` (no extra privilege) |
| Ubuntu Pro entitlement | `pro` CLI on `PATH` (ubuntu-advantage-tools), or a readable `/var/lib/ubuntu-advantage/status.json` (no extra privilege) |
| Per-unit cgroup metrics | cgroup v1 or v2 mounted at `/sys/fs/cgroup` |
| Ceph cluster status | `ceph` CLI + read-only cephx keyring (no sudo) |
| Docker image vulnerability scanning | same Docker socket as container metrics (no extra privilege) |
| HAProxy stats socket | read access to the socket (e.g. `/run/haproxy/admin.sock`); the HTTP CSV endpoint needs none |
| Windows disk health | WMI `root\Microsoft\Windows\Storage` read access (delegated by the MSI) |
| Windows software inventory | `HKLM\...\Uninstall` registry read access |

### Capabilities by Permission Level

**Always Available (no special permissions):**
- CPU usage and model
- Memory and swap usage
- Load average
- Disk I/O statistics
- Network I/O statistics, per interface: byte/packet/error/drop counters plus
  interface type (bridge / physical / virtual), link speed from
  `/sys/class/net/<if>/speed`, and bridge member count, so the dashboard can
  compute per-interface saturation (agent version **1.11.6+**)
- Disk partition usage
- Open file handles (kernel handle count on Windows)
- Listening ports
- Process list (own user's processes)
- Installed packages (dpkg / rpm / apk / pacman / synopkg, or the Windows
  Uninstall registry)

**May Work Without Sudo/Root:**
- Hardware temperatures (depends on `/sys/class/hwmon` permissions)
- Fan speeds (depends on `/sys/class/hwmon` permissions)
- NVIDIA GPU metrics (requires NVIDIA driver and pynvml library)

**Requires Group Membership:**
- Docker: Add `fivenines` user to `docker` group
  ```bash
  sudo usermod -aG docker fivenines
  ```
- QEMU/libvirt: Add `fivenines` user to `libvirt` group
  ```bash
  sudo usermod -aG libvirt fivenines
  ```

**Requires Sudo Configuration:**
- SMART storage health monitoring
- RAID (mdadm) array monitoring

### Rootless Docker

This section covers how the agent reaches the Docker socket. For what it
collects once it gets there, see [Docker Monitoring](#docker-monitoring).

Two setups get called "non-root Docker", and they are not the same:

- **Agent as a non-root user (`User=fivenines`) talking to a root daemon** via
  `/var/run/docker.sock` works out of the box once `fivenines` is in the
  `docker` group (see above). This is the common case and needs no extra
  privilege for
  [image vulnerability scanning](#image-vulnerability-scanning) either -- it uses
  the same socket.
- **Rootless Docker** (the daemon itself runs as an unprivileged user, with its
  socket at `$XDG_RUNTIME_DIR/docker.sock`, e.g. `/run/user/1000/docker.sock`)
  needs the agent pointed at that socket, because the daemon's on-disk layers
  are owned by subordinate UIDs (`/etc/subuid`, 100000+) that a process outside
  the user namespace cannot read at all. The archive API is the only way in, and
  it works only against the daemon's own socket.

The agent resolves the Docker socket in this order, and both the collector and
the capability probe follow it:

1. the socket URL configured for this host in the fivenines UI (sent as
   `docker.socket_url` in the agent config),
2. the `DOCKER_HOST` environment variable,
3. `/var/run/docker.sock`,
4. `$XDG_RUNTIME_DIR/docker.sock` (rootless).

To monitor a rootless daemon, use **one** of:

1. **Point the service at the rootless socket** with a systemd drop-in
   (`sudo systemctl edit fivenines-agent`):
   ```ini
   [Service]
   Environment=DOCKER_HOST=unix:///run/user/1000/docker.sock
   ```
   Replace `1000` with the rootless daemon's UID. Note that `/run/user/<uid>`
   is mode `0700` and owned by that UID, so the `fivenines` user generally
   **cannot** reach another user's rootless socket -- run the agent as that user
   instead (option 2) unless you have explicitly widened the permissions.
2. **Run the agent as the rootless user**, so `XDG_RUNTIME_DIR` is set and
   `/run/user/<uid>/docker.sock` resolves via step 4 above (no `DOCKER_HOST`
   needed).

The agent will **not** auto-discover another user's rootless socket: `/run/user/<uid>`
is `0700` by design, and reaching into it would be wrong. If the socket is not
reachable, the capabilities banner reports the exact path it tried.

> **User-install trap:** `fivenines_setup_user.sh` starts the agent from an
> `@reboot` cron job, where `XDG_RUNTIME_DIR` is typically unset. `docker.from_env()`
> then works in an interactive shell but fails under cron -- a classic rootless
> false negative. Set `DOCKER_HOST` explicitly (option 1) for cron-launched
> user installs.

### Refreshing Capabilities After Permission Changes

The agent automatically re-probes capabilities every 5 minutes. If you make permission changes and want immediate detection:

```bash
# Send SIGHUP to refresh capabilities without restart
sudo kill -HUP $(pgrep -f fivenines_agent)

# Or restart the service
sudo systemctl restart fivenines-agent
```

### Viewing Available Capabilities

When the agent starts, it displays a banner showing which features are available:

```
============================================================
  Fivenines Agent - Capabilities Detection
============================================================

  Core Metrics:
    [+] Cpu
    [+] Memory
    [+] Load Average
    [+] Io
    [+] Network
    [+] Partitions
    [+] File Handles
    [+] Ports
    [+] Processes

  Hardware Sensors:
    [+] Temperatures
    [-] Fans (no accessible sensors)
    [-] Nvidia Gpu (requires NVIDIA driver)

  Storage:
    [-] Smart Storage (requires sudo smartctl)
    [-] Raid Storage (requires sudo mdadm)
    [-] Zfs (requires zfs permissions)
    [-] Ceph (requires ceph CLI + client keyring)

  Services:
    [+] Docker
    [-] Qemu (requires libvirt group)
    [+] Proxmox
    [+] Systemd
    [+] Cgroup v2

  Security:
    [-] Fail2Ban (requires sudo fail2ban-client)
    [+] Packages

  Networking:
    [+] Snmp

  Logs:
    [+] Journald

  [!] Some features unavailable. See: https://docs.fivenines.io/agent/permissions

============================================================
```

Windows reports a Windows-shaped capability set rather than Linux keys marked
unavailable -- no load average, and two native groups instead of the Linux
storage and security ones:

```
  Core Metrics:
    [+] Cpu
    [+] Memory
    [+] Io
    [+] Network
    [+] Partitions
    [+] File Handles
    [+] Ports
    [+] Processes

  Hardware Sensors:
    [-] Temperatures (no accessible sensors)
    [-] Fans (no accessible sensors)
    [-] Nvidia Gpu (requires NVIDIA driver)

  Storage:
    [+] Disk Health

  Inventory:
    [+] Software Inventory
```

## Docker Monitoring

Enabled per host from the fivenines dashboard. The agent talks to the Docker
daemon over its socket -- see [Rootless Docker](#rootless-docker) for how the
socket is resolved and what rootless setups need.

### Container states and metrics

Requires agent version **1.11.2+**. Every container ships an identity + state
block on **every** tick, from its first sighting, whatever its status:

- Name, image, image id, image tags and repo digests
- `status`, `exit_code`, `oom_killed`, `restart_count`
- `started_at` / `finished_at`, and the container's health-check state

That is deliberately unconditional: "why did this container die" needs the exit
code and the OOM flag of a container that is no longer running, so state is not
gated behind the resource stats. **Running** containers additionally report CPU,
memory, block I/O and per-network counters -- but only from their second tick,
since CPU percent needs a delta between two samples.

Failure and emptiness are distinct signals, which is what keeps a daemon hiccup
from looking like a mass deletion: a genuinely empty host reports zero
containers and the dashboard prunes its rows, while an unreachable daemon
reports a collection failure and the dashboard changes nothing.

Two bounds worth knowing: containers are capped at 500 per tick (running ones
first, then newest-first, so a large graveyard of exited containers cannot bloat
the payload), and a container that both starts and exits between two ticks --
`docker run --rm` of something short-lived -- is never observed. Catching those
needs the Docker events API and is a later phase.

### Image vulnerability scanning

Requires agent version **1.14.0+**, and `image_inventory` enabled for the host
(which also requires Docker collection to be on, since the image list is derived
from the containers). The agent extracts the **OS package list from inside each
container image** and uploads it so the backend can match it against
vulnerability feeds -- the same scanner that covers host packages, pointed at
your images.

Nothing runs inside your container. The agent asks the daemon to tar a path out
of the image's layers (`GET /containers/{id}/archive`, the same call `docker cp`
uses) and parses the package database from the stream. That choice buys four
things:

- **No binary is needed inside the image** -- no `dpkg-query`, no `rpm`, not even
  a shell, so distroless images are covered.
- **Stopped and never-started containers are covered.** A `created` container
  that has never run is still scannable.
- **Nothing executes in your container**, unlike `docker exec`.
- **It is the only design that works under rootless / userns-remap Docker**,
  where the on-disk layer files belong to subordinate UIDs a host process cannot
  read at all. The daemon lives inside that namespace; the archive API is the way
  in.

Phase 1 reads **dpkg** (Debian / Ubuntu) and **apk** (Alpine). RPM-based images
are reported as `unsupported` rather than silently empty.

Because an image digest is immutable, each image is extracted **once, ever** --
not once per tick. Completed digests are recorded on disk and survive a restart.
All of it (the archive fetches, the tar parsing, the upload) runs on a dedicated
worker thread, never on the collection loop, so scanning a host with many images
cannot stretch a collection tick.

> **Honesty contract.** A security feature must never emit a false all-clear, so
> an extraction failure is never reported as an empty-and-clean package list.
> Every failure path records a structured reason and the dashboard renders
> `not scannable: <reason>` instead of "0 vulnerabilities".

## Proxmox VE Monitoring

Enabled per host from the fivenines dashboard, for Proxmox VE clusters and
standalone nodes. Reports:

- **Cluster**: status and quorum
- **Nodes**: CPU, memory and uptime
- **Guests**: per-VM (QEMU/KVM) and per-LXC-container metrics
- **Storage**: per-pool usage (total / used / available / active)

Authenticate with a Proxmox **API token** (`token_id` in the
`user@realm!tokenname` form, plus `token_secret`); `host`, `port` (default 8006)
and `verify_ssl` are configurable from the dashboard. A read-only role is enough.

Each section is collected independently and carries its own completeness flag
(agent version **1.10.0+**): if the storage call fails but the node call
succeeds, you get node metrics plus an explicit "storage incomplete" marker
rather than a blank tick, so a partial API failure never reads as "the cluster
lost its VMs".

Agent version **1.11.7+** adds the `pool` property to `zfspool`, `rbd` and
`cephfs` storage entries -- the join key that lets the dashboard line a Proxmox
storage pool up with the [ZFS pool health](#zfs-pool-health) or
[Ceph](#ceph-cluster-monitoring) data collected from the same host.

## systemd Unit Monitoring

Requires agent version **1.9.1+** and a systemd host. Enabled per host from the
dashboard; `unit_types` selects which unit types to watch (default
`service,timer,socket`).

Two surfaces:

**Per-tick health.** One `systemctl list-units` plus one bulk `systemctl show`
for *all* units (not one call per unit), giving active/sub state, load state and
restart counts. Per-unit CPU and memory come from the unit's cgroup, read
directly from `/sys/fs/cgroup` with no extra process spawned -- the agent
detects a v1 or v2 hierarchy at startup and reports which one it found in the
capabilities banner.

**Failure drilldown.** When a unit newly enters a failed state, the agent
collects a journal tail and its reverse dependencies for that unit only, so an
alert arrives with the error text and the list of what else depends on it.
Journal tails require journal read access; the bundled systemd unit grants
`SupplementaryGroups=systemd-journal`. Without it, everything else still works
and the tails are simply empty.

**Inventory sync.** With `scan` enabled the agent snapshots full unit properties
-- including **disabled** units, since a disabled unit is still configuration --
hashes the snapshot and uploads it only when the hash changes, so a stable host
costs nothing after the first send. Secrets are redacted from `Exec*` argv before
the snapshot is hashed or sent. Sending `SIGHUP` forces a full resend.

## Log Monitoring

Requires agent version **1.11.1+** and journal read access (the `journald`
capability -- the bundled systemd unit grants `SupplementaryGroups=systemd-journal`;
for user installs, add your user to the `systemd-journal` group). Enabled per
host from the dashboard, with a `units` allowlist -- the agent never reads the
journal at large, only the units you name.

**Continuous signals.** Each tick the agent scans a short window (60s by
default) of each allowlisted unit's journal and reports per-severity error/warn
counts plus the top error **fingerprints** -- a stable hash of the message with
variable parts masked out, so "connection refused to 10.0.0.7:5432" and
"connection refused to 10.0.0.9:5432" collapse to one recurring signal instead
of two novel ones. The agent stays deliberately stateless here: it reports this
window's counts and the backend derives new-vs-recurring from its own history.
Units are capped at 12 per tick and each unit's scan is bounded and isolated, so
one noisy or wedged unit never blanks the others.

**Incident capture.** When the backend needs context for an incident it can ask
for a bounded retroactive slice of a unit's journal. The agent runs one capped
`journalctl` query, turns it into a digest, and uploads it on a dedicated worker
thread -- never on the collection loop, so a large capture cannot stall metric
collection or trip the systemd watchdog. Each request carries a nonce that is
persisted to disk, so a capture fires exactly once and never replays after a
service restart.

### Redaction

**Raw log lines never leave the host.** What is sent is a digest: per-severity
counts, and for each fingerprint one *representative excerpt*, capped at 500
characters and redacted first. The redaction pass masks PEM private-key headers,
JWTs, AWS access keys, `Bearer` tokens, passwords embedded in connection strings
(`scheme://user:pass@host`), generic `password=` / `secret=` / `token=` /
`api_key=` / `authorization=` assignments, email addresses, and any opaque
base64/hex run of 40 characters or more (key bodies, session blobs, hashes). The
same redaction is applied to the journal tails collected by
[systemd unit monitoring](#systemd-unit-monitoring).

Redaction is best-effort by nature -- it cannot recognise a secret format it has
never seen. The digest-only posture is the real mitigation: a novel secret format
has to appear *inside* a chosen fingerprint's single 500-character excerpt to
escape, rather than in any of the thousands of lines that were scanned. An
opt-in raw-lines mode is a planned follow-up and is not available in this
version.

## ZFS Pool Health

Requires agent version **1.11.3+** and the `zpool` command. Enabled per host from
the dashboard; results are cached for 60s by default (`interval`) so a short
collection interval does not re-run `zpool status` every tick.

Per pool:

- `health` verbatim (`ONLINE` / `DEGRADED` / `FAULTED` / `OFFLINE` / ...) plus a
  stable numeric `health_code` for alerting
- Count of degraded vdevs, and the full vdev tree with per-device state and
  read / write / checksum error counters
- Resilver progress and scrub error counts
- Pool size, allocated and free bytes, capacity and fragmentation percentages,
  and dedup ratio
- The pool's `errors:` line as reported by `zpool status`

Both `zpool` calls run with a hard 10s timeout: a SUSPENDED pool or a dying
controller -- exactly the states this collector exists to report -- can wedge
`zpool` indefinitely, and that must never hang the collection tick.

On Proxmox hosts, pools reported here join to the Proxmox `zfspool` storage
entries through the `pool` key (agent version **1.11.7+**), so one pool is one
row rather than two unrelated ones.

## SNMP Network Device Monitoring

The agent can poll network devices (switches, routers, firewalls, printers) via SNMP when configured from the fivenines dashboard.

### Requirements

Install `net-snmp` tools on the agent host:

```bash
# Debian/Ubuntu
sudo apt install snmp

# RHEL/Rocky/CentOS
sudo yum install net-snmp-utils

# Alpine
sudo apk add net-snmp-tools
```

### Supported Protocols

- **SNMPv2c** - Community string authentication
- **SNMPv3** - USM with auth (MD5/SHA) and privacy (DES/AES)

### Collected Metrics

**Per device:** hostname, description, uptime

**Per interface:** name, type, admin/oper status, speed, traffic (bytes/packets in/out), errors, discards, broadcast counts. Prefers 64-bit high-capacity counters when available, falls back to 32-bit.

**Custom OIDs:** The server can send vendor-specific OIDs (CPU, memory, temperature, etc.) based on the device model detected via `sysDescr`. No agent-side configuration needed.

### How It Works

1. Add SNMP devices in the fivenines dashboard (IP + credentials)
2. The server sends `snmp_targets` to the agent via `sync_config`
3. The agent polls devices concurrently using `snmpget`/`snmpbulkwalk`
4. Per-device polling intervals are configurable from the dashboard

## MQTT Broker Monitoring

Requires agent version **1.12.0+**. When MQTT monitoring is enabled for a host in the fivenines dashboard, the agent keeps a persistent background subscription to each configured broker and reports per-topic freshness every tick. This is the agent's first long-lived-connection feature; it relies on the bundled `paho-mqtt` client's own network thread, so nothing extra needs installing on the host.

### Scope (v1)

- MQTT **3.1.1** over TCP or **TLS**, username/password auth
- Subscriptions at **QoS 0 with a clean session** (the agent never publishes)
- Out of scope: MQTT 5, WebSockets transport, mTLS client certificates

### Collected Metrics

**Per broker:** connection `status` (connected / error / auth_error), an `error` detail, and `connected_age_s`.

**Per monitor** (a subscription filter, e.g. `iot/+/status`): `subscribed_age_s` (the alarm-arming input) and a `capped` flag, grouped by the concrete topics seen under it.

**Per topic:** `last_message_age_s` (any delivery), `last_live_seen_age_s` (RETAIN=0 deliveries **only** -- a stored retained replay is never counted as device liveness), `first_seen_age_s`, and, when payload capture is enabled, a truncated `last_payload` plus `last_payload_retained`. Everything is reported as an age in seconds, so the backend anchors freshness to its own receive time and agent clock drift is irrelevant.

### How It Works

1. Add MQTT brokers + topic monitors in the fivenines dashboard (host/port/TLS/credentials + topic filters)
2. The server sends the `mqtt` broker list to the agent via `sync_config`
3. Each tick the agent diffs desired-vs-current and only starts, stops, or resubscribes on an actual change (it never reconnects on an unchanged config, which would re-trigger retained replays)
4. A bounded per-topic snapshot is reported under `data["mqtt"]`; discovery is capped per monitor to bound memory under a topic storm

## VPN Monitoring (WireGuard + Tailscale)

Requires agent version **1.16.0+**. Both collectors are enabled per host from
the fivenines dashboard and are off by default. They are independent: enable
either, both, or neither.

### WireGuard

One `wg show all dump` per tick reports every interface and every peer:

- Per peer: last handshake **age**, cumulative rx/tx bytes, endpoint, AllowedIPs
  and the configured `PersistentKeepalive` interval
- Per interface: name, listen port and peer count (reported even when the
  interface has zero peers, so the per-interface rollups read an honest 0)

The dashboard turns each peer into its own row so a `wireguard_peer_stale`
incident fires per tunnel -- which is the point when a dead tunnel means blind
monitoring of everything behind it.

Two things worth knowing:

- **Peers without `PersistentKeepalive` are not watched by default.** WireGuard
  is silent by design, so an idle laptop with a three-hour-old handshake is
  perfectly healthy. The staleness alert only watches keepalive-configured
  peers, which are the ones that should be chattering.
- **Secrets never leave the host.** `wg show all dump` prints the interface
  private key and each peer's preshared key; the agent drops both and transmits
  only the peer's *public* key, which is public by construction and is the
  peer's durable identity.

**Privilege.** `wg show all dump` reads device state over netlink, which needs
root or `CAP_NET_ADMIN`. The bundled systemd unit grants
`AmbientCapabilities=CAP_NET_ADMIN` (systemd >= 229) rather than running the
agent as root; the capability is inherited by the `wg` child process. Remove
that line if you do not monitor WireGuard. Without the privilege -- and on
OpenRC/Alpine and user-level installs, where the agent has no way to acquire it
short of running as root -- the collector reports a *collection failure*, never
an empty peer list, so existing peers are preserved and no open incident is
falsely resolved.

**Peer names.** The dashboard labels peers by the `# Name = <alias>` comment
next to the `[Peer]` block in `/etc/wireguard/<interface>.conf`, the de-facto
convention. That file is root-only, so an agent running as `fivenines` will not
see it and peers fall back to a short key fingerprint; nothing else in the
config is read.

### Tailscale

One `tailscale status --json` per tick reports:

- `backend_state` verbatim (`Running` / `Stopped` / `NeedsLogin` / ...)
- The node's **key expiry** instant, so the dashboard can alert days ahead
- Tailnet rollups: peers total and peers online

This half exists for one failure mode: an expired node key silently drops the
machine off the tailnet. tailscaled stays alive, flips to `NeedsLogin`, and
nothing on the box logs an error while every tailnet-only service stops
answering.

No extra privilege is needed, and it works identically on Linux and Windows
(the agent has no macOS build). Only the tailnet-wide rollups are sent, never per-peer rows: every node
sees every peer, so per-peer series would cost hosts x peers across a fleet.
A node whose key expiry is disabled in the admin console reports "no expiry"
rather than a fabricated countdown.

## Ubuntu Pro Entitlement

Requires agent version **1.16.1+**. On Linux hosts the agent reports whether the
machine is attached to an Ubuntu Pro subscription and **which Pro services are
actually enabled** on it. There is nothing to configure and nothing to turn on:
collection is unconditional and a host without the `pro` client simply reports
"could not determine".

This exists for the vulnerability scanner. When the only published patch for a
CVE lives in an Ubuntu Pro archive (ESM, FIPS), the finding is filed under
"fixable only with a subscription" instead of in the work queue. That is correct
for a machine that is not attached, and needlessly pessimistic for one that is --
an attached host can `apt install` the fix today. This signal is what lets the
dashboard tell the two apart.

The service list is the load-bearing half, not the attachment flag. A machine
can be attached with every service disabled (`pro disable esm-infra` is one
command), and each Ubuntu Pro archive pocket is opened by one specific service --
`esm-infra` does not unlock a FIPS-only fix. Only services reported as **enabled**
are sent.

Read from `pro api u.pro.status.is_attached.v1` and
`pro api u.pro.status.enabled_services.v1`, falling back to
`/var/lib/ubuntu-advantage/status.json` for clients too old to implement those
endpoints. **No extra privilege is needed** -- the agent reads the world-readable
machine token, not the root-only one. The reading is cached for 15 minutes, since
it changes about once in a machine's lifetime.

A `pro` that is missing, times out or errors reports "could not determine" and
the dashboard keeps whatever it last knew. It is never reported as "not
attached": a hiccup is not evidence that a machine detached, and treating it as
one would bounce that host's findings between the two buckets on every miss.

## Ceph Cluster Monitoring

Requires agent version **1.9.0+**. When Ceph monitoring is enabled for a host in the fivenines dashboard, the agent polls `ceph status`, `ceph df` and `ceph osd tree` and reports cluster health (status + active checks), monitor quorum, OSD up/in counts, PG states (degraded/inactive/undersized), raw capacity and per-host OSD counts. Multiple clusters per host are supported (each entry can carry its own `--cluster` name, config file and keyring).

Agent version **1.13.0+** adds a Datadog-parity second tier from the same targets (no extra config): client I/O throughput/IOPS and recovery/rebalance progress (curated out of `ceph status`), nearfull/full OSD counts (from the `OSD_NEARFULL`/`OSD_FULL` health checks), per-pool usage (from `ceph df`), and two additional read-only commands -- `ceph osd perf` (per-OSD commit/apply latency) and `ceph osd df` (per-OSD fullness). Each new command is independently isolated: a failure or timeout leaves its section absent without affecting the core metrics, and the server presence-guards every field, so older agents keep reporting unchanged.

### Requirements

The `ceph` CLI must be present on the host:

```bash
# Debian/Ubuntu
sudo apt install ceph-common

# RHEL/Rocky/CentOS
sudo yum install ceph-common
```

**Containerized Ceph (Kolla-Ansible, cephadm, Rook):** on these deployments the host often has no `ceph` binary -- the CLI lives inside a container. The agent detects this and skips Ceph collection gracefully, but to monitor the cluster you must install `ceph-common` on the host (plus a copy of `ceph.conf` and the keyring below, e.g. via `cephadm shell -- ceph auth get-or-create ...` or by copying them out of the container). A shell alias to `cephadm shell` is not enough: the agent needs a real `ceph` executable in `PATH`.

### Authentication (no sudo required)

The agent authenticates with a least-privilege cephx identity, `client.fivenines`, read-only on mon and mgr. Create it on any node with admin keys:

```bash
sudo ceph auth get-or-create client.fivenines mon 'allow r' mgr 'allow r' \
  -o /etc/ceph/ceph.client.fivenines.keyring
sudo chown fivenines /etc/ceph/ceph.client.fivenines.keyring
sudo chmod 600 /etc/ceph/ceph.client.fivenines.keyring
```

`/etc/ceph/ceph.client.fivenines.keyring` is on the standard keyring search path, so no extra agent configuration is needed -- the default target polls the local `ceph` cluster with `--name client.fivenines`. `/etc/ceph/ceph.conf` must be readable by the `fivenines` user (it is world-readable on standard installs). Non-default cluster names, config paths, keyring paths and client ids can be set per cluster from the dashboard.

The `use_sudo` per-cluster option is accepted but **reserved**: this version always uses keyring auth (the agent logs a notice and proceeds). No sudoers entry is needed or honored for Ceph.

### Capability Detection

The capabilities banner reports Ceph as available when the `ceph` CLI is found in `PATH` (`requires ceph CLI + client keyring` otherwise). Cluster reachability and keyring validity are deliberately NOT part of the capability probe -- a cluster outage or auth failure is reported as data (an unreachable cluster with an error type), so monitoring does not go blind exactly when the cluster breaks.

## AI Inference Serving (vLLM and SGLang)

Requires agent version **1.17.0+** (vLLM) / **1.17.1+** (SGLang). Both are
enabled per host from the dashboard and are plain HTTP scrapes of the inference
server's own Prometheus endpoint -- no capability gate, no extra package, and
they work anywhere the agent runs. Configure `metrics_url`, plus optionally
`auth_header_name` / `auth_header_value` and `verify_ssl`.

This is the serving layer *above* the [NVIDIA GPU metrics](#permissions), and it
exists for one failure mode those cannot see: **the inference server crashed or
wedged while every GPU still reads green**. GPU utilisation, memory and
temperature all look healthy on a box whose vLLM process OOM-died -- only the
serving endpoint knows.

Both collectors report a reachability envelope and **never** a bare "no data", so
the dashboard can tell "the server is down" (the signal) apart from "the
collector is off". Per served model you get request counts and running/waiting
queue depth, token throughput, KV-cache utilisation, prefix-cache hit rate, and
the end-to-end / time-to-first-token / inter-token latency histograms. Counters
and histogram sums ship raw -- the dashboard derives every rate -- and a metric
the server does not publish simply omits its key rather than being reported as
zero.

Two edges that would otherwise read as outages:

- **vLLM** (default `http://127.0.0.1:8000/metrics`). A 2xx response with zero
  `vllm:*` metrics means `reachable`, not down: launching with
  `--disable-log-stats` is a supported configuration. vLLM has also renamed
  several metrics across versions and exposes both spellings during the
  deprecation window; the agent folds each pair onto one canonical key so a
  metric is never double-counted.
- **SGLang** (default `http://127.0.0.1:30000/metrics`). Metrics are **opt-in**:
  SGLang publishes `sglang:*` samples only when launched with
  `--enable-metrics`. A reachable server reporting no models is therefore the
  expected stock-launch state, and the dashboard prompts you to add the flag
  rather than raising an outage.

On multi-GPU deployments the two engines differ in a way that matters: vLLM's
data-parallel engines each serve a share of the traffic, so their counters add
up, while SGLang's tensor-parallel ranks each report the *same* scheduler
reading, so summing them would multiply throughput by the TP degree. The agent
reduces each accordingly.

## Application Integrations

The agent can collect metrics from various applications when configured.

### Apache

Collects metrics from Apache's `mod_status` machine-readable endpoint
(`server-status?auto`). Works with both `mpm_prefork` and `mpm_event`:
- Requests/sec and bytes/sec
- Busy/idle workers (the dashboard derives worker utilization %)
- Total accesses and kBytes served (cumulative counters)
- Scoreboard: per-state worker distribution (waiting, reading, sending,
  keepalive, closing, ...)

Requires the `mod_status` module enabled (`a2enmod status` on Debian/Ubuntu;
often on by default) and a `server-status` handler:
```apache
<Location "/server-status">
    SetHandler server-status
    Require local
</Location>
```
Scrapes `http://127.0.0.1/server-status?auto` by default; `?auto` is appended
automatically if the configured URL omits it. All derived values (worker
utilization %, request/byte rates) are computed server-side from these raw
fields.

### Caddy

Collects metrics from Caddy's admin API (default: `http://localhost:2019`):
- Upstream health status
- HTTP server configuration
- TLS automation policies
- Process metrics (CPU, memory, goroutines)

Caddy's admin API is enabled by default. No additional configuration required.

### Nginx

Collects metrics from Nginx's stub status module:
- Active connections
- Reading/writing/waiting connections

Requires the `stub_status` module enabled in Nginx config:
```nginx
location /nginx_status {
    stub_status;
    allow 127.0.0.1;
    deny all;
}
```

### HAProxy

Reads HAProxy's `show stat` output and reports one row per **frontend**,
**backend** and **server**:

- Verbatim `status` (`UP` / `DOWN` / `MAINT` / `DRAIN` / `no check` and the
  transitional `UP 1/3` forms)
- Current sessions and the session limit, and current queue depth
- Cumulative 4xx and 5xx responses, retries, and bytes in/out
- Health-check status and check duration

Available in agent version **1.14.3+**. All counters are raw cumulative values;
the dashboard derives the rates and drives a per-backend "backend down" alert --
with `MAINT`/`DRAIN` kept distinct from `DOWN`, so planned maintenance never
pages.

Two transports, and the **stats socket is preferred** because it needs no web
exposure of the stats page:

```
# haproxy.cfg -- stats socket (Linux only; the agent's default path is
# /run/haproxy/admin.sock). "level admin" is NOT required: the agent only
# ever issues "show stat".
global
    stats socket /run/haproxy/admin.sock mode 660 group fivenines level operator
```

The socket must be readable by the `fivenines` user -- the `mode`/`group`
settings above are what grant that. Otherwise, point the agent at the HTTP CSV
endpoint instead (cross-platform, and the only option on non-Linux hosts); the
agent appends HAProxy's `;csv` modifier itself, and HTTP basic auth is supported:

```
frontend stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /stats
```

An unreachable socket or endpoint is reported as a collection failure rather than
"zero proxies", so a restarting HAProxy never resolves an open backend-down
incident. On very large deployments `server` rows are capped at 400, sorted
problems-first so `DOWN`/`MAINT`/`DRAIN` servers are kept ahead of healthy ones;
a capped tick is flagged so the dashboard knows not to prune the rows it did not
receive.

### PHP-FPM

Collects the FPM status page for every pool and reports per-pool saturation --
`max children reached`, listen queue depth and its high-water mark, active /
idle / total processes, slow requests, and accepted-connection counts. Available
in agent version **1.13.1+**. This is the usual root cause behind "the site is
slow": the pool is out of workers, not the database.

Three ways to point the agent at it:

- **HTTP** -- scrape the status page through your web server, like the Nginx and
  Apache integrations. One URL is one pool.
- **Direct FastCGI** -- `unix:///run/php/php8.2-fpm.sock/status` or
  `tcp://127.0.0.1:9000/status`. The agent speaks FastCGI itself (pure Python, no
  extra dependency), so `/status` never has to be exposed through the web server
  at all. This is the security-friendlier setup.
- **`auto`** -- discover every pool from the FPM `pool.d` configs
  (`/etc/php/*/fpm/pool.d/*.conf` and the equivalents on other distributions) and
  poll each over its own socket. Multi-pool hosts come for free.

Requires `pm.status_path` to be set in each pool's config (e.g.
`pm.status_path = /status`) and the socket to be readable by the `fivenines`
user for the direct-FastCGI and `auto` transports.

If **any** known pool fails to answer, the whole tick is reported as a collection
failure rather than as a shorter array. A pool silently missing from the array
would read as "the operator deleted that pool" and resolve its open saturation
incident -- unknown is not recovered. A pool you genuinely removed simply stops
being discovered and is pruned normally.

### PostgreSQL

Collects metrics via a direct connection (pure-Python `pg8000` driver, no `psql` binary required):
- Connection counts by state
- Database statistics (transactions, cache hit ratio)
- Database sizes
- Replication lag (for replicas)
- Lock counts

Requires appropriate database credentials.

### MySQL / MariaDB

Collects metrics via the `mysql`/`mariadb` client CLI (unix socket or TCP;
`MYSQL_PWD` keeps the password out of the process list). Works with MySQL 8 and
MariaDB. Reports a reachability status so the dashboard can tell an outage apart
from a credentials problem. Available in agent version **1.11.4+**:

- Reachable / unreachable / config-error status with the underlying error
- Connections and `max_connections`; queries, slow queries, aborted connects
  (raw counters; the dashboard derives rates)
- Uptime and server version
- InnoDB buffer-pool hit ratio and usage (computed)
- Replication status and lag for replicas (`SHOW REPLICA STATUS` with a
  `SHOW SLAVE STATUS` fallback for MariaDB / MySQL < 8.0.22)
- Galera / wsrep cluster state on MariaDB/MySQL Galera nodes (cluster size and
  status, local state, ready/connected, flow-control pause and receive-queue
  averages). Detection is implicit: a non-Galera server reports no wsrep data,
  so these keys are simply absent. Available in agent version **1.15.0+**.

Requires a `mysql` (or `mariadb`) client on the host and appropriate database
credentials.

### Redis / Valkey

Collects metrics from a single `INFO` call over the Redis protocol. Works with
Redis and [Valkey](https://valkey.io) (the collector also reports
`valkey_version` when present). Deepened in agent version **1.11.0+**:

- Version and uptime (`valkey_version` on Valkey)
- Connected/blocked clients, commands processed, ops/sec
- Memory: used memory, `maxmemory` limit, fragmentation ratio
- Keyspace hits/misses (the dashboard derives the hit ratio)
- Evicted/expired keys, per-database key counts
- Replication: role, connected replicas, replication offset, per-replica
  state/offset/lag (master) and link status/lag (replica)
- Persistence: last RDB save time, last background-save status, AOF enabled

Connects to `localhost:6379` by default; an optional password is supported. All
derived values (memory usage %, hit ratio, RDB age, replication lag) are
computed server-side from these raw fields.

### Memcached

Collects a snapshot from a single `stats` command over the Memcached text
protocol (one short-lived TCP connection, no extra dependency). Available in
agent version **1.14.4+**:

- Server version and uptime
- Current connections, stored bytes vs the `limit_maxbytes` ceiling
- Raw cumulative counters: get hits/misses, get/set commands, evictions,
  expired-unfetched items (the dashboard derives the hit ratio and rates)

Connects to `127.0.0.1:11211` by default; set `host`/`port` to point elsewhere.
A refused connection, timeout, or malformed reply reports as a collection
failure, so a transient outage is never mistaken for an empty cache.

### RabbitMQ

Polls the RabbitMQ **management API** over HTTP (default
`http://127.0.0.1:15672`) and reports broker health plus per-queue backlog.
Available in agent version **1.14.2+**:

- Broker version and reachability, with the failure reason (connection refused,
  timeout, authentication failure, HTTP error) when it is down
- Local node health: memory and disk **alarms**, file-descriptor and socket
  usage against their limits -- the headroom metrics that predict an outage
  before it lands
- Per queue: `messages`, `messages_unacknowledged`, consumer count, and raw
  cumulative publish/deliver counters

Enable the management plugin and create a least-privilege monitoring user -- the
`monitoring` tag grants read access to the API without any permission on the
queues themselves:

```bash
rabbitmq-plugins enable rabbitmq_management
rabbitmqctl add_user fivenines 'CHANGE_ME'
rabbitmqctl set_user_tags fivenines monitoring
rabbitmqctl set_permissions -p / fivenines "^$" "^$" "^$"
```

The three empty regexes deny configure, write and read on every resource: the
`monitoring` tag alone is what the API needs, so this user can observe the broker
but cannot publish, consume, or reconfigure anything.

The queue list is **bounded** on brokers with thousands of queues: the agent
sends the top queues by depth, the top by unacknowledged messages, and any queue
you explicitly name -- the unacknowledged dimension is not redundant, since a
small queue whose consumers are stuck is exactly the case an alert exists for. A
`queues_total` field always carries the broker's true count so the dashboard can
show that the list is a sample. A dead broker or a queue listing that came back
incomplete is reported as unreachable rather than as a shorter list, so queue
rows are never pruned and an open backlog incident cannot falsely resolve.

### Prometheus / VictoriaMetrics

Monitors the health of a **Prometheus or VictoriaMetrics server** itself
(default `http://127.0.0.1:9090`) -- who watches the watcher. Available in agent
version **1.14.1+**. When your TSDB dies, the whole observability stack goes dark
silently: nothing reports the outage, because the thing that reports outages is
the thing that is down.

- Reachability, flavor (Prometheus vs VictoriaMetrics) and version
- **Prometheus**: head series, storage bytes, WAL corruptions, rule-evaluation
  failures, dropped alert notifications, and -- from the targets API -- how many
  scrape targets exist and how many are down
- **VictoriaMetrics**: free disk space (the critical one -- VM refuses inserts
  once it drops below its threshold), data size, active series, new series
  created, slow inserts and ignored rows

Counters ship raw; the dashboard derives the rates. A metric the server does not
publish omits its key rather than being reported as zero, and no target or rule
keys are sent for a single-node VictoriaMetrics, which scrapes nothing.

Auth is optional -- a custom header (`auth_header_name` / `auth_header_value`) or
HTTP basic auth, with `verify_ssl` configurable.

Reachability means exactly one thing: the server answered `/metrics`. A 2xx
response yields "reachable" even if the flavor is unrecognised, no expected
metric is present, or the follow-up targets API is locked down -- an agent-mode
Prometheus is a normal deployment, and an agent-side parsing gap must never page
you with "your Prometheus is down". Only a connection-level failure -- refused,
timeout, TLS error, auth failure, non-2xx -- reports as unreachable.

## Contribute

Feel free to open a PR/issues if you encounter any bug or want to contribute.

## Contact

You can shoot me an email at: [sebastien@fivenines.io](mailto:sebastien@fivenines.io)
