# fivenines agent

This agent collects server metrics from the monitored host and sends it to the [fivenines](https://fivenines.io) API.

## Installation

### Standard Installation (Recommended)

Requires sudo/root access for initial setup. The agent runs as a dedicated `fivenines` user with limited permissions.

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN
```

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

## Remove

### Standard Removal (with sudo/root)

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_uninstall.sh && sudo bash fivenines_uninstall.sh
```

### User-Level Removal (no sudo/root)

```bash
wget -T 3 -q https://releases.fivenines.io/latest/fivenines_uninstall_user.sh && bash fivenines_uninstall_user.sh
```

## Debug

If you need to debug the agent collected data, you can run the following command:

```bash
# Standard installation
sudo -u fivenines /opt/fivenines/fivenines_agent --dry-run

# User-level installation
~/.local/fivenines/fivenines-agent-linux-*/fivenines-agent-linux-* --dry-run
```

## Permissions

The agent runs as the `fivenines` user and automatically detects available monitoring capabilities at startup. Most metrics work without any special permissions.

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
| Per-unit cgroup metrics | cgroup v1 or v2 mounted at `/sys/fs/cgroup` |
| Ceph cluster status | `ceph` CLI + read-only cephx keyring (no sudo) |

### Capabilities by Permission Level

**Always Available (no special permissions):**
- CPU usage and model
- Memory and swap usage
- Load average
- Disk I/O statistics
- Network I/O statistics
- Disk partition usage
- Open file handles
- Listening ports
- Process list (own user's processes)
- Packages

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

  [!] Some features unavailable. See: https://docs.fivenines.io/agent/permissions

============================================================
```

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

## Ceph Cluster Monitoring

Requires agent version **1.9.0+**. When Ceph monitoring is enabled for a host in the fivenines dashboard, the agent polls `ceph status`, `ceph df` and `ceph osd tree` and reports cluster health (status + active checks), monitor quorum, OSD up/in counts, PG states (degraded/inactive/undersized), raw capacity and per-host OSD counts. Multiple clusters per host are supported (each entry can carry its own `--cluster` name, config file and keyring).

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

## Application Integrations

The agent can collect metrics from various applications when configured.

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

### PostgreSQL

Collects metrics via a direct connection (pure-Python `pg8000` driver, no `psql` binary required):
- Connection counts by state
- Database statistics (transactions, cache hit ratio)
- Database sizes
- Replication lag (for replicas)
- Lock counts

Requires appropriate database credentials.

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

## Contribute

Feel free to open a PR/issues if you encounter any bug or want to contribute.

## Contact

You can shoot me an email at: [sebastien@fivenines.io](mailto:sebastien@fivenines.io)
