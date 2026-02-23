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
    [OK] Cpu
    [OK] Memory
    [OK] Load Average
    [OK] Io
    [OK] Network
    [OK] Partitions
    [OK] File Handles
    [OK] Ports
    [OK] Processes

  Hardware Sensors:
    [OK] Temperatures
    [X] Fans (no accessible sensors)

  Storage:
    [X] Smart Storage (requires: sudo smartctl)
    [X] Raid Storage (requires: sudo mdadm)

  Services:
    [OK] Docker
    [OK] Caddy
    [X] Qemu (requires: libvirt group)
    [OK] Proxmox

  Security:
    [X] Fail2Ban (requires: sudo fail2ban-client)
    [X] Packages

  [!] Some features unavailable. See: https://docs.fivenines.io/agent/permissions

============================================================
```

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

Collects metrics via `psql`:
- Connection counts by state
- Database statistics (transactions, cache hit ratio)
- Database sizes
- Replication lag (for replicas)
- Lock counts

Requires `psql` available and appropriate database credentials.

### Redis

Collects metrics via Redis protocol:
- Version and uptime
- Connected/blocked clients
- Commands processed
- Evicted/expired keys
- Per-database key counts

Connects to `localhost:6379` by default.

## Security

The agent communicates exclusively with `api.fivenines.io` over TLS, validating the server certificate against the `certifi` CA bundle. All API responses are validated and sanitized before use — server-supplied configuration cannot redirect collectors to non-loopback addresses, disable SSL verification, or inject commands through credential fields.

For the full security posture, hardening measures, and known design considerations see [SECURITY.md](SECURITY.md).

To report a vulnerability, email [sebastien@fivenines.io](mailto:sebastien@fivenines.io).

## Contribute

Feel free to open a PR/issues if you encounter any bug or want to contribute.

## Contact

You can shoot me an email at: [sebastien@fivenines.io](mailto:sebastien@fivenines.io)
