# fivenines agent

This agent collects server metrics from the monitored host and sends it to the [fivenines](https://fivenines.io) API.

## Installation

### Standard Installation (Recommended)

Requires root access for initial setup. The agent runs as a dedicated `fivenines` user with limited permissions.

```bash
wget --connect-timeout=3 -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN
```

### User-Level Installation (No Root Access)

For environments where you don't have root access (shared hosting, managed VPS, etc.):

```bash
wget --connect-timeout=3 -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_setup_user.sh && bash fivenines_setup_user.sh TOKEN
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

## Update

### Standard Update (with root)

```bash
wget --connect-timeout=3 -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_update.sh && sudo bash fivenines_update.sh
```

### User-Level Update (no root)

```bash
wget --connect-timeout=3 -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_update_user.sh && bash fivenines_update_user.sh
```

## Remove

### Standard Removal (with root)

```bash
wget --connect-timeout=3 -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_uninstall.sh && sudo bash fivenines_uninstall.sh
```

### User-Level Removal (no root)

```bash
wget --connect-timeout=3 -q -N https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_uninstall_user.sh && bash fivenines_uninstall_user.sh
```

## Debug

If you need to debug the agent collected data, you can run the following command:

```bash
# Standard installation
/opt/fivenines/fivenines_agent --dry-run

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

The agent works without sudo, but these features will be unavailable:

| Feature | Requirement |
|---------|-------------|
| SMART disk health | `sudo smartctl` |
| RAID array status | `sudo mdadm` |
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

**May Work Without Root:**
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
═══════════════════════════════════════════════════════════════
  Fivenines Agent - Capabilities Detection
═══════════════════════════════════════════════════════════════

  Core Metrics:
    ✓ Cpu
    ✓ Memory
    ✓ Load Average
    ✓ Io
    ✓ Network
    ✓ Partitions
    ✓ File Handles
    ✓ Ports
    ✓ Processes

  Hardware Sensors:
    ✓ Temperatures
    ✗ Fans (no accessible sensors)

  Storage:
    ✗ Smart Storage (requires: sudo smartctl)
    ✗ Raid Storage (requires: sudo mdadm)

  Services:
    ✓ Docker
    ✗ Qemu (requires: libvirt group)

  ⚠ Some features unavailable. See: https://docs.fivenines.io/agent/permissions

═══════════════════════════════════════════════════════════════
```

## Contribute

Feel free to open a PR/issues if you encounter any bug or want to contribute.

## Contact

You can shoot me an email at: [sebastien@fivenines.io](mailto:sebastien@fivenines.io)
