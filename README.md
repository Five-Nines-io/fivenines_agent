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
| Log monitoring (journald capture + signals) | journal read access (`systemd-journal` group) |
| WireGuard peer health | root or `CAP_NET_ADMIN` (the bundled systemd unit grants `AmbientCapabilities=CAP_NET_ADMIN`) |
| Tailscale node state | `tailscale` CLI on `PATH` + a reachable `tailscaled` (no extra privilege) |
| Ubuntu Pro entitlement | `pro` CLI on `PATH` (ubuntu-advantage-tools), or a readable `/var/lib/ubuntu-advantage/status.json` (no extra privilege) |
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

### Rootless Docker

Two setups get called "non-root Docker", and they are not the same:

- **Agent as a non-root user (`User=fivenines`) talking to a root daemon** via
  `/var/run/docker.sock` works out of the box once `fivenines` is in the
  `docker` group (see above). This is the common case and needs no extra
  privilege for Docker image inventory (image vulnerability scanning) either --
  it uses the same socket.
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

No extra privilege is needed, and it works identically on Linux, Windows and
macOS. Only the tailnet-wide rollups are sent, never per-peer rows: every node
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

## Contribute

Feel free to open a PR/issues if you encounter any bug or want to contribute.

## Contact

You can shoot me an email at: [sebastien@fivenines.io](mailto:sebastien@fivenines.io)
