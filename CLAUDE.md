# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

fivenines-agent is a monitoring agent that collects server metrics and sends them to the fivenines API (https://fivenines.io). The agent runs continuously, probing system capabilities and collecting various metrics at configurable intervals.

## Development Commands

### Setup
```bash
# Install dependencies using Poetry
make install
```

### Code Quality
```bash
# Run linters (isort, black, flake8, mypy, bandit)
make lint

# Auto-format code (isort, black)
make format

# Run tests with coverage (requires 100% coverage)
make test

# Run a single test file
poetry run pytest tests/test_collectors.py -v
```

### Build Binary
```bash
# Build standalone executable for Linux (uses PyInstaller)
./py2exe.sh
```

The build process creates a self-contained binary at `./dist/linux/fivenines-agent-linux-*/` that includes all dependencies (libvirt, libcrypt, etc.) for compatibility with CentOS 7+.

### Running the Agent
```bash
# Run directly with Poetry
poetry run fivenines_agent

# Run with dry-run mode (collects metrics once and exits, prints JSON to stdout)
poetry run fivenines_agent --dry-run

# Check version
poetry run fivenines_agent --version
```

## Architecture

### Core Components

**Agent Loop (`agent.py`)**
- Main orchestrator that runs the collection loop
- Handles signals (SIGTERM, SIGINT for shutdown; SIGHUP for capability refresh)
- Collects static info once (version, uname, boot time, capabilities, user context)
- On each iteration: collects configured metrics, enqueues data, sleeps until next interval
- Manages graceful shutdown with proper cleanup

**Permission Probing (`permissions.py`)**
- Detects available monitoring capabilities at startup based on file permissions, sudo access, and group memberships
- Re-probes automatically every 5 minutes or on SIGHUP signal to detect permission changes
- Capabilities include: core metrics (always available), hardware sensors, storage (SMART/RAID), services (Docker/QEMU/Proxmox/systemd), kernel surfaces (cgroup, tri-state "v1"/"v2"/None), security (fail2ban), logs (`journald` read access, probed via `journalctl -n 0`), etc.
- Prints a capabilities banner showing what features are available/unavailable with hints

**Synchronizer (`synchronizer.py`)**
- Background thread that sends collected data to the fivenines API
- Fetches configuration from server before starting metric collection
- Handles retries with exponential backoff
- Compresses data with gzip before sending
- Uses custom DNS resolution with IPv4/IPv6 fallback

**SynchronizationQueue (`synchronization_queue.py`)**
- Thread-safe queue with maxsize limit for buffering collected metrics
- Prevents memory exhaustion if API is unreachable

**Log Uploader (`log_uploader.py`, `log_capture.py`)**
- Dedicated `LogUploader` worker thread + bounded queue that upload incident log-capture bundles to `/logs` via `Synchronizer.send_logs`, kept off the metric-collection loop so a slow/large upload never stalls collection, `/collect`, or the systemd watchdog
- `CaptureCoordinator` applies the backend `capture_logs` command with a capture_id nonce + on-disk `last_capture_id` persistence: each command fires exactly once and never replays after a `Restart=always` restart; `last_served` advances only after a confirmed upload, so a failed capture retries
- Part of log-monitoring V1; inert until the backend implements the `/collect` `capture_logs` command and the `/logs` endpoint

**Out-of-band Upload Workers (`queue_uploader.py`)**
- `QueueUploader` is the shared thread body for every off-loop uploader: bounded-queue drain, `None` shutdown sentinel, per-job isolation (a bad job never kills the thread), and exactly one `on_success`/`on_failure` callback per job so a coordinator can retire or retry the work item
- Subclasses supply only vocabulary (`label`, `job_id_key`, `payload_noun`). Users: `LogUploader` (`/logs`) and `ImageInventoryUploader` (`/image_packages`)
- Anything slower or larger than a metric payload belongs here rather than on the collection loop (which the systemd watchdog bounds) or the Synchronizer drain

**Image Inventory Worker (`docker_image_inventory.py`)**
- `ImageInventoryUploader` + `ImageInventoryCoordinator`: extraction (N archive fetches + tar parsing) and the `/image_packages` POST run entirely off the collection loop, so a 3-image tick does not extend the tick
- Image digests are immutable, so each is extracted **once per image forever**: done digests persist to `image_inventory_done` (bounded, FIFO-evicted) and survive a `Restart=always` restart. Failures back off exponentially and are given up on after `max_attempts` (in-memory, so a long outage cannot permanently blind an image); a queue-full shed releases the slot without counting an attempt
- `once per image forever` has one escape hatch, and it is server-driven: a transient `api_error` is reported INSIDE a 200, so the digest is marked done and the image would read "not scannable" forever. `ImageInventoryCoordinator.reset()` (via the top-level `rescan_images` config key) re-opens exactly those. A digest with no failure history is re-offered on the same tick the FIRST time it is requested; one the agent had already **given up** on is re-armed onto its retry ladder instead of made immediately eligible. Because the directive is level-triggered (the last `/collect` config is replayed by the Synchronizer during an outage, and a buggy server could re-send it), two agent-side floors keep a stale/looping request from re-extracting every tick: the retry ladder for given-up digests, and a per-digest `rescan_min_interval` (default 1h, `RESCAN_MIN_INTERVAL_SECONDS`) that throttles repeat re-opens even in the immediate `attempts==0` case. `apply_rescan_requests` bounds the untrusted list on three axes -- entries scanned (`MAX_RESCAN_SCANNED`), digests honoured (`MAX_RESCAN_IMAGES`), per-entry length (`MAX_FIELD_CHARS`) -- so a hostile config cannot burn the watchdog-bounded collection loop. `_persist` writes via a temp file + `os.replace` under a dedicated lock and re-reads the done set under `_lock`, since `reset()` (collection loop) is now a second writer alongside `mark_done()` (uploader thread)
- Inert until the backend sends the top-level `image_inventory` config key and implements `/image_packages`

**Subprocess Utilities (`subprocess_utils.py`)**
- Critical for PyInstaller compatibility: removes LD_LIBRARY_PATH and other environment variables that can interfere with system commands
- PyInstaller bundles libraries (like libselinux from libvirt) that conflict with system utilities (sudo, smartctl, mdadm)
- Always use `get_clean_env()` when calling subprocess commands

**Environment (`env.py`)**
- Central source for runtime configuration: `api_url()`, `config_dir()`, `dry_run()`, `log_level()`
- Config directory defaults to `/etc/fivenines_agent`; override with `CONFIG_DIR` env var
- `get_user_context()` collects user/group info sent with each payload

**Collector Registry (`collectors.py`)**
- Declarative `COLLECTORS` list maps config keys to `(data_key, callable, pass_kwargs)` tuples
- `agent.py` iterates this registry each tick; `pass_kwargs=True` unpacks the config dict as `**kwargs` to the callable
- Add new metrics here rather than modifying the agent loop

### Metric Collectors

Each metric collector is a separate module that exports functions to collect specific metrics:

- **Core metrics** (always enabled): `cpu.py`, `memory.py`, `load_average.py`, `io.py`, `network.py` (per-interface byte/packet/error/drop counters, plus Linux bridge detection, `interface_type` bridge/physical/virtual, `network_link_speed_bps` from `/sys/class/net/<if>/speed`, and `bridge_member_count` so the backend can compute per-interface saturation), `partitions.py`, `files.py`, `ports.py`, `processes.py`, `temperatures.py`, `fans.py`
- **Storage**: `smart_storage.py` (requires sudo smartctl), `raid_storage.py` (requires sudo mdadm), `zfs.py`
- **Services**: `docker.py` (per-container state + metrics: status/health/exit-code/OOM/restart-count for every container from its first tick, plus running-container CPU/memory/block-I/O; keyed by full container id; `docker_metrics` returns `None` on daemon-unreachable so the server never prunes on error, `{}` only when genuinely zero containers), `qemu.py`, `proxmox.py`, `caddy.py`, `nginx.py`, `apache.py` (Apache mod_status `?auto`: busy/idle workers, per-state scoreboard, request/byte throughput; MPM-tolerant key/value parse, `None` on failure), `haproxy.py` (HAProxy `show stat` over the AF_UNIX stats socket or HTTP `;csv` endpoint: per-frontend/backend/server rows with verbatim status and raw cumulative counters; CSV columns mapped by header name, `server` rows capped at 400 problems-first; `[]` when genuinely zero proxies, `None` on failure), `postgresql.py`, `mysql.py` (MySQL/MariaDB via the `mysql`/`mariadb` CLI; emits a reachable/unreachable/config-error status plus connections, query/InnoDB buffer-pool metrics, replication lag, and Galera/wsrep cluster state via a whitelisted `SHOW GLOBAL STATUS LIKE 'wsrep%'` -- implicit detection, keys absent on non-Galera hosts), `redis.py`, `memcached.py` (single `stats` command over TCP; flat whitelisted snapshot of version/uptime/connections/bytes-vs-limit plus RAW cumulative `*_total` counters (hits/misses/get/set/evictions/expired-unfetched); `None` on collection failure -- refused/timeout/no-`END`-terminator; config-driven `{host, port}`, no capability gate), `rabbitmq.py` (RabbitMQ management-API poll: a reachability envelope + node alarms/fd-socket headroom + a bounded per-queue array = top-N by `messages` UNION top-N by `messages_unacknowledged` UNION `include_queues`, with `queues_total` carrying the broker's true count. postgresql-style `reachable:false` envelope -- never `None` -- on a dead broker OR an untrustworthy/partial queue listing, so the server never prunes queue rows or false-resolves an open `rabbitmq_queue_backlog` incident; raw `message_stats` counters (server derives rates); include tail bounded by a count cap AND a wall-clock watchdog deadline. Config-driven `{url, username, password, vhost, include_queues}`, no capability gate), `systemd.py` (per-unit health + inventory delta-sync, requires systemctl; journalctl only for failure journal tails, redacted before send)
- **Security**: `fail2ban.py` (requires sudo fail2ban-client)
- **Network/connectivity**: `ip.py` (public IPv4/IPv6 via ip.fivenines.io with 60s cache), `ping.py` (TCP latency), `snmp.py` (SNMP device polling via net-snmp CLI tools), `mqtt.py` (persistent MQTT broker subscriptions via bundled `paho-mqtt`; the agent's first long-lived-connection collector -- a `MQTTManager` singleton keeps one client per broker alive across ticks, reconciles start/stop/resubscribe on config change only, and snapshots per-topic freshness ages under `data["mqtt"]`. RETAIN=1 deliveries update `last_message_age_s` but NEVER `last_live_seen_age_s` -- the retained-vs-live honesty the feature exists for. Reconcile is called EVERY tick from `agent._collect_metrics` so a removed `mqtt` config tears clients down; `mqtt_metrics` returns `None` when unconfigured so the key is omitted, an error/auth_error envelope -- never `None` -- on failure. `Agent._cleanup` calls `shutdown_mqtt()`. Config-pushed like `snmp_targets`; not in the COLLECTORS registry.)
- **Security scanning**: `packages.py` (installed packages via dpkg/rpm/apk/pacman with hash-based delta sync), `docker_image_inventory.py` (OS package lists extracted from Docker **images** via the archive API `container.get_archive` -- no `docker exec`, works on stopped/never-started containers, and the only design that works under rootless, where layer files belong to subordinate UIDs a host process cannot read; dpkg + apk in phase 1, RPM reported `unsupported`. `/etc/os-release` is a symlink the GET does NOT follow, so the absolute `stat["linkTarget"]` is re-requested. Reuses `packages.parse_os_release` + `get_packages_hash` so host and image distro strings/hashes cannot drift. Honesty contract: a failure is NEVER an empty-and-clean payload -- every failure path records a structured `errors[]` entry, because `packages: []` with `errors: []` renders as a false "0 vulnerabilities")
- **Kernel surfaces**: `cgroup.py` (v1/v2 hierarchy detection + safe per-unit metric reads, used by `systemd.py`)
- **Log monitoring** (V1): `logs.py` (continuous per-unit error/warn signals + top fingerprints via `collect_log_signals`, wired as the `logs` collector; incident capture via `build_capture_bundle`: bounded retroactive `journalctl` slice -> redacted enriched digest; shared best-effort `redact()` for secrets/PII, also used by `systemd.py`). Gated on the `journald` capability (journal read access); transport/coordination live in `log_capture.py` + `log_uploader.py` (see Core Components).

Collectors use the `@debug` decorator from `debug.py` to log execution time and results.

### Configuration

- Agent reads `TOKEN` file from config directory (default `/etc/fivenines_agent`, `~/.local/fivenines` for user install, overridable via `CONFIG_DIR`)
- Configuration is fetched from the API server on startup and includes:
  - `enabled`: whether collection is active
  - `interval`: seconds between collections (default 60)
  - Feature flags for each metric type (cpu, memory, etc.)
  - Service-specific config (e.g., redis host/port, `docker.socket_url` which drives both per-container state and metrics collection)
  - `request_options`: timeout, retry count, retry interval
  - `packages.scan`: triggers package inventory sync with hash-based deduplication
  - `image_inventory`: **TOP-LEVEL** truthy flag enabling Docker image OS-package extraction (uploaded to `/image_packages` off the collection loop). It must NEVER be nested under `docker`: `collectors.py` splats `config["docker"]` as `**kwargs` into `docker_metrics`, so a new nested key would raise `TypeError` on older agents, be swallowed into `data["docker"] = None`, and -- with the server's never-prune-on-null rule -- freeze container-state rows fleet-wide. Requires `docker` collection to also be enabled, since the digest set is derived from `data["docker"]["containers"]`
  - `rescan_images`: **TOP-LEVEL** bounded array of image digests the server wants re-inventoried (server issue #676), same splat-safety rule as `image_inventory`. The server sends only `api_error` digests this host runs, past its own 6h backoff; the agent drops them from `image_inventory_done` so the normal selection path re-offers them. Honoured only while `image_inventory` is on. The directive is level-triggered and untrusted, so the agent does not rely on the server for safety: it caps how much of the list it scans/honours/reads per entry, and floors repeat re-opens per digest (`rescan_min_interval`, default 1h) so a stale directive replayed during a `/collect` outage cannot treadmill re-extraction every tick
  - `systemd`: unit collection config (`unit_types` as comma-separated string or list; `scan` triggers inventory delta-sync to `/systemd_inventory`)
  - `logs`: continuous log-signal collection (`units` allowlist, `signal_interval_s` window); gated on the `journald` capability
  - `capture_logs`: backend-pull incident capture command (`capture_id`, `unit`, `since`, `lines`, `expiry`); fired exactly once via the capture_id nonce + on-disk persistence, uploaded to `/logs` off the collection loop
  - `mqtt`: list of brokers (`broker_id`, `host`, `port`, `tls`, `username`, `password`, `monitors[{id, topic_filter, capture_payload}]`); replaces the agent's MQTT state wholesale each tick (absent/falsy tears all clients down). Consumed as a special-case collector (like `snmp_targets`), not via the COLLECTORS registry

### Installation Types

The agent supports two installation modes:

1. **System installation**: Runs as dedicated `fivenines` user via systemd service (`fivenines-agent.service`) or OpenRC (`fivenines-agent.openrc`)
2. **User installation**: Runs as current user with helper scripts (start.sh, stop.sh, status.sh, logs.sh, refresh.sh)

User context is collected and sent with metrics to help the backend understand permission limitations.

## Code Style

- Python 3.10+ required (compatible with 3.10-3.13)
- Code must pass: isort (black profile), black, flake8 (ignore W503, E501), mypy, bandit (skip B608)
- **ASCII-only characters in codebase** - do not use non-ASCII characters (enforced since v1.4.0)
- Test coverage must be 100%
- Use `from fivenines_agent.debug import log, debug` for logging
- Log levels: 'debug', 'info', 'error'

## Important Patterns

### Subprocess Calls
Always use clean environment to avoid PyInstaller library conflicts:
```python
from fivenines_agent.subprocess_utils import get_clean_env
result = subprocess.run(cmd, env=get_clean_env(), ...)
```

### Permission-Dependent Features
Check permissions before attempting operations:
```python
from fivenines_agent.permissions import get_permissions
perms = get_permissions()
if perms.get('smart_storage'):
    # Collect SMART data
```

### Signal Handling
- SIGTERM/SIGINT: Sets `exit_event` to trigger graceful shutdown
- SIGHUP: Sets `refresh_permissions_event` to re-probe capabilities without restart; also forces a full systemd inventory resend and re-detects the cached cgroup hierarchy/systemd version

### Debug Decorator
Wrap metric collection functions for automatic timing and error logging:
```python
@debug('metric_name')
def collect_metric():
    # Returns metric data
    return data
```

## Dependencies

Key dependencies:
- `psutil` (^7.2.1): Cross-platform system monitoring
- `systemd-watchdog` (^0.9.0): Systemd watchdog notifications
- `docker` (^7.1.0): Docker container monitoring
- `libvirt-python` (^11.6.0): QEMU/KVM VM monitoring
- `proxmoxer` (^2.1.0): Proxmox VE monitoring
- `certifi` (^2024.12.14): SSL/TLS certificate validation

## Binary Build Process

The `py2exe.sh` script creates a standalone Linux binary:
1. Sets up cross-compilation environment for target architecture (amd64/arm64)
2. Creates virtualenv and installs dependencies
3. Builds `libpython3.10.so` from source for PyInstaller compatibility
4. Bundles all dependencies including libvirt 6.10.0, libcrypt, libtirpc
5. Creates onedir distribution with all shared libraries included
6. Output: `./dist/linux/fivenines-agent-linux-*/`

This enables the agent to run on CentOS 7+ without system-level Python dependencies.

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming -> invoke /office-hours
- Strategy/scope -> invoke /plan-ceo-review
- Architecture -> invoke /plan-eng-review
- Design system/plan review -> invoke /design-consultation or /plan-design-review
- Full review pipeline -> invoke /autoplan
- Bugs/errors -> invoke /investigate
- QA/testing site behavior -> invoke /qa or /qa-only
- Code review/diff check -> invoke /review
- Visual polish -> invoke /design-review
- Ship/deploy/PR -> invoke /ship or /land-and-deploy
- Save progress -> invoke /context-save
- Resume context -> invoke /context-restore
