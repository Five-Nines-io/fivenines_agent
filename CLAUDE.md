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

- **Core metrics** (always enabled): `cpu.py`, `memory.py`, `load_average.py`, `io.py`, `network.py`, `partitions.py`, `files.py`, `ports.py`, `processes.py`, `temperatures.py`, `fans.py`
- **Storage**: `smart_storage.py` (requires sudo smartctl), `raid_storage.py` (requires sudo mdadm), `zfs.py`
- **Services**: `docker.py` (per-container state + metrics: status/health/exit-code/OOM/restart-count for every container from its first tick, plus running-container CPU/memory/block-I/O; keyed by full container id; `docker_metrics` returns `None` on daemon-unreachable so the server never prunes on error, `{}` only when genuinely zero containers), `qemu.py`, `proxmox.py`, `caddy.py`, `nginx.py`, `apache.py` (Apache mod_status `?auto`: busy/idle workers, per-state scoreboard, request/byte throughput; MPM-tolerant key/value parse, `None` on failure), `postgresql.py`, `redis.py`, `systemd.py` (per-unit health + inventory delta-sync, requires systemctl; journalctl only for failure journal tails, redacted before send)
- **Security**: `fail2ban.py` (requires sudo fail2ban-client)
- **Network/connectivity**: `ip.py` (public IPv4/IPv6 via ip.fivenines.io with 60s cache), `ping.py` (TCP latency), `snmp.py` (SNMP device polling via net-snmp CLI tools)
- **Security scanning**: `packages.py` (installed packages via dpkg/rpm/apk/pacman with hash-based delta sync)
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
  - `systemd`: unit collection config (`unit_types` as comma-separated string or list; `scan` triggers inventory delta-sync to `/systemd_inventory`)
  - `logs`: continuous log-signal collection (`units` allowlist, `signal_interval_s` window); gated on the `journald` capability
  - `capture_logs`: backend-pull incident capture command (`capture_id`, `unit`, `since`, `lines`, `expiry`); fired exactly once via the capture_id nonce + on-disk persistence, uploaded to `/logs` off the collection loop

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
