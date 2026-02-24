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
- Capabilities include: core metrics (always available), hardware sensors, storage (SMART/RAID), services (Docker/QEMU/Proxmox), security (fail2ban), etc.
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
- **Services**: `docker.py`, `qemu.py`, `proxmox.py`, `caddy.py`, `nginx.py`, `postgresql.py`, `redis.py`
- **Security**: `fail2ban.py` (requires sudo fail2ban-client)
- **Network/connectivity**: `ip.py` (public IPv4/IPv6 via ip.fivenines.io with 60s cache), `ping.py` (TCP latency)
- **Security scanning**: `packages.py` (installed packages via dpkg/rpm/apk/pacman with hash-based delta sync)

Collectors use the `@debug` decorator from `debug.py` to log execution time and results.

### Configuration

- Agent reads `TOKEN` file from config directory (default `/etc/fivenines_agent`, `~/.local/fivenines` for user install, overridable via `CONFIG_DIR`)
- Configuration is fetched from the API server on startup and includes:
  - `enabled`: whether collection is active
  - `interval`: seconds between collections (default 60)
  - Feature flags for each metric type (cpu, memory, etc.)
  - Service-specific config (e.g., redis host/port, docker socket path)
  - `request_options`: timeout, retry count, retry interval
  - `packages.scan`: triggers package inventory sync with hash-based deduplication

### Installation Types

The agent supports two installation modes:

1. **System installation**: Runs as dedicated `fivenines` user via systemd service (`fivenines-agent.service`) or OpenRC (`fivenines-agent.openrc`)
2. **User installation**: Runs as current user with helper scripts (start.sh, stop.sh, status.sh, logs.sh, refresh.sh)

User context is collected and sent with metrics to help the backend understand permission limitations.

## Code Style

- Python 3.9+ required (compatible with 3.9-3.13)
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
- SIGHUP: Sets `refresh_permissions_event` to re-probe capabilities without restart

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
3. Builds `libpython3.9.so` from source for PyInstaller compatibility
4. Bundles all dependencies including libvirt 6.10.0, libcrypt, libtirpc
5. Creates onedir distribution with all shared libraries included
6. Output: `./dist/linux/fivenines-agent-linux-*/`

This enables the agent to run on CentOS 7+ without system-level Python dependencies.
