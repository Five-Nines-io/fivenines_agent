# TODOS

## P3: Docker image caching for CI resilience

Mirror the 14 distro base images used in `test-distro-matrix` to ghcr.io or use
a Docker pull-through cache. Currently, all distro tests pull from Docker Hub
directly. A Docker Hub outage or rate-limit event would block the entire CI
pipeline.

- **Effort:** M (human) / S (CC)
- **Depends on:** #30 (distro regression testing) shipping first
- **Files:** `.github/workflows/build-release.yml`

## P3: Nightly distro matrix runs

Add a `schedule` trigger to the distro regression testing workflow to run the
matrix nightly or weekly. This catches upstream distro changes (new Alpine
minor release changing BusyBox behavior, new Ubuntu release changing adduser
flags) before users do.

- **Effort:** S (human) / S (CC)
- **Depends on:** #30 (distro regression testing) shipping first
- **Files:** `.github/workflows/build-release.yml` (add `schedule:` trigger)

## P2: Promote Rocky 10 to blocking

The `rockylinux:10` test matrix entry runs with `allow_failure: "1"` because the
Docker image does not exist yet. When Rocky Linux 10 GA ships and the Docker image
is available on Docker Hub, remove `allow_failure` from the matrix entry so that
RHEL 10 generation regressions block releases.

- **Effort:** S (human) / S (CC)
- **Depends on:** Rocky Linux 10 GA release
- **Files:** `.github/workflows/build-release.yml` (remove `allow_failure: "1"` from rockylinux:10 entry)

## P3: User-mode systemd units (systemctl --user)

Extend the systemd collector to optionally include user-mode systemd units
(`systemctl --user list-units`). Deferred from the initial systemd module ship
because user-mode systemd is rare on monitored fleets (mostly servers, not
developer desktops). Surface only if a customer asks for per-user service
visibility.

- **Effort:** M (human) / S (CC)
- **Depends on:** systemd module shipping first
- **Files:** `fivenines_agent/systemd.py` (add per-user invocation loop), `fivenines_agent/permissions.py` (probe), tests

## P3: Event-driven D-Bus subscription for systemd state transitions

The 10x version of systemd monitoring: subscribe to `org.freedesktop.systemd1`
D-Bus signals and push state transitions in real-time, eliminating polling lag
and dropping inventory cost to zero between changes. Rejected for the initial
ship because `pystemd` / `dbus-python` add native build deps that conflict with
the PyInstaller bundling story (CentOS 7+ binary target). Worth revisiting if
the binary build constraint changes (e.g., dropping CentOS 7 support, or moving
to a different bundler).

- **Effort:** L (human) / M (CC)
- **Depends on:** binary build constraints relaxing OR pystemd alternative emerging
- **Files:** new `fivenines_agent/systemd_events.py`, `pyproject.toml`, `py2exe.sh`

## P3: OOM detection journal-parse fallback for cgroup v1

The systemd module ships OOM kill detection via cgroup v2 `memory.events`.
On cgroup v1 and hybrid hosts, OOM count is reported as null. If backend
alerting needs v1 OOM coverage, add a journal-parse fallback that scans
`journalctl -k` for "Killed process" entries and correlates by PID/unit.
Avoided in initial ship because journal-parse is fragile and adds ongoing
subprocess cost; deferred until a concrete backend requirement appears.

- **Effort:** M (human) / S (CC)
- **Depends on:** backend signal that v1 OOM coverage matters
- **Files:** `fivenines_agent/systemd.py` (add fallback path), tests, fixtures
