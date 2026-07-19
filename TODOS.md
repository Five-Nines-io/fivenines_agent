# TODOS

## P2: Log monitoring - flat-file (non-journald) source (E2)

Deferred from `ceo-plans/2026-06-30-log-file-monitoring.md` at the Codex
cut-scope. V1 reads journald only, so services that log to their own files
(`/var/log/nginx/*.log`, apps writing files, non-systemd hosts) are uncovered.
Add a log2journal-style parser + a ring-buffer for rotation (no retroactive
read on rotating files). This is the "second subsystem" the review flagged.

- **Effort:** L (human) / M (CC)
- **Depends on:** log monitoring V1 shipped
- **Files:** `fivenines_agent/logs.py` (file source alongside journald), tests

## P3: Log monitoring - remaining V1 fast-follows

Consolidated deferrals from the same CEO plan, each a complete follow-up:
- **E1 ML edge trigger** (k-means anomaly detection on the agent) - gated behind
  a PyInstaller/BLAS feasibility spike; deterministic triggers suffice for now.
- **Local instant capture trigger** (sub-second, agent-side) - V1 uses
  backend-pull + incident-mode interval drop; the local detector is deferred.
- **Windows Event Log source** - V1 is Linux/journald only.
- **Raw posture opt-in** - V1 hardcodes `posture: "digest"`; wire the per-account
  raw flag through and enforce `max_bytes` (only meaningful for raw). E4
  log-based alerting is backend-side.

- **Effort:** varies (see plan) / mostly M (CC)
- **Depends on:** log monitoring V1 in production + demand signal
- **Files:** `fivenines_agent/logs.py`, `fivenines_agent/log_capture.py`

## P3: Log monitoring - DRY debt from pre-landing review

Two duplications flagged (confidence 4-5, deferred rather than refactor at ship):
`logs._signals_for_unit` and `logs.build_digest` share a fingerprint-grouping
loop with subtly different outputs (info counted or not, `sample` vs `excerpt`
key, top-N cap); and journald `-o json` MESSAGE parsing is duplicated between
`logs._capture_entries` and `systemd._parse_journalctl_failed`. Extract shared
helpers once the shapes stabilize.

- **Effort:** S (human) / S (CC)
- **Depends on:** nothing
- **Files:** `fivenines_agent/logs.py`, `fivenines_agent/systemd.py`, tests

## P1: Hourly re-send TTL for stuck-failed unit drilldowns

Deferred from plan `2026-05-04-systemd-services.md` (ship gate decision). The
failure drilldown is debounced by `(NRestarts, ActiveEnterTimestamp)` signature,
so a unit that stays failed with an unchanged signature sends its journal tail +
reverse-deps (the latter only on systemd >= 230) exactly once. The plan called for a 1-hour TTL that forces a
re-send so the backend periodically refreshes the evidence. Marginal in
practice (a dead unit's err-priority journal rarely changes), which is why it
was deferred rather than reopening the reviewed debounce logic at ship time.

- **Effort:** S (human) / S (CC)
- **Depends on:** systemd module shipped
- **Files:** `fivenines_agent/systemd.py` (`_is_newly_failed` LRU entry gains a timestamp + TTL check), tests

## P2: Inventory/packages POST retries stall the collection thread during API outages

`synchronizer._post` retries 3x with backoff (~30-60s worst case) and both
`systemd_inventory_sync` and `packages_sync` call it synchronously from the
collection thread. During an API outage with an unacknowledged inventory hash,
every tick re-attempts the send and stalls collection for the retry duration.
Shared architecture with packages_sync (pre-existing pattern), so fix both at
once: either single-attempt sends for delta-synced payloads (the per-tick hash
recheck already provides retry semantics) or dispatch through the synchronizer
thread.

- **Effort:** M (human) / S (CC)
- **Depends on:** nothing (architecture change, touch synchronizer + agent)
- **Files:** `fivenines_agent/synchronizer.py`, `fivenines_agent/agent.py`, tests

## P3: Generalized resilience to an unshowable name in the bulk show

A single unit name that `systemctl show` rejects fails the whole bulk fetch
(exit non-zero -> `_run_subprocess` drops all stdout), blacking out health +
inventory for the host every tick. Bare template units were the known trigger
and are now filtered (`_is_template_unit`), and `list-units` only yields
concrete showable units, so the surface is showable in practice. But if any
other unshowable name ever appears, the blast radius is the whole host. Harden
by isolating the bad name on a `cli_error` -- bisect the failing chunk and drop
the offending unit(s) -- instead of failing the entire fetch. Locale-independent
(no error-message parsing); bounded at log2(chunk) retries.

- **Effort:** M (human) / S (CC)
- **Depends on:** nothing
- **Files:** `fivenines_agent/systemd.py` (`_show_bulk`), tests

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

## P4: Additional systemd unit types (.mount/.path/.swap/.slice/.scope)

Deferred from the initial systemd ship. Already reachable today WITHOUT a code
change: the backend can set `systemd.unit_types` to any comma-separated list
(the collector normalizes list/tuple config too). This entry exists to decide
whether any of these types should join the DEFAULT set once real-fleet payload
sizes are known.

- **Effort:** S (human) / S (CC)
- **Depends on:** payload-size data from fleets running the shipped defaults
- **Files:** `fivenines_agent/systemd.py` (`DEFAULT_UNIT_TYPES`)

## P4: Boot-time analysis via systemd-analyze blame

Deferred from the initial systemd ship (plan listed it as a possible drilldown
extension). `systemd-analyze blame`/`critical-chain` would let the backend show
slow-boot culprits. One-shot data per boot, so it belongs in static/boot-time
collection rather than the per-tick loop.

- **Effort:** M (human) / S (CC)
- **Depends on:** product signal that boot-time analysis matters to customers
- **Files:** `fivenines_agent/systemd.py` (one-shot collection), `fivenines_agent/agent.py` (static data), tests

## P3: Docker events API for short-lived container capture

The container-state collector (server #492) polls `containers.list(all=True)` once
per tick, so a container that starts and exits (or is `--rm`'d) entirely between
two ticks is never observed -- its death, exit code, and OOM status are invisible.
The 10x version subscribes to the Docker events stream (`client.events()`) and
records terminal transitions as they happen, eliminating the polling blind spot.
Deferred from the initial ship because an events subscription is a persistent
connection with its own lifecycle/reconnect handling (a different shape from the
per-tick poll loop) and the poll already covers every container that lives at
least one interval -- the common case. Documented as a known limitation in the
`docker.py` module docstring.

- **Effort:** L (human) / M (CC)
- **Depends on:** container-state collector shipped (done, 1.11.0)
- **Files:** new events-stream path in `fivenines_agent/docker.py` (or a sibling), `fivenines_agent/agent.py` (subscription lifecycle), tests

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

## P3: Hoist net_if_addrs() out of the per-interface loop in interfaces()

Pre-existing (predates the issue #50 bridge/link-speed work, flagged by its
pre-landing review). `interfaces()` calls `psutil.net_if_addrs()` once per
interface, and each call rebuilds the full address map for every interface --
O(N^2). Harmless on a normal host, but the bridge-saturation feature aims
exactly at Proxmox hosts with thousands of veth/tap interfaces, where this is
the dominant cost each tick. Fix is a one-liner (compute the map once before the
loop), but it touches the address-lookup try/except that
`test_interfaces_skips_when_net_if_addrs_raises` pins, so do it deliberately
with the test in front of you. Kept out of the #50 PR to keep that diff scoped
to the contract.

- **Effort:** S (human) / S (CC)
- **Depends on:** nothing
- **Files:** `fivenines_agent/network.py` (`interfaces()`), `tests/test_network.py`

## P4: Finer interface_type classification (bond / vlan / paravirtual)

The issue #50 `interface_type` is a coarse three-way heuristic: bridge (has
`bridge/`), physical (has a `device` node), else virtual. That mislabels bond
and vlan masters -- which can carry the host's real uplink -- as "virtual", and
labels paravirtual NICs (virtio-net, Xen, Hyper-V, SR-IOV VFs) as "physical".
Not a correctness bug: saturation keys off `network_link_speed_bps` presence,
not `interface_type` (documented in the collector + the contract fixture), so a
mislabel only affects backend grouping. If the backend wants precise grouping,
read `bonding/` / vlan markers (or `uevent` DEVTYPE) and widen the enum. Deferred
as an enhancement beyond the bridge-vs-physical ask in #50.

- **Effort:** S (human) / M (CC)
- **Depends on:** a backend grouping requirement that needs bond/vlan precision
- **Files:** `fivenines_agent/network.py` (`_interface_type`), `tests/test_network.py`, `tests/fixtures/network_contract_payload.json`
