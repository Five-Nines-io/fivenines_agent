"""
systemd units collector for fivenines agent.

Two surfaces:
  * Per-tick health: systemctl list-units + bulk systemctl show, cgroup metrics,
    failure drilldown (journal tail + reverse deps) for newly-failed units.
  * Inventory snapshot: full unit properties hashed for delta-sync, sent only
    when the hash changes. Forced resend by passing force_resend=True from the
    agent loop on SIGHUP.

Architecture:
  sync_config["systemd"]
       |
       v
  systemd_metrics()
       |
       +---> SystemdCollector.collect()
                |
                +---> _list_units (one subprocess)
                +---> _show_bulk (one subprocess for ALL units)
                +---> cgroup.read_unit_resources() per unit (no fork)
                +---> _drilldown_failed_units (ThreadPoolExecutor max 10)
                |         each thread runs journalctl + list-dependencies
                +---> aggregate -> {"units": [...], "drilldowns": {...}}

  sync_config["systemd"]["scan"]
       |
       v
  systemd_inventory_sync(config, send_fn)
       |
       +---> _build_inventory (one subprocess: systemctl show all units)
       +---> _canonical_inventory_hash
       +---> compare to server hash + local hash
       +---> send_fn(inventory) if changed (or forced)

Subprocess discipline:
  - All calls go through get_clean_env() per CLAUDE.md.
  - Per-call timeout 5s, mirrors snmp.py.
  - PermissionError on cgroup files is silent (capability gap is expected).
"""

import concurrent.futures
import hashlib
import json
import re
import shutil
import subprocess
import time

from fivenines_agent.cgroup import detect_hierarchy, read_unit_resources
from fivenines_agent.cgroup import reset_cache as cgroup_reset_cache
from fivenines_agent.debug import debug, log
from fivenines_agent.env import dry_run
from fivenines_agent.subprocess_utils import get_clean_env

# Subprocess timeouts (seconds)
SYSTEMCTL_TIMEOUT = 5
JOURNALCTL_TIMEOUT = 5
LIST_DEPS_TIMEOUT = 5

# Drilldown parallelism cap
MAX_DRILLDOWN_WORKERS = 10

# Default unit types we collect
DEFAULT_UNIT_TYPES = "service,timer,socket"

# Number of journal lines to capture per failed unit
JOURNAL_TAIL_LINES = 5

# Failure signature LRU max size (per-host bound)
FAILURE_SIG_MAX = 1024

# Stable identity + drift fields. Present in BOTH the per-tick health payload
# and the inventory snapshot. LoadState (loaded/masked/not-found) and
# UnitFileState (enabled/disabled/masked) are drift signals that SHOULD move
# the inventory hash, so they live here, not in VOLATILE_STATE_PROPERTIES.
IDENTITY_PROPERTIES = (
    "Id",
    "LoadState",
    "UnitFileState",
)

# Volatile runtime state. Changes on every restart/flap/timer-fire. Belongs in
# the per-tick health payload ONLY -- never in the inventory hash, or the
# delta-sync would resend the full inventory on routine operation.
VOLATILE_STATE_PROPERTIES = (
    "ActiveState",
    "SubState",
    "Result",
    "NRestarts",
    "ActiveEnterTimestamp",
    "InactiveEnterTimestamp",
)

# Config properties. Change only on admin action (edit/install/override). These
# are what the inventory snapshot exists to capture.
CONFIG_PROPERTIES = (
    "FragmentPath",
    "Restart",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecStop",
    "ExecStopPost",
    "ExecReload",
    "ExecCondition",
    "After",
    "Before",
    "Wants",
    "Requires",
    "WantedBy",
    "RequiredBy",
    "DropInPaths",
    "OnCalendar",
)

# ControlGroup is systemd's real cgroup path for the unit (e.g.
# "/system.slice/nginx.service", or "/machine.slice/..." for a Slice=-relocated
# unit). Needed on the health path to read per-unit cgroup metrics without
# assuming system.slice. It is volatile (empty when the unit is inactive), so
# it is stripped from the inventory hash via RUNTIME_FIELDS_TO_STRIP below.
HEALTH_PROPERTIES = IDENTITY_PROPERTIES + VOLATILE_STATE_PROPERTIES + ("ControlGroup",)

# Properties fetched for the inventory snapshot (config-only, hash-stable).
INVENTORY_PROPERTIES = IDENTITY_PROPERTIES + CONFIG_PROPERTIES

# Superset fetched in a single `systemctl show` when scan is enabled, so the
# per-tick health AND the inventory snapshot share one subprocess per tick.
# Health reads the volatile fields; inventory strips them (see
# RUNTIME_FIELDS_TO_STRIP) so the canonical form is identical to a config-only
# fetch.
ALL_PROPERTIES = HEALTH_PROPERTIES + CONFIG_PROPERTIES

# Top-level properties stripped from the inventory hash because they mutate per
# restart and would flap the delta-sync. Includes VOLATILE_STATE_PROPERTIES so
# that canonicalizing an ALL_PROPERTIES fetch yields the same hash as a
# config-only fetch.
RUNTIME_FIELDS_TO_STRIP = frozenset(
    VOLATILE_STATE_PROPERTIES
    + (
        "ControlGroup",
        "MainPID",
        "ControlPID",
        "ExecMainPID",
        "ExecMainStartTimestamp",
        "ExecMainStartTimestampMonotonic",
        "ExecMainExitTimestamp",
        "ExecMainExitTimestampMonotonic",
        "ExecMainCode",
        "ExecMainStatus",
        "StatusText",
        "StatusErrno",
        "InvocationID",
        "WatchdogTimestamp",
        "WatchdogTimestampMonotonic",
        "StateChangeTimestamp",
        "StateChangeTimestampMonotonic",
        "ActiveEnterTimestampMonotonic",
        "InactiveEnterTimestampMonotonic",
    )
)

# Properties that hold space-separated lists (sorted for canonical hash)
LIST_VALUED_PROPERTIES = frozenset(
    (
        "After",
        "Before",
        "Wants",
        "Requires",
        "WantedBy",
        "RequiredBy",
        "DropInPaths",
    )
)

# Reverse dependencies are gated on systemd >= 230 (CentOS 7 ships 219).
MIN_SYSTEMD_VERSION_REVERSE_DEPS = 230

# Inventory is config-only and rarely changes, so we canonicalize + hash it at
# most once per this window rather than on every health tick. Between snapshots
# the per-tick `systemctl show` fetches only HEALTH_PROPERTIES (cheaper output,
# fewer parsed lines) and the inventory sync is skipped entirely. The collection
# interval is a natural floor: a host polled less often than this just snapshots
# every tick. A forced resend (SIGHUP / capability flip) bypasses the window.
INVENTORY_SNAPSHOT_INTERVAL = 300

# _pending_inventory sentinel: collect() attempted the shared inventory show this
# tick and it failed. snapshot_inventory() uses this to skip rather than re-run
# the same failing subprocess (a distinct state from None = "nothing stashed").
_FETCH_FAILED = object()


def _monotonic():
    """Wrapped for test injection; monotonic clock for the snapshot cadence."""
    return time.monotonic()


# Static fields to keep from Exec*= structured records. Everything else
# (start_time, pid, status, etc.) is runtime noise that flaps the hash.
#
# `systemctl show` serializes each invocation as one space-delimited record:
#   { path=P ; argv[]=A B C ; ignore_errors=BOOL ; start_time=... ; pid=N ; ... }
# path, argv[] and ignore_errors always lead, in that fixed order. We anchor on
# those literal field keys rather than the surrounding `{ }` or a bare `;`,
# because systemd does NOT escape `;`, `}`, or `path=` when they appear inside an
# argv element. Anchoring argv[] on the next field's key (` ; ignore_errors=`)
# keeps the command line intact for the most common service shape -- a shell
# wrapper like ExecStart=/bin/sh -c 'sleep 1; echo done' or a `${VAR}` expansion.
# Runtime tail fields (start_time, pid, status, ...) never form this triple, so
# finditer walks straight to the next record without any brace bookkeeping.
EXEC_RECORD_RE = re.compile(
    r"path=(?P<path>[^\s;]+)\s*;\s*"
    r"argv\[\]=(?P<argv>.*?)\s*;\s*"
    r"ignore_errors=(?P<ignore_errors>[^\s;]+)"
)


def _parse_exec_property(value):
    """Parse a multi-record Exec*= property value into static-field records.

    Returns a list of {path, argv, ignore_errors} dicts -- one per invocation
    record -- with all runtime fields dropped. Robust to `;`, `}`, and `path=`
    inside the command line (see EXEC_RECORD_RE).
    """
    if not value:
        return []
    return [
        {
            "path": m.group("path"),
            "argv": m.group("argv").strip(),
            "ignore_errors": m.group("ignore_errors"),
        }
        for m in EXEC_RECORD_RE.finditer(value)
    ]


def _systemd_version():
    """Detect systemd version (integer major). Returns None if unavailable."""
    if not shutil.which("systemctl"):
        return None
    try:
        result = subprocess.run(
            ["systemctl", "--version"],
            capture_output=True,
            text=True,
            timeout=SYSTEMCTL_TIMEOUT,
            env=get_clean_env(),
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        log(f"systemctl --version failed: {e}", "debug")
        return None
    if result.returncode != 0:
        return None
    # First line: "systemd 252 (252.4-1ubuntu3.1)" or "systemd 219".
    # Guard on the post-strip result, not raw stdout truthiness: whitespace-only
    # output (e.g. a wrapper systemctl) is truthy but splitlines() to [].
    lines = result.stdout.strip().splitlines() if result.stdout else []
    first = lines[0] if lines else ""
    parts = first.split()
    if len(parts) >= 2 and parts[0] == "systemd":
        try:
            return int(parts[1])
        except ValueError:
            return None
    return None


def _run_systemctl(args, timeout=SYSTEMCTL_TIMEOUT):
    """Run systemctl with clean env. Returns (stdout, error_dict_or_None)."""
    return _run_subprocess("systemctl", args, timeout)


def _run_journalctl(args, timeout=JOURNALCTL_TIMEOUT):
    """Run journalctl with clean env. Returns (stdout, error_dict_or_None)."""
    return _run_subprocess("journalctl", args, timeout)


def _run_subprocess(cmd, args, timeout):
    """Generic subprocess wrapper used by both systemctl and journalctl.

    Returns (stdout, error_dict_or_None) where error_dict has "type" and
    "message" keys for telemetry consumers.
    """
    if not shutil.which(cmd):
        return None, {"type": "missing", "message": f"{cmd} not in PATH"}
    try:
        result = subprocess.run(
            [cmd] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=get_clean_env(),
        )
    except subprocess.TimeoutExpired:
        return None, {
            "type": "timeout",
            "message": f"{cmd} timed out after {timeout}s",
        }
    except (OSError, ValueError) as e:
        # ValueError covers UnicodeDecodeError from text=True decoding when a
        # unit emits non-UTF-8 bytes (e.g. a Latin-1 ExecStart argv). Without
        # this, one bad unit kills the entire systemd collection for the host
        # instead of degrading. Mirrors snmp.py's broad subprocess guard.
        return None, {"type": "unknown", "message": str(e)}
    if result.returncode != 0:
        return None, {
            "type": "cli_error",
            "message": result.stderr.strip() or f"exit {result.returncode}",
        }
    return result.stdout, None


def _parse_list_units(stdout):
    """Parse `systemctl list-units --no-legend --plain` output.

    Format per line: "UNIT LOAD ACTIVE SUB DESCRIPTION" with arbitrary
    whitespace separators. Returns a list of unit name strings.
    """
    units = []
    if not stdout:
        return units
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit = parts[0]
        # Skip `not-found` placeholder rows where the unit doesn't actually exist
        if parts[1] == "not-found":
            continue
        units.append(unit)
    return units


def _parse_show_bulk(stdout):
    """Parse `systemctl show <unit1> <unit2> ...` output.

    Format: KEY=VALUE blocks separated by blank lines, one block per unit.
    Returns dict keyed by unit Id, values are property dicts.
    """
    units = {}
    if not stdout:
        return units
    for block in stdout.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        props = {}
        for line in block.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            props[key] = value
        unit_id = props.get("Id")
        if unit_id:
            units[unit_id] = props
    return units


def _parse_journalctl_failed(stdout):
    """Parse journalctl --output=json output. Returns list of message strings."""
    messages = []
    if not stdout:
        return messages
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        msg = entry.get("MESSAGE")
        if isinstance(msg, list):
            try:
                msg = bytes(msg).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                msg = ""
        if msg:
            messages.append(msg)
    return messages


# Box-drawing characters systemctl uses for the dependency tree, plus the
# whitespace around them: U+251C (|-), U+2500 (-), U+2502 (|), U+2514 (L-).
# Built via chr() to keep the source ASCII-only. We strip ONLY these from the
# left, NOT "any non-alphanumeric": the root mount unit is literally "-.mount",
# so a leading-dash strip would corrupt it into "mount".
_REVERSE_DEP_TREE_CHARS = (
    "".join(chr(c) for c in (0x2502, 0x2500, 0x251C, 0x2514)) + " \t"
)


def _parse_reverse_deps(stdout):
    """Parse `systemctl list-dependencies --reverse` indented tree output.

    First line is the unit being queried; subsequent indented lines are
    prefixed with Unicode box-drawing characters (U+251C, U+2502, U+2500,
    U+2514) plus spaces. Strip exactly those prefix characters (not all
    non-alphanumerics) so unit names that start with punctuation -- notably
    the root mount "-.mount" -- survive intact. Returns a deduplicated list
    of dependent unit names.
    """
    if not stdout:
        return []
    seen = set()
    deps = []
    lines = stdout.splitlines()
    # Skip first line (the unit being queried)
    for line in lines[1:]:
        cleaned = line.lstrip(_REVERSE_DEP_TREE_CHARS).strip()
        if not cleaned:
            continue
        # Some entries include an active marker bullet; take first whitespace-token
        name = cleaned.split()[0]
        if name and name not in seen:
            seen.add(name)
            deps.append(name)
    return deps


def _normalize_property_for_hash(key, value):
    """Canonicalize a property value for the inventory hash.

    - Exec*= records keep only static sub-fields (path/argv/ignore_errors),
      sorted by (path, argv).
    - List-valued properties are space-split and sorted.
    - Everything else is stripped of trailing whitespace.
    """
    if key.startswith("Exec"):
        # Preserve definition order: `systemctl show` emits Exec* records in
        # unit-file order, deterministically across fetches. Sorting would make
        # a real reorder (e.g. swapping two ExecStartPre= lines on a oneshot,
        # which changes execution order) invisible to the inventory hash.
        return _parse_exec_property(value)
    if key in LIST_VALUED_PROPERTIES:
        items = [s for s in (value or "").split() if s]
        items.sort()
        return items
    return (value or "").strip()


def _canonicalize_unit(props):
    """Return a hash-stable dict for a single unit.

    Strips runtime fields, normalizes Exec records and list properties.
    """
    canon = {}
    for key, value in props.items():
        if key in RUNTIME_FIELDS_TO_STRIP:
            continue
        canon[key] = _normalize_property_for_hash(key, value)
    return canon


def _canonical_inventory_hash(units_props):
    """SHA-256 of the canonical inventory.

    units_props: dict keyed by unit name -> property dict.
    Sorts by name, strips runtime fields, sort_keys=True for stable output.
    """
    canonical = {
        name: _canonicalize_unit(props) for name, props in sorted(units_props.items())
    }
    blob = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class SystemdCollector:
    """Collects per-tick systemd unit health and inventory snapshots.

    Class-level state survives instance recreation across ticks (mirrors
    snmp.py's SNMPCollector pattern).
    """

    # unit_name -> (NRestarts_str, ActiveEnterTimestamp_str)
    _last_failure_signatures: dict = {}
    # Hash of last sent inventory (for force-resend tracking)
    _last_local_inventory_hash = None
    # Cached systemd version
    _version = None
    # Cached cgroup hierarchy
    _hierarchy = None

    def __init__(
        self, unit_types=DEFAULT_UNIT_TYPES, journal_tail_lines=JOURNAL_TAIL_LINES
    ):
        self.unit_types = _normalize_unit_types(unit_types)
        self.journal_tail_lines = journal_tail_lines
        # When collect(scan=True) runs, it stashes (unit_names, raw_props) here
        # so the inventory snapshot in the same tick reuses the single
        # `systemctl show` instead of running its own. Consumed and cleared by
        # snapshot_inventory(); None means "fetch fresh".
        self._pending_inventory = None
        # Monotonic timestamp of the last inventory snapshot we built; None means
        # "never", so the first scan tick always snapshots. Throttles inventory
        # to INVENTORY_SNAPSHOT_INTERVAL (see _inventory_snapshot_due).
        self._last_inventory_snapshot_monotonic = None
        if SystemdCollector._version is None:
            SystemdCollector._version = _systemd_version()
        if SystemdCollector._hierarchy is None:
            SystemdCollector._hierarchy = detect_hierarchy()

    # ---- Per-tick health ----

    def _empty_result(self, errors):
        return {
            "version": SystemdCollector._version,
            "cgroup": SystemdCollector._hierarchy,
            "units": [],
            "drilldowns": {},
            "errors": errors,
        }

    def collect(self, scan=False):
        """Collect per-tick health for all units.

        When *scan* is True the inventory snapshot is enabled for this host, so
        a single `systemctl show` fetches the superset (ALL_PROPERTIES) and the
        raw output is stashed for snapshot_inventory() to reuse this tick.

        Returns a dict shape:
          {
            "version": <int|None>,
            "cgroup": <"v1"|"v2"|None>,
            "units": [<unit_dict>, ...],
            "drilldowns": {<unit_name>: <drilldown_dict>, ...},
            "errors": [<error_dict>, ...],
          }
        Returns None if systemctl is unavailable.
        """
        errors = []
        # Drop any stash from a prior tick before this tick's fetch.
        self._pending_inventory = None

        unit_names, error = self._list_units()
        if error:
            errors.append({"step": "list_units", **error})
            return self._empty_result(errors)

        if not unit_names:
            return self._empty_result(errors)

        # Only pull the heavier ALL_PROPERTIES superset (and stash it for the
        # inventory snapshot) on ticks where an inventory snapshot is actually
        # due; otherwise health needs only HEALTH_PROPERTIES. This keeps the
        # steady-state per-tick show small and avoids parsing ~14 config-only
        # properties per unit that the health payload never reads.
        take_inventory = scan and self._inventory_snapshot_due()
        properties = ALL_PROPERTIES if take_inventory else HEALTH_PROPERTIES
        unit_props, error = self._show_bulk(unit_names, properties)
        if error:
            # A transient show failure must NOT blank every unit (which would
            # misreport failed units as empty state) nor wipe the failure-
            # signature debounce cache (every unit would look non-failed).
            # Return no health this tick; the next tick recovers. Flag the
            # failure so a forced inventory_sync this same tick skips instead of
            # re-running the same failing subprocess.
            self._pending_inventory = _FETCH_FAILED
            errors.append({"step": "show_bulk", **error})
            return self._empty_result(errors)

        if take_inventory:
            self._pending_inventory = (unit_names, unit_props)

        units = []
        newly_failed = []
        for name in unit_names:
            props = unit_props.get(name)
            if props is None:
                # Unit vanished or was aliased between list-units and show.
                # Skip rather than emit a blank entry that lies about its state.
                continue
            units.append(self._build_health_entry(name, props))
            if self._is_newly_failed(name, props):
                newly_failed.append(name)

        drilldowns = {}
        if newly_failed:
            drilldowns = self._drilldown_failed_units(newly_failed)

        return {
            "version": SystemdCollector._version,
            "cgroup": SystemdCollector._hierarchy,
            "units": units,
            "drilldowns": drilldowns,
            "errors": errors,
        }

    def _list_units(self):
        """List unit names of the configured types."""
        args = [
            "list-units",
            f"--type={self.unit_types}",
            "--all",
            "--no-legend",
            "--plain",
            "--no-pager",
        ]
        stdout, error = _run_systemctl(args)
        if error:
            return [], error
        return _parse_list_units(stdout), None

    def _show_bulk(self, unit_names, properties):
        """Bulk fetch properties for many units in one subprocess call."""
        args = [
            "show",
            f"--property={','.join(properties)}",
            "--no-pager",
        ]
        args.extend(unit_names)
        stdout, error = _run_systemctl(args)
        if error:
            return {}, error
        return _parse_show_bulk(stdout), None

    def _build_health_entry(self, name, props):
        """Build the per-tick payload for a single unit."""
        try:
            n_restarts = int(props.get("NRestarts", "0") or 0)
        except (ValueError, TypeError):
            n_restarts = 0

        cgroup_data = {}
        hierarchy = SystemdCollector._hierarchy
        if hierarchy:
            control_group = props.get("ControlGroup", "")
            try:
                cgroup_data = read_unit_resources(control_group, hierarchy)
            except ValueError:
                # Path-traversal defense raised - extremely unlikely with a
                # ControlGroup path from systemctl, but log and continue.
                log(
                    f"systemd: invalid control group for {name!r}: "
                    f"{control_group!r}",
                    "error",
                )
                cgroup_data = {}

        return {
            "name": name,
            "load_state": props.get("LoadState", ""),
            "active_state": props.get("ActiveState", ""),
            "sub_state": props.get("SubState", ""),
            "result": props.get("Result", ""),
            "n_restarts": n_restarts,
            "active_enter_timestamp": props.get("ActiveEnterTimestamp", ""),
            "inactive_enter_timestamp": props.get("InactiveEnterTimestamp", ""),
            "unit_file_state": props.get("UnitFileState", ""),
            "memory_current": cgroup_data.get("memory_current"),
            "cpu_usec": cgroup_data.get("cpu_usec"),
            "oom_kill_count": cgroup_data.get("oom_kill_count"),
            "cgroup_inception_id": cgroup_data.get("inception_id"),
        }

    def _is_newly_failed(self, name, props):
        """Decide whether to drill into this unit on the current tick.

        A unit qualifies if its active_state == "failed" AND its
        (NRestarts, ActiveEnterTimestamp) signature differs from the cached one.
        Bounds the cache at FAILURE_SIG_MAX entries with true LRU eviction:
        every access (insert OR re-confirm) moves the entry to the most-recent
        end, so eviction targets the genuinely least-recently-seen unit, not
        whichever failed first.
        """
        sigs = SystemdCollector._last_failure_signatures
        if props.get("ActiveState") != "failed":
            # Drop from cache when no longer failed so a future failure re-drills.
            sigs.pop(name, None)
            return False
        sig = (props.get("NRestarts", "0"), props.get("ActiveEnterTimestamp", ""))
        prev = sigs.pop(name, None)  # pop+reinsert refreshes recency (dict order)
        if prev == sig:
            sigs[name] = sig
            return False
        sigs[name] = sig
        # Bound cache size: evict the least-recently-seen entry.
        if len(sigs) > FAILURE_SIG_MAX:
            oldest = next(iter(sigs))
            sigs.pop(oldest, None)
        return True

    # ---- Failure drilldown ----

    def _drilldown_failed_units(self, unit_names):
        """Run journal tail + reverse-deps in parallel for newly-failed units.

        Returns dict keyed by unit name -> {"journal_tail": [...], "reverse_deps": [...] | None}.
        """
        results = {}
        workers = min(len(unit_names), MAX_DRILLDOWN_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {
                ex.submit(self._drilldown_one, name): name for name in unit_names
            }
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    log(f"systemd drilldown error for {name}: {e}", "error")
                    results[name] = {
                        "journal_tail": [],
                        "reverse_deps": None,
                        "error": str(e),
                    }
        return results

    def _drilldown_one(self, unit_name):
        """Single-unit drilldown: journal tail + reverse deps."""
        journal = self._journal_tail(unit_name)
        reverse_deps = self._reverse_deps(unit_name)
        return {"journal_tail": journal, "reverse_deps": reverse_deps}

    def _journal_tail(self, unit_name):
        """Last few error-priority journal lines for a unit."""
        args = [
            "-u",
            unit_name,
            "-n",
            str(self.journal_tail_lines),
            "-p",
            "err",
            "--output=json",
            "--no-pager",
        ]
        stdout, error = _run_journalctl(args)
        if error:
            return []
        return _parse_journalctl_failed(stdout)

    def _reverse_deps(self, unit_name):
        """Reverse dependency map for a unit. None on systemd < 230 or failure."""
        version = SystemdCollector._version
        if version is None or version < MIN_SYSTEMD_VERSION_REVERSE_DEPS:
            return None
        args = [
            "list-dependencies",
            "--reverse",
            "--all",
            unit_name,
            "--no-pager",
        ]
        stdout, error = _run_systemctl(args, timeout=LIST_DEPS_TIMEOUT)
        if error:
            return None
        return _parse_reverse_deps(stdout)

    # ---- Inventory snapshot ----

    def _inventory_snapshot_due(self):
        """Whether an inventory snapshot is due (cadence throttle).

        True on the first scan tick and once per INVENTORY_SNAPSHOT_INTERVAL
        thereafter. collect() and inventory_sync() consult this within the same
        tick; the timestamp only advances after inventory_sync() builds a
        snapshot, so both see a consistent answer.
        """
        last = self._last_inventory_snapshot_monotonic
        return last is None or (_monotonic() - last) >= INVENTORY_SNAPSHOT_INTERVAL

    def snapshot_inventory(self):
        """Build the full inventory snapshot for all units.

        Returns (unit_props_dict, hash, errors) tuple. unit_props_dict is the
        canonical (hash-stable) form, hash is the SHA-256, errors is a list.
        hash is None when the snapshot cannot be trusted this tick (subprocess
        error, or a successful-but-empty `systemctl show` against a non-empty
        unit list) -- inventory_sync skips a None hash so a transient hiccup
        never ships units={} and wipes the backend inventory.
        """
        errors = []

        # Reuse this tick's shared fetch from collect(scan=True) when available,
        # so health + inventory cost one list-units + one show per tick instead
        # of two of each. canonicalizing the ALL_PROPERTIES output strips the
        # volatile fields, yielding the same canonical form as a config-only
        # fetch.
        pending = self._pending_inventory
        self._pending_inventory = None
        if pending is _FETCH_FAILED:
            # collect() already ran (and logged) the shared show this tick and it
            # failed; don't hammer the same failing systemctl again. Skip.
            return {}, None, errors
        if isinstance(pending, tuple):
            unit_names, raw_props = pending
        else:
            unit_names, error = self._list_units()
            if error:
                errors.append({"step": "list_units", **error})
                return {}, None, errors
            if not unit_names:
                return {}, _canonical_inventory_hash({}), errors

            raw_props, error = self._show_bulk(unit_names, INVENTORY_PROPERTIES)
            if error:
                # A transient `systemctl show` failure must NOT publish an empty
                # inventory: shipping units={} tells the backend "this host has
                # zero units" and wipes the whole inventory until the next clean
                # sync. Return a None hash so inventory_sync skips this tick.
                errors.append({"step": "show_bulk_inventory", **error})
                return {}, None, errors

        # A non-empty unit list that parses to zero properties means the show
        # exited 0 but returned empty/unparseable output (wrapper systemctl,
        # daemon hiccup, truncated stream). Same blast radius as an error: a None
        # hash makes inventory_sync skip rather than wipe the backend inventory.
        if unit_names and not raw_props:
            errors.append({"step": "show_bulk_inventory", "error": "empty output"})
            return {}, None, errors

        # Canonicalize each unit (strip runtime, normalize Exec/list fields)
        canon_units = {
            name: _canonicalize_unit(props) for name, props in raw_props.items()
        }
        # Hash the same canonical form we ship
        blob = json.dumps(
            {k: canon_units[k] for k in sorted(canon_units)},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        h = hashlib.sha256(blob).hexdigest()
        return canon_units, h, errors

    def inventory_sync(self, config, send_fn, force_resend=False):
        """Compute inventory hash; send if changed (or force_resend).

        Returns True when the force obligation is discharged (sent OK, nothing
        to send, or dry-run) and False when a forced/changed send could not go
        through this tick (snapshot failed or send failed). The agent clears its
        SIGHUP force flag only on a True return, so a forced resend survives a
        failed send instead of being silently dropped.
        """
        scan_config = config.get("systemd")
        if not isinstance(scan_config, dict) or not scan_config.get("scan"):
            return True

        # Throttle: config drift is checked at most once per
        # INVENTORY_SNAPSHOT_INTERVAL, not every health tick. A forced resend
        # (SIGHUP / capability flip) bypasses the window. Nothing to discharge
        # when simply throttled, so this returns True.
        if not force_resend and not self._inventory_snapshot_due():
            return True

        units, h, errors = self.snapshot_inventory()
        if h is None:
            # Snapshot failed (e.g. transient systemctl error); we could not
            # send, so keep any force flag and retry next tick. The cadence
            # timestamp is NOT advanced, so the next tick retries immediately.
            log("systemd inventory snapshot failed; skipping", "debug")
            return False
        # A trusted snapshot was built this tick: start the next throttle window
        # now, regardless of whether the send below is needed or succeeds (the
        # expensive work we are rate-limiting is the canonicalize + hash above).
        self._last_inventory_snapshot_monotonic = _monotonic()

        server_hash = scan_config.get("last_inventory_hash")
        local_hash = SystemdCollector._last_local_inventory_hash
        # OR, not AND: a confirmed local send (local_hash == h) suppresses
        # repeats on its own, before the backend echoes the hash back via
        # /collect. Under AND the local-hash dedup and force_inventory_resend
        # were dead weight -- the agent resent every tick until the server
        # round-tripped the hash.
        if not force_resend and (h == server_hash or h == local_hash):
            log("systemd inventory unchanged, skipping", "debug")
            return True

        payload = {
            "inventory_hash": h,
            "units": units,
            "version": SystemdCollector._version,
            "cgroup": SystemdCollector._hierarchy,
        }
        if errors:
            payload["errors"] = errors

        if dry_run():
            log(
                "systemd inventory (dry-run): " + json.dumps(payload, indent=2),
                "debug",
            )
            return True

        response = send_fn(payload)
        if response is not None:
            SystemdCollector._last_local_inventory_hash = h
            log("systemd inventory sent successfully", "info")
            return True
        log("systemd inventory send failed, will retry", "error")
        return False


# ---- Module-level singleton + public API ----

_collector = None


def _normalize_unit_types(value):
    """Coerce unit_types config into the comma-separated string systemctl wants.

    The backend may deliver unit_types as a JSON array (the natural shape for a
    set of types); `--type=['service', 'timer']` would make systemctl exit
    non-zero and silently disable the collector. Accept list/tuple and join.
    """
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    return value


def _config_unit_types(config):
    """Extract normalized unit_types from config, defaulting when absent."""
    systemd_config = config.get("systemd")
    if isinstance(systemd_config, dict):
        return _normalize_unit_types(
            systemd_config.get("unit_types", DEFAULT_UNIT_TYPES)
        )
    return DEFAULT_UNIT_TYPES


def _get_collector(unit_types=DEFAULT_UNIT_TYPES):
    """Return the cached SystemdCollector, creating it on first call.

    When unit_types changes, the failure-signature cache is cleared: it is
    scoped to the previous unit set, and entries for units no longer enumerated
    would otherwise never be popped (stale orphans toward the cap).
    """
    global _collector
    unit_types = _normalize_unit_types(unit_types)
    if _collector is None or _collector.unit_types != unit_types:
        if _collector is not None:
            SystemdCollector._last_failure_signatures = {}
        _collector = SystemdCollector(unit_types=unit_types)
    return _collector


def reset_collector():
    """Reset the module-level collector. Used by tests."""
    global _collector
    _collector = None
    SystemdCollector._last_failure_signatures = {}
    SystemdCollector._last_local_inventory_hash = None
    SystemdCollector._version = None
    SystemdCollector._hierarchy = None


@debug("systemd_metrics")
def systemd_metrics(unit_types=DEFAULT_UNIT_TYPES, scan=False, **_kwargs):
    """Per-tick collector entry point. Called from collectors registry.

    The whole config["systemd"] dict is unpacked as kwargs, so `scan` arrives
    here and is threaded into collect() to share one `systemctl show` with the
    inventory snapshot this tick. Extra kwargs are accepted but ignored so new
    server-side config keys do not break older agents.
    """
    if not shutil.which("systemctl"):
        return None
    return _get_collector(unit_types=unit_types).collect(scan=bool(scan))


def systemd_inventory_sync(config, send_fn, force_resend=False):
    """Inventory snapshot push. Called from agent.py per tick (analogous to packages_sync).

    Reads unit_types from config["systemd"] so the inventory snapshot stays
    consistent with the per-tick metrics scope and the module-level singleton
    is not churned every tick when metrics + inventory disagree on which unit
    types to enumerate.

    Returns True when the force obligation is discharged (sent / nothing to send
    / dry-run / no systemctl), False when a forced or changed send could not go
    through this tick. The agent clears its SIGHUP force flag only on True.
    """
    if not shutil.which("systemctl"):
        return True
    return _get_collector(unit_types=_config_unit_types(config)).inventory_sync(
        config, send_fn, force_resend=force_resend
    )


def force_inventory_resend():
    """Mark next inventory_sync to resend regardless of hash equality.

    Called from agent.py when SIGHUP triggers a permission refresh, so the
    next inventory check pushes a fresh snapshot even if nothing changed
    on the host.
    """
    SystemdCollector._last_local_inventory_hash = None


def refresh_runtime_caches():
    """Re-detect host-level systemd state after a permission/capability change.

    The cgroup hierarchy and systemd version are detected once and cached for
    the process lifetime. A host that gains a cgroup mount (e.g. early container
    boot) would otherwise report cgroup=None and null per-unit memory/cpu
    forever, even after permissions.py re-probes the capability. Called from the
    agent on SIGHUP (operator-driven, e.g. after a systemd upgrade) and on a
    cgroup/systemd capability flip, so the next tick reflects reality.
    """
    cgroup_reset_cache()
    SystemdCollector._hierarchy = detect_hierarchy()
    version = _systemd_version()
    # Keep the last good version if a transient `systemctl --version` hiccup
    # returns None: clobbering a known version to None would wrongly disable the
    # reverse-deps drilldown (gated on version >= 230) and ship version=null
    # until the next successful re-detect.
    if version is not None:
        SystemdCollector._version = version
