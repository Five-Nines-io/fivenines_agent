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

from fivenines_agent.cgroup import detect_hierarchy, read_unit_resources
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

# Properties read for per-tick health
HEALTH_PROPERTIES = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "NRestarts",
    "ActiveEnterTimestamp",
    "InactiveEnterTimestamp",
    "UnitFileState",
)

# Properties read for inventory snapshot (in addition to HEALTH_PROPERTIES)
INVENTORY_PROPERTIES = HEALTH_PROPERTIES + (
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

# Top-level properties stripped from inventory hash because they mutate per
# restart and would flap the delta-sync.
RUNTIME_FIELDS_TO_STRIP = frozenset(
    (
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

# Static fields to keep from Exec*= structured records. Everything else
# (start_time, pid, status, etc.) is runtime noise that flaps the hash.
EXEC_PATH_RE = re.compile(r"path=([^\s;]+)")
EXEC_ARGV_RE = re.compile(r"argv\[\]=(.*?)(?=\s*;\s|\s*\})")
EXEC_IGNORE_RE = re.compile(r"ignore_errors=([^\s;]+)")


def _extract_exec_record(record_str):
    """Extract static fields (path, argv, ignore_errors) from one Exec= record.

    Returns a dict with only the static keys; runtime fields are dropped.
    Returns None if no path can be extracted (malformed record).
    """
    out = {}
    m = EXEC_PATH_RE.search(record_str)
    if not m:
        return None
    out["path"] = m.group(1)
    m = EXEC_ARGV_RE.search(record_str)
    if m:
        out["argv"] = m.group(1).strip()
    m = EXEC_IGNORE_RE.search(record_str)
    if m:
        out["ignore_errors"] = m.group(1)
    return out


def _parse_exec_property(value):
    """Parse a multi-record Exec*= property value into static-field records.

    Each record is wrapped in `{ ... }`; multiple records may appear.
    Returns a list of dicts.
    """
    if not value:
        return []
    records = []
    depth = 0
    start = None
    for i, ch in enumerate(value):
        if ch == "{":
            if depth == 0:
                start = i + 1
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                rec = _extract_exec_record(value[start:i])
                if rec:
                    records.append(rec)
                start = None
    return records


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
    # First line: "systemd 252 (252.4-1ubuntu3.1)" or "systemd 219"
    first = result.stdout.strip().splitlines()[0] if result.stdout else ""
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
    except OSError as e:
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


def _parse_reverse_deps(stdout):
    """Parse `systemctl list-dependencies --reverse` indented tree output.

    First line is the unit being queried; subsequent indented lines are the
    dependents. Returns deduplicated list of dependent unit names.
    """
    if not stdout:
        return []
    seen = set()
    deps = []
    lines = stdout.splitlines()
    # Skip first line (the unit being queried)
    for line in lines[1:]:
        # Strip tree drawing characters and whitespace
        cleaned = line.lstrip(" ├│─└").strip()
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
        records = _parse_exec_property(value)
        records.sort(key=lambda r: (r.get("path", ""), r.get("argv", "")))
        return records
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
        self.unit_types = unit_types
        self.journal_tail_lines = journal_tail_lines
        if SystemdCollector._version is None:
            SystemdCollector._version = _systemd_version()
        if SystemdCollector._hierarchy is None:
            SystemdCollector._hierarchy = detect_hierarchy()

    # ---- Per-tick health ----

    def collect(self):
        """Collect per-tick health for all units.

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

        unit_names, error = self._list_units()
        if error:
            errors.append({"step": "list_units", **error})
            return {
                "version": SystemdCollector._version,
                "cgroup": SystemdCollector._hierarchy,
                "units": [],
                "drilldowns": {},
                "errors": errors,
            }

        if not unit_names:
            return {
                "version": SystemdCollector._version,
                "cgroup": SystemdCollector._hierarchy,
                "units": [],
                "drilldowns": {},
                "errors": errors,
            }

        unit_props, error = self._show_bulk(unit_names, HEALTH_PROPERTIES)
        if error:
            errors.append({"step": "show_bulk", **error})

        units = []
        newly_failed = []
        for name in unit_names:
            props = unit_props.get(name, {})
            entry = self._build_health_entry(name, props)
            units.append(entry)
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
            try:
                cgroup_data = read_unit_resources(name, hierarchy)
            except ValueError:
                # Path-traversal defense raised - extremely unlikely with names
                # from systemctl, but log and continue.
                log(f"systemd: invalid unit name from list-units: {name!r}", "error")
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
        Bounds the cache at FAILURE_SIG_MAX entries (LRU-style).
        """
        if props.get("ActiveState") != "failed":
            # Drop from cache when no longer failed so a future failure re-drills.
            SystemdCollector._last_failure_signatures.pop(name, None)
            return False
        sig = (props.get("NRestarts", "0"), props.get("ActiveEnterTimestamp", ""))
        prev = SystemdCollector._last_failure_signatures.get(name)
        if prev == sig:
            return False
        SystemdCollector._last_failure_signatures[name] = sig
        # Bound cache size
        if len(SystemdCollector._last_failure_signatures) > FAILURE_SIG_MAX:
            # Drop the oldest entry (Python 3.7+ dict insertion order)
            oldest = next(iter(SystemdCollector._last_failure_signatures))
            SystemdCollector._last_failure_signatures.pop(oldest, None)
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

    def snapshot_inventory(self):
        """Build the full inventory snapshot for all units.

        Returns (unit_props_dict, hash, errors) tuple. unit_props_dict is the
        canonical (hash-stable) form, hash is the SHA-256, errors is a list.
        """
        errors = []
        unit_names, error = self._list_units()
        if error:
            errors.append({"step": "list_units", **error})
            return {}, None, errors
        if not unit_names:
            return {}, _canonical_inventory_hash({}), errors

        raw_props, error = self._show_bulk(unit_names, INVENTORY_PROPERTIES)
        if error:
            errors.append({"step": "show_bulk_inventory", **error})

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
        """Compute inventory hash; send if changed (or force_resend)."""
        scan_config = config.get("systemd")
        if not isinstance(scan_config, dict) or not scan_config.get("scan"):
            return

        units, h, errors = self.snapshot_inventory()
        if h is None:
            log("systemd inventory snapshot failed; skipping", "debug")
            return

        server_hash = scan_config.get("last_inventory_hash")
        local_hash = SystemdCollector._last_local_inventory_hash
        if not force_resend and h == server_hash and h == local_hash:
            log("systemd inventory unchanged, skipping", "debug")
            return

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
            return

        response = send_fn(payload)
        if response is not None:
            SystemdCollector._last_local_inventory_hash = h
            log("systemd inventory sent successfully", "info")
        else:
            log("systemd inventory send failed, will retry", "error")


# ---- Module-level singleton + public API ----

_collector = None


def _get_collector(unit_types=DEFAULT_UNIT_TYPES):
    """Return the cached SystemdCollector, creating it on first call."""
    global _collector
    if _collector is None or _collector.unit_types != unit_types:
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
def systemd_metrics(unit_types=DEFAULT_UNIT_TYPES, **_kwargs):
    """Per-tick collector entry point. Called from collectors registry.

    Extra kwargs are accepted but ignored so future config keys can be added
    server-side without breaking older agents.
    """
    if not shutil.which("systemctl"):
        return None
    return _get_collector(unit_types=unit_types).collect()


def systemd_inventory_sync(config, send_fn, force_resend=False):
    """Inventory snapshot push. Called from agent.py per tick (analogous to packages_sync)."""
    if not shutil.which("systemctl"):
        return
    _get_collector().inventory_sync(config, send_fn, force_resend=force_resend)


def force_inventory_resend():
    """Mark next inventory_sync to resend regardless of hash equality.

    Called from agent.py when SIGHUP triggers a permission refresh, so the
    next inventory check pushes a fresh snapshot even if nothing changed
    on the host.
    """
    SystemdCollector._last_local_inventory_hash = None
