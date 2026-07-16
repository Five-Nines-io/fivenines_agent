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
  systemd_inventory_sync(config, send_fn, force_resend=...)
       |
       +---> snapshot_inventory
       |         reuses this tick's collect(scan=True) fetch when stashed
       |         (zero extra subprocess), else list-units + list-unit-files
       |         (disabled units are config too) + chunked show
       +---> canonicalize + hash (secrets redacted from Exec argv)
       +---> compare to server hash + local hash
       +---> send_fn(inventory) if changed (or forced)

Subprocess discipline:
  - All calls go through get_clean_env() per CLAUDE.md.
  - Per-call timeout 5s (SHOW_BULK_TIMEOUT 15s for the chunked bulk show).
  - PermissionError on cgroup files is silent (capability gap is expected).
"""

import concurrent.futures
import hashlib
import json
import re
import shutil
import subprocess

from fivenines_agent.cgroup import detect_hierarchy, read_unit_resources
from fivenines_agent.cgroup import reset_cache as cgroup_reset_cache
from fivenines_agent.debug import debug, log
from fivenines_agent.env import dry_run
from fivenines_agent.logs import redact
from fivenines_agent.subprocess_utils import get_clean_env

# Subprocess timeouts (seconds)
SYSTEMCTL_TIMEOUT = 5
JOURNALCTL_TIMEOUT = 5
LIST_DEPS_TIMEOUT = 5

# Bulk `systemctl show` of every unit gets a wider budget than the other
# calls: one GetAll round-trip per unit means unit-heavy hosts (thousands of
# templated units) can legitimately exceed the 5s default, and a persistent
# timeout here blacks out the whole collector.
SHOW_BULK_TIMEOUT = 15

# Units per `systemctl show` invocation (argv-size bound; Linux ARG_MAX is
# ~2MB but transient-unit storms shouldn't take the collector near any limit).
SHOW_BULK_CHUNK = 500

# Cap per journal message shipped in a drilldown (journald's LineMax default
# is 48K; 5 messages x 20 drilldowns of that would bloat one payload to MBs).
JOURNAL_MSG_MAX_CHARS = 2048

# Drilldown parallelism cap
MAX_DRILLDOWN_WORKERS = 10

# Max units drilled per tick. A correlated mass failure (bad deploy, failed
# dependency target) or the first tick after an agent restart (empty signature
# cache re-qualifying every chronically-failed unit) would otherwise fork two
# subprocesses per failed unit in one tick -- a fork storm that stalls the
# collection loop exactly when the host is degraded. Units beyond the cap are
# NOT signature-committed, so they re-qualify and drill on subsequent ticks.
MAX_DRILLDOWNS_PER_TICK = 20

# Default unit types we collect
DEFAULT_UNIT_TYPES = "service,timer,socket"

# Number of journal lines to capture per failed unit
JOURNAL_TAIL_LINES = 5

# Failure signature LRU max size (per-host bound)
FAILURE_SIG_MAX = 1024

# Inventory partial-show guard: if show returns properties for fewer than
# this fraction of the units list-units just enumerated (on hosts with at
# least MIN_UNITS units), the fetch is treated as truncated and the snapshot
# is not trusted (see snapshot_inventory).
PARTIAL_SHOW_MIN_RATIO = 0.8
PARTIAL_SHOW_MIN_UNITS = 10

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
    # Timer schedules. There is NO bus property literally named "OnCalendar";
    # systemctl show exposes schedules as TimersCalendar / TimersMonotonic
    # records: { OnCalendar=... ; next_elapse=... } / { OnUnitActiveSec=... ;
    # next_elapse=... }. next_elapse is runtime (stripped for the hash, see
    # TIMER_SPEC_RE in _normalize_property_for_hash).
    "TimersCalendar",
    "TimersMonotonic",
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

# _pending_inventory sentinel: collect(scan=True) attempted this tick's shared
# fetch (list-units or show) and it failed. snapshot_inventory() uses this to
# skip rather than re-run the same failing subprocess in the same tick -- a
# distinct state from None ("nothing stashed, fetch fresh").
_FETCH_FAILED = object()


# Static fields to keep from Exec*= structured records. Everything else
# (start_time, pid, status, etc.) is runtime noise that flaps the hash.
#
# `systemctl show` serializes each invocation as one space-delimited record:
#   { path=P ; argv[]=A B C ; ignore_errors=BOOL ; start_time=... ; pid=N ; ... }
# path, argv[] and ignore_errors always lead, in that fixed order. We anchor each
# field on the NEXT field's literal key rather than the surrounding `{ }` or a
# bare `;`, because systemd does NOT escape `;`, `}`, `path=`, or spaces when they
# appear inside path or argv. path runs up to ` ; argv[]=` and argv up to
# ` ; ignore_errors=`, so a spaced binary path (e.g. /opt/Acme Agent/bin/run) and
# a shell wrapper (ExecStart=/bin/sh -c 'sleep 1; echo done', a `${VAR}` expansion)
# both survive intact. Runtime tail fields (start_time, pid, status, ...) never
# form this triple, so finditer walks straight to the next record.
#
# Known residual: a path or argv element that literally contains the next field's
# key substring (` ; argv[]=` or ` ; ignore_errors=`) truncates there. This is
# astronomically rarer than the `;`/`}`/`${VAR}`/space cases above; the robust
# alternative (brace matching) would reintroduce the `${VAR}` truncation, so
# anchoring on the next field key is the better trade. The truncation is
# deterministic, so the inventory hash stays stable.
# systemctl's serializer emits exactly " ; " between fields, so the separators
# are literal -- a tolerant `\s*;\s*` would overlap with the lazy `.*?` on
# whitespace runs and open O(n^2) backtracking on degenerate generated units.
EXEC_RECORD_RE = re.compile(
    r"path=(?P<path>.*?) ; "
    r"argv\[\]=(?P<argv>.*?) ; "
    r"ignore_errors=(?P<ignore_errors>[^\s;]+)"
)

# Secret redaction for Exec argv before it is hashed and shipped in the
# inventory payload. Unit command lines routinely embed credentials
# (--password=..., --api-key ..., DSN URLs, VAR=secret prefixes in shell
# wrappers); the backend must never receive them. Patterns are deliberately
# conservative (named credential flags, URL userinfo, uppercase env-style
# assignments) and deterministic, so the canonical hash stays stable.
# Extract the schedule spec from a TimersCalendar / TimersMonotonic record,
# dropping the runtime next_elapse sub-field that would flap the hash on
# every timer fire: { OnCalendar=Mon *-*-* 12:00:00 ; next_elapse=... }.
TIMER_SPEC_RE = re.compile(r"\{ (?P<spec>.+?) ; next_elapse=")

_SECRET_KEYWORDS = r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|credential[s]?|access[_-]?key|private[_-]?key|auth[_-]?token)"
_SECRET_FLAG = r"(--?[a-z0-9_-]*" + _SECRET_KEYWORDS + r"[a-z0-9_-]*)"
_REDACT_FLAG_EQ_RE = re.compile(r"(?i)" + _SECRET_FLAG + r"=(\S+)")
# Space-separated form must not eat a FOLLOWING flag when the secret flag is
# boolean (`--enable-token-auth --port 8080` must keep --port intact), so the
# value cannot start with a dash.
_REDACT_FLAG_SP_RE = re.compile(r"(?i)" + _SECRET_FLAG + r" (?!-)(\S+)")
# Assignment-style secrets, any case: bare (PASSWORD=, token=) and prefixed
# (DB_PASSWORD=, redis_password=). The flag patterns above run first, so what
# remains here is env/positional assignments.
_REDACT_ENV_RE = re.compile(
    r"(?i)\b((?:[a-z][a-z0-9_]*_)?" + _SECRET_KEYWORDS + r"[a-z0-9_]*)=(\S+)"
)
# HTTP auth header values passed on command lines (curl -H "Authorization:
# Bearer <tok>" serializes into argv with the scheme word intact).
_REDACT_AUTH_HEADER_RE = re.compile(
    r"(?i)(authorization[=:]\s*(?:bearer|basic|token)\s+)(\S+)"
)
_REDACT_URL_USERINFO_RE = re.compile(r"(://[^/\s:@]+:)([^/\s@]+)(@)")
# Credentials passed as URL query parameters (?api_key=..., &token=...).
_REDACT_URL_QUERY_RE = re.compile(
    r"(?i)([?&][a-z0-9_-]*" + _SECRET_KEYWORDS + r"[a-z0-9_-]*=)([^&\s]+)"
)
_REDACTED = "[REDACTED]"


def _redact_secrets(argv):
    """Mask credential values in an Exec argv string (see patterns above).

    Known residuals (documented, FP-avoidance tradeoffs): short flags (-p, -a),
    a token-as-userinfo URL without a colon (https://TOKEN@host), secret values
    containing spaces, and secret flag values that start with a dash.
    """
    argv = _REDACT_FLAG_EQ_RE.sub(r"\1=" + _REDACTED, argv)
    argv = _REDACT_FLAG_SP_RE.sub(r"\1 " + _REDACTED, argv)
    argv = _REDACT_ENV_RE.sub(r"\1=" + _REDACTED, argv)
    argv = _REDACT_AUTH_HEADER_RE.sub(r"\1" + _REDACTED, argv)
    argv = _REDACT_URL_USERINFO_RE.sub(r"\1" + _REDACTED + r"\3", argv)
    argv = _REDACT_URL_QUERY_RE.sub(r"\1" + _REDACTED, argv)
    return argv


def _parse_exec_property(value):
    """Parse a multi-record Exec*= property value into static-field records.

    Returns a list of {path, argv, ignore_errors} dicts -- one per invocation
    record -- with all runtime fields dropped and credential values in argv
    redacted (see _redact_secrets). Robust to `;`, `}`, and `path=` inside the
    command line (see EXEC_RECORD_RE).
    """
    if not value:
        return []
    return [
        {
            "path": m.group("path"),
            "argv": _redact_secrets(m.group("argv").strip()),
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
            # One non-UTF-8 byte in one unit's properties (a Latin-1 ExecStart
            # argv, a mojibake description) must not fail the decode of the
            # WHOLE bulk output -- that would black out systemd collection for
            # the host every tick until the unit file changes. Replacement is
            # deterministic, so the inventory hash stays stable.
            errors="replace",
            timeout=timeout,
            env=get_clean_env(),
        )
    except subprocess.TimeoutExpired:
        return None, {
            "type": "timeout",
            "message": f"{cmd} timed out after {timeout}s",
        }
    except (OSError, ValueError) as e:
        # Defensive guard for OS-level failures (fork, exec, fd exhaustion).
        # Mirrors snmp.py's broad subprocess guard.
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
        parts = line.split(None, 5)
        # Old systemctl prints a unit-state mark column (U+25CF / "*" etc.)
        # even when piped; --plain only suppresses it on newer versions. A
        # mark taken as the unit name would poison the follow-up bulk show
        # (non-zero exit -> whole-host blackout every tick while any unit is
        # failed). Marks are standalone single-glyph tokens, real unit names
        # always contain a dot -- dropping a leading mark token is unambiguous.
        if parts and parts[0] in _UNIT_STATE_MARKS:
            parts = parts[1:]
        if len(parts) < 4:
            continue
        unit = parts[0]
        # Skip `not-found` placeholder rows -- EXCEPT failed ones: a unit whose
        # unit file was removed while the service is still broken (package
        # uninstalled mid-incident) must stay visible as failed rather than
        # silently vanish from monitoring.
        if parts[1] == "not-found" and parts[2] != "failed":
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
            # Defensive: if `systemctl show` ever emits a property as REPEATED
            # key= lines, last-wins would silently drop all but the last and
            # hide config drift. Accumulate repeats into a list; single-valued
            # keys stay strings.
            if key in props:
                existing = props[key]
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    props[key] = [existing, value]
            else:
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
            # Journal tails ship in the /collect payload, so scrub secrets/PII
            # with the same best-effort redaction as the log-monitoring digests
            # (an error line often embeds the credential that caused the
            # failure). Redact BEFORE truncating: truncating first could split
            # a token and let the remainder slip past the patterns.
            # Payload bound: journald's LineMax default is 48K per line.
            messages.append(redact(msg)[:JOURNAL_MSG_MAX_CHARS])
    return messages


# Box-drawing characters systemctl uses for the dependency tree, plus the
# whitespace around them: U+251C (|-), U+2500 (-), U+2502 (|), U+2514 (L-).
# Built via chr() to keep the source ASCII-only. We strip ONLY these from the
# left, NOT "any non-alphanumeric": the root mount unit is literally "-.mount",
# so a leading-dash strip would corrupt it into "mount".
_REVERSE_DEP_TREE_CHARS = (
    "".join(chr(c) for c in (0x2502, 0x2500, 0x251C, 0x2514)) + " \t"
)
# Unit-state marks systemctl prefixes in list-dependencies tree output and in
# list-units rows on versions where --plain does not suppress them: U+25CF
# (active), U+25CB (inactive), U+00D7 (failed), U+21BB (reloading), plus their
# C-locale ASCII fallbacks. Kept as standalone tokens only -- never stripped
# from a name -- so "-.mount" and friends survive intact (real unit names
# always carry a dot; marks never do).
_UNIT_STATE_MARKS = frozenset(
    (chr(0x25CF), chr(0x25CB), chr(0x00D7), chr(0x21BB), "*", "o", "x")
)
# Max dependencies shipped per drilldown (payload bound; a root target can
# reverse-depend on nearly every unit on the host).
MAX_REVERSE_DEPS = 100


def _parse_reverse_deps(stdout):
    """Parse `systemctl list-dependencies --reverse --plain` output.

    With --plain the output is the queried unit on the first line, then one
    indented dependency name per line. Defense-in-depth for non-plain forms:
    a leading unit-state mark token (see _UNIT_STATE_MARKS) is dropped,
    and Unicode tree-drawing prefixes (U+251C, U+2502, U+2500, U+2514) are
    stripped -- exactly those characters, not "any punctuation", so names
    like the root mount "-.mount" survive intact. Returns a deduplicated
    list of dependent unit names, capped at MAX_REVERSE_DEPS.
    """
    if not stdout:
        return []
    seen = set()
    deps = []
    lines = stdout.splitlines()
    # Skip first line (the unit being queried)
    for line in lines[1:]:
        # Strip interleaved tree drawing + indentation first (no-op for
        # --plain output), then drop a standalone leading state-mark token,
        # then strip tree chars again for the glyph-prefixed tree form where
        # the mark precedes the branch ("* <tree>name").
        cleaned = line.lstrip(_REVERSE_DEP_TREE_CHARS)
        tokens = cleaned.split()
        if tokens and tokens[0] in _UNIT_STATE_MARKS:
            tokens = tokens[1:]
        if not tokens:
            continue
        name = tokens[0].lstrip(_REVERSE_DEP_TREE_CHARS)
        if name and name not in seen:
            seen.add(name)
            deps.append(name)
            if len(deps) >= MAX_REVERSE_DEPS:
                break
    return deps


def _normalize_property_for_hash(key, value):
    """Canonicalize a property value for the inventory hash.

    - Exec*= records keep only static sub-fields (path/argv/ignore_errors),
      sorted by (path, argv).
    - Timer schedule records (TimersCalendar/TimersMonotonic) keep only the
      spec, sorted, with runtime next_elapse dropped.
    - Repeated-line properties (a list from _parse_show_bulk) are sorted.
    - List-valued properties are space-split and sorted.
    - Everything else is stripped of trailing whitespace.
    """
    if key.startswith("Exec"):
        # Preserve definition order: `systemctl show` emits Exec* records in
        # unit-file order, deterministically across fetches. Sorting would make
        # a real reorder (e.g. swapping two ExecStartPre= lines on a oneshot,
        # which changes execution order) invisible to the inventory hash.
        if isinstance(value, list):
            # Defensive: repeated-line accumulation yields a list; the record
            # parser wants one string.
            value = " ".join(value)
        return _parse_exec_property(value)
    if key in ("TimersCalendar", "TimersMonotonic"):
        # Keep only the schedule specs, sorted (directive order is not
        # significant); next_elapse is runtime and would flap the hash.
        if isinstance(value, list):
            value = " ".join(value)
        return sorted(m.group("spec") for m in TIMER_SPEC_RE.finditer(value or ""))
    if isinstance(value, list):
        # Property emitted as repeated key= lines (e.g. OnCalendar=). Sort so the
        # directive order in the unit file is not significant for the hash.
        return sorted(value)
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


def _hash_canonical(canonical):
    """SHA-256 of an already-canonicalized inventory dict.

    Single source of the serialization parameters: snapshot_inventory (ships
    this hash) and _canonical_inventory_hash (tests, empty-host path) must
    produce byte-identical blobs, or the shipped hash and the test-validated
    hash silently diverge.
    """
    blob = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _canonical_inventory_hash(units_props):
    """SHA-256 of the canonical inventory.

    units_props: dict keyed by unit name -> property dict.
    Strips runtime fields; key order is normalized by the sort_keys dump.
    """
    canonical = {name: _canonicalize_unit(props) for name, props in units_props.items()}
    return _hash_canonical(canonical)


def _is_template_unit(name):
    """A bare template unit (empty instance), e.g. getty@.service.

    Templates are NOT instantiable, so `systemctl show` rejects them ("Unit
    name X is neither a valid invocation ID nor unit name") -- and because the
    bulk show passes every name in one call, a single template name fails the
    WHOLE fetch, blacking out health + inventory for the host every tick.
    They only reach us via `list-unit-files` (bare templates are never loaded,
    so list-units never yields them); their running instances
    (getty@tty1.service) are concrete and show fine, so only the empty-instance
    template file is excluded. Detected structurally: the "@" sits immediately
    before the type extension (empty instance).
    """
    at = name.rfind("@")
    if at == -1:
        return False
    return name.rfind(".") == at + 1


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

    def __init__(self, unit_types=DEFAULT_UNIT_TYPES):
        self.unit_types = _normalize_unit_types(unit_types)
        # When collect(scan=True) runs, it stashes (unit_names, raw_props) here
        # so the inventory snapshot in the same tick reuses the single
        # `systemctl show` instead of running its own. Consumed and cleared by
        # snapshot_inventory(); None means "fetch fresh", _FETCH_FAILED means
        # "this tick's fetch failed, skip".
        self._pending_inventory = None
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

        if SystemdCollector._version is None:
            # Self-heal: a transient `systemctl --version` failure at first
            # construction (agent starts at boot, when systemd is busiest)
            # would otherwise pin version=None -- and disable the reverse-deps
            # drilldown -- for the whole process lifetime. Bounded to one
            # attempt per tick, only while undetected.
            SystemdCollector._version = _systemd_version()

        unit_names, error = self._list_units()
        if error:
            # Flag the failure so a forced inventory_sync this same tick skips
            # rather than re-running the same failing `systemctl list-units`.
            self._pending_inventory = _FETCH_FAILED
            errors.append({"step": "list_units", **error})
            return self._empty_result(errors)

        # Health covers LOADED units (unit_names). The inventory additionally
        # covers INSTALLED-but-never-loaded unit files (disabled services are a
        # prime drift signal that list-units --all cannot see).
        inventory_names = unit_names
        if scan:
            inventory_names, error = self._inventory_unit_names(unit_names)
            if error:
                # Inventory completeness is lost this tick; skip the snapshot
                # (sentinel) but keep collecting health for the loaded units.
                self._pending_inventory = _FETCH_FAILED
                errors.append({"step": "list_unit_files", **error})
                inventory_names = unit_names

        if not unit_names and not inventory_names:
            if scan and self._pending_inventory is not _FETCH_FAILED:
                # Genuinely zero units of the configured types: stash an empty
                # result so the inventory snapshot this tick reuses it (snapshot
                # ships the same empty-inventory hash) instead of re-running
                # the enumeration a second time.
                self._pending_inventory = ([], {})
            return self._empty_result(errors)

        # When scan is on, fetch the ALL_PROPERTIES superset (health + config)
        # over the inventory surface in one show and stash the raw output so
        # the inventory snapshot this tick reuses it instead of running its own
        # enumeration + show.
        fetch_scan = scan and self._pending_inventory is not _FETCH_FAILED
        fetch_names = inventory_names if fetch_scan else unit_names
        properties = ALL_PROPERTIES if fetch_scan else HEALTH_PROPERTIES
        unit_props, error = self._show_bulk(fetch_names, properties)
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

        if not unit_props:
            # show exited 0 but parsed to nothing for a non-empty unit list
            # (wrapper systemctl, daemon hiccup, truncated stream). Every unit
            # would be skipped below, silently reporting units=[] as if the host
            # idled. Treat it like a fetch failure: flag an error and the
            # _FETCH_FAILED sentinel so the inventory snapshot skips too.
            self._pending_inventory = _FETCH_FAILED
            errors.append(
                {
                    "step": "show_bulk",
                    "type": "empty_output",
                    "message": "show exited 0 with no parseable units",
                }
            )
            return self._empty_result(errors)

        if fetch_scan:
            self._pending_inventory = (fetch_names, unit_props)

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

        # Cap drilldowns per tick; roll back the signature commit for the
        # overflow so those units re-qualify next tick instead of being
        # silently dropped (see MAX_DRILLDOWNS_PER_TICK).
        if len(newly_failed) > MAX_DRILLDOWNS_PER_TICK:
            deferred = newly_failed[MAX_DRILLDOWNS_PER_TICK:]
            newly_failed = newly_failed[:MAX_DRILLDOWNS_PER_TICK]
            for name in deferred:
                SystemdCollector._last_failure_signatures.pop(name, None)

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
            # No ellipsizing of long unit names (systemctl may truncate to the
            # assumed 80-col width when piped; a truncated name then fails the
            # follow-up `show`).
            "--full",
            "--no-pager",
        ]
        stdout, error = _run_systemctl(args)
        if error:
            return [], error
        return _parse_list_units(stdout), None

    def _list_unit_files(self):
        """Names of INSTALLED unit files of the configured types.

        `list-units --all` only enumerates units loaded into PID 1; a unit
        file that is installed but disabled/never started -- the classic
        "service present but off" drift signal -- is invisible to it.
        `--type=` on list-unit-files is not portable back to systemd 219, so
        filter suffixes ourselves. Bare template files (getty@.service) are
        excluded -- they cannot be `systemctl show`n (see _is_template_unit).
        """
        args = [
            "list-unit-files",
            "--no-legend",
            "--plain",
            "--full",
            "--no-pager",
        ]
        stdout, error = _run_systemctl(args)
        if error:
            return [], error
        types = {t.strip() for t in self.unit_types.split(",") if t.strip()}
        names = []
        for line in (stdout or "").splitlines():
            parts = line.split()
            if parts and parts[0] in _UNIT_STATE_MARKS:
                parts = parts[1:]
            if not parts:
                continue
            name = parts[0]
            if (
                "." in name
                and name.rsplit(".", 1)[-1] in types
                and not _is_template_unit(name)
            ):
                names.append(name)
        return names, None

    def _inventory_unit_names(self, loaded_names):
        """Inventory surface: loaded units plus installed-but-unloaded files."""
        file_names, error = self._list_unit_files()
        if error:
            return loaded_names, error
        loaded = set(loaded_names)
        extras = sorted(n for n in file_names if n not in loaded)
        return list(loaded_names) + extras, None

    def _show_bulk(self, unit_names, properties):
        """Bulk fetch properties for many units, chunked.

        Chunking bounds the argv size (a host with tens of thousands of
        transient units would otherwise risk E2BIG, blacking out collection)
        and gives each chunk its own SHOW_BULK_TIMEOUT budget. Any chunk
        error fails the whole fetch -- partial data must not masquerade as
        the full unit set.
        """
        units = {}
        for start in range(0, len(unit_names), SHOW_BULK_CHUNK):
            end = start + SHOW_BULK_CHUNK
            chunk = unit_names[start:end]
            args = [
                "show",
                f"--property={','.join(properties)}",
                "--no-pager",
                # End-of-options guard: the root mount unit is literally
                # "-.mount", which getopt would otherwise parse as an option
                # and fail the whole bulk show (possible whenever unit_types
                # includes mount).
                "--",
            ]
            args.extend(chunk)
            stdout, error = _run_systemctl(args, timeout=SHOW_BULK_TIMEOUT)
            if error:
                return {}, error
            units.update(_parse_show_bulk(stdout))
        return units, None

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
            str(JOURNAL_TAIL_LINES),
            "-p",
            "err",
            # Bound the reverse journal scan: a unit with few/zero err-priority
            # entries would otherwise walk the entire journal (seconds of disk
            # IO on multi-GB journals). 24h (not 1h) because the first tick
            # after an agent restart re-drills chronically-failed units whose
            # err lines can be hours old; a genuinely new failure is minutes
            # old either way.
            "--since",
            "-24h",
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
            # Flat list without tree glyphs / unit-state bullets, un-ellipsized
            # names (the tree form prefixes state marks the parser must not
            # mistake for names, and piped output may truncate long names).
            "--plain",
            "--full",
            "--no-pager",
            # End-of-options guard (see _show_bulk: "-.mount").
            "--",
            unit_name,
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
            # collect() already ran (and logged) this tick's list-units/show and
            # it failed; don't hammer the same failing systemctl again. Skip.
            return {}, None, errors
        if isinstance(pending, tuple):
            unit_names, raw_props = pending
        else:
            unit_names, error = self._list_units()
            if error:
                errors.append({"step": "list_units", **error})
                return {}, None, errors
            unit_names, error = self._inventory_unit_names(unit_names)
            if error:
                errors.append({"step": "list_unit_files", **error})
                return {}, None, errors
            if not unit_names:
                # Ships the empty-inventory hash so a host that genuinely has no
                # units of the configured types is recorded as such. NOTE: an
                # empty `list-units` is ambiguous -- a transient exit-0-but-empty
                # enumeration (wrapper systemctl, truncation) is indistinguishable
                # here from a real "all units removed", and treating it as
                # untrusted would break the legitimate zero-units host. Same
                # backend-delta-validator concern as the partial-show case below.
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
            errors.append(
                {
                    "step": "show_bulk_inventory",
                    "type": "empty_output",
                    "message": "show exited 0 with no parseable units",
                }
            )
            return {}, None, errors

        # PARTIAL show guard: unlike a real bulk removal (which drops units
        # from list-units too), a truncated show leaves units listed but
        # property-less. A large gap between the two therefore proves
        # truncation, not removal -- ship nothing rather than silently delete
        # those units from the backend inventory. Small gaps pass: aliased
        # names legitimately collapse onto their canonical Id, and a unit can
        # vanish in the list->show window.
        if len(unit_names) >= PARTIAL_SHOW_MIN_UNITS and len(raw_props) < (
            PARTIAL_SHOW_MIN_RATIO * len(unit_names)
        ):
            errors.append(
                {
                    "step": "show_bulk_inventory",
                    "type": "partial_output",
                    "message": f"show returned {len(raw_props)} of "
                    f"{len(unit_names)} listed units",
                }
            )
            return {}, None, errors

        # Canonicalize each unit (strip runtime, normalize Exec/list fields)
        canon_units = {
            name: _canonicalize_unit(props) for name, props in raw_props.items()
        }
        # Hash the same canonical form we ship (shared serializer, see
        # _hash_canonical).
        return canon_units, _hash_canonical(canon_units), errors

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

        units, h, errors = self.snapshot_inventory()
        if h is None:
            # Snapshot failed (e.g. transient systemctl error); we could not
            # send, so keep any force flag and retry next tick. NOTE: the
            # snapshot's `errors` are dropped here -- surfacing them would need an
            # errors-only payload shape (we must NOT ship units={} on a None
            # hash), which is a backend contract change left for later.
            log("systemd inventory snapshot failed; skipping", "debug")
            return False

        server_hash = scan_config.get("last_inventory_hash")
        local_hash = SystemdCollector._last_local_inventory_hash
        # Backend rebuild contract: the key PRESENT with an explicit null means
        # "resend regardless" (server lost/cleared its copy). Key absent means
        # the server simply hasn't echoed a hash yet -- local dedup applies.
        server_cleared = "last_inventory_hash" in scan_config and server_hash is None
        # OR, not AND: a confirmed local send (local_hash == h) suppresses
        # repeats on its own, before the backend echoes the hash back via
        # /collect. Under AND the local-hash dedup and force_inventory_resend
        # were dead weight -- the agent resent every tick until the server
        # round-tripped the hash.
        if (
            not force_resend
            and not server_cleared
            and (h == server_hash or h == local_hash)
        ):
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
    Falsy input (explicit null in the config, empty string/list) falls back to
    the default set -- `--type=None` / `--type=` would likewise kill collection
    every tick.
    """
    if isinstance(value, (list, tuple)):
        value = ",".join(str(v) for v in value)
    if not value:
        return DEFAULT_UNIT_TYPES
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
