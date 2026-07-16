import re
import shutil
import subprocess
import time

from fivenines_agent.debug import debug, log
from fivenines_agent.subprocess_utils import get_clean_env

# Default poll throttle (seconds). Overridable via the "zfs" config dict, which
# collectors.py unpacks as kwargs: {"interval": N} -> zfs_storage_health(interval=N).
_DEFAULT_INTERVAL = 60

# Hard subprocess timeout (seconds). A wedged `zpool` call -- SUSPENDED pool,
# dying controller, kernel stuck on I/O, the exact states this collector exists
# to report -- must never hang the whole collect tick. zpool reads kernel state
# and answers in milliseconds when healthy, so 10s is generous. Mirrors
# ceph.py's SUBPROCESS_TIMEOUT posture.
_SUBPROCESS_TIMEOUT = 10

_zfs_cache = {
    "timestamp": 0,
    "data": [],
}

# Stable wire contract: zpool health string -> numeric code. Append-only, never
# renumber (the server's ZFS ingester depends on these values). Unknown -> None,
# and the raw "health" string is kept so the backend can still react to it.
_HEALTH_CODES = {
    "ONLINE": 0,
    "DEGRADED": 1,
    "FAULTED": 2,
    "OFFLINE": 3,
    "REMOVED": 4,
    "UNAVAIL": 5,
    "SUSPENDED": 6,
}

# vdev/device states that count toward degraded_vdevs. ONLINE and spare states
# (AVAIL/INUSE) are healthy and excluded.
_UNHEALTHY_VDEV_STATES = {"DEGRADED", "FAULTED", "OFFLINE", "REMOVED", "UNAVAIL"}

# `zpool status` line labels, used to bound the multi-line scan block.
_STATUS_LABELS = (
    "pool:",
    "state:",
    "status:",
    "action:",
    "see:",
    "scan:",
    "config:",
    "errors:",
    "remove:",
    "checkpoint:",
    "dedup:",
)


def zfs_available() -> bool:
    """Check if ZFS is available on the system."""
    return shutil.which("zpool") is not None


def _run(cmd):
    """Run a zpool command, bounded by _SUBPROCESS_TIMEOUT.

    A timeout is returned as a synthetic failed result (returncode 1, empty
    stdout, stderr "timeout") so it is indistinguishable from any other command
    failure. Every existing failure path then applies unchanged: the
    -pPLv -> -PLv retry, the list-only degrade, the pool skip, and the
    collector returning [].
    """
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
            env=get_clean_env(),
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="timeout")


def get_zfs_version():
    """Get ZFS version information (first line of `zpool version`)."""
    r = _run(["zpool", "version"])
    if r.returncode != 0:
        return None
    line = r.stdout.split("\n", 1)[0].strip()
    return line or None


def list_zfs_pools():
    """List ZFS pool names, or None if the `zpool list` command failed.

    None (command failure/timeout) is deliberately distinct from [] (command
    succeeded, host has zero pools): the collector maps the former to a null
    payload (collection failure) and the latter to an empty list, so the server
    never mistakes a transient CLI failure for "all pools destroyed".
    """
    r = _run(["zpool", "list", "-H", "-o", "name"])
    if r.returncode != 0:
        return None
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]


def _safe_int(x, default=None):
    try:
        return int(x)
    except (TypeError, ValueError):
        try:
            return int(float(x))
        except (TypeError, ValueError):
            return default


def _health_code(health):
    """Map a zpool health string to the stable numeric contract code (or None)."""
    if not health:
        return None
    return _HEALTH_CODES.get(health.strip().upper())


def _count_degraded_vdevs(vdev_tree):
    """Count devices/vdevs below the pool root whose state is unhealthy.

    Walks the primary child tree only. Section devices (spares/cache/logs) are
    already reachable there via the indentation parser, so they are counted once.
    Returns None when there is no vdev tree (status unavailable).
    """
    if not vdev_tree:
        return None
    count = 0
    stack = list(vdev_tree.get("children", []) or [])
    while stack:
        node = stack.pop()
        state = node.get("state")
        if state and state.strip().upper() in _UNHEALTHY_VDEV_STATES:
            count += 1
        stack.extend(node.get("children", []) or [])
    return count


def _parse_resilver_progress(scan_text):
    """Percent (0-100) of an in-progress resilver; 0.0 when not resilvering.

    Returns None when no scan information is available (status unavailable).
    """
    if scan_text is None:
        return None
    if "resilver in progress" not in scan_text.lower():
        return 0.0
    m = re.search(r"(\d+(?:\.\d+)?)\s*% done", scan_text)
    return float(m.group(1)) if m else 0.0


def _parse_scrub_errors(scan_text):
    """Error count reported by the last completed scrub.

    Returns None when the last scan was not a completed scrub (never scrubbed,
    resilver in progress, or status unavailable), so the backend can tell a clean
    scrub (0) from an unknown one.
    """
    if not scan_text or "scrub repaired" not in scan_text.lower():
        return None
    m = re.search(r"with (\d+) errors", scan_text)
    return _safe_int(m.group(1)) if m else None


def _indent_width(line):
    expanded = line.expandtabs(8)
    return len(expanded) - len(expanded.lstrip(" "))


def _is_status_label(stripped):
    return any(stripped.startswith(lbl) for lbl in _STATUS_LABELS)


def _push_by_indent(indent_stack, root, indent, node):
    while indent_stack and indent_stack[-1][0] >= indent:
        indent_stack.pop()
    if indent_stack:
        parent = indent_stack[-1][1]
        parent.setdefault("children", []).append(node)
    else:
        root.setdefault("children", []).append(node)
    indent_stack.append((indent, node))


def _parse_zpool_status(text):
    pools = {}
    cur = None
    in_config = False
    header_seen = False
    in_scan = False
    indent_stack = []
    section = None  # logs/spares/cache/special
    pool_name = None

    def finalize_current():
        nonlocal cur, pool_name
        if cur and pool_name:
            pools[pool_name] = cur
        cur = None
        pool_name = None

    for line in text.splitlines():
        if line.startswith("  pool:"):
            finalize_current()
            pool_name = line.split(":", 1)[1].strip()
            cur = {
                "scan": None,
                "scan_full": None,
                "errors": None,
                "vdev_tree": {
                    "name": None,
                    "state": None,
                    "read": None,
                    "write": None,
                    "cksum": None,
                    "children": [],
                    "logs": [],
                    "spares": [],
                    "cache": [],
                    "special": [],
                },
                "_scan_lines": [],
            }
            in_config = False
            header_seen = False
            in_scan = False
            indent_stack = []
            section = None
            continue

        if not cur:
            continue

        # Accumulate the multi-line scan block. Continuation lines are indented
        # and are not themselves status labels. This must run before the label
        # handlers so the "% done" / "with N errors" details are not dropped.
        if in_scan:
            stripped_c = line.strip()
            if (
                line[:1] in (" ", "\t")
                and stripped_c
                and not _is_status_label(stripped_c)
            ):
                cur["_scan_lines"].append(stripped_c)
                continue
            in_scan = False  # not a continuation: fall through to normal handling

        if line.startswith(" state:"):
            cur["vdev_tree"]["state"] = line.split(":", 1)[1].strip()
            continue
        if line.strip().startswith("scan:"):
            first = line.split(":", 1)[1].strip()
            cur["scan"] = first
            cur["_scan_lines"] = [first]
            in_scan = True
            continue
        if line.strip().startswith("errors:"):
            cur["errors"] = line.split(":", 1)[1].strip()
            continue
        if line.strip() == "config:":
            in_config = True
            header_seen = False
            indent_stack = []
            section = None
            continue

        if not in_config:
            continue

        if not line.strip():
            continue

        if not header_seen and line.strip().startswith("NAME"):
            header_seen = True
            continue

        st = line.strip()
        if st.endswith(":") and st[:-1] in ("logs", "spares", "cache", "special"):
            section = st[:-1]
            continue
        if st in ("logs", "spares", "cache", "special"):
            section = st
            continue

        # Device/vdev row (line is already known non-empty here)
        leading = _indent_width(line)
        cols = line.split()
        name = cols[0]
        state = cols[1] if len(cols) > 1 else None

        def _num(i):
            try:
                return int(cols[i])
            except (IndexError, ValueError):
                return None

        node = {
            "name": name,
            "state": state,
            "read": _num(2),
            "write": _num(3),
            "cksum": _num(4),
        }

        root = cur["vdev_tree"]

        if root["name"] is None and name == pool_name:
            root.update(node)
            indent_stack = [(leading, root)]
            continue

        if section:
            _push_by_indent(indent_stack, root, leading, node)
            root[section].append(node)
        else:
            _push_by_indent(indent_stack, root, leading, node)

    finalize_current()

    # Collapse the scan block into a single string for numeric derivation and
    # drop the scratch field.
    for p in pools.values():
        lines = p.pop("_scan_lines", [])
        p["scan_full"] = " ".join(lines) if lines else p.get("scan")

    return pools


def _zpool_list_summary():
    res = {}
    q = _run(
        [
            "zpool",
            "list",
            "-Hp",
            "-o",
            "name,health,size,alloc,free,frag,cap,dedupratio",
        ]
    )
    if q.returncode != 0:
        return res
    for line in filter(None, q.stdout.splitlines()):
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        name, health, size_b, alloc_b, free_b, frag, cap, dedup = parts[:8]
        res[name] = {
            "health": health,
            "summary": {
                "size_bytes": _safe_int(size_b),
                "alloc_bytes": _safe_int(alloc_b),
                "free_bytes": _safe_int(free_b),
                "frag_percent": _safe_int(frag),
                "capacity_percent": _safe_int(cap),
                "dedup_ratio": (None if dedup in ("-", "") else float(dedup)),
            },
        }
    return res


def get_zfs_pool_info(pool_name):
    """Collect the health contract for a single ZFS pool."""
    try:
        list_summary = _zpool_list_summary()

        # -p (parseable) is unsupported on very old ZFS; fall back to -PLv.
        status_cp = _run(["zpool", "status", "-pPLv", pool_name])
        if status_cp.returncode != 0:
            status_cp = _run(["zpool", "status", "-PLv", pool_name])

        if status_cp.returncode != 0 and pool_name not in list_summary:
            log(
                f"Error getting ZFS pool info for {pool_name}: "
                f"{status_cp.stderr.strip() or 'zpool failed'}",
                "error",
            )
            return None

        details = (
            _parse_zpool_status(status_cp.stdout) if status_cp.returncode == 0 else {}
        )
        d = details.get(pool_name, {})
        s = list_summary.get(pool_name, {})
        summary = s.get("summary")
        health = s.get("health")
        vdev_tree = d.get("vdev_tree")
        scan_full = d.get("scan_full")

        return {
            "name": pool_name,
            "health": health,
            "health_code": _health_code(health),
            "degraded_vdevs": _count_degraded_vdevs(vdev_tree),
            "resilver_progress": _parse_resilver_progress(scan_full),
            "scrub_errors": _parse_scrub_errors(scan_full),
            "fragmentation": (summary or {}).get("frag_percent"),
            "summary": summary,
            "errors": d.get("errors"),
            "vdev_tree": vdev_tree,
        }

    except Exception as e:
        log(f"Error fetching ZFS pool info for {pool_name}: {e}", "error")
        return None


@debug("zfs_storage_health")
def zfs_storage_health(interval=_DEFAULT_INTERVAL):
    """Collect health for all ZFS pools.

    Returns one of three outcomes, cached for `interval` seconds (default 60):

    - ``None`` -- COLLECTION FAILURE: the `zpool` binary vanished mid-run, the
      pool listing failed/timed out, or pools exist but every per-pool read
      failed. Surfaced as ``data["zfs"] = null`` so the server never mistakes a
      transient CLI failure for "all pools destroyed" and prunes health rows
      (same null-vs-empty discipline as the docker contract).
    - ``[]`` -- the listing succeeded and the host genuinely has zero pools
      (safe for the server to prune).
    - a non-empty list of per-pool health objects.

    The outcome (including ``None``) is cached like any other, so a failure does
    not turn into a per-tick re-probe storm.
    """
    now = time.time()

    ttl = _safe_int(interval, _DEFAULT_INTERVAL)
    if ttl < 0:
        ttl = _DEFAULT_INTERVAL

    if now - _zfs_cache["timestamp"] < ttl:
        return _zfs_cache["data"]

    data = _collect_zfs_pools()

    _zfs_cache["timestamp"] = now
    _zfs_cache["data"] = data

    return data


def _collect_zfs_pools():
    """Collect all pools, or None on any collection failure. See caller."""
    if not zfs_available():
        # zpool binary gone mid-run -> collection failure, not "no pools".
        log("ZFS not available", "debug")
        return None

    pools = list_zfs_pools()
    if pools is None:
        log("ZFS pool listing failed", "debug")
        return None
    if not pools:
        # Listing succeeded, host genuinely has zero pools.
        return []

    zfs_version = get_zfs_version()
    infos = [get_zfs_pool_info(pool) for pool in pools]
    infos = [d for d in infos if d is not None]
    if not infos:
        # Pools exist but not one could be read -> collection failure.
        log("ZFS pools present but all reads failed", "debug")
        return None

    for pool_info in infos:
        pool_info["zfs_version"] = zfs_version
    return infos
