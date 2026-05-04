"""
Cgroup helper for fivenines agent.

Resolves cgroup paths for systemd units across cgroup v1 and v2 hierarchies,
and provides safe per-unit metric reads. EACCES on cgroup files is treated as
the expected capability gap (silent None) rather than an error to log.

Path layout:
  v2 (unified):  /sys/fs/cgroup/system.slice/<unit>/<file>
  v1 (per-ctrl): /sys/fs/cgroup/<controller>/system.slice/<unit>/<file>

Hybrid systems (v1 + v2 unified at /sys/fs/cgroup/unified) are detected as v1
because per-unit memory/cpu accounting still lives in the v1 hierarchy.
"""

import os

from fivenines_agent.debug import log

CGROUP_ROOT = "/sys/fs/cgroup"

# Module-level cache - cleared by reset_cache() in tests
_cached_hierarchy = None
_cached_hierarchy_set = False


def reset_cache():
    """Reset the cached hierarchy detection. Used in tests."""
    global _cached_hierarchy, _cached_hierarchy_set
    _cached_hierarchy = None
    _cached_hierarchy_set = False


def detect_hierarchy():
    """Detect cgroup hierarchy.

    Returns:
        "v2" if cgroup v2 unified hierarchy is mounted at /sys/fs/cgroup
        "v1" if v1 per-controller hierarchy or hybrid mode
        None if no cgroup hierarchy found
    """
    global _cached_hierarchy, _cached_hierarchy_set
    if _cached_hierarchy_set:
        return _cached_hierarchy

    if os.path.exists(os.path.join(CGROUP_ROOT, "cgroup.controllers")):
        _cached_hierarchy = "v2"
    elif os.path.isdir(os.path.join(CGROUP_ROOT, "memory")):
        _cached_hierarchy = "v1"
    else:
        _cached_hierarchy = None

    _cached_hierarchy_set = True
    return _cached_hierarchy


def _validate_unit_name(unit_name):
    """Reject unit names that could escape the cgroup root.

    systemd unit names are kernel-validated, but defense in depth costs nothing.
    """
    if "/" in unit_name or "\x00" in unit_name:
        raise ValueError(f"invalid unit name: {unit_name!r}")


def unit_path(unit_name, hierarchy, controller=None):
    """Build the cgroup directory path for a systemd unit.

    Args:
        unit_name: full unit name (e.g. "nginx.service")
        hierarchy: "v1" or "v2"
        controller: required for v1 (e.g. "memory", "cpuacct")

    Returns:
        Absolute filesystem path string. The caller checks if the path exists.

    Raises:
        ValueError: if unit_name contains path-traversal characters.
    """
    _validate_unit_name(unit_name)

    if hierarchy == "v2":
        return os.path.join(CGROUP_ROOT, "system.slice", unit_name)
    if hierarchy == "v1":
        if not controller:
            raise ValueError("controller is required for cgroup v1 path")
        return os.path.join(CGROUP_ROOT, controller, "system.slice", unit_name)
    raise ValueError(f"unsupported hierarchy: {hierarchy!r}")


def _read_text(path):
    """Read a small cgroup text file safely.

    Returns the stripped text on success, None on missing file or denied access.
    Logs unexpected errors at debug level so capability-gap noise stays quiet.
    """
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return None
    except PermissionError:
        # EACCES on cgroup files is the expected state when the agent user
        # lacks the right group memberships. Silent on purpose.
        return None
    except OSError as e:
        log(f"cgroup read error for {path}: {e}", "debug")
        return None


def _parse_int(text):
    """Parse a single integer from cgroup text. Returns None on failure or 'max'."""
    if text is None or text == "max":
        return None
    try:
        return int(text)
    except (ValueError, TypeError):
        return None


def _parse_kv_field(text, key):
    """Extract a numeric value from key=value cgroup files (e.g. cpu.stat, memory.events).

    Format example (cpu.stat):
        usage_usec 12345
        user_usec 11111

    Returns int value or None if key absent or unparseable.
    """
    if text is None:
        return None
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[0] == key:
            try:
                return int(parts[1])
            except (ValueError, TypeError):
                return None
    return None


def read_memory_current(unit_name, hierarchy):
    """Current memory usage for a unit in bytes. None if unavailable."""
    if hierarchy == "v2":
        path = os.path.join(unit_path(unit_name, "v2"), "memory.current")
        return _parse_int(_read_text(path))
    if hierarchy == "v1":
        path = os.path.join(
            unit_path(unit_name, "v1", controller="memory"),
            "memory.usage_in_bytes",
        )
        return _parse_int(_read_text(path))
    return None


def read_cpu_usec(unit_name, hierarchy):
    """Cumulative CPU usage for a unit in microseconds. None if unavailable."""
    if hierarchy == "v2":
        path = os.path.join(unit_path(unit_name, "v2"), "cpu.stat")
        return _parse_kv_field(_read_text(path), "usage_usec")
    if hierarchy == "v1":
        # cpuacct.usage is in nanoseconds; convert to microseconds
        path = os.path.join(
            unit_path(unit_name, "v1", controller="cpuacct"),
            "cpuacct.usage",
        )
        ns = _parse_int(_read_text(path))
        if ns is None:
            return None
        return ns // 1000
    return None


def read_oom_kill_count(unit_name, hierarchy):
    """Cumulative OOM kill count for a unit (cgroup v2 only).

    cgroup v1 has no equivalent surface; returns None. Hybrid mode is treated
    as v1.
    """
    if hierarchy != "v2":
        return None
    path = os.path.join(unit_path(unit_name, "v2"), "memory.events")
    return _parse_kv_field(_read_text(path), "oom_kill")


def read_inception_id(unit_name, hierarchy):
    """Inode of the unit's cgroup directory.

    Used jointly with NRestarts to detect counter resets when a unit restarts
    and its cgroup is recreated. Returns None if the directory does not exist.
    """
    if hierarchy == "v2":
        path = unit_path(unit_name, "v2")
    elif hierarchy == "v1":
        path = unit_path(unit_name, "v1", controller="memory")
    else:
        return None
    try:
        return os.stat(path).st_ino
    except FileNotFoundError:
        return None
    except PermissionError:
        return None
    except OSError as e:
        log(f"cgroup stat error for {path}: {e}", "debug")
        return None


def read_unit_resources(unit_name, hierarchy):
    """Read all per-unit cgroup metrics in one call.

    Returns dict with keys: memory_current, cpu_usec, oom_kill_count,
    inception_id. Each value is None if the underlying surface is unavailable.
    Returns empty dict if hierarchy is None.
    """
    if hierarchy not in ("v1", "v2"):
        return {}
    return {
        "memory_current": read_memory_current(unit_name, hierarchy),
        "cpu_usec": read_cpu_usec(unit_name, hierarchy),
        "oom_kill_count": read_oom_kill_count(unit_name, hierarchy),
        "inception_id": read_inception_id(unit_name, hierarchy),
    }
