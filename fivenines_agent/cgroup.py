"""
Cgroup helper for fivenines agent.

Resolves cgroup paths for systemd units across cgroup v1 and v2 hierarchies,
and provides safe per-unit metric reads. EACCES on cgroup files is treated as
the expected capability gap (silent None) rather than an error to log.

Paths are built from systemd's per-unit ControlGroup= value (e.g.
"/system.slice/nginx.service", or "/machine.slice/foo.service" for a unit
relocated with Slice=), so units outside the default system.slice still report
metrics:
  v2 (unified):  /sys/fs/cgroup<ControlGroup>/<file>
  v1 (per-ctrl): /sys/fs/cgroup/<controller><ControlGroup>/<file>

Hybrid systems (v1 + v2 unified at /sys/fs/cgroup/unified) are detected as v1
because per-unit memory/cpu accounting still lives in the v1 hierarchy.
"""

import os

from fivenines_agent.debug import log

CGROUP_ROOT = "/sys/fs/cgroup"

# Module-level cache - cleared by reset_cache() in tests
_cached_hierarchy = None
_cached_hierarchy_set = False
_cached_v1_cpu_controller = None
_cached_v1_cpu_controller_set = False


def reset_cache():
    """Reset the cached hierarchy detection. Used in tests."""
    global _cached_hierarchy, _cached_hierarchy_set
    global _cached_v1_cpu_controller, _cached_v1_cpu_controller_set
    _cached_hierarchy = None
    _cached_hierarchy_set = False
    _cached_v1_cpu_controller = None
    _cached_v1_cpu_controller_set = False


def _v1_cpu_controller():
    """Detect the v1 controller mount that exposes cpuacct.usage.

    Older kernels mount cpuacct as its own controller at
    /sys/fs/cgroup/cpuacct/. CentOS 7 / RHEL 7 (and most modern v1 systems)
    mount it combined with cpu at /sys/fs/cgroup/cpu,cpuacct/. Detect once
    at first call and cache the result.

    Returns the controller name to pass to unit_path, or None if neither
    mount exists.
    """
    global _cached_v1_cpu_controller, _cached_v1_cpu_controller_set
    if _cached_v1_cpu_controller_set:
        return _cached_v1_cpu_controller
    for candidate in ("cpuacct", "cpu,cpuacct"):
        if os.path.isdir(os.path.join(CGROUP_ROOT, candidate)):
            _cached_v1_cpu_controller = candidate
            break
    _cached_v1_cpu_controller_set = True
    return _cached_v1_cpu_controller


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


def _validate_control_group(control_group):
    """Reject ControlGroup paths that could escape the cgroup root.

    systemd's ControlGroup= is a clean absolute path (e.g.
    "/system.slice/nginx.service"); validate defensively before joining it
    under /sys/fs/cgroup.
    """
    if not control_group or not control_group.startswith("/"):
        raise ValueError(f"invalid control group: {control_group!r}")
    if "\x00" in control_group or ".." in control_group.split("/"):
        raise ValueError(f"invalid control group: {control_group!r}")


def cgroup_dir(control_group, hierarchy, controller=None):
    """Build the cgroup directory for a unit's ControlGroup path.

    Args:
        control_group: systemd's ControlGroup= value for the unit, e.g.
            "/system.slice/nginx.service" or "/machine.slice/foo.service" for a
            unit relocated with Slice=. Using it directly (instead of assuming
            system.slice) is what makes per-unit metrics work for Slice= and
            transient units.
        hierarchy: "v1" or "v2"
        controller: required for v1 (e.g. "memory", "cpuacct")

    Returns:
        Absolute filesystem path string. The caller checks if the path exists.

    Raises:
        ValueError: if control_group is malformed or hierarchy is unsupported.
    """
    _validate_control_group(control_group)
    rel = control_group.lstrip("/")

    if hierarchy == "v2":
        return os.path.join(CGROUP_ROOT, rel)
    if hierarchy == "v1":
        if not controller:
            raise ValueError("controller is required for cgroup v1 path")
        return os.path.join(CGROUP_ROOT, controller, rel)
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


def read_memory_current(control_group, hierarchy):
    """Current memory usage for a unit in bytes. None if unavailable."""
    if hierarchy == "v2":
        path = os.path.join(cgroup_dir(control_group, "v2"), "memory.current")
        return _parse_int(_read_text(path))
    if hierarchy == "v1":
        path = os.path.join(
            cgroup_dir(control_group, "v1", controller="memory"),
            "memory.usage_in_bytes",
        )
        return _parse_int(_read_text(path))
    return None


def read_cpu_usec(control_group, hierarchy):
    """Cumulative CPU usage for a unit in microseconds. None if unavailable."""
    if hierarchy == "v2":
        path = os.path.join(cgroup_dir(control_group, "v2"), "cpu.stat")
        return _parse_kv_field(_read_text(path), "usage_usec")
    if hierarchy == "v1":
        controller = _v1_cpu_controller()
        if controller is None:
            return None
        # cpuacct.usage is in nanoseconds; convert to microseconds
        path = os.path.join(
            cgroup_dir(control_group, "v1", controller=controller),
            "cpuacct.usage",
        )
        ns = _parse_int(_read_text(path))
        if ns is None:
            return None
        return ns // 1000
    return None


def read_oom_kill_count(control_group, hierarchy):
    """Cumulative OOM kill count for a unit (cgroup v2 only).

    cgroup v1 has no equivalent surface; returns None. Hybrid mode is treated
    as v1.
    """
    if hierarchy != "v2":
        return None
    path = os.path.join(cgroup_dir(control_group, "v2"), "memory.events")
    return _parse_kv_field(_read_text(path), "oom_kill")


def read_inception_id(control_group, hierarchy):
    """Inode of the unit's cgroup directory.

    Used jointly with NRestarts to detect counter resets when a unit restarts
    and its cgroup is recreated. Returns None if the directory does not exist.
    """
    if hierarchy == "v2":
        path = cgroup_dir(control_group, "v2")
    elif hierarchy == "v1":
        path = cgroup_dir(control_group, "v1", controller="memory")
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


def read_unit_resources(control_group, hierarchy):
    """Read all per-unit cgroup metrics in one call.

    Args:
        control_group: systemd's ControlGroup= value for the unit. Empty for
            inactive/transient units with no live cgroup.
        hierarchy: "v1" or "v2".

    Returns dict with keys: memory_current, cpu_usec, oom_kill_count,
    inception_id. Each value is None if the underlying surface is unavailable.
    Returns empty dict if hierarchy is None or the unit has no cgroup.
    """
    if hierarchy not in ("v1", "v2"):
        return {}
    if not control_group:
        # Inactive/transient unit: no live cgroup to read.
        return {}
    return {
        "memory_current": read_memory_current(control_group, hierarchy),
        "cpu_usec": read_cpu_usec(control_group, hierarchy),
        "oom_kill_count": read_oom_kill_count(control_group, hierarchy),
        "inception_id": read_inception_id(control_group, hierarchy),
    }
