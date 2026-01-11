import os
import shutil
import subprocess
import time

from fivenines_agent.debug import debug, log

_zfs_cache = {
    "timestamp": 0,
    "data": []
}

def zfs_available() -> bool:
    """Check if ZFS is available on the system."""
    return shutil.which("zpool") is not None

def get_zfs_version():
    """Get ZFS version information."""
    try:
        result = subprocess.run(
            ["zpool", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )
        return result.stdout.split('\n')[0].strip()
    except Exception as e:
        log(f"Error fetching ZFS version: {e}", 'error')
        return None

def list_zfs_pools():
    """List all ZFS pools."""
    pools = []
    try:
        result = subprocess.run(
            ["zpool", "list", "-H", "-o", "name"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        for line in result.stdout.splitlines():
            if line.strip():
                pools.append(line.strip())
    except Exception as e:
        log(f"Error listing ZFS pools: {e}", 'error')
    return pools

def _run(cmd):
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False
    )

def _safe_int(x, default=None):
    try:
        return int(x)
    except Exception:
        try:
            return int(float(x))
        except Exception:
            return default

def _indent_width(line):
    expanded = line.expandtabs(8)
    return len(expanded) - len(expanded.lstrip(" "))

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
                "name": pool_name,
                "scan": None,
                "errors": None,
                "vdev_tree": {
                    "name": None, "state": None, "read": None, "write": None, "cksum": None,
                    "children": [], "logs": [], "spares": [], "cache": [], "special": []
                },
                "parser_warnings": []
            }
            in_config = False
            header_seen = False
            indent_stack = []
            section = None
            continue

        if not cur:
            continue

        if line.startswith(" state:"):
            cur["vdev_tree"]["state"] = line.split(":", 1)[1].strip()
            continue
        if line.strip().startswith("scan:"):
            cur["scan"] = line.split(":", 1)[1].strip()
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

        # Device/vdev row
        leading = _indent_width(line)
        cols = line.split()
        if not cols:
            continue

        name = cols[0]
        state = cols[1] if len(cols) > 1 else None

        def _num(i):
            try:
                return int(cols[i])
            except Exception:
                return None

        read = _num(2)
        write = _num(3)
        cksum = _num(4)
        node = {"name": name, "state": state, "read": read, "write": write, "cksum": cksum}

        root = cur["vdev_tree"]

        if root["name"] is None and name == cur["name"]:
            root.update(node)
            indent_stack = [(leading, root)]
            continue

        if section:
            _push_by_indent(indent_stack, root, leading, node)
            root[section].append(node)
        else:
            _push_by_indent(indent_stack, root, leading, node)

    finalize_current()

    return pools

def _zpool_list_summary():
    res = {}
    q = _run(["zpool", "list", "-Hp", "-o", "name,health,size,alloc,free,frag,cap,dedupratio"])
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
            }
        }
    return res

def get_zfs_pool_info(pool_name):
    """Get comprehensive ZFS pool information."""
    try:
        list_summary = _zpool_list_summary()
        status_cp = _run(["zpool", "status", "-PLv", pool_name])

        if status_cp.returncode != 0 and pool_name not in list_summary:
            log(f"Error getting ZFS pool info for {pool_name}: {status_cp.stderr.strip() or 'zpool failed'}", 'error')
            return None

        details = _parse_zpool_status(status_cp.stdout) if status_cp.returncode == 0 else {}
        d = details.get(pool_name, {})
        s = list_summary.get(pool_name, {})
        vdev_tree = d.get("vdev_tree")

        parser_warnings = d.get("parser_warnings", [])
        if vdev_tree and vdev_tree.get("name") != pool_name:
            parser_warnings.append(f"root.name={vdev_tree.get('name')} != pool {pool_name}")

        pool_info = {
            "name": pool_name,
            "health": s.get("health"),
            "summary": s.get("summary"),
            "scan": d.get("scan"),
            "errors": d.get("errors"),
            "vdev_tree": vdev_tree,
            "parser_warnings": parser_warnings,
            "status_raw": status_cp.stdout if status_cp.returncode == 0 else None,
        }

        return pool_info

    except Exception as e:
        log(f"Error fetching ZFS pool info for {pool_name}: {e}", 'error')
        return None

@debug('zfs_storage_health')
def zfs_storage_health():
    """
    Collect health info for all ZFS pools.
    Cached for 60 seconds.
    """
    global _zfs_cache
    now = time.time()

    if now - _zfs_cache["timestamp"] < 60:
        return _zfs_cache["data"]

    if not zfs_available():
        log("ZFS not available", 'error')
        data = []
    else:
        zfs_version = get_zfs_version()

        pools = list_zfs_pools()
        if not pools:
            log("No ZFS pools found", 'error')
            data = []
        else:
            data = [get_zfs_pool_info(pool) for pool in pools]
            data = [d for d in data if d is not None]
            for pool_info in data:
                pool_info["zfs_version"] = zfs_version

    _zfs_cache["timestamp"] = now
    _zfs_cache["data"] = data

    return data
