"""Ceph cluster monitoring collector.

Multi-cluster and list-driven (like the SNMP collector): config provides a list
of clusters, each polled independently and reported keyed by its fsid. The agent
NEVER deduplicates across hosts -- it emits one entry per configured cluster and
the backend arbitrates by fsid (see the backend cluster-scope contract:
plus-complet > arrivee-serveur > plus petit machine_id).

Per cluster, every tick (cached per (cluster, command) for CACHE_TTL):
    ceph status -f json    -> health, mon quorum, osd counts, pg states, fsid
    ceph df -f json        -> raw capacity
    ceph osd tree -f json  -> best-effort per-host OSD count

Auth: a least-privilege cephx keyring (client.fivenines, caps mon 'allow r'
mgr 'allow r'), invoked explicitly with --name/--keyring. No sudo by default.

Reachability and health are reported as DATA (collection.reachable +
health.status), not via the capability gate: a cluster outage must surface as a
red metric, not make the collector vanish for the 5-minute reprobe window.
"""

import json
import shutil
import subprocess

from fivenines_agent.cache import TTLCache
from fivenines_agent.debug import log
from fivenines_agent.subprocess_utils import get_clean_env


CONNECT_TIMEOUT = 5  # seconds, --connect-timeout passed to the ceph CLI
SUBPROCESS_TIMEOUT = 15  # seconds, hard subprocess kill (a wedged mon can hang)
CACHE_TTL = 30  # seconds, per (cluster, command)

_cache = TTLCache()


def ceph_metrics(clusters=None):
    """Poll all configured Ceph clusters.

    Entry point dispatched from COLLECTORS (pass_kwargs=True): the config dict
    {"clusters": [...]} is unpacked, so this receives clusters=[...].

    Returns {"clusters": [<per-cluster dict>, ...]} or None when there is
    nothing to do.
    """
    if not clusters:
        return None
    if not shutil.which("ceph"):
        log("ceph not found in PATH, skipping Ceph collection", "error")
        return None
    return {"clusters": [_poll_cluster(cluster) for cluster in clusters]}


def _poll_cluster(cluster):
    """Poll one cluster and build its contract payload.

    status drives reachability + most metrics. df and osd tree are partial:
    a failure leaves their *_ok False and value None without making the whole
    cluster unreachable.
    """
    name = cluster.get("name", "ceph")
    base = _base_args(cluster)
    result = _empty_result(name)

    status, error = _run_ceph_cached(base, ["status"], name)
    if error:
        result["collection"]["error"] = error
        return result

    result["collection"]["reachable"] = True
    result["collection"]["status_ok"] = True
    _apply_status(result, status)

    df, error = _run_ceph_cached(base, ["df"], name)
    if error:
        log(
            "ceph df failed for cluster {}: {}".format(name, error.get("message")),
            "error",
        )
    else:
        result["collection"]["df_ok"] = True
        result["capacity"] = _parse_capacity(df)

    tree, error = _run_ceph_cached(base, ["osd", "tree"], name)
    if error:
        log(
            "ceph osd tree failed for cluster {}: {}".format(
                name, error.get("message")
            ),
            "error",
        )
    else:
        result["collection"]["tree_ok"] = True
        result["hosts"] = _parse_host_osd_counts(tree)

    return result


def _empty_result(name):
    return {
        "fsid": None,
        "configured_name": name,
        "collection": {
            "reachable": False,
            "status_ok": False,
            "df_ok": False,
            "tree_ok": False,
            "error": None,
        },
        "health": None,
        "mon": None,
        "osd": None,
        "pg": None,
        "capacity": None,
        "hosts": None,
    }


def _base_args(cluster):
    """Build the shared CLI args for auth/connection for one cluster."""
    args = ["--connect-timeout", str(CONNECT_TIMEOUT)]
    name = cluster.get("name", "ceph")
    if name and name != "ceph":
        args += ["--cluster", name]
    conf = cluster.get("conf")
    if conf:
        args += ["-c", conf]
    cid = cluster.get("id", "fivenines")
    args += ["--name", "client.{}".format(cid)]
    keyring = cluster.get("keyring")
    if keyring:
        args += ["--keyring", keyring]
    # use_sudo is reserved by the contract for a future restricted-wrapper
    # fallback; v1 is keyring-only. Surface intent rather than silently ignore.
    if cluster.get("use_sudo"):
        log(
            "ceph use_sudo is not supported yet; using keyring auth for {}".format(
                name
            ),
            "info",
        )
    return args


def _run_ceph_cached(base, cmd, name):
    key = (name, tuple(cmd))
    return _cache.get_or_compute(key, CACHE_TTL, lambda: _run_ceph(base, cmd, name))


def _run_ceph(base, cmd, name):
    """Run one `ceph ... -f json` subcommand.

    Returns (parsed_json, None) on success or (None, error_dict) on failure.
    Never raises -- a failure becomes an error dict the caller records.
    """
    full = ["ceph"] + base + cmd + ["-f", "json"]
    try:
        proc = subprocess.run(
            full,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            env=get_clean_env(),
        )
    except subprocess.TimeoutExpired:
        log("ceph {} timed out for cluster {}".format(" ".join(cmd), name), "error")
        return None, {
            "type": "timeout",
            "message": "timed out after {}s".format(SUBPROCESS_TIMEOUT),
        }
    except Exception as e:
        return None, {"type": "unknown", "message": str(e)}

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        return None, {"type": _classify_error(stderr), "message": stderr[:500]}

    try:
        return json.loads(proc.stdout), None
    except (ValueError, TypeError) as e:
        return None, {"type": "parse_error", "message": str(e)}


def _classify_error(stderr):
    low = stderr.lower()
    if "auth" in low or "permission denied" in low or "access denied" in low:
        return "auth_error"
    if (
        "connect" in low
        or "unreachable" in low
        or "no mon" in low
        or "timed out" in low
    ):
        return "unreachable"
    return "ceph_error"


def _apply_status(result, status):
    result["fsid"] = status.get("fsid")
    result["health"] = _parse_health(status)
    result["mon"] = _parse_mon(status)
    result["osd"] = _parse_osd(status)
    result["pg"] = _parse_pg(status)


def _parse_health(status):
    """Health is {status, checks} on Luminous+ and a plain string before it."""
    health = status.get("health")
    if isinstance(health, dict):
        checks = health.get("checks")
        names = list(checks.keys()) if isinstance(checks, dict) else []
        return {"status": health.get("status"), "checks": names}
    if isinstance(health, str):
        return {"status": health, "checks": []}
    overall = status.get("overall_status")
    if isinstance(overall, str):
        return {"status": overall, "checks": []}
    return {"status": "UNKNOWN", "checks": []}


def _parse_mon(status):
    quorum = status.get("quorum")
    monmap = status.get("monmap") or {}
    mons = monmap.get("mons")
    total = len(mons) if isinstance(mons, list) else monmap.get("num_mons")
    in_quorum = len(quorum) if isinstance(quorum, list) else None
    return {"in_quorum": in_quorum, "total": total}


def _parse_osd(status):
    osdmap = status.get("osdmap") or {}
    # Older releases double-nest under osdmap.osdmap; newer flatten it.
    nested = osdmap.get("osdmap")
    inner = nested if isinstance(nested, dict) else osdmap
    return {
        "up": inner.get("num_up_osds"),
        "in": inner.get("num_in_osds"),
        "total": inner.get("num_osds"),
    }


def _parse_pg(status):
    """Bucket PGs by substring over state_name. Compound states (e.g.
    active+undersized+degraded) count in every matching bucket -- overlap is
    expected. inactive == any PG whose state does not contain "active".
    """
    pgmap = status.get("pgmap") or {}
    by_state = pgmap.get("pgs_by_state")
    degraded = inactive = undersized = 0
    if isinstance(by_state, list):
        for entry in by_state:
            name = (entry.get("state_name") or "").lower()
            count = entry.get("count") or 0
            if "degraded" in name:
                degraded += count
            if "undersized" in name:
                undersized += count
            if "active" not in name:
                inactive += count
    return {
        "total": pgmap.get("num_pgs"),
        "degraded": degraded,
        "inactive": inactive,
        "undersized": undersized,
    }


def _parse_capacity(df):
    stats = df.get("stats") or {}
    used = stats.get("total_used_bytes")
    if used is None:
        used = stats.get("total_used_raw_bytes")
    return {
        "total_bytes": stats.get("total_bytes"),
        "used_bytes": used,
        "avail_bytes": stats.get("total_avail_bytes"),
    }


def _parse_host_osd_counts(tree):
    """Best-effort per-host OSD count from the CRUSH tree.

    Counts the children of each type=="host" bucket. Custom topologies without
    host buckets yield a partial/empty list -- never a hard source of truth.
    """
    nodes = tree.get("nodes")
    if not isinstance(nodes, list):
        return []
    hosts = []
    for node in nodes:
        if node.get("type") == "host":
            children = node.get("children")
            count = len(children) if isinstance(children, list) else 0
            hosts.append({"host": node.get("name"), "osd_count": count})
    return hosts
