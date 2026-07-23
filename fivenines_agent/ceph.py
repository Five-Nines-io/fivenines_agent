"""Ceph cluster monitoring collector.

Multi-cluster and list-driven (like the SNMP collector): config provides a list
of clusters, each polled independently and reported keyed by its fsid. The agent
NEVER deduplicates across hosts -- it emits one entry per configured cluster and
the backend arbitrates by fsid (see the backend cluster-scope contract:
plus-complet > arrivee-serveur > plus petit machine_id).

Per cluster, every tick (cached per (cluster, command) for CACHE_TTL):
    ceph status -f json    -> health, mon quorum, osd counts, pg states, fsid,
                              client io, recovery/rebalance progress, nearfull/full
    ceph df -f json        -> raw capacity + per-pool usage
    ceph osd tree -f json  -> best-effort per-host OSD count
    ceph osd perf -f json  -> per-OSD commit/apply latency
    ceph osd df -f json    -> per-OSD fullness (bytes + utilization)

The status/df surfaces above the "raw capacity" line are the v1 (1.9.0) shape;
io/recovery/osd_fullness/pools + the two per-OSD commands are the v2 (1.13.0)
extension. Every v2 field is additive and independently isolated: a new command
failing leaves its *_ok flag False and value None without touching the core
sections, and the server presence-guards every key so an older agent (which
omits them entirely) keeps ingesting bit-identically.

Auth: a least-privilege cephx keyring (client.fivenines, caps mon 'allow r'
mgr 'allow r'), invoked explicitly with --name/--keyring. No sudo by default.

Reachability and health are reported as DATA (collection.reachable +
health.status), not via the capability gate: a cluster outage must surface as a
red metric, not make the collector vanish for the 5-minute reprobe window.
"""

import json
import re
import shutil
import subprocess

from fivenines_agent.cache import TTLCache
from fivenines_agent.debug import log
from fivenines_agent.subprocess_utils import get_clean_env


CONNECT_TIMEOUT = 5  # seconds, --connect-timeout passed to the ceph CLI
SUBPROCESS_TIMEOUT = 15  # seconds, hard subprocess kill (a wedged mon can hang)
CACHE_TTL = 30  # seconds, per (cluster, command)

# Per-cluster emission caps. pools is small in practice; the per-OSD arrays can
# be large on a big cluster, so they are capped harder. A hit sets the matching
# *_truncated flag so the server can skip that section (honesty over partial
# data) rather than ingest a silently-clipped list.
POOLS_CAP = 200
OSD_CAP = 2048

# Leading integer of a health-check summary message ("3 nearfull osd(s)" -> 3).
# ASCII [0-9] (not \d) so a Unicode digit in an odd locale cannot slip through
# the codebase's ASCII-only rule.
_LEADING_INT = re.compile(r"\s*([0-9]+)")

_cache = TTLCache()


def ceph_metrics(clusters=None, **_):
    """Poll all configured Ceph clusters.

    Entry point dispatched from COLLECTORS (pass_kwargs=True): the config dict
    {"clusters": [...]} is unpacked, so this receives clusters=[...]. **_ absorbs
    any future top-level config key so a forward-compatible backend addition
    cannot crash (and blank) the whole collector on an older agent.

    Returns {"clusters": [<per-cluster dict>, ...]} or None when there is
    nothing to do.
    """
    if not clusters:
        return None
    if not shutil.which("ceph"):
        log("ceph not found in PATH, skipping Ceph collection", "error")
        return None

    # Per-cluster isolation: one malformed entry or one unexpected field type
    # must not blank every other cluster. The registry try/except wraps the
    # whole collector, so without this loop a single raise would lose all
    # clusters for the tick. Each cluster degrades to an error result instead.
    # NOTE (v1.5): clusters are polled serially; a wedged mon costs up to
    # SUBPROCESS_TIMEOUT per command. For many-cluster hosts, mirror snmp.py's
    # ThreadPoolExecutor. Single/few-cluster hosts (the common case) are fine.
    results = []
    for cluster in clusters:
        if not isinstance(cluster, dict):
            log("ceph: ignoring non-dict cluster config: {!r}".format(cluster), "error")
            continue
        try:
            results.append(_poll_cluster(cluster))
        except Exception as e:
            name = cluster.get("name") or "ceph"
            log("ceph: unexpected error polling cluster {}: {}".format(name, e), "error")
            result = _empty_result(name)
            result["collection"]["error"] = {"type": "unknown", "message": str(e)}
            results.append(result)
    return {"clusters": results}


def _poll_cluster(cluster):
    """Poll one cluster and build its contract payload.

    status drives reachability + most metrics (health, mon, osd, pg, io,
    recovery, osd_fullness). df, osd tree, osd perf and osd df are each partial
    and independently isolated: a failure leaves that command's *_ok flag False
    and its value None without making the whole cluster unreachable.
    """
    name = cluster.get("name") or "ceph"
    base = _base_args(cluster)
    result = _empty_result(name)

    status, error = _run_ceph_cached(base, ["status"], name)
    if error:
        # fsid stays None here: an unreachable/auth-broken cluster cannot report
        # its own fsid. The result still carries configured_name, and the host
        # carries machine_id, so the backend attributes the error at the host
        # level keyed by (machine_id, configured_name) rather than by fsid (see
        # the cluster-scope contract). fsid-keying applies only to reachable
        # clusters whose status succeeded.
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
        result["pools"], result["pools_truncated"] = _parse_pools(df)

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

    perf, error = _run_ceph_cached(base, ["osd", "perf"], name)
    if error:
        log(
            "ceph osd perf failed for cluster {}: {}".format(
                name, error.get("message")
            ),
            "error",
        )
    else:
        result["collection"]["perf_ok"] = True
        result["osd_perf"], result["osd_perf_truncated"] = _parse_osd_perf(perf)

    osd_df, error = _run_ceph_cached(base, ["osd", "df"], name)
    if error:
        log(
            "ceph osd df failed for cluster {}: {}".format(
                name, error.get("message")
            ),
            "error",
        )
    else:
        result["collection"]["osd_df_ok"] = True
        result["osd_df"], result["osd_df_truncated"] = _parse_osd_df(osd_df)

    return result


def _empty_result(name):
    # Every value here is the "not collected" default. A reachable cluster
    # overwrites the sections whose command succeeded; the *_truncated flags stay
    # False until a real cap hit sets them (an omitted section is never
    # "truncated"). An unreachable cluster returns this dict verbatim (fsid None,
    # all metrics None) -- the new v2 keys are additive nulls the server
    # presence-guards, so the unreachable payload stays semantically "as-is".
    return {
        "fsid": None,
        "configured_name": name,
        "collection": {
            "reachable": False,
            "status_ok": False,
            "df_ok": False,
            "tree_ok": False,
            "perf_ok": False,
            "osd_df_ok": False,
            "error": None,
        },
        "health": None,
        "mon": None,
        "osd": None,
        "pg": None,
        "io": None,
        "recovery": None,
        "osd_fullness": None,
        "capacity": None,
        "pools": None,
        "pools_truncated": False,
        "osd_perf": None,
        "osd_perf_truncated": False,
        "osd_df": None,
        "osd_df_truncated": False,
        "hosts": None,
    }


def _base_args(cluster):
    """Build the shared CLI args for auth/connection for one cluster.

    Trust model: cluster config (name/conf/keyring/id) comes from the fivenines
    backend, the same trusted control plane that supplies snmp communities and
    redis/postgres credentials. Values go into an argv LIST (no shell), so there
    is no shell injection, and we do not allowlist paths (inconsistent with
    every other collector's trust of backend config). Each value is coerced to
    str so a mis-typed (non-string, even non-hashable) config field cannot crash
    the subprocess call or the cache key -- it degrades to a clean CLI error
    contained by the per-cluster guard in ceph_metrics.
    """
    args = ["--connect-timeout", str(CONNECT_TIMEOUT)]
    name = cluster.get("name") or "ceph"
    if name != "ceph":
        args += ["--cluster", str(name)]
    conf = cluster.get("conf")
    if conf:
        args += ["-c", str(conf)]
    cid = cluster.get("id") or "fivenines"
    args += ["--name", "client.{}".format(cid)]
    keyring = cluster.get("keyring")
    if keyring:
        args += ["--keyring", str(keyring)]
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
    # Cache successes only (store_if): caching an error would keep reporting a
    # stale failure for the whole TTL after the cluster recovers. A persistently
    # down cluster is re-tried every tick, which is what we want -- the
    # subprocess timeout bounds the cost.
    #
    # Key on the connection identity (base carries conf/keyring/id/--cluster),
    # NOT just name: two clusters that share a name -- or both omit it and
    # default to "ceph" -- but point at different clusters must not collide and
    # serve each other's cached status/fsid. base also changes when the backend
    # re-points a cluster's conf/keyring/id, so a config change invalidates the
    # entry instead of serving stale data for the TTL.
    key = (tuple(base), tuple(cmd))
    return _cache.get_or_compute(
        key,
        CACHE_TTL,
        lambda: _run_ceph(base, cmd, name),
        store_if=lambda result: result[1] is None,
    )


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
        parsed = json.loads(proc.stdout)
    except (ValueError, TypeError) as e:
        return None, {"type": "parse_error", "message": str(e)}
    # json.loads accepts any valid JSON; a returncode-0 command that emits
    # null / a list / a scalar would otherwise pass as "success" and crash the
    # parsers' top-level .get(). Treat non-object output as a parse error so a
    # responding-but-odd command degrades cleanly instead of blanking the
    # cluster as an "unknown" error.
    if not isinstance(parsed, dict):
        return None, {
            "type": "parse_error",
            "message": "expected JSON object, got {}".format(type(parsed).__name__),
        }
    return parsed, None


def _classify_error(stderr):
    low = stderr.lower()
    # Connectivity first: a mon-hunting "authenticate timed out" is an outage,
    # not a keyring problem, and must not be swallowed by an "auth" match.
    if (
        "connect" in low
        or "unreachable" in low
        or "no mon" in low
        or "timed out" in low
        or "timeout" in low
    ):
        return "unreachable"
    if (
        "permission" in low
        or "access denied" in low
        or "eacces" in low
        or "errno 13" in low
        or "authentication error" in low
    ):
        return "auth_error"
    return "ceph_error"


def _apply_status(result, status):
    result["fsid"] = status.get("fsid")
    result["health"] = _parse_health(status)
    result["mon"] = _parse_mon(status)
    result["osd"] = _parse_osd(status)
    result["pg"] = _parse_pg(status)
    # io/recovery/osd_fullness ride the status call that already succeeded, so
    # they are set unconditionally here (no separate *_ok flag): if status_ok is
    # True the server can trust all three objects exist.
    result["io"] = _parse_io(status)
    result["recovery"] = _parse_recovery(status)
    result["osd_fullness"] = _parse_osd_fullness(status)


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
    monmap = status.get("monmap")
    if not isinstance(monmap, dict):
        monmap = {}
    mons = monmap.get("mons")
    total = len(mons) if isinstance(mons, list) else monmap.get("num_mons")
    in_quorum = len(quorum) if isinstance(quorum, list) else None
    return {"in_quorum": in_quorum, "total": total}


def _parse_osd(status):
    osdmap = status.get("osdmap")
    if not isinstance(osdmap, dict):
        osdmap = {}
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
    pgmap = status.get("pgmap")
    if not isinstance(pgmap, dict):
        pgmap = {}
    by_state = pgmap.get("pgs_by_state")
    degraded = inactive = undersized = 0
    if isinstance(by_state, list):
        for entry in by_state:
            if not isinstance(entry, dict):
                continue
            state_name = entry.get("state_name")
            name = state_name.lower() if isinstance(state_name, str) else ""
            count = entry.get("count")
            # bool is an int subclass; reject it so a JSON boolean count
            # is not silently added as 0/1.
            if not isinstance(count, int) or isinstance(count, bool):
                count = 0
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


def _num_or_zero(value):
    """Numeric passthrough with absent/malformed -> 0.

    pgmap io/recovery keys are omitted by the mgr when a cluster is idle -- that
    is a true zero, not missing data, so a missing (None) or non-numeric value
    normalizes to 0. bool is an int subclass; reject it so a stray JSON boolean
    is not forwarded as 0/1.
    """
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return value
    return 0


def _parse_io(status):
    """Client I/O throughput/IOPS from pgmap (absent keys -> 0).

    Emitted whenever status succeeded (the caller only reaches this after
    status_ok), so an idle cluster reports an all-zeros object rather than a
    null -- the server can graph a flat line instead of a gap.
    """
    pgmap = status.get("pgmap")
    if not isinstance(pgmap, dict):
        pgmap = {}
    return {
        "read_bytes_sec": _num_or_zero(pgmap.get("read_bytes_sec")),
        "write_bytes_sec": _num_or_zero(pgmap.get("write_bytes_sec")),
        "read_op_per_sec": _num_or_zero(pgmap.get("read_op_per_sec")),
        "write_op_per_sec": _num_or_zero(pgmap.get("write_op_per_sec")),
    }


def _parse_recovery(status):
    """Recovery/rebalance progress from pgmap (absent keys -> 0, same as io)."""
    pgmap = status.get("pgmap")
    if not isinstance(pgmap, dict):
        pgmap = {}
    return {
        "recovering_objects_per_sec": _num_or_zero(
            pgmap.get("recovering_objects_per_sec")
        ),
        "recovering_bytes_per_sec": _num_or_zero(
            pgmap.get("recovering_bytes_per_sec")
        ),
        "misplaced_objects": _num_or_zero(pgmap.get("misplaced_objects")),
        "misplaced_total": _num_or_zero(pgmap.get("misplaced_total")),
        "degraded_objects": _num_or_zero(pgmap.get("degraded_objects")),
        "degraded_total": _num_or_zero(pgmap.get("degraded_total")),
    }


def _parse_osd_fullness(status):
    """nearfull/full OSD counts from the OSD_NEARFULL / OSD_FULL health checks.

    A count of None means "unknown" -- the check was unparseable, so the server
    emits no sample rather than a fabricated 0 (see _extract_fullness_count).
    """
    health = status.get("health")
    checks = health.get("checks") if isinstance(health, dict) else None
    if not isinstance(checks, dict):
        checks = {}
    return {
        "nearfull": _extract_fullness_count(checks.get("OSD_NEARFULL")),
        "full": _extract_fullness_count(checks.get("OSD_FULL")),
    }


def _extract_fullness_count(check):
    """Pull an OSD count out of one health check, else None.

    Prefer summary.count (added in later releases); fall back to the leading
    integer of summary.message ("3 nearfull osd(s)") for older mons that only
    carry the human string. Anything we cannot turn into an integer -- an absent
    check, a non-dict summary, an unparseable message -- is None ("unknown"),
    NEVER a fabricated 0: the health-check counts drive alerting, so a wrong 0
    would silence a real nearfull/full condition.
    """
    if not isinstance(check, dict):
        return None
    summary = check.get("summary")
    if not isinstance(summary, dict):
        return None
    count = summary.get("count")
    if isinstance(count, int) and not isinstance(count, bool):
        return count
    message = summary.get("message")
    if isinstance(message, str):
        return _leading_int(message)
    return None


def _leading_int(message):
    match = _LEADING_INT.match(message)
    return int(match.group(1)) if match else None


def _parse_capacity(df):
    stats = df.get("stats")
    if not isinstance(stats, dict):
        stats = {}
    used = stats.get("total_used_bytes")
    if used is None:
        used = stats.get("total_used_raw_bytes")
    return {
        "total_bytes": stats.get("total_bytes"),
        "used_bytes": used,
        "avail_bytes": stats.get("total_avail_bytes"),
    }


def _parse_pools(df):
    """Per-pool usage from `ceph df`. Returns (pools, truncated).

    percent_used is forwarded verbatim as the 0-1 float ceph reports (the server
    converts for display). Capped at POOLS_CAP: the flag is set from the raw
    input length so it is honest even if some entries are skipped as non-dicts.
    """
    pools = df.get("pools")
    if not isinstance(pools, list):
        return [], False
    truncated = len(pools) > POOLS_CAP
    result = []
    for pool in pools[:POOLS_CAP]:
        if not isinstance(pool, dict):
            continue
        stats = pool.get("stats")
        if not isinstance(stats, dict):
            stats = {}
        result.append(
            {
                "name": pool.get("name"),
                "id": pool.get("id"),
                "stored_bytes": stats.get("stored"),
                "objects": stats.get("objects"),
                "percent_used": stats.get("percent_used"),
                "max_avail_bytes": stats.get("max_avail"),
            }
        )
    return result, truncated


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
        if not isinstance(node, dict):
            continue
        if node.get("type") == "host":
            children = node.get("children")
            count = len(children) if isinstance(children, list) else 0
            hosts.append({"host": node.get("name"), "osd_count": count})
    return hosts


def _kb_to_bytes(value):
    """ceph reports OSD sizes in KiB; the contract is bytes-native. x1024, or
    None when the field is absent/non-numeric (bool rejected as an int subclass).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value * 1024
    return None


def _osd_perf_infos(perf):
    """The per-OSD perf list, tolerant of both JSON shapes.

    Nautilus+ nests it under osdstats.osd_perf_infos; older releases put
    osd_perf_infos at the top level. Return [] when neither is present so the
    caller ships an empty (not null) array on a responding-but-empty cluster.
    """
    osdstats = perf.get("osdstats")
    if isinstance(osdstats, dict):
        infos = osdstats.get("osd_perf_infos")
        if isinstance(infos, list):
            return infos
    infos = perf.get("osd_perf_infos")
    if isinstance(infos, list):
        return infos
    return []


def _parse_osd_perf(perf):
    """Per-OSD commit/apply latency. Returns (osd_perf, truncated).

    Capped at OSD_CAP; the flag is set from the raw list length so the server
    can skip per-OSD emission on a clipped tick rather than ingest partial data.
    """
    infos = _osd_perf_infos(perf)
    truncated = len(infos) > OSD_CAP
    result = []
    for info in infos[:OSD_CAP]:
        if not isinstance(info, dict):
            continue
        stats = info.get("perf_stats")
        if not isinstance(stats, dict):
            stats = {}
        result.append(
            {
                "id": info.get("id"),
                "commit_latency_ms": stats.get("commit_latency_ms"),
                "apply_latency_ms": stats.get("apply_latency_ms"),
            }
        )
    return result, truncated


def _parse_osd_df(osd_df):
    """Per-OSD fullness (bytes + utilization). Returns (osd_df, truncated).

    kb_* fields are converted to bytes (x1024) to stay bytes-native like
    capacity; utilization is forwarded verbatim as the 0-100 float. Capped at
    OSD_CAP with the same honest-flag semantics as _parse_osd_perf.
    """
    nodes = osd_df.get("nodes")
    if not isinstance(nodes, list):
        return [], False
    truncated = len(nodes) > OSD_CAP
    result = []
    for node in nodes[:OSD_CAP]:
        if not isinstance(node, dict):
            continue
        result.append(
            {
                "id": node.get("id"),
                "name": node.get("name"),
                "utilization": node.get("utilization"),
                "total_bytes": _kb_to_bytes(node.get("kb")),
                "used_bytes": _kb_to_bytes(node.get("kb_used")),
                "avail_bytes": _kb_to_bytes(node.get("kb_avail")),
                "status": node.get("status"),
            }
        )
    return result, truncated
