"""Declarative collector registry for metric dispatch."""

import time

from fivenines_agent.apache import apache_metrics
from fivenines_agent.caddy import caddy_metrics
from fivenines_agent.ceph import ceph_metrics
from fivenines_agent.cpu import cpu_count, cpu_data, cpu_model, cpu_usage
from fivenines_agent.debug import log, start_log_capture, stop_log_capture
from fivenines_agent.disk_health_windows import disk_health_windows
from fivenines_agent.docker import docker_metrics
from fivenines_agent.fail2ban import fail2ban_metrics
from fivenines_agent.fans import fans
from fivenines_agent.gpu import gpu_metrics
from fivenines_agent.haproxy import haproxy_metrics
from fivenines_agent.io import io
from fivenines_agent.logs import collect_log_signals
from fivenines_agent.memcached import memcached_metrics
from fivenines_agent.memory import memory, swap
from fivenines_agent.mysql import mysql_metrics
from fivenines_agent.network import network
from fivenines_agent.nginx import nginx_metrics
from fivenines_agent.partitions import partitions_metadata, partitions_usage
from fivenines_agent.php_fpm import php_fpm_metrics
from fivenines_agent.ports import listening_ports
from fivenines_agent.postgresql import postgresql_metrics
from fivenines_agent.processes import processes
from fivenines_agent.proxmox import proxmox_metrics
from fivenines_agent.qemu import qemu_metrics
from fivenines_agent.rabbitmq import rabbitmq_metrics
from fivenines_agent.raid_storage import raid_storage_health
from fivenines_agent.redis import redis_metrics
from fivenines_agent.sglang import sglang_metrics
from fivenines_agent.smart_storage import (
    smart_storage_health,
    smart_storage_identification,
)
from fivenines_agent.systemd import systemd_metrics
from fivenines_agent.tailscale import tailscale_metrics
from fivenines_agent.temperatures import temperatures
from fivenines_agent.tsdb import tsdb_metrics
from fivenines_agent.vllm import vllm_metrics
from fivenines_agent.wireguard import wireguard_metrics
from fivenines_agent.zfs import zfs_storage_health

# Registry of metric collectors.
# Each entry: (config_key, [(data_key, callable, pass_kwargs), ...])
#
# pass_kwargs=True means the config value (a dict) is unpacked as **kwargs
# to the callable. pass_kwargs=False means the callable takes no arguments.
COLLECTORS = [
    (
        "cpu",
        [
            ("cpu", cpu_data, False),
            ("cpu_usage", cpu_usage, False),
            ("cpu_model", cpu_model, False),
            ("cpu_count", cpu_count, False),
        ],
    ),
    (
        "memory",
        [
            ("memory", memory, False),
            ("swap", swap, False),
        ],
    ),
    ("network", [("network", network, False)]),
    (
        "partitions",
        [
            ("partitions_metadata", partitions_metadata, False),
            ("partitions_usage", partitions_usage, False),
        ],
    ),
    ("io", [("io", io, False)]),
    # Brique C log signals: per-unit error/warn rate + fingerprints. pass_kwargs
    # unpacks the logs config (units allowlist, signal_interval_s) as **kwargs.
    ("logs", [("logs", collect_log_signals, True)]),
    (
        "smart_storage_health",
        [
            ("smart_storage_identification", smart_storage_identification, False),
            ("smart_storage_health", smart_storage_health, False),
        ],
    ),
    ("raid_storage_health", [("raid_storage_health", raid_storage_health, False)]),
    # Ceph: list-driven multi-cluster. config["ceph"] == {"clusters": [...]} is
    # unpacked (pass_kwargs) into ceph_metrics(clusters=[...]).
    ("ceph", [("ceph", ceph_metrics, True)]),
    # ZFS: host-local pool health (generic, not Proxmox-scoped). config["zfs"]
    # may be True (defaults) or {"interval": N}, unpacked into
    # zfs_storage_health(interval=N). Gated on the "zfs" capability.
    ("zfs", [("zfs", zfs_storage_health, True)]),
    ("processes", [("processes", processes, False)]),
    ("ports", [("ports", listening_ports, True)]),
    ("temperatures", [("temperatures", temperatures, False)]),
    ("fans", [("fans", fans, False)]),
    ("nvidia_gpu", [("nvidia_gpu", gpu_metrics, False)]),
    ("redis", [("redis", redis_metrics, True)]),
    # Memcached: config-driven single `stats` scrape over TCP (nginx/caddy
    # posture, no capability gate). config["memcached"] == {"host":..,"port":..}
    # is unpacked (pass_kwargs) into memcached_metrics(host=.., port=..). Emits a
    # flat snapshot dict, or None (collection failure). `false` disables it.
    ("memcached", [("memcached", memcached_metrics, True)]),
    ("nginx", [("nginx", nginx_metrics, True)]),
    ("apache", [("apache", apache_metrics, True)]),
    # PHP-FPM: config-driven per-pool status scrape (nginx/apache posture, no
    # capability gate). config["php_fpm"] == {"status_page_url": ...} is unpacked
    # (pass_kwargs) into php_fpm_metrics(status_page_url=...). Emits an array of
    # per-pool objects, [] (zero pools), or None (collection failure).
    ("php_fpm", [("php_fpm", php_fpm_metrics, True)]),
    # HAProxy: config-driven stats scrape (nginx/apache posture, no capability
    # gate). config["haproxy"] == {"stats_socket": ..., "stats_url": ...,
    # "username": ..., "password": ...} is unpacked (pass_kwargs) into
    # haproxy_metrics(**config). Emits a list of frontend/backend/server rows,
    # the capped wrapper {"rows": [...], "servers_capped": True}, [] (zero
    # proxies), or None (collection failure).
    ("haproxy", [("haproxy", haproxy_metrics, True)]),
    ("docker", [("docker", docker_metrics, True)]),
    ("qemu", [("qemu", qemu_metrics, True)]),
    ("fail2ban", [("fail2ban", fail2ban_metrics, False)]),
    ("caddy", [("caddy", caddy_metrics, True)]),
    # TSDB (Prometheus / VictoriaMetrics) server health: config-driven HTTP
    # scrape, no capability gate (nginx/apache posture). config["tsdb"] is
    # unpacked (pass_kwargs) into tsdb_metrics(url=..., ...). Emits a
    # reachability envelope -- NEVER None -- so the server distinguishes "TSDB
    # unreachable" (the signal) from "collector disabled".
    ("tsdb", [("tsdb", tsdb_metrics, True)]),
    # vLLM inference serving health (server #887): config-driven HTTP scrape of
    # the vLLM server's native Prometheus endpoint, no capability gate (the
    # tsdb/nginx posture). config["vllm"] == {metrics_url, auth_header_name,
    # auth_header_value, verify_ssl} is unpacked (pass_kwargs) into
    # vllm_metrics(...). Emits a reachability envelope -- NEVER None -- so the
    # server distinguishes "vLLM crashed" (the signal, and the whole point:
    # every GPU still reads green) from "collector disabled".
    ("vllm", [("vllm", vllm_metrics, True)]),
    # SGLang inference serving health (server #893): the vLLM sibling, same
    # config-driven HTTP scrape and same never-None reachability envelope,
    # sharing every helper via inference_metrics.py. config["sglang"] ==
    # {metrics_url, auth_header_name, auth_header_value, verify_ssl} is
    # unpacked (pass_kwargs) into sglang_metrics(...). Note that SGLang only
    # publishes sglang:* samples when launched with --enable-metrics, so a
    # reachable tick carrying models: [] is the expected stock-launch state,
    # never an outage.
    ("sglang", [("sglang", sglang_metrics, True)]),
    ("postgresql", [("postgresql", postgresql_metrics, True)]),
    ("mysql", [("mysql", mysql_metrics, True)]),
    # RabbitMQ: config-driven management-API poll (nginx/apache/postgresql
    # posture, no capability gate). config["rabbitmq"] == {url, username,
    # password, vhost, include_queues} is unpacked (pass_kwargs) into
    # rabbitmq_metrics(...). Emits a reachability envelope: reachable:true with
    # node health + a bounded queues array + queues_total, or reachable:false
    # (a dead broker / partial listing) so the server never prunes queue rows.
    ("rabbitmq", [("rabbitmq", rabbitmq_metrics, True)]),
    ("proxmox", [("proxmox", proxmox_metrics, True)]),
    # WireGuard peer health (#508). config["wireguard"] is a TOP-LEVEL plain
    # boolean and the collector takes no parameters, so pass_kwargs is False --
    # a future dict value is then ignored rather than splatted into a
    # TypeError. LINUX-ONLY: the key is in the server's
    # Host::WINDOWS_OMIT_CONFIG_KEYS and is stripped for Windows agents; on any
    # host without `wg` the collector reports null anyway. There IS a
    # "wireguard" capability (sudo wg show all dump, #144), but it deliberately
    # does NOT gate this entry -- see CAPABILITY_GATE_EXEMPT below: a privilege
    # failure must surface as data["wireguard"] = null (collection failure),
    # not as a skipped key.
    ("wireguard", [("wireguard", wireguard_metrics, False)]),
    # Tailscale node + tailnet rollups (#508). Same top-level plain-boolean
    # config posture as "wireguard", but CROSS-OS -- never stripped, since
    # `tailscale status --json` is identical on Linux/Windows/macOS.
    ("tailscale", [("tailscale", tailscale_metrics, False)]),
    ("systemd", [("systemd", systemd_metrics, True)]),
    # Windows-only: gated by the disk_health capability, only present in the
    # Windows-tailored capability set (D13 - permissions._build_windows_*).
    ("disk_health", [("disk_health", disk_health_windows, False)]),
]


# Some config keys do not exactly match the capability key produced by the
# permission probe. Override here for those cases. Keys absent from this
# mapping fall back to the config key itself as the capability key.
CAPABILITY_KEY_OVERRIDES = {
    "smart_storage_health": "smart_storage",
    "raid_storage_health": "raid_storage",
    # Log signals are gated by journald read access, probed via `journalctl -n 0`
    # in permissions.py (_can_read_journal). Hosts where the cap is absent (non
    # systemd, or no group) are simply not gated on it.
    "logs": "journald",
}

# Config keys whose capability is INFORMATIONAL ONLY: probed, banner-listed and
# reported as pending, but never used to skip collection.
#
# wireguard is here because its contract is that a privilege failure surfaces
# as data["wireguard"] = null -- a collection failure the server skips -- and
# NOT as a missing key (tests/fixtures/vpn_contract_payload.json: an enabled
# collector always contributes its key). The collector re-reads the privilege
# itself on every tick and reports the honest failure with its real reason; the
# 5-minute probe exists only so the dashboard can name the missing sudoers rule
# (#144). Gating on it would let a stale or transient probe result -- a sudo
# spawn that lost a 5s race under load -- drop the key entirely on a host whose
# tunnels are fine.
CAPABILITY_GATE_EXEMPT = frozenset({"wireguard"})

# Tracks (config_key, capability_value) pairs that have already been logged
# as skipped this process, to avoid per-tick log spam.
_logged_capability_skips = set()

# Same, for gate-exempt collectors reported as null without being run.
_logged_capability_nulls = set()


def _capability_key_for(config_key):
    return CAPABILITY_KEY_OVERRIDES.get(config_key, config_key)


def _is_capability_gated(config_key, permissions):
    """Return True if collection should be skipped due to a False capability."""
    if not permissions:
        return False
    if config_key in CAPABILITY_GATE_EXEMPT:
        return False
    cap_key = _capability_key_for(config_key)
    if cap_key not in permissions:
        return False
    return not permissions[cap_key]


def _gate_exempt_null(config_key, permissions):
    """True when a gate-exempt collector's capability is already known False.

    A gate-exempt collector must always contribute its key, so it cannot be
    skipped the way a gated one is -- but RUNNING it on a host whose capability
    the probe has already read as False buys nothing. The WireGuard collector
    would spawn `sudo -n` every tick just to be refused, and each refusal
    writes a sudo authentication failure to the auth log: ~1440/day, which is a
    standard fail2ban/Wazuh/OSSEC alert signature, on exactly the VPN gateways
    this collector exists for (and on Debian defaults it can mail root too).

    So: emit the null the contract requires, skip the spawn. Nothing about the
    payload changes -- the key is present and null either way, which is the
    whole point of CAPABILITY_GATE_EXEMPT. The probe keeps re-checking on its
    own backoff ladder, so a newly-granted sudoers rule is picked up within
    ~2 minutes without the collector hammering sudo in the meantime.
    """
    if not permissions or config_key not in CAPABILITY_GATE_EXEMPT:
        return False
    cap_key = _capability_key_for(config_key)
    return cap_key in permissions and not permissions[cap_key]


def _log_capability_null_once(config_key):
    if config_key in _logged_capability_nulls:
        return
    _logged_capability_nulls.add(config_key)
    log(
        f"Reporting '{config_key}' as null: capability unavailable "
        "(not spawning the privileged command until the probe says otherwise)",
        "info",
    )


def _log_capability_skip_once(config_key):
    if config_key in _logged_capability_skips:
        return
    _logged_capability_skips.add(config_key)
    log(f"Skipping '{config_key}' collection: capability unavailable", "info")


def _collect_with_telemetry(name, fn, telemetry, *args, **kwargs):
    """Wrap a collector call with timing and log capture for telemetry.

    When *telemetry* is None, runs the collector without capture/timing.
    """
    start = time.monotonic()
    capture = telemetry is not None
    if capture:
        start_log_capture()
    try:
        result = fn(*args, **kwargs)
    except Exception as e:
        if capture:
            errors = stop_log_capture()
            errors.append(str(e))
            duration_ms = round((time.monotonic() - start) * 1000, 2)
            telemetry[name] = {"duration_ms": duration_ms, "errors": errors}
        log(f"Error collecting {name}: {e}", "error")
        return None

    if capture:
        duration_ms = round((time.monotonic() - start) * 1000, 2)
        errors = stop_log_capture()
        entry = {"duration_ms": duration_ms}
        if errors:
            entry["errors"] = errors
        telemetry[name] = entry
    return result


def collect_metrics(config, data, telemetry=None, permissions=None):
    """Run all registered collectors based on config flags.

    Mutates *data* in place, adding one key per collected metric.
    When *telemetry* is not None, each collector is wrapped with timing
    and log capture. When *permissions* is provided, collectors whose
    matching capability is False are skipped (logged once per process).
    """
    for config_key, collectors in COLLECTORS:
        config_value = config.get(config_key)
        if not config_value:
            continue
        if _is_capability_gated(config_key, permissions):
            _log_capability_skip_once(config_key)
            continue
        if _gate_exempt_null(config_key, permissions):
            # The key must still travel (see CAPABILITY_GATE_EXEMPT); only the
            # doomed privileged spawn is skipped.
            _log_capability_null_once(config_key)
            for data_key, _fn, _pass_kwargs in collectors:
                data[data_key] = None
            continue
        for data_key, fn, pass_kwargs in collectors:
            if pass_kwargs and isinstance(config_value, dict):
                kw = config_value
            else:
                kw = {}
            data[data_key] = _collect_with_telemetry(data_key, fn, telemetry, **kw)
