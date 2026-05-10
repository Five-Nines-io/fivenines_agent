"""Declarative collector registry for metric dispatch."""

import time

from fivenines_agent.caddy import caddy_metrics
from fivenines_agent.cpu import cpu_count, cpu_data, cpu_model, cpu_usage
from fivenines_agent.debug import log, start_log_capture, stop_log_capture
from fivenines_agent.docker import docker_metrics
from fivenines_agent.fail2ban import fail2ban_metrics
from fivenines_agent.fans import fans
from fivenines_agent.gpu import gpu_metrics
from fivenines_agent.io import io
from fivenines_agent.memory import memory, swap
from fivenines_agent.network import network
from fivenines_agent.nginx import nginx_metrics
from fivenines_agent.partitions import partitions_metadata, partitions_usage
from fivenines_agent.ports import listening_ports
from fivenines_agent.postgresql import postgresql_metrics
from fivenines_agent.processes import processes
from fivenines_agent.proxmox import proxmox_metrics
from fivenines_agent.qemu import qemu_metrics
from fivenines_agent.raid_storage import raid_storage_health
from fivenines_agent.redis import redis_metrics
from fivenines_agent.smart_storage import (
    smart_storage_health,
    smart_storage_identification,
)
from fivenines_agent.systemd import systemd_metrics
from fivenines_agent.temperatures import temperatures


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
    (
        "smart_storage_health",
        [
            ("smart_storage_identification", smart_storage_identification, False),
            ("smart_storage_health", smart_storage_health, False),
        ],
    ),
    ("raid_storage_health", [("raid_storage_health", raid_storage_health, False)]),
    ("processes", [("processes", processes, False)]),
    ("ports", [("ports", listening_ports, True)]),
    ("temperatures", [("temperatures", temperatures, False)]),
    ("fans", [("fans", fans, False)]),
    ("nvidia_gpu", [("nvidia_gpu", gpu_metrics, False)]),
    ("redis", [("redis", redis_metrics, True)]),
    ("nginx", [("nginx", nginx_metrics, True)]),
    ("docker", [("docker", docker_metrics, True)]),
    ("qemu", [("qemu", qemu_metrics, True)]),
    ("fail2ban", [("fail2ban", fail2ban_metrics, False)]),
    ("caddy", [("caddy", caddy_metrics, True)]),
    ("postgresql", [("postgresql", postgresql_metrics, True)]),
    ("proxmox", [("proxmox", proxmox_metrics, True)]),
    ("systemd", [("systemd", systemd_metrics, True)]),
]


# Some config keys do not exactly match the capability key produced by the
# permission probe. Override here for those cases. Keys absent from this
# mapping fall back to the config key itself as the capability key.
CAPABILITY_KEY_OVERRIDES = {
    "smart_storage_health": "smart_storage",
    "raid_storage_health": "raid_storage",
}

# Tracks (config_key, capability_value) pairs that have already been logged
# as skipped this process, to avoid per-tick log spam.
_logged_capability_skips = set()


def _capability_key_for(config_key):
    return CAPABILITY_KEY_OVERRIDES.get(config_key, config_key)


def _is_capability_gated(config_key, permissions):
    """Return True if collection should be skipped due to a False capability."""
    if not permissions:
        return False
    cap_key = _capability_key_for(config_key)
    if cap_key not in permissions:
        return False
    return not permissions[cap_key]


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
        for data_key, fn, pass_kwargs in collectors:
            if pass_kwargs and isinstance(config_value, dict):
                kw = config_value
            else:
                kw = {}
            data[data_key] = _collect_with_telemetry(data_key, fn, telemetry, **kw)
