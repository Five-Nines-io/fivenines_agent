"""Declarative collector registry for metric dispatch."""

import time

from fivenines_agent.caddy import caddy_metrics
from fivenines_agent.cpu import cpu_count, cpu_data, cpu_model, cpu_usage
from fivenines_agent.debug import log, start_log_capture, stop_log_capture
from fivenines_agent.docker import docker_metrics
from fivenines_agent.fail2ban import fail2ban_metrics
from fivenines_agent.fans import fans
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
    ("redis", [("redis", redis_metrics, True)]),
    ("nginx", [("nginx", nginx_metrics, True)]),
    ("docker", [("docker", docker_metrics, True)]),
    ("qemu", [("qemu", qemu_metrics, True)]),
    ("fail2ban", [("fail2ban", fail2ban_metrics, False)]),
    ("caddy", [("caddy", caddy_metrics, True)]),
    ("postgresql", [("postgresql", postgresql_metrics, True)]),
    ("proxmox", [("proxmox", proxmox_metrics, True)]),
]


def _collect_with_telemetry(name, fn, telemetry, *args, **kwargs):
    """Wrap a collector call with timing and log capture for telemetry."""
    start = time.monotonic()
    start_log_capture()
    try:
        result = fn(*args, **kwargs)
        duration_ms = round((time.monotonic() - start) * 1000, 2)
        errors = stop_log_capture()
        entry = {"duration_ms": duration_ms}
        if errors:
            entry["errors"] = errors
        telemetry[name] = entry
        return result
    except Exception as e:
        errors = stop_log_capture()
        errors.append(str(e))
        duration_ms = round((time.monotonic() - start) * 1000, 2)
        telemetry[name] = {"duration_ms": duration_ms, "errors": errors}
        log(f"Error collecting {name}: {e}", "error")
        return None


def collect_metrics(config, data, telemetry=None):
    """Run all registered collectors based on config flags.

    Mutates *data* in place, adding one key per collected metric.
    When *telemetry* is not None, each collector is wrapped with timing
    and log capture.
    """
    for config_key, collectors in COLLECTORS:
        config_value = config.get(config_key)
        if not config_value:
            continue
        for data_key, fn, pass_kwargs in collectors:
            if pass_kwargs and isinstance(config_value, dict):
                kw = config_value
            else:
                kw = {}
            if telemetry is not None:
                data[data_key] = _collect_with_telemetry(data_key, fn, telemetry, **kw)
            else:
                if kw:
                    data[data_key] = fn(**kw)
                else:
                    data[data_key] = fn()
