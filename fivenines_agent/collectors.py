"""Declarative collector registry for metric dispatch."""

from fivenines_agent.caddy import caddy_metrics
from fivenines_agent.cpu import cpu_count, cpu_data, cpu_model, cpu_usage
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


def collect_metrics(config, data):
    """Run all registered collectors based on config flags.

    Mutates *data* in place, adding one key per collected metric.
    """
    for config_key, collectors in COLLECTORS:
        config_value = config.get(config_key)
        if not config_value:
            continue
        for data_key, fn, pass_kwargs in collectors:
            if pass_kwargs and isinstance(config_value, dict):
                data[data_key] = fn(**config_value)
            else:
                data[data_key] = fn()
