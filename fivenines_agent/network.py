import os

import psutil

from fivenines_agent.debug import debug
from fivenines_agent.env import os_family


def _is_loopback(name):
    """OS-aware loopback interface check.

    Linux uses 'lo'; Windows names loopback interfaces 'Loopback Pseudo-Interface 1'
    (and variants); macOS exposes 'lo0' which is handled via the scutil path.
    """
    return name == 'lo' or name.lower().startswith('loopback')


def interfaces():
    """Return names of UP, non-loopback interfaces that have an address."""
    family = os_family()
    if family in ('linux', 'windows'):
        all_interfaces = psutil.net_if_stats()
        working_interfaces = []

        for interface, stats in all_interfaces.items():
            if not stats.isup:
                continue
            if _is_loopback(interface):
                continue
            try:
                addrs = psutil.net_if_addrs().get(interface, [])
                if not addrs:
                    continue
            except Exception:
                continue

            working_interfaces.append(interface)

        return working_interfaces
    elif family == 'darwin':
        with os.popen('scutil --nwi | grep "Network interfaces" | cut -d " " -f3') as f:
            return f.read().strip().split('\n')
    return []


@debug('network')
def network():
    network = []
    network_interfaces = interfaces()

    for k, v in psutil.net_io_counters(pernic=True).items():
        if k not in network_interfaces:
            continue
        network.append({ k: v._asdict() })

    return network
