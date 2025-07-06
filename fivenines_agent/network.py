import os
import platform
import psutil
from fivenines_agent.debug import debug

def interfaces(operating_system):
    if operating_system == 'Linux':
        all_interfaces = psutil.net_if_stats()
        working_interfaces = []

        for interface, stats in all_interfaces.items():
            # Skip interfaces that are down
            if not stats.isup:
                continue

            # Skip loopback interfaces
            if interface == 'lo':
                continue

            # Skip interfaces with no address
            try:
                addrs = psutil.net_if_addrs().get(interface, [])
                if not addrs:
                    continue
            except Exception:
                continue

            working_interfaces.append(interface)

        return working_interfaces
    elif operating_system == 'Darwin':
        with os.popen('scutil --nwi | grep "Network interfaces" | cut -d " " -f3') as f:
            return f.read().strip().split('\n')
    else:
        return []

@debug('network')
def network():
    network = []
    network_interfaces = interfaces(platform.system())

    for k, v in psutil.net_io_counters(pernic=True).items():
        if k not in network_interfaces:
            continue
        network.append({ k: v._asdict() })

    return network
