import os
import platform
import psutil

def interfaces(operating_system):
    if operating_system == 'Linux':
        with os.popen('ls -l /sys/class/net/ | grep -v virtual | grep devices | rev | cut -d "/" -f1 | rev') as f:
            return f.read().strip().split('\n')
    elif operating_system == 'Darwin':
        with os.popen('scutil --nwi | grep "Network interfaces" | cut -d " " -f3') as f:
            return f.read().strip().split('\n')
    else:
        return []

def network():
    network = []
    network_interfaces = interfaces(platform.system())

    for k, v in psutil.net_io_counters(pernic=True).items():
        if k not in network_interfaces:
            continue
        network.append({ k: v._asdict() })

    return network
