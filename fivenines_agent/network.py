import os
import platform
import psutil

def interfaces(operating_system):
  if operating_system == 'Linux':
      return os.popen("ls -l /sys/class/net/ | grep -v virtual | grep devices | cut -d ' ' -f9").read().strip().split("\n")
  elif operating_system == 'Darwin':
      return os.popen("scutil --nwi | grep 'Network interfaces' | cut -d ' ' -f3").read().strip().split("\n")
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
