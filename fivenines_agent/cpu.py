import psutil
import os
import platform

def cpu_data():
    cpu_times_percent = psutil.cpu_times_percent(percpu=True)
    cpu_percent = psutil.cpu_percent(percpu=True)
    cores_usage = []

    for i, v in enumerate(cpu_times_percent):
      _cpu_usage = { 'percentage': cpu_percent[i] }
      _cpu_usage.update(v._asdict())
      cores_usage.append(_cpu_usage)

    return cores_usage


def cpu_model():
    operating_system = platform.system()
    if operating_system == 'Linux':
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        return line.split(':')[1].strip()
        except FileNotFoundError:
            return '-'
    elif operating_system == 'Darwin':
        try:
            with os.popen('/usr/sbin/sysctl -n machdep.cpu.brand_string') as f:
                return f.read().strip()
        except FileNotFoundError:
            return '-'
    else:
        '-'
