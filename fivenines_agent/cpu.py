import psutil
import os
import platform
from fivenines_agent.debug import debug

@debug('cpu_data')
def cpu_data():
    cpu_times_percent = psutil.cpu_times_percent(percpu=True)
    cpu_percent = psutil.cpu_percent(percpu=True)
    cores_usage = []

    for i, v in enumerate(cpu_times_percent):
      _cpu_usage = { 'percentage': cpu_percent[i] }
      _cpu_usage.update(v._asdict())
      cores_usage.append(_cpu_usage)

    return cores_usage

@debug('cpu_usage')
def cpu_usage():
    return psutil.cpu_times(percpu=True)

@debug('cpu_model')
def cpu_model():
    cpu_model = '-'
    operating_system = platform.system()

    try:
        if operating_system == 'Linux':
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        cpu_model =  line.split(':')[1].strip()
        elif operating_system == 'Darwin':
                with os.popen('/usr/sbin/sysctl -n machdep.cpu.brand_string') as f:
                    cpu_model = f.read().strip()
    except FileNotFoundError:
        pass

    return cpu_model

@debug('cpu_count')
def cpu_count():
    return os.cpu_count()
