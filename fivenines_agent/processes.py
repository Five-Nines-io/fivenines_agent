import platform
import psutil

def processes():
    operating_system = platform.system()
    processes = []
    attrs = [
        'pid',
        'ppid',
        'name',
        'username',
        'memory_percent',
        'cpu_percent',
        'num_threads',
        'status',
        'connections',
    ]

    for proc in psutil.process_iter(attrs=attrs):
        try:
            process = proc.as_dict(attrs=attrs)
            processes.append(process)
        except psutil.NoSuchProcess:
            pass
    return processes
