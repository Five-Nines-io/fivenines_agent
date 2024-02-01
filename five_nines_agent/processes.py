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
        'create_time',
        'memory_percent',
        'memory_full_info',
        'cpu_percent',
        'cpu_times',
        'num_fds',
        'cwd',
        'nice',
        'num_threads',
        'status',
        'connections',
        'threads'
    ]
    if operating_system == 'Linux':
        attrs.append('io_counters')

    for proc in psutil.process_iter(attrs=attrs):
        try:
            process = proc.as_dict(attrs=attrs)
            processes.append(process)
        except psutil.NoSuchProcess:
            pass
    return processes
