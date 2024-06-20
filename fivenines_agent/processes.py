import psutil

def processes():
    processes = []
    attrs = [
        'pid',
        'ppid',
        'name',
        'username',
        'memory_percent',
        'cpu_percent',
        'cpu_times',
        'num_threads',
        'status',
        'connections',
    ]

    for proc in psutil.process_iter():
        try:
            process = proc.as_dict(attrs=attrs)
            processes.append(process)
        except psutil.NoSuchProcess:
            pass
    return processes
