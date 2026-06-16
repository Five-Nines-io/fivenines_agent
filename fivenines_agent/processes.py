import psutil
from fivenines_agent.debug import debug

@debug('processes')
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
    ]

    for proc in psutil.process_iter():
        # Skip PID 0. On Windows this is the "System Idle Process" pseudo-
        # process - it accounts for CPU time the cores spent doing NOTHING
        # and routinely reports ~(cpu_count * 100)% CPU. Including it in
        # the payload makes it dominate every "Top CPU" view, which is
        # exactly the opposite of useful. On Linux PID 0 is the kernel
        # scheduler and not exposed via /proc, so this branch is a no-op
        # there (the filter just costs one integer comparison per tick).
        if proc.pid == 0:
            continue
        try:
            process = proc.as_dict(attrs=attrs)
            processes.append(process)
        except psutil.NoSuchProcess:
            pass
    return processes
