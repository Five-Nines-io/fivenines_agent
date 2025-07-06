import platform
from fivenines_agent.debug import debug

@debug('file_handles_used')
def file_handles_used():
    return file_handles_stats()[0]

@debug('file_handles_limit')
def file_handles_limit():
    return file_handles_stats()[2]

def file_handles_stats():
    operating_system = platform.system()

    if operating_system != 'Linux':
        return [0, 0, 0]
    else:
        try:
            with open('/proc/sys/fs/file-nr', 'r') as f:
                return list(map(int, f.read().strip().split('\t')))
        except FileNotFoundError:
            return [0, 0, 0]
