import platform

def file_handles_used():
    file_handles_stats()[0]

def file_handles_limit():
    file_handles_stats()[2]


def file_handles_stats():
    operating_system = platform.system()

    if operating_system != 'Linux':
        return [0, 0, 0]
    else:
        try:
            f = open('/proc/sys/fs/file-nr')
            return list(map(int, f.read().strip().split('\t')))
        except FileNotFoundError:
            print('File handles file is missing')
            return [0, 0, 0]
