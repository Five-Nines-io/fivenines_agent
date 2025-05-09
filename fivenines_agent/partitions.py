import psutil
from fivenines_agent.env import debug_mode


IGNORED_DEVICES = ['/loop', '/snap']
IGNORED_FS = ['squashfs', 'cagefs-skeleton']

def partitions_metadata():
    partitions_metadata = []

    for part in psutil.disk_partitions(False):
        if part.device.startswith(tuple(IGNORED_DEVICES)):
            continue

        if part.fstype in IGNORED_FS:
            continue

        partitions_metadata.append({
            'device': part.device,
            'mountpoint': part.mountpoint,
            'fstype': part.fstype,
            'opts': part.opts,
        })

    return partitions_metadata

def partitions_usage():
    partitions_usage = {}

    for _, v in enumerate(psutil.disk_partitions(all=False)):
        try:
            if v.device.startswith(tuple(IGNORED_DEVICES)):
                continue

            if v.fstype in IGNORED_FS:
                continue

            partitions_usage[v.mountpoint] = psutil.disk_usage(v.mountpoint)._asdict()
        except PermissionError as e:
            if debug_mode:
                print(f"Error getting disk usage for {v.mountpoint}: {e}")
            continue

    return partitions_usage
