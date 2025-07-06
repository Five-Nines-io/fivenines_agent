import psutil
from fivenines_agent.env import debug_mode
from fivenines_agent.debug import debug

IGNORED_FS = ['squashfs', 'cagefs-skeleton', 'overlay', 'devtmpfs', 'tmpfs', 'loop', 'nullfs']

@debug('partitions_metadata')
def partitions_metadata():
    partitions_metadata = []

    for part in psutil.disk_partitions(False):
        if part.fstype in IGNORED_FS:
            continue

        partitions_metadata.append({
            'device': part.device,
            'mountpoint': part.mountpoint,
            'fstype': part.fstype,
            'opts': part.opts,
        })

    return partitions_metadata


@debug('partitions_usage')
def partitions_usage():
    partitions_usage = {}

    for _, v in enumerate(psutil.disk_partitions(all=False)):
        try:
            if v.fstype in IGNORED_FS:
                continue

            partitions_usage[v.mountpoint] = psutil.disk_usage(v.mountpoint)._asdict()
        except PermissionError as e:
            if debug_mode:
                print(f"Error getting disk usage for {v.mountpoint}: {e}")
            continue

    return partitions_usage
