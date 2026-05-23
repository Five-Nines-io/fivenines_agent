import psutil
from fivenines_agent.debug import debug, log

# Filesystems we don't want to track. Includes pseudo / overlay filesystems
# common on Linux containers (squashfs, overlay, tmpfs, ...) as well as
# read-only optical media (CDFS, UDF) which on Windows show up as 100%-full
# CD/DVD drives - reporting them as "full disks" triggers misleading
# disk-full alerts on the dashboard.
IGNORED_FS = [
    'squashfs', 'cagefs-skeleton', 'overlay', 'devtmpfs', 'tmpfs', 'loop', 'nullfs',
    'cdfs', 'udf', 'iso9660',
]

# Mount option markers we use to filter out media we never want to monitor,
# regardless of fstype. Windows tags optical drives with 'cdrom' in opts even
# when the media is some non-CDFS filesystem, so we belt-and-suspender on both.
IGNORED_OPTS = ('cdrom',)


def _should_ignore(fstype, opts):
    if fstype and fstype.lower() in IGNORED_FS:
        return True
    if opts:
        opts_lower = opts.lower()
        if any(marker in opts_lower for marker in IGNORED_OPTS):
            return True
    return False

@debug('partitions_metadata')
def partitions_metadata():
    partitions_metadata = []

    for part in psutil.disk_partitions(False):
        if _should_ignore(part.fstype, part.opts):
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
            if _should_ignore(v.fstype, v.opts):
                continue

            partitions_usage[v.mountpoint] = psutil.disk_usage(v.mountpoint)._asdict()
        except PermissionError as e:
            log(f"Error getting disk usage for {v.mountpoint}: {e}")
            continue

    return partitions_usage
