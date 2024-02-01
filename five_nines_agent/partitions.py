import psutil

def partitions_metadata():
    partitions_metadata = []
    for _, v in enumerate(psutil.disk_partitions(all=False)):
        partitions_metadata.append(v._asdict())

    return partitions_metadata

def partitions_usage():
    partitions_usage = {}

    for _, v in enumerate(psutil.disk_partitions(all=False)):
        partitions_usage[v.mountpoint] = psutil.disk_usage(v.mountpoint)._asdict()

    return partitions_usage
