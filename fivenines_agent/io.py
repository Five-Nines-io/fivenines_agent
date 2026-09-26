import os

import psutil

from fivenines_agent.debug import debug
from fivenines_agent.env import os_family

# Every whole block device the kernel knows about has an entry here (a symlink
# into /sys/devices/). Partitions do NOT: a partition is a directory nested
# inside its disk's entry (/sys/block/sda/sda1/), which is the structural
# "is this a partition" signal, with no name rule involved.
SYS_BLOCK = "/sys/block"


@debug("io")
def io():
    io = []
    for k, v in psutil.disk_io_counters(perdisk=True).items():
        io.append({k: v._asdict()})

    return io


def _io_name(sysfs_name):
    """The name the `io` payload uses for a device sysfs names `sysfs_name`.

    A kobject name cannot contain '/', so the kernel rewrites it to '!' in
    sysfs (cciss/c0d0 -> /sys/block/cciss!c0d0) while /proc/diskstats -- and
    so psutil and the `io` rows -- print the disk name unrewritten. psutil
    applies the same substitution in the other direction to find a disk in
    sysfs. Reversing it keeps io_topology keyed exactly like `io`.
    """
    return sysfs_name.replace("!", "/")


def _whole_device(path):
    """{"slaves": [...], "virtual": bool} for /sys/block/<dev>, or None.

    slaves/ lists the devices this one is stacked on (md members, the PVs under
    a dm/LVM/LUKS device, bcache's backing and cache devices, the paths under a
    multipath map). [] is a positive claim -- nothing beneath it -- so it is
    only ever reported from a successful read; an unreadable directory is None,
    which leaves the device out of the topology rather than calling it a leaf.

    virtual is sysstat's definition: no `device` link, i.e. no device in the
    driver model beneath this one -- the kernel built it (md, dm, bcache, loop,
    zram, zvol, nbd, rbd). That is what separates a real disk from a zvol or a
    loop device, which have no slaves either: their I/O lands on something the
    kernel does not model as a block device (a ZFS pool, a file, RAM, the
    network). A paravirtual disk (virtio vda, Xen xvda) HAS a device link and
    is not virtual here: it is the bottom of this host's stack.
    """
    try:
        slaves = os.listdir(os.path.join(path, "slaves"))
    except OSError:
        return None
    try:
        os.lstat(os.path.join(path, "device"))
        virtual = False
    except FileNotFoundError:
        virtual = True
    except OSError:
        return None
    return {"slaves": sorted(_io_name(s) for s in slaves), "virtual": virtual}


def _partitions(path, disk):
    """Sysfs names of the partitions nested in /sys/block/<disk>/.

    A partition is a subdirectory carrying a `partition` attribute. The kernel
    names every partition after its disk (sda -> sda1, nvme0n1 -> nvme0n1p1),
    so the name prefix is only a cheap pre-filter that skips the disk's ~25
    other entries (queue/, holders/, power/...) without a stat each; the
    `partition` file is what decides. [] when the directory is unreadable: an
    unlisted partition is unknown to the server, never misclassified.
    """
    try:
        with os.scandir(path) as entries:
            candidates = [
                entry.name
                for entry in entries
                if entry.name.startswith(disk) and entry.is_dir(follow_symlinks=False)
            ]
    except OSError:
        return []
    return sorted(
        name
        for name in candidates
        if os.path.isfile(os.path.join(path, name, "partition"))
    )


@debug("io_topology")
def io_topology():
    """What each block device is stacked on, keyed like the `io` rows (#155).

    /proc/diskstats records one write at every layer it passes through: once
    at md0 and again at each member, once at dm-0 and again at the partition
    under it. A server summing `io` rows counts one physical write two or three
    times, and cannot tell md0 or dm-0 from the disk under it by name. This
    reports the structure instead:

      {"sda":  {"slaves": [], "virtual": false},
       "sda1": {"partition_of": "sda"},
       "md0":  {"slaves": ["sda1", "sdb1"], "virtual": true},
       "zd0":  {"slaves": [], "virtual": true}}

    A device whose entry could not be read is simply absent, so the server
    falls back to its name rules for that row. None when /sys/block cannot be
    listed, and on every non-Linux host (which has no stacked layers in `io`);
    the server treats None and {} as "not reported", never as "no stacking".

    Read every tick, uncached: it is a few directory reads per device (~26us
    measured, so ~10ms for a 400-device hypervisor), and membership changes
    without the device set changing -- a pvmove, an md member re-added -- so a
    cache keyed on the device set would serve a stale answer.
    """
    if os_family() != "linux":
        return None
    try:
        disks = os.listdir(SYS_BLOCK)
    except OSError:
        return None

    topology = {}
    for disk in sorted(disks):
        path = os.path.join(SYS_BLOCK, disk)
        entry = _whole_device(path)
        if entry is not None:
            topology[_io_name(disk)] = entry
        for part in _partitions(path, disk):
            topology[_io_name(part)] = {"partition_of": _io_name(disk)}
    return topology
