import os
import threading

import psutil

from fivenines_agent.debug import debug, log
from fivenines_agent.env import os_family

# Every whole block device the kernel knows about has an entry here (a symlink
# into /sys/devices/). Partitions do NOT: a partition is a directory nested
# inside its disk's entry (/sys/block/sda/sda1/), which is the structural
# "is this a partition" signal, with no name rule involved.
SYS_BLOCK = "/sys/block"

# Wall-clock bound on one topology read, on the watchdog-bounded collection
# loop. A healthy read is well under 1ms here and ~10ms for 400 devices; this
# only ever fires on a stalled sysfs (see io_topology).
TOPOLOGY_READ_TIMEOUT = 5

# The worker of a read that outlived TOPOLOGY_READ_TIMEOUT, while it is still
# blocked. Single-flight: no new read starts until it returns, so a sysfs stall
# costs one leaked thread, not one per tick.
_stalled_worker = None


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

    virtual is sysstat's definition: no `device` link, i.e. the driver
    registered the disk with no parent device (add_disk() rather than
    device_add_disk(parent, ...)): md, dm, bcache, drbd, loop, brd, zram, nbd,
    zvol. That is what separates a real disk from a zvol or a loop device,
    which have no slaves either: their I/O lands on something the kernel does
    not model as a block device (a ZFS pool, a file, RAM, the network). It is a
    statement about the driver model, not about hardware: a paravirtual disk
    (virtio vda, Xen xvda) has a parent and is not virtual -- it is the bottom
    of this host's stack -- and neither is Ceph RBD, whose parent is its rbd
    bus device even though every byte goes over the network.
    """
    try:
        slaves = os.listdir(os.path.join(path, "slaves"))
    except OSError:
        return None
    try:
        os.lstat(os.path.join(path, "device"))
        virtual = False
    except FileNotFoundError:
        # A device hot-removed after slaves/ was read (a pulled USB disk, an
        # iSCSI logout) answers ENOENT here too. Its `io` row is already
        # collected, and virtual: true would drop it from the server's total,
        # so only a device that is still there is virtual.
        if not os.path.lexists(os.path.join(path, "slaves")):
            return None
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

    The read runs in a daemon worker bounded by TOPOLOGY_READ_TIMEOUT (the
    libvirt-probe posture). sysfs is kernfs, answered from kernel memory, so a
    wedged DISK cannot stall it; machine-wide memory pressure can -- another
    sysfs reader faulting into reclaim while holding kernfs_rwsem blocks every
    lookup behind a queued writer, for minutes (LKML, 2026-09: "kernfs: don't
    hold kernfs_rwsem across dir_emit()"), past WatchdogSec=90. A read that
    times out reports None and is abandoned; until it returns, later ticks
    report None without starting another.
    """
    global _stalled_worker
    if os_family() != "linux":
        return None
    if _stalled_worker is not None:
        if _stalled_worker.is_alive():
            log(
                "io_topology: previous sysfs read still blocked; reporting None",
                "debug",
            )
            return None
        _stalled_worker = None

    outcome = {}

    def target():
        try:
            outcome["value"] = _read_topology()
        except BaseException as e:  # re-raised on the caller's thread below
            outcome["error"] = e

    worker = threading.Thread(target=target, name="io-topology", daemon=True)
    worker.start()
    worker.join(TOPOLOGY_READ_TIMEOUT)
    if worker.is_alive():
        _stalled_worker = worker
        log(
            f"io_topology: sysfs read blocked for {TOPOLOGY_READ_TIMEOUT}s; "
            "reporting None until it returns",
            "error",
        )
        return None
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def _read_topology():
    """The sysfs walk itself; see io_topology() for the shape."""
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
