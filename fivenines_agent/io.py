import os
import sys

import psutil

from fivenines_agent.bounded import WorkerTimeout, call_bounded
from fivenines_agent.debug import debug, log
from fivenines_agent.env import os_family

# Every whole block device the kernel knows about has an entry here (a symlink
# into /sys/devices/). Partitions do NOT: a partition is a directory nested
# inside its disk's entry (/sys/block/sda/sda1/), which is the structural
# "is this a partition" signal, with no name rule involved.
SYS_BLOCK = "/sys/block"

# Only read to resolve a '!' in a sysfs name (see _IoNames).
PROC_DISKSTATS = "/proc/diskstats"

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


class _IoNames:
    """sysfs name -> the spelling /proc/diskstats (so the `io` rows) uses.

    A kobject name cannot contain '/', so the kernel writes it as '!' in sysfs
    (cciss/c0d0 -> /sys/block/cciss!c0d0) while /proc/diskstats prints the disk
    name unrewritten. A '!' in sysfs is therefore EITHER a rewritten '/' or a
    literal '!' -- md takes any `md_*` array name verbatim, so md_a/b! is
    md_a!b! in sysfs -- and only /proc/diskstats can say which. Its names are
    escaped the way the kernel escapes them and looked up by that; it is read
    at most once per walk and only when a '!' shows up, so the common case
    costs nothing. A name it cannot place is None: left out as unknown, never
    guessed.
    """

    def __init__(self):
        self._by_sysfs_name = None

    def __call__(self, sysfs_name):
        if "!" not in sysfs_name:
            return sysfs_name
        if self._by_sysfs_name is None:
            self._by_sysfs_name = {}
            for name in _diskstats_names():
                escaped = name.replace("/", "!")
                # Two names escaping alike could not both be registered in
                # sysfs; if they ever were, neither could be told apart.
                ambiguous = escaped in self._by_sysfs_name
                self._by_sysfs_name[escaped] = None if ambiguous else name
        return self._by_sysfs_name.get(sysfs_name)


def _diskstats_names():
    """Every device name in /proc/diskstats; empty when it cannot be read.

    Decoded the way psutil decodes it for the `io` rows (filesystem encoding,
    surrogateescape), so a name that is not valid UTF-8 keys identically on
    both sides -- and one such byte cannot fail the read for every name.
    """
    try:
        with open(
            PROC_DISKSTATS,
            encoding=sys.getfilesystemencoding(),
            errors="surrogateescape",
        ) as f:
            return {fields[2] for fields in map(str.split, f) if len(fields) > 2}
    except OSError:
        return set()


def _whole_device(path, io_name):
    """{"slaves": [...], "virtual": bool} for /sys/block/<dev>, or None.

    slaves/ lists the devices this one is stacked on (md members, the PVs under
    a dm/LVM/LUKS device, bcache's backing and cache devices, the paths under a
    dm-multipath map). An NVMe native-multipath head links its paths from
    multipath/ instead (see _multipath_paths), so those count too. [] is a
    positive claim -- nothing beneath it -- so it is only ever reported from a
    successful read; an unreadable directory is None, which leaves the device
    out of the topology rather than calling it a leaf. So does a slave io_name
    cannot place: a partial list is a false claim too.

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
        beneath = os.listdir(os.path.join(path, "slaves")) + _multipath_paths(path)
    except OSError:
        return None
    slaves = [io_name(s) for s in beneath]
    if None in slaves:
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
    return {"slaves": sorted(slaves), "virtual": virtual}


def _multipath_paths(path):
    """The path devices of an NVMe native-multipath head, [] for anything else.

    The head (nvme0n1) is stacked on its hidden per-path disks (nvme0c0n1,
    nvme0c1n1) exactly as a dm-multipath map is on its sdX paths, but NVMe
    links them from /sys/block/<head>/multipath/, not slaves/. Both rows are
    in /proc/diskstats with the same I/O -- the paths account it through
    blk-mq, the head through nvme_mpath_start_request -- so without this the
    head reads as a leaf and every I/O counts twice. The directory holds only
    those links, and exists since Linux 6.15 (_attach_hidden_paths covers
    older kernels). ENOENT (not a head, or a kernel without the links) is [];
    any other failure propagates, so the caller reports the device as unknown
    rather than with a partial list.
    """
    try:
        return os.listdir(os.path.join(path, "multipath"))
    except FileNotFoundError:
        return []


def _read_attr(path, attr):
    """A sysfs attribute's stripped text, or None when it cannot be read."""
    try:
        with open(os.path.join(path, attr)) as f:
            return f.read().strip()
    except (OSError, ValueError):
        return None


def _attach_hidden_paths(topology, paths):
    """List each hidden NVMe path disk under its head, without multipath/.

    Before Linux 6.15 a native-multipath head has no multipath/ links, yet its
    path disks are already hidden gendisks (`hidden` reads 1; NVMe is the only
    user) and every one of them reports its head's wwid -- the attribute reads
    the namespace head's ids on both. So a hidden disk belongs to the one
    VISIBLE disk that shares its wwid. No candidate, or more than one, attaches
    nothing: the head then stays a leaf as before, never a wrong claim. On 6.15
    and later this finds the same paths multipath/ already listed.
    """
    hidden = [name for name, path in paths.items() if _read_attr(path, "hidden") == "1"]
    if not hidden:
        return
    heads_by_wwid = {}
    for name, path in paths.items():
        if name not in hidden:
            wwid = _read_attr(path, "wwid")
            if wwid:
                heads_by_wwid.setdefault(wwid, []).append(name)
    for name in hidden:
        heads = heads_by_wwid.get(_read_attr(paths[name], "wwid"), [])
        if len(heads) == 1:
            slaves = topology[heads[0]]["slaves"]
            if name not in slaves:
                slaves.append(name)
                slaves.sort()


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
    listed, and on every non-Linux host (the structure is read from sysfs);
    the server treats None and {} as "not reported", never as "no stacking".

    Read every tick, uncached: it is a few directory reads per device (~26us
    measured, so ~10ms for a 400-device hypervisor), and membership changes
    without the device set changing -- a pvmove, an md member re-added -- so a
    cache keyed on the device set would serve a stale answer.

    The read runs in a daemon worker bounded by TOPOLOGY_READ_TIMEOUT
    (bounded.call_bounded, as run_privileged and the libvirt probe). sysfs is
    kernfs, answered from kernel memory, so a wedged DISK cannot stall it;
    machine-wide memory pressure can -- another sysfs reader faulting into
    reclaim while holding kernfs_rwsem blocks every lookup behind a queued
    writer, for minutes (LKML, 2026-09: "kernfs: don't hold kernfs_rwsem across
    dir_emit()"), past WatchdogSec=90. A read that times out reports None and
    is abandoned; until it returns, later ticks report None without starting
    another. This bounds this collector's share of the tick only: the network,
    temperatures and fans collectors read sysfs unbounded (TODOS.md).
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

    try:
        return call_bounded(_read_topology, TOPOLOGY_READ_TIMEOUT, name="io-topology")
    except WorkerTimeout as stalled:
        _stalled_worker = stalled.worker
        log(
            f"io_topology: sysfs read blocked for {TOPOLOGY_READ_TIMEOUT}s; "
            "reporting None until it returns",
            "error",
        )
        return None


def _read_topology():
    """The sysfs walk itself; see io_topology() for the shape."""
    try:
        disks = os.listdir(SYS_BLOCK)
    except OSError:
        return None

    io_name = _IoNames()
    topology = {}
    whole = {}
    for disk in sorted(disks):
        name = io_name(disk)
        if name is None:
            continue
        path = os.path.join(SYS_BLOCK, disk)
        entry = _whole_device(path, io_name)
        if entry is not None:
            topology[name] = entry
            whole[name] = path
        for part in _partitions(path, disk):
            part_name = io_name(part)
            if part_name is not None:
                topology[part_name] = {"partition_of": name}
    _attach_hidden_paths(topology, whole)
    return topology
