import os

import psutil

from fivenines_agent.debug import debug
from fivenines_agent.env import os_family

# Linux exposes every interface under /sys/class/net/<iface>/. We read three
# things from it (all world-readable, no privilege needed):
#   bridge/  -> directory present only on Linux bridge masters (issue #50)
#   brif/    -> one symlink per bridge member port
#   speed    -> negotiated link speed in Mbit/s (or -1 for virtual/down links)
SYS_CLASS_NET = "/sys/class/net"

# Upper sanity bound for /sys/class/net/<iface>/speed, in Mbit/s. Above any real
# NIC (800GbE = 800000 today, headroom to 1.6TbE) yet well below the unsigned
# sentinels a broken or out-of-tree driver can print (e.g. 2^32-1 = 4294967295).
# The kernel prints -1 for unknown speed, which we already reject as <= 0; this
# guards the high end so a garbage value can't become an absurd link_speed_bps
# that silently drives the backend's rate/speed saturation ratio toward zero.
MAX_LINK_SPEED_MBPS = 1_600_000


def _is_loopback(name):
    """OS-aware loopback interface check.

    Linux uses 'lo'; Windows names loopback interfaces 'Loopback Pseudo-Interface 1'
    (and variants); macOS exposes 'lo0' which is handled via the scutil path.
    """
    return name == 'lo' or name.lower().startswith('loopback')


def interfaces():
    """Return names of UP, non-loopback interfaces that have an address."""
    family = os_family()
    if family in ('linux', 'windows'):
        all_interfaces = psutil.net_if_stats()
        working_interfaces = []

        for interface, stats in all_interfaces.items():
            if not stats.isup:
                continue
            if _is_loopback(interface):
                continue
            try:
                addrs = psutil.net_if_addrs().get(interface, [])
                if not addrs:
                    continue
            except Exception:
                continue

            working_interfaces.append(interface)

        return working_interfaces
    elif family == 'darwin':
        with os.popen('scutil --nwi | grep "Network interfaces" | cut -d " " -f3') as f:
            return f.read().strip().split('\n')
    return []


def _read_sysfs_net(iface, attr):
    """Read /sys/class/net/<iface>/<attr>, stripped. None on any error.

    Covers the whole failure surface uniformly: a missing file, denied access,
    or the EINVAL the kernel raises when `speed` is read on a down or virtual
    interface all collapse to None (the metric is simply unavailable). ValueError
    (a null byte in the path) and its UnicodeDecodeError subclass (a non-ASCII
    text attr) are caught too, so the helper stays safe if reused for text
    surfaces like operstate/address, not just the ASCII-digit `speed`.
    """
    path = os.path.join(SYS_CLASS_NET, iface, attr)
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except (OSError, ValueError):
        return None


def _is_bridge(iface):
    """True if iface is a Linux bridge master.

    The kernel exposes /sys/class/net/<iface>/bridge/ only for bridge devices,
    so its presence is the detection signal (issue #50).
    """
    return os.path.isdir(os.path.join(SYS_CLASS_NET, iface, "bridge"))


def _bridge_members(iface):
    """Sorted member port names of a bridge.

    Members appear as symlinks under /sys/class/net/<iface>/brif/. Returns the
    full member set (including addressless slaves like enslaved NICs and VM
    tap devices), so the count reflects real bridge fan-out. [] when the
    interface is not a bridge or the directory is unreadable.
    """
    try:
        return sorted(os.listdir(os.path.join(SYS_CLASS_NET, iface, "brif")))
    except OSError:
        return []


def _interface_type(iface):
    """Classify a Linux interface so the backend can group by kind.

    - "bridge":   /sys/class/net/<iface>/bridge/ exists (bridge master)
    - "physical": /sys/class/net/<iface>/device exists -- a device node in the
                  driver model. Real PCI/USB NICs have one; so do paravirtual
                  NICs (virtio-net, Xen netfront, Hyper-V netvsc) and SR-IOV VFs,
                  which are therefore "physical" here even though their `speed`
                  is often unknown.
    - "virtual":  no device node (veth, tun/tap, wireguard, vlan, bond master).

    This is a coarse grouping hint, not a hardware assertion. Saturation is
    computed downstream from network_link_speed_bps wherever that value is
    present -- it must NOT be gated on interface_type == "physical", or a bond
    or vlan carrying the host's real uplink (labelled "virtual" here) would be
    skipped.
    """
    if _is_bridge(iface):
        return "bridge"
    if os.path.exists(os.path.join(SYS_CLASS_NET, iface, "device")):
        return "physical"
    return "virtual"


def _link_speed_bps(iface):
    """Negotiated link speed in bits/s (/sys/class/net/<iface>/speed, Mbps->bps).

    None when the speed is unknown or meaningless: the file is missing,
    unreadable, non-numeric, or reports a non-positive value. The kernel
    returns -1 for many virtual and down interfaces -- that is "unknown", not a
    real speed, so we emit None rather than a negative bit rate that would
    corrupt a downstream saturation ratio.
    """
    raw = _read_sysfs_net(iface, "speed")
    if raw is None:
        return None
    try:
        mbps = int(raw)
    except ValueError:
        return None
    # Reject both ends of the nonsense range: <= 0 is the kernel's -1/0 "unknown"
    # sentinel; above MAX_LINK_SPEED_MBPS is driver garbage. Either way the
    # speed is unknown, so emit None rather than a value that would corrupt the
    # downstream saturation ratio.
    if mbps <= 0 or mbps > MAX_LINK_SPEED_MBPS:
        return None
    return mbps * 1_000_000


@debug('network')
def network():
    result = []
    network_interfaces = interfaces()
    # Bridge topology + link speed live in sysfs, which only exists on Linux.
    # On other platforms the payload keeps its historical shape (raw counters).
    enrich = os_family() == 'linux'

    # One classification pass before reading counters: interface_type, member
    # count, and member->bridge tags are all derived from a single sysfs
    # snapshot per interface. This classifies each interface exactly once (no
    # repeated bridge/ stat in the loop below) and guarantees interface_type can
    # never contradict bridge_member_count -- both come from the same read.
    types = {}
    member_counts = {}
    member_to_bridge = {}
    if enrich:
        for iface in network_interfaces:
            itype = _interface_type(iface)
            types[iface] = itype
            if itype == "bridge":
                members = _bridge_members(iface)
                member_counts[iface] = len(members)
                for member in members:
                    member_to_bridge[member] = iface

    for k, v in psutil.net_io_counters(pernic=True).items():
        if k not in network_interfaces:
            continue
        entry = v._asdict()
        if enrich:
            entry["interface_type"] = types[k]
            entry["network_link_speed_bps"] = _link_speed_bps(k)
            if k in member_counts:
                entry["bridge_member_count"] = member_counts[k]
            if k in member_to_bridge:
                entry["bridge"] = member_to_bridge[k]
        result.append({k: entry})

    return result
