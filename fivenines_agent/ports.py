"""Listening-ports collector.

Uses psutil.net_connections() so the same code path works on Linux and
Windows (D8). The /proc/net/{tcp,tcp6,udp,udp6} parser this replaced is gone -
psutil reads the same kernel tables on Linux and the Windows IP Helper API on
Windows. The dual-stack post-processing and ephemeral-port filtering match the
prior behavior; the Linux output is pinned by tests/test_ports.py.
"""

import socket

import psutil

from fivenines_agent.debug import debug

PROTOCOLS = {
    'tcp': 'TCP (IPv4)',
    'tcp6': 'TCP (IPv6)',
    'udp': 'UDP (IPv4)',
    'udp6': 'UDP (IPv6)',
}


def get_ephemeral_port_range():
    """Return the ephemeral port range. Linux /proc, or Linux defaults."""
    try:
        with open('/proc/sys/net/ipv4/ip_local_port_range', 'r') as f:
            start, end = map(int, f.read().strip().split())
            return (start, end)
    except (FileNotFoundError, ValueError, OSError):
        # Linux default; also a reasonable fallback for Windows where the
        # equivalent range lives in the registry and rarely matters.
        return (32768, 60999)


def check_ipv6_dual_stack():
    """True when the kernel allows IPv6 sockets to also accept IPv4 (bindv6only=0)."""
    try:
        with open('/proc/sys/net/ipv6/bindv6only', 'r') as f:
            return f.read().strip() == '0'
    except FileNotFoundError:
        # No bindv6only sysctl -> assume modern dual-stack default. On Windows,
        # dual-stack is per-socket (IPV6_V6ONLY), and we can't inspect it from
        # here; treating it as True keeps the IPv6-listener accounting honest.
        return True


def _proto_key(family, type_):
    """Map psutil family/type to a proto key, or None for non-inet sockets."""
    if family == socket.AF_INET:
        is_v6 = False
    elif family == socket.AF_INET6:
        is_v6 = True
    else:
        return None
    is_tcp = type_ == socket.SOCK_STREAM
    if is_tcp:
        return 'tcp6' if is_v6 else 'tcp'
    return 'udp6' if is_v6 else 'udp'


def _enumerate_connections():
    """Enumerate inet connections, falling back to per-kind on AccessDenied.

    On Windows, psutil.net_connections(kind='inet') needs admin to see
    connections owned by other users. Per-kind enumeration sometimes succeeds
    even when the unified call raises - return whatever we can see and let the
    caller treat partial visibility as expected (capability_reasons captures
    the underlying error at probe time).
    """
    try:
        return psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, PermissionError):
        collected = []
        for kind in ('tcp4', 'tcp6', 'udp4', 'udp6'):
            try:
                collected.extend(psutil.net_connections(kind=kind))
            except (psutil.AccessDenied, PermissionError):
                continue
        return collected


@debug('listening_ports')
def listening_ports(monitored_ports=[]):
    """List listening sockets as (port, proto_name, address) tuples."""
    dual_stack_enabled = check_ipv6_dual_stack()
    ephemeral_start, ephemeral_end = get_ephemeral_port_range()

    ipv6_listening_addr = {}  # port -> local IPv6 address
    ipv4_listening_ports = set()
    intermediate = []  # (port, proto_name, address)

    for conn in _enumerate_connections():
        # net_connections can return entries without a local address; skip.
        if not conn.laddr:
            continue
        port = conn.laddr.port
        addr = conn.laddr.ip

        proto_key = _proto_key(conn.family, conn.type)
        if proto_key is None:
            continue
        proto_name = PROTOCOLS[proto_key]

        # Match the prior "listening" semantics: TCP LISTEN, UDP no-state ('UNCONN').
        if proto_key.startswith('tcp'):
            if conn.status != psutil.CONN_LISTEN:
                continue
        else:
            if conn.status != psutil.CONN_NONE:
                continue

        # Ephemeral ports are skipped unless explicitly monitored.
        if ephemeral_start <= port <= ephemeral_end and port not in monitored_ports:
            continue

        # Normalize IPv6 unspecified for the dual-stack lookup below.
        if proto_key.endswith('6') and addr in ("::", "::0", "0:0:0:0:0:0:0:0"):
            addr = "::"

        if proto_key == 'tcp6':
            ipv6_listening_addr[port] = addr
        elif proto_key == 'tcp':
            ipv4_listening_ports.add(port)

        intermediate.append((port, proto_name, addr))

    final_results = []
    for port, proto_name, address in intermediate:
        if (proto_name == 'TCP (IPv6)' and dual_stack_enabled
                and port not in ipv4_listening_ports
                and ipv6_listening_addr.get(port) == "::"):
            proto_name = 'TCP (Dual-Stack)'
        final_results.append((port, proto_name, address))

    return final_results
