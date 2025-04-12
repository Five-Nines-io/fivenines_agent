TCP_STATES = {
    '01': 'ESTABLISHED',
    '02': 'SYN_SENT',
    '03': 'SYN_RECV',
    '04': 'FIN_WAIT1',
    '05': 'FIN_WAIT2',
    '06': 'TIME_WAIT',
    '07': 'CLOSE',
    '08': 'CLOSE_WAIT',
    '09': 'LAST_ACK',
    '0A': 'LISTEN',
    '0B': 'CLOSING'
}

PROTOCOLS = {
    'tcp': 'TCP (IPv4)',
    'tcp6': 'TCP (IPv6)',
    'udp': 'UDP (IPv4)',
    'udp6': 'UDP (IPv6)'
}

# Default ephemeral port range on most Linux systems
def get_ephemeral_port_range():
    """Get the ephemeral port range from the system"""
    try:
        with open('/proc/sys/net/ipv4/ip_local_port_range', 'r') as f:
            start, end = map(int, f.read().strip().split())
            return (start, end)
    except:
        # Default range if we can't read the system configuration
        return (32768, 60999)

def check_ipv6_dual_stack():
    """Check if the system has IPv6 dual-stack support enabled"""
    try:
        with open('/proc/sys/net/ipv6/bindv6only', 'r') as f:
            return f.read().strip() == '0'
    except FileNotFoundError:
        # If we can't read the sysctl, assume modern default (dual-stack enabled)
        return True

def extract_ipv6_addr(hex_addr):
    """Convert IPv6 hex address to readable format"""
    if hex_addr == "00000000000000000000000000000000":
        return "::"  # All zeros means any address
    return ":".join([hex_addr[i:i+4] for i in range(0, len(hex_addr), 4)])

def extract_ipv4_addr(hex_addr):
    """Convert IPv4 hex address to readable format"""
    if hex_addr == "00000000":
        return "0.0.0.0"  # All zeros means any address

    # IPv4 addresses are stored in reverse byte order
    bytes_list = [hex_addr[i:i+2] for i in range(0, len(hex_addr), 2)]
    bytes_list.reverse()
    return ".".join([str(int(byte, 16)) for byte in bytes_list])

def listening_ports():
    """Get only listening ports with protocol information, excluding ephemeral ports"""
    results = []
    dual_stack_enabled = check_ipv6_dual_stack()
    ephemeral_start, ephemeral_end = get_ephemeral_port_range()

    # Dictionary to track IPv6 sockets that might be dual-stack
    ipv6_sockets = {}  # key = port, value = local_addr
    ipv4_ports = set()

    # First pass: collect IPv4 and IPv6 socket information
    for proto_file, proto_name in PROTOCOLS.items():
        try:
            with open(f'/proc/net/{proto_file}', 'r') as f:
                next(f)  # Skip header
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        local_addr_port = parts[1]
                        addr_hex, port_hex = local_addr_port.split(':')
                        port = int(port_hex, 16)

                        # Skip ephemeral ports
                        if ephemeral_start <= port <= ephemeral_end:
                            continue

                        # Check if this is a listening socket
                        state_hex = parts[3].upper()
                        is_listening = False

                        if proto_file.startswith('tcp'):
                            is_listening = (state_hex == '0A')  # 0A = LISTEN state
                            state = 'LISTEN' if is_listening else TCP_STATES.get(state_hex, 'UNKNOWN')
                        else:  # UDP
                            is_listening = (state_hex == '07')  # 07 = UNCONN for UDP (essentially listening)
                            state = 'UNCONN' if is_listening else 'UNKNOWN'

                        # Skip non-listening sockets
                        if not is_listening:
                            continue

                        # Track IPv6 listening sockets with their addresses
                        if proto_file == 'tcp6':
                            addr = extract_ipv6_addr(addr_hex)
                            ipv6_sockets[port] = addr

                        # Track IPv4 ports
                        if proto_file == 'tcp':
                            ipv4_ports.add(port)

                        # Extract and add address information for more context
                        if proto_file.endswith('6'):  # IPv6
                            address = extract_ipv6_addr(addr_hex)
                        else:  # IPv4
                            address = extract_ipv4_addr(addr_hex)

                        # Add to results (including address for context)
                        results.append((port, proto_name, state, address))
        except FileNotFoundError:
            continue

    final_results = []
    for port, proto_name, state, address in results:
        # IPv6 socket not explicitly bound to IPv4
        if (proto_name == 'TCP (IPv6)' and
            dual_stack_enabled and port not in ipv4_ports):

            # Check if this IPv6 socket is listening on all interfaces (::)
            if port in ipv6_sockets and ipv6_sockets[port] in ["::", "::0"]:
                proto_name = 'TCP (Dual-Stack)'

        final_results.append((port, proto_name, address))

    return final_results
