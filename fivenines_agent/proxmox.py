"""
Proxmox VE monitoring collector.

Collects metrics from Proxmox VE clusters and standalone nodes including:
- Cluster status and quorum
- Node resources (CPU, memory, uptime)
- VM metrics (QEMU/KVM)
- LXC container metrics
- Storage pool usage
"""

from fivenines_agent.debug import debug, log

try:
    from proxmoxer import ProxmoxAPI
except ImportError:
    ProxmoxAPI = None  # type: ignore[assignment, misc]


class ProxmoxCollector:
    """Collector for Proxmox VE metrics."""

    def __init__(self, host="localhost", port=8006,
                 token_id=None, token_secret=None, verify_ssl=True):
        """
        Initialize Proxmox connection.

        Args:
            host: Proxmox host address
            port: Proxmox API port (default 8006)
            token_id: API token ID for token auth (e.g., user@pam!mytoken)
            token_secret: API token secret
            verify_ssl: Whether to verify SSL certificates
        """
        self.host = host
        self.port = port
        self.verify_ssl = verify_ssl
        self.proxmox = None
        self._connect(token_id, token_secret)

    def _connect(self, token_id, token_secret):
        """Establish connection to Proxmox API."""
        try:
            if token_id and token_secret:
                # Token-based authentication
                self.proxmox = ProxmoxAPI(
                    self.host,
                    port=self.port,
                    user=token_id.split('!')[0] if '!' in token_id else token_id,
                    token_name=token_id.split('!')[1] if '!' in token_id else None,
                    token_value=token_secret,
                    verify_ssl=self.verify_ssl
                )
                log(f"Connected to Proxmox at {self.host}:{self.port} using API token", 'debug')
            else:
                log("No valid authentication credentials provided for Proxmox", 'error')
        except Exception as e:
            log(f"Failed to connect to Proxmox at {self.host}:{self.port}: {e}", 'error')
            self.proxmox = None

    def _safe_append(self, data, metric_name, value, labels):
        """Safely append a metric to the data list."""
        try:
            if value is not None:
                data.append({
                    'name': metric_name,
                    'value': value,
                    'labels': labels
                })
        except Exception as e:
            log(f"Error appending metric {metric_name}: {e}", 'error')

    def collect(self):
        """Collect all Proxmox metrics."""
        if not self.proxmox:
            return None

        result = {
            'version': None,
            'cluster': None,
            'nodes': [],
            'vms': [],
            'lxc': [],
            'storage': []
        }

        try:
            # Get Proxmox version
            version_info = self.proxmox.version.get()
            result['version'] = version_info.get('version', 'unknown')
            log(f"Proxmox version: {result['version']}", 'debug')
        except Exception as e:
            log(f"Error getting Proxmox version: {e}", 'error')

        # Collect cluster status
        try:
            result['cluster'] = self._collect_cluster()
        except Exception as e:
            log(f"Error collecting cluster metrics: {e}", 'error')

        # Collect node metrics
        try:
            result['nodes'] = self._collect_nodes()
        except Exception as e:
            log(f"Error collecting node metrics: {e}", 'error')

        # Collect VM metrics
        try:
            result['vms'] = self._collect_vms()
        except Exception as e:
            log(f"Error collecting VM metrics: {e}", 'error')

        # Collect LXC metrics
        try:
            result['lxc'] = self._collect_lxc()
        except Exception as e:
            log(f"Error collecting LXC metrics: {e}", 'error')

        # Collect storage metrics
        try:
            result['storage'] = self._collect_storage()
        except Exception as e:
            log(f"Error collecting storage metrics: {e}", 'error')

        return result

    def _collect_cluster(self):
        """Collect cluster status information."""
        try:
            cluster_status = self.proxmox.cluster.status.get()

            cluster_info = None
            nodes_total = 0
            nodes_online = 0

            for item in cluster_status:
                if item.get('type') == 'cluster':
                    cluster_info = {
                        'name': item.get('name'),
                        'quorate': item.get('quorate', 0) == 1,
                        'nodes': item.get('nodes', 0),
                        'nodes_online': 0  # Will be counted below
                    }
                elif item.get('type') == 'node':
                    nodes_total += 1
                    if item.get('online', 0) == 1:
                        nodes_online += 1

            if cluster_info:
                cluster_info['nodes'] = nodes_total
                cluster_info['nodes_online'] = nodes_online
                return cluster_info

            # Single node (not in cluster)
            return None

        except Exception as e:
            log(f"Error getting cluster status: {e}", 'debug')
            return None

    def _collect_nodes(self):
        """Collect metrics for all nodes."""
        nodes = []
        try:
            node_list = self.proxmox.nodes.get()

            for node_info in node_list:
                node_name = node_info.get('node')
                if not node_name:
                    continue

                try:
                    # Get detailed node status
                    node_status = self.proxmox.nodes(node_name).status.get()

                    # Count running VMs and LXC containers
                    vms_running = 0
                    lxc_running = 0

                    try:
                        qemu_list = self.proxmox.nodes(node_name).qemu.get()
                        vms_running = sum(1 for vm in qemu_list if vm.get('status') == 'running')
                    except Exception:
                        pass

                    try:
                        lxc_list = self.proxmox.nodes(node_name).lxc.get()
                        lxc_running = sum(1 for ct in lxc_list if ct.get('status') == 'running')
                    except Exception:
                        pass

                    node_data = {
                        'name': node_name,
                        'status': node_info.get('status', 'unknown'),
                        'cpu_usage': node_info.get('cpu', 0),
                        'memory_used': node_info.get('mem', 0),
                        'memory_total': node_info.get('maxmem', 0),
                        'uptime': node_status.get('uptime', 0),
                        'vms_running': vms_running,
                        'lxc_running': lxc_running
                    }
                    nodes.append(node_data)

                except Exception as e:
                    log(f"Error getting status for node {node_name}: {e}", 'error')

        except Exception as e:
            log(f"Error listing nodes: {e}", 'error')

        return nodes

    def _collect_vms(self):
        """Collect metrics for all QEMU/KVM VMs."""
        vms = []
        try:
            node_list = self.proxmox.nodes.get()

            for node_info in node_list:
                node_name = node_info.get('node')
                if not node_name:
                    continue

                try:
                    qemu_list = self.proxmox.nodes(node_name).qemu.get()

                    for vm in qemu_list:
                        vmid = vm.get('vmid')
                        if vmid is None:
                            continue

                        vm_data = {
                            'vmid': vmid,
                            'name': vm.get('name', f'vm-{vmid}'),
                            'node': node_name,
                            'status': vm.get('status', 'unknown'),
                            'cpu_usage': vm.get('cpu', 0),
                            'memory_used': vm.get('mem', 0),
                            'memory_max': vm.get('maxmem', 0),
                            'disk_read': vm.get('diskread', 0),
                            'disk_write': vm.get('diskwrite', 0),
                            'net_in': vm.get('netin', 0),
                            'net_out': vm.get('netout', 0),
                            'uptime': vm.get('uptime', 0)
                        }
                        vms.append(vm_data)

                except Exception as e:
                    log(f"Error getting VMs for node {node_name}: {e}", 'error')

        except Exception as e:
            log(f"Error listing VMs: {e}", 'error')

        return vms

    def _collect_lxc(self):
        """Collect metrics for all LXC containers."""
        containers = []
        try:
            node_list = self.proxmox.nodes.get()

            for node_info in node_list:
                node_name = node_info.get('node')
                if not node_name:
                    continue

                try:
                    lxc_list = self.proxmox.nodes(node_name).lxc.get()

                    for ct in lxc_list:
                        vmid = ct.get('vmid')
                        if vmid is None:
                            continue

                        ct_data = {
                            'vmid': vmid,
                            'name': ct.get('name', f'ct-{vmid}'),
                            'node': node_name,
                            'status': ct.get('status', 'unknown'),
                            'cpu_usage': ct.get('cpu', 0),
                            'memory_used': ct.get('mem', 0),
                            'memory_max': ct.get('maxmem', 0),
                            'disk_read': ct.get('diskread', 0),
                            'disk_write': ct.get('diskwrite', 0),
                            'net_in': ct.get('netin', 0),
                            'net_out': ct.get('netout', 0),
                            'uptime': ct.get('uptime', 0)
                        }
                        containers.append(ct_data)

                except Exception as e:
                    log(f"Error getting LXC containers for node {node_name}: {e}", 'error')

        except Exception as e:
            log(f"Error listing LXC containers: {e}", 'error')

        return containers

    def _collect_storage(self):
        """Collect metrics for all storage pools."""
        storage_pools = []
        try:
            node_list = self.proxmox.nodes.get()

            for node_info in node_list:
                node_name = node_info.get('node')
                if not node_name:
                    continue

                try:
                    storage_list = self.proxmox.nodes(node_name).storage.get()

                    for storage in storage_list:
                        storage_name = storage.get('storage')
                        if not storage_name:
                            continue

                        storage_data = {
                            'name': storage_name,
                            'node': node_name,
                            'type': storage.get('type', 'unknown'),
                            'total': storage.get('total', 0),
                            'used': storage.get('used', 0),
                            'available': storage.get('avail', 0),
                            'active': storage.get('active', 0) == 1
                        }
                        storage_pools.append(storage_data)

                except Exception as e:
                    log(f"Error getting storage for node {node_name}: {e}", 'error')

        except Exception as e:
            log(f"Error listing storage: {e}", 'error')

        return storage_pools


@debug('proxmox_metrics')
def proxmox_metrics(host="localhost", port=8006,
                    token_id=None, token_secret=None, verify_ssl=True):
    """
    Collect Proxmox VE metrics.

    Args:
        host: Proxmox host address
        port: Proxmox API port (default 8006)
        token_id: API token ID for token auth (e.g., user@pam!mytoken)
        token_secret: API token secret
        verify_ssl: Whether to verify SSL certificates

    Returns:
        dict: Proxmox metrics data or None if collection fails
    """
    if ProxmoxAPI is None:
        log("proxmoxer not available, skipping Proxmox metrics", "debug")
        return None
    try:
        collector = ProxmoxCollector(
            host=host,
            port=port,
            token_id=token_id,
            token_secret=token_secret,
            verify_ssl=verify_ssl
        )
        return collector.collect()
    except Exception as e:
        log(f"Error collecting Proxmox metrics: {e}", 'error')
        return None
