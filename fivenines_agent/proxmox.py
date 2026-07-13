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
except ImportError:  # pragma: no cover
    ProxmoxAPI = None  # type: ignore[assignment, misc]


# Defensive cap on the collection.error hint. The messages the collector emits
# are short and structured; this only bounds a pathological value.
_ERROR_MAX_LEN = 500


def _record_failure(collection, flag, message):
    """Flip a section completeness flag off and record the first failure.

    `collection` is the mutable flags block collect() threads through every
    section. It is None when a _collect_* helper is exercised in isolation (the
    unit tests call them directly), in which case recording is a no-op so the
    helper's return value is unchanged. collect() runs the sections in a fixed
    order (cluster, nodes, vms, lxc, storage), so the first message recorded is
    deterministic: it wins, and later failures only flip their own flag.
    """
    if collection is None:
        return
    collection[flag] = False
    if collection["error"] is None:
        collection["error"] = message[:_ERROR_MAX_LEN]


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
        """Collect all Proxmox metrics.

        Returns None when the Proxmox API is unreachable (host down, connection
        refused, or auth failure). proxmoxer builds the token-auth client
        lazily, so an unreachable API is not caught at construction time --
        every request raises instead. Left un-normalized the result would be
        an empty-but-shaped dict a reachable node can never produce (it always
        reports a version and lists at least itself) yet still easy to misread
        as "empty but healthy". Collapsing whole-module failure to None gives
        the server one unambiguous signal -- data["proxmox"] is null iff the
        API was unreachable -- instead of inferring reachability from empty
        arrays.

        A non-null payload also carries an explicit `collection` flags block
        (reachable / cluster_ok / nodes_ok / guests_ok / storage_ok / error),
        ceph-style, so the server no longer has to infer per-section
        completeness from the payload shape. Each *_ok flag is True iff every
        API call backing that section succeeded (`guests_ok` covers both the
        qemu and lxc loops); `error` is the first failure message. The key
        disambiguation the block adds: cluster:null with cluster_ok True is a
        genuine standalone node, whereas cluster:null with cluster_ok False is
        a clustered reporter whose /cluster/status call failed -- two shapes
        the server otherwise could not tell apart. See
        tests/fixtures/proxmox_contract_payload.json.
        """
        if not self.proxmox:
            return None

        result = {
            'version': None,
            'cluster': None,
            'nodes': [],
            'vms': [],
            'lxc': [],
            'storage': [],
            'collection': {
                'reachable': False,
                'cluster_ok': True,
                'nodes_ok': True,
                'guests_ok': True,
                'storage_ok': True,
                'error': None,
            },
        }
        collection = result['collection']

        reachable = False

        try:
            # Get Proxmox version
            version_info = self.proxmox.version.get()
            result['version'] = version_info.get('version', 'unknown')
            reachable = True
            log(f"Proxmox version: {result['version']}", 'debug')
        except Exception as e:
            log(f"Error getting Proxmox version: {e}", 'error')

        if not reachable:
            # /version failed. Probe the node listing before declaring the
            # whole module unreachable: a reachable-but-restricted token whose
            # /version is denied still enumerates nodes and must count as
            # reachable (partial payload), whereas a down/unreachable API fails
            # here too and yields a None payload the server reads as
            # unreachable.
            try:
                self.proxmox.nodes.get()
                reachable = True
            except Exception as e:
                log(f"Proxmox API unreachable, skipping collection: {e}", 'debug')
                return None

        # We reached this point, so the API responded (an unreachable API
        # returned None above). State reachability explicitly rather than
        # leaving the server to re-derive it from a non-null payload.
        collection['reachable'] = True

        # Collect cluster status
        try:
            result['cluster'] = self._collect_cluster(collection)
        except Exception as e:
            log(f"Error collecting cluster metrics: {e}", 'error')
            _record_failure(collection, 'cluster_ok', 'cluster status query failed')

        # Collect node metrics
        try:
            result['nodes'] = self._collect_nodes(collection)
        except Exception as e:
            log(f"Error collecting node metrics: {e}", 'error')
            _record_failure(collection, 'nodes_ok', 'node listing failed')

        # Collect VM metrics
        try:
            result['vms'] = self._collect_vms(collection)
        except Exception as e:
            log(f"Error collecting VM metrics: {e}", 'error')
            _record_failure(collection, 'guests_ok', 'node listing failed')

        # Collect LXC metrics
        try:
            result['lxc'] = self._collect_lxc(collection)
        except Exception as e:
            log(f"Error collecting LXC metrics: {e}", 'error')
            _record_failure(collection, 'guests_ok', 'node listing failed')

        # Collect storage metrics
        try:
            result['storage'] = self._collect_storage(collection)
        except Exception as e:
            log(f"Error collecting storage metrics: {e}", 'error')
            _record_failure(collection, 'storage_ok', 'node listing failed')

        return result

    def _collect_cluster(self, collection=None):
        """Collect cluster status information.

        Returns None both for a genuine standalone node (no cluster-type entry
        in /cluster/status) and when the /cluster/status call itself fails --
        but only the latter flips cluster_ok, so the server can tell the two
        apart. A standalone node leaves cluster_ok True.
        """
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
            _record_failure(collection, 'cluster_ok', 'cluster status query failed')
            return None

    def _collect_nodes(self, collection=None):
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
                        'cpu_usage': node_info.get('cpu') or 0,
                        'memory_used': node_info.get('mem') or 0,
                        'memory_total': node_info.get('maxmem') or 0,
                        'uptime': node_status.get('uptime') or 0,
                        'vms_running': vms_running,
                        'lxc_running': lxc_running
                    }
                    nodes.append(node_data)

                except Exception as e:
                    log(f"Error getting status for node {node_name}: {e}", 'error')
                    _record_failure(
                        collection,
                        'nodes_ok',
                        f'node {node_name}: status query failed',
                    )

        except Exception as e:
            log(f"Error listing nodes: {e}", 'error')
            _record_failure(collection, 'nodes_ok', 'node listing failed')

        return nodes

    def _collect_vms(self, collection=None):
        """Collect metrics for all QEMU/KVM VMs."""
        vms = []
        try:
            node_list = self.proxmox.nodes.get()

            for node_info in node_list:
                node_name = node_info.get('node')
                if not node_name:
                    continue

                try:
                    # full=1 makes Proxmox query each VM's QEMU monitor for
                    # diskread/diskwrite. Without it those fields are null.
                    # ~3ms per running VM extra.
                    qemu_list = self.proxmox.nodes(node_name).qemu.get(full=1)

                    for vm in qemu_list:
                        vmid = vm.get('vmid')
                        if vmid is None:
                            continue

                        vm_data = {
                            'vmid': vmid,
                            'name': vm.get('name', f'vm-{vmid}'),
                            'node': node_name,
                            'status': vm.get('status', 'unknown'),
                            'cpu_usage': vm.get('cpu') or 0,
                            'memory_used': vm.get('mem') or 0,
                            'memory_max': vm.get('maxmem') or 0,
                            'disk_read': vm.get('diskread') or 0,
                            'disk_write': vm.get('diskwrite') or 0,
                            'net_in': vm.get('netin') or 0,
                            'net_out': vm.get('netout') or 0,
                            'uptime': vm.get('uptime') or 0
                        }
                        vms.append(vm_data)

                except Exception as e:
                    log(f"Error getting VMs for node {node_name}: {e}", 'error')
                    _record_failure(
                        collection,
                        'guests_ok',
                        f'node {node_name}: qemu query failed',
                    )

        except Exception as e:
            log(f"Error listing VMs: {e}", 'error')
            _record_failure(collection, 'guests_ok', 'node listing failed')

        return vms

    def _collect_lxc(self, collection=None):
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
                            'cpu_usage': ct.get('cpu') or 0,
                            'memory_used': ct.get('mem') or 0,
                            'memory_max': ct.get('maxmem') or 0,
                            'disk_read': ct.get('diskread') or 0,
                            'disk_write': ct.get('diskwrite') or 0,
                            'net_in': ct.get('netin') or 0,
                            'net_out': ct.get('netout') or 0,
                            'uptime': ct.get('uptime') or 0
                        }
                        containers.append(ct_data)

                except Exception as e:
                    log(f"Error getting LXC containers for node {node_name}: {e}", 'error')
                    _record_failure(
                        collection,
                        'guests_ok',
                        f'node {node_name}: lxc query failed',
                    )

        except Exception as e:
            log(f"Error listing LXC containers: {e}", 'error')
            _record_failure(collection, 'guests_ok', 'node listing failed')

        return containers

    def _collect_storage(self, collection=None):
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
                            'total': storage.get('total') or 0,
                            'used': storage.get('used') or 0,
                            'available': storage.get('avail') or 0,
                            'active': storage.get('active', 0) == 1
                        }
                        storage_pools.append(storage_data)

                except Exception as e:
                    log(f"Error getting storage for node {node_name}: {e}", 'error')
                    _record_failure(
                        collection,
                        'storage_ok',
                        f'node {node_name}: storage query failed',
                    )

        except Exception as e:
            log(f"Error listing storage: {e}", 'error')
            _record_failure(collection, 'storage_ok', 'node listing failed')

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
