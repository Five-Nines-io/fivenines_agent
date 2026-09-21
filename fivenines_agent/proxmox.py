"""
Proxmox VE monitoring collector.

Collects metrics from Proxmox VE clusters and standalone nodes including:
- Cluster status and quorum
- Node resources (CPU, memory, uptime)
- VM metrics (QEMU/KVM)
- LXC container metrics
- Storage pool usage
- Backups (#156): per-guest latest backup per storage, vzdump task outcomes,
  backup job definitions and guests covered by no job -- everything the server
  needs to answer "has every guest had a backup in the last N hours, whatever
  the target" without a new credential (all four reads sit inside PVEAuditor)
"""

import time

from fivenines_agent.cache import TTLCache
from fivenines_agent.debug import debug, log
from fivenines_agent.logs import redact

try:
    from proxmoxer import ProxmoxAPI
except ImportError:  # pragma: no cover
    ProxmoxAPI = None  # type: ignore[assignment, misc]


# Defensive cap on the collection.error hint. The messages the collector emits
# are short and structured; this only bounds a pathological value.
_ERROR_MAX_LEN = 500

# Prefix bound applied to a raw error message BEFORE redact() runs over it, so a
# pathological (customer-controlled) blob cannot turn the redaction regexes into
# a CPU sink on the watchdog-bounded loop; the final _ERROR_MAX_LEN cap trims the
# redacted result. Same posture as the ceph stderr envelope.
_ERROR_PRE_REDACT_MAX_LEN = 2000

# C0 + C1 control characters (incl. newlines) mapped to a space, so a
# customer-controlled value (a PVE error body, a volid, a storage id) written to
# a journal log line cannot forge extra log lines. The wire path already scrubs
# and redacts (see _backup_error); _log_safe gives the log path the same guard.
_LOG_CONTROL_TO_SPACE = {
    c: ord(" ") for c in list(range(0x20)) + [0x7F] + list(range(0x80, 0xA0))
}

# --- backups block (#156) ---------------------------------------------------
#
# The storage content listing is the most expensive call this collector makes
# (a PBS datastore with thousands of snapshots, proxied through to PBS) and
# backup age has a granularity of hours, so the whole block is computed once
# per BACKUPS_CACHE_TTL through the shared TTLCache and re-emitted with `age_s`
# in between. Not a config key: config["proxmox"] is splatted into
# proxmox_metrics(**config), so a key the server started sending would be a
# TypeError on every older agent and kill the whole Proxmox collector there.
BACKUPS_CACHE_TTL = 600

# Wall-clock budget for one build of the block. proxmoxer bounds each request
# at 5s (its default `timeout`), but the block chains 1 + 2*nodes + storages
# + 2 requests, so a wedged PVE/PBS could otherwise hold the single-threaded,
# WatchdogSec=90 collection loop for a minute (the docker COLLECT_DEADLINE /
# openvpn _COLLECT_DEADLINE / agent PING_LOOP_DEADLINE posture). Once the
# budget is spent, every remaining read is SKIPPED and recorded in `errors`
# under its own scope with _DEADLINE_MESSAGE, so the server reads its guests
# as unknown -- a short block is never mistaken for a complete one. The budget
# is checked BETWEEN reads, so on a healthy endpoint the worst case is the
# ~10s ungated prefix (the node list + the one /storage config call, neither
# budget-gated) plus the budget plus one in-flight request; proxmoxer's 5s is
# an inactivity timeout, so a single slow-trickling PBS listing can still run
# past it (bounded by the response size, not the clock) -- the PVE API is the
# operator's own server.
BACKUPS_COLLECT_DEADLINE = 30
_DEADLINE_MESSAGE = 'skipped: backups collection deadline exceeded'

# The PVE content index filters backup volumes PER-VOLUME: an audit-only token
# (the PVEAuditor role the setup guide provisions) gets HTTP 200 with the
# backups REMOVED, indistinguishable from a storage that genuinely has none.
# Confirmed on a real PVE (agent #156): root sees the volume, a Datastore.Audit
# token sees []. Only a token holding this privilege on the storage sees backup
# volumes, so WITHOUT it an empty content read is untrustworthy and the storage
# is reported `unknown` (a scoped error) rather than emitting a false "never
# backed up". Checked on the storage path or an ancestor (ACL propagation).
_BACKUP_READ_PRIV = 'Datastore.Allocate'
_NO_BACKUP_PRIV_MESSAGE = (
    'insufficient privilege to list backups: the token needs Datastore.Allocate '
    'on this storage (PVEAuditor cannot see backup volumes)'
)

# Hard caps on every array in the block. A trim is never silent: it lands in
# `errors` with scope "cap", because a trimmed guest_backups reads as "never
# backed up" for whoever fell off the end.
MAX_GUEST_BACKUPS = 5000
MAX_TASKS_PER_NODE = 50
MAX_BACKUP_JOBS = 200
MAX_NOT_BACKED_UP = 2000
# A degraded cluster (every node erroring, or 1000s of nodes past the deadline)
# must not emit an unbounded `errors` array. Past this many entries the tail is
# dropped and one 'cap'-scope error records how many, so the payload stays
# bounded without hiding that the read was massively incomplete.
MAX_ERRORS = 500

# Every string in the block is customer-controlled (volid, task status, job
# comment...). Bound each one so a pathological value cannot bloat the tick.
_BACKUP_FIELD_MAX_LEN = 500

# Keyed on the connection identity (host, port, token id) the way ceph keys on
# its conf/keyring: proxmox_metrics builds a fresh ProxmoxCollector every tick,
# so the cache has to live at module level, and a re-pointed config must not be
# served the previous cluster's block for the rest of the TTL.
_backups_cache = TTLCache()


def _scrub_str(value, max_len=_BACKUP_FIELD_MAX_LEN):
    """Make a customer-controlled value safe for the wire: UTF-8 with invalid
    sequences replaced, NUL deleted (Postgres refuses to store it), capped.

    None stays None so "the daemon reported no value" survives as null.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    # Bound the work BEFORE the encode/decode/replace pass: a pathological
    # multi-MB field from a hostile PVE response must not be fully re-encoded on
    # the watchdog loop to return max_len chars. Slicing a str is by code point,
    # so a generous pre-slice yields the same result for any real (short) value;
    # NUL removal only shrinks, so the final [:max_len] still holds.
    cleaned = value[:max_len].encode("utf-8", errors="replace").decode(
        "utf-8", errors="replace"
    )
    return cleaned.replace("\x00", "")[:max_len]


def _scrub_csv(value, max_len=_BACKUP_FIELD_MAX_LEN):
    """Scrub a comma-separated ID list (a job's `vmid`/`exclude`) WITHOUT
    splitting an ID. A plain char cap can turn ",224" into ",22" and name a
    guest that was never configured; truncate at the last comma instead, so the
    result is always a prefix of WHOLE ids.
    """
    cleaned = _scrub_str(value, max_len=_ERROR_PRE_REDACT_MAX_LEN)
    if cleaned is None or len(cleaned) <= max_len:
        return cleaned
    cut = cleaned.rfind(',', 0, max_len)
    return cleaned[:cut] if cut != -1 else cleaned[:max_len]


def _as_int(value):
    """int() that answers None instead of raising on anything non-numeric.

    Bools are refused: True would otherwise read as vmid 1.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _as_bool(value):
    """PVE spells booleans as 0/1 ints, "0"/"1" strings, and -- for a PBS
    volume's `encrypted` -- the key fingerprint or "1"."""
    if isinstance(value, str):
        return value.strip() not in ("", "0")
    return bool(value)


def _backup_error(errors, scope, message, node=None, storage=None):
    """Append one structured failure to the block's `errors` list.

    Per-storage entries are load-bearing, not diagnostics: the server's rule for
    a partial read is that a guest with NO backup found is `unknown`, never
    `never`/`aged`, because its backups may live on the storage that failed --
    which only works if the entry says WHICH storage. The message carries the
    API's own reason (a 403 naming the missing privilege is the hint the
    operator needs) through the same prefix-bound + redact + cap posture as the
    ceph error envelope.
    """
    errors.append({
        "scope": scope,
        # node/storage are customer-controlled (a hostile PVE can return an
        # oversized/NUL-laden node name); bound them like every other field.
        "node": _scrub_str(node),
        "storage": _scrub_str(storage),
        "message": _scrub_str(
            redact(str(message)[:_ERROR_PRE_REDACT_MAX_LEN]), _ERROR_MAX_LEN
        ),
    })


def _log_safe(value):
    """Make a customer-controlled value safe to interpolate into a log line:
    redact secrets (a PVE error body can echo a credential, the reason this
    module imports redact) and collapse control characters so a newline in a
    volid, storage id, or error body cannot forge journal lines. The wire path
    guards `errors[].message` the same way -- the log path must match it,
    including the pre-redact prefix bound: a proxmoxer exception's str() carries
    the full HTTP error body, so redact() must never see an unbounded blob on
    the watchdog-bounded loop.
    """
    bounded = str(value)[:_ERROR_PRE_REDACT_MAX_LEN]
    return redact(bounded).translate(_LOG_CONTROL_TO_SPACE)[:_ERROR_MAX_LEN]


def _cap_list(rows, limit, errors, noun, node=None):
    """Trim `rows` to `limit`, recording a 'cap'-scope error naming how many
    were dropped when it trims -- a trimmed array must never be mistaken for a
    complete one (a dropped guest_backups entry reads as "never backed up").
    """
    if len(rows) > limit:
        _backup_error(
            errors,
            'cap',
            f'{noun} capped at {limit}: {len(rows) - limit} dropped',
            node=node,
        )
        return rows[:limit]
    return rows


def _as_list_or_error(listing, errors, scope, node=None, storage=None):
    """Return `listing` if it is a list, else record a scoped error and return
    None. A dict/str/None envelope (a malformed response or a proxmoxer quirk)
    must never be iterated into a silent empty result -- that reads as "no
    backups" when the truth is "unreadable", the false all-clear this block
    exists to prevent.
    """
    if isinstance(listing, list):
        return listing
    _backup_error(
        errors, scope, 'unexpected response shape (not a list)',
        node=node, storage=storage,
    )
    return None


def _has_backup_read_priv(perms, sid):
    """Whether an empty backup content read on storage `sid` can be TRUSTED.

    PVE filters backup volumes per-volume, so an audit-only token gets an empty
    200 whether or not backups exist. Only a token holding _BACKUP_READ_PRIV on
    the storage (or an ancestor path, honouring ACL propagation) sees them.
    `perms` is None when the effective-permissions read failed: degrade to True
    (attempt the read best-effort) rather than freezing every storage unknown on
    a transient blip.
    """
    if perms is None:
        return True
    for path in (f"/storage/{sid}", "/storage", "/"):
        node = perms.get(path)
        if isinstance(node, dict) and node.get(_BACKUP_READ_PRIV):
            return True
    return False


def _deadline_hit(deadline, errors, scope, node=None, storage=None):
    """True (and one `errors` entry recorded) when the block's wall-clock
    budget is spent; False when there is still time or no budget applies
    (`deadline` None, the unit-test entry point)."""
    if deadline is None or time.monotonic() < deadline:
        return False
    _backup_error(errors, scope, _DEADLINE_MESSAGE, node=node, storage=storage)
    return True


def _holds_backups(storage):
    """Whether a per-node storage row is worth a content listing.

    A storage whose `content` set lacks `backup` (lvmthin, zfspool, rbd...)
    cannot hold one, and a `disable`d storage is one the operator took out of
    service on purpose -- listing it would fail every TTL and keep the block
    permanently partial. When `content` is missing (older PVE) we list anyway.
    """
    content = storage.get("content")
    if isinstance(content, str) and "backup" not in content.split(","):
        return False
    if "enabled" in storage and not _as_bool(storage["enabled"]):
        return False
    return True


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
        # Identity of the cluster this collector talks to, for the backups TTL
        # cache. verify_ssl is part of it (a TLS-posture change must invalidate);
        # the secret is deliberately not, so it never sits in a cache key -- a
        # rotated secret on the same token_id serves the same cluster's block
        # for at most the TTL, which is benign.
        self._backups_cache_key = (host, port, token_id, verify_ssl)
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

        `backups` (#156) is the one section OUTSIDE the flags block. It carries
        its own three-level signal -- key absent (older agent: "unknown"),
        null (the block could not be built at all), or an object whose
        `errors` list names every sub-read that failed -- and never touches
        `collection`: on the server completeness_score is a stored generated
        column over the five flags that elects the authoritative reporter, so
        a sixth bit would be a migration plus a rollout window in which every
        not-yet-upgraded reporter loses authority. The _storage_config_map
        precedent, applied to a whole block.
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
            'backups': None,
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

        # Backups block (#156): deliberately NOT recorded into `collection`
        # (see the docstring). A failure here is backups:null, nothing else.
        try:
            result['backups'] = self._collect_backups()
        except Exception as e:
            log(f"Error collecting backup metrics: {e}", 'error')
            result['backups'] = None

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

    def _storage_config_map(self):
        """Map storage id -> its datacenter /storage config entry.

        The per-node /nodes/<n>/storage endpoint returns runtime status only
        (total/used/avail/active); the 'pool' property -- a zfspool's ZFS
        dataset (e.g. 'rpool/data'), an rbd/cephfs's Ceph pool -- lives in the
        cluster-wide datacenter storage config (/storage). One call per collect,
        used to enrich each per-node storage row with the ZFS<->Proxmox join key
        (issue #49). Best-effort: a restricted token that cannot read /storage,
        or an older PVE, yields {} and no 'pool' enrichment rather than failing
        the storage section -- deliberately NOT threaded through the `collection`
        flags block, so it never flips storage_ok.
        """
        config = {}
        try:
            for entry in self.proxmox.storage.get():
                storage_id = entry.get('storage')
                if storage_id:
                    config[storage_id] = entry
        except Exception as e:
            log(f"Error listing datacenter storage config: {e}", 'debug')
        return config

    def _effective_permissions(self):
        """The agent's own effective permission map (/access/permissions), used
        to tell "no backups" apart from "backups hidden by per-volume filtering"
        (#156). Best-effort: None on any failure, so the caller degrades to a
        plain read instead of freezing every storage unknown.
        """
        try:
            perms = self.proxmox.access.permissions.get()
        except Exception as e:
            log(f"Error reading effective permissions for backups: {_log_safe(e)}", 'debug')
            return None
        return perms if isinstance(perms, dict) else None

    def _collect_storage(self, collection=None):
        """Collect metrics for all storage pools."""
        storage_pools = []
        try:
            node_list = self.proxmox.nodes.get()

            # Datacenter storage config (/storage), one cluster-wide call, maps
            # storage id -> its config entry so each per-node storage row can be
            # enriched with 'pool' (the ZFS<->Proxmox join key, issue #49).
            config_map = self._storage_config_map()

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

                        # Additive 'pool' enrichment: present only for storage
                        # types that carry one (zfspool/rbd/cephfs), omitted
                        # (never null) otherwise, so a host with only dir/lvmthin
                        # stays byte-identical to the pre-field payload.
                        pool = config_map.get(storage_name, {}).get('pool')
                        if pool is not None:
                            storage_data['pool'] = pool

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

    # --- backups block (#156) -----------------------------------------------

    def _collect_backups(self):
        """Return the `backups` block, computed at most once per TTL.

        The cached value is (computed_at_monotonic, block); every tick inside
        the TTL re-emits the same block with a fresh `age_s` = seconds since it
        was computed, the subscribed_age_s / handshake-age pattern: the server
        anchors freshness as received_at - age_s and never trusts the agent's
        wall clock. `latest_ctime` and the task times are PVE's own data
        timestamps and pass through untouched.

        store_if rejects None so a failed build (node listing down) is retried
        next tick and a recovered API is reported promptly instead of serving
        the failure for the rest of the TTL. A PARTIAL block (some sub-read in
        `errors`) IS cached: retrying a 403 every tick would not change it, and
        the per-storage errors already tell the server what is missing.
        """
        cached = _backups_cache.get_or_compute(
            self._backups_cache_key,
            BACKUPS_CACHE_TTL,
            self._build_backups_block,
            store_if=lambda value: value is not None,
        )
        if cached is None:
            return None
        computed_at, block = cached
        age = int(time.monotonic() - computed_at)
        return {'age_s': max(age, 0), **block}

    def _build_backups_block(self):
        """One full pass over the four reads. None iff the node listing fails
        (nothing below can run without it); every other failure is an entry
        in `errors` and the block is still emitted with whatever was read."""
        deadline = time.monotonic() + BACKUPS_COLLECT_DEADLINE
        try:
            node_list = self.proxmox.nodes.get()
        except Exception as e:
            log(f"Error listing nodes for backups: {_log_safe(e)}", 'error')
            return None
        # A non-list node envelope is a build failure, not an empty cluster:
        # backups:null, never a block of empty arrays the server reads as
        # "no backups anywhere".
        if not isinstance(node_list, list):
            log("Proxmox node listing for backups was not a list", 'error')
            return None

        node_names = [
            n.get('node') for n in node_list if isinstance(n, dict) and n.get('node')
        ]
        errors = []
        block = {
            'guest_backups': self._collect_guest_backups(node_names, errors, deadline),
            'tasks': self._collect_vzdump_tasks(node_names, errors, deadline),
            'jobs': self._collect_backup_jobs(errors, deadline),
            'not_backed_up': self._collect_not_backed_up(errors, deadline),
            'errors': errors,
        }
        # Bound the errors array itself (a 1000-node cluster past the deadline
        # would otherwise emit thousands of entries). errors is the same list
        # referenced by block['errors'], so trim it in place.
        if len(errors) > MAX_ERRORS:
            dropped = len(errors) - (MAX_ERRORS - 1)
            del errors[MAX_ERRORS - 1:]
            _backup_error(errors, 'cap', f'errors capped at {MAX_ERRORS}: {dropped} dropped')
        # Stamped AFTER the reads, like TTLCache's own timestamp, so a slow
        # PBS listing is not charged against the block's age.
        return (time.monotonic(), block)

    def _collect_guest_backups(self, node_names, errors, deadline=None):
        """Latest backup per (vmid, storage), aggregated agent-side.

        The raw listing is never shipped: a PBS datastore with thousands of
        snapshots would otherwise put thousands of entries on every emission.
        One entry per guest x storage-with-backups, carrying the latest
        volume's ctime/volid/size (+ verification/protected/encrypted when the
        storage reports them) and a count.

        A SHARED storage (PBS/NFS/CIFS) is the same content from every node,
        so it is listed once -- from the first node where it is active -- and
        emitted with node:null; a local storage is listed per node with node
        set. The `shared` flag comes from the per-node row, falling back to the
        datacenter /storage config. A storage that is inactive everywhere it is
        seen is not listed (the call would only fail) but IS recorded as an
        error naming it, so the server treats its guests as unknown. A storage
        the token lacks Datastore.Allocate on is also reported unknown WITHOUT a
        content read, because PVE would filter its backups to an empty list that
        is indistinguishable from "no backups" (#156).
        """
        config_map = self._storage_config_map()
        # One /access/permissions read tells a trustworthy empty ("no backups")
        # apart from a filtered empty ("backups hidden from an audit-only token").
        perms = self._effective_permissions()
        latest = {}
        shared_done = set()
        shared_inactive = set()

        for node_name in node_names:
            if _deadline_hit(deadline, errors, 'storage', node=node_name):
                continue
            try:
                storage_list = self.proxmox.nodes(node_name).storage.get()
            except Exception as e:
                log(
                    f"Error listing storage on {_log_safe(node_name)} "
                    f"for backups: {_log_safe(e)}",
                    'error',
                )
                _backup_error(
                    errors, 'storage', f'storage listing failed: {e}', node=node_name
                )
                continue
            storage_list = _as_list_or_error(storage_list, errors, 'storage', node=node_name)
            if storage_list is None:
                continue

            for storage in storage_list:
                if not isinstance(storage, dict):
                    continue
                raw_sid = storage.get('storage')
                if not raw_sid or not _holds_backups(storage):
                    continue
                storage_name = _scrub_str(raw_sid)
                shared = _as_bool(
                    storage.get('shared', config_map.get(raw_sid, {}).get('shared', 0))
                )
                active = _as_bool(storage.get('active', 0))

                if shared:
                    if storage_name in shared_done:
                        continue
                    if not active:
                        shared_inactive.add(storage_name)
                        continue
                    if not _has_backup_read_priv(perms, raw_sid):
                        # Cannot trust an empty read here: mark unknown once and
                        # do not re-error for this shared storage on later nodes.
                        _backup_error(
                            errors, 'storage', _NO_BACKUP_PRIV_MESSAGE,
                            storage=storage_name,
                        )
                        shared_done.add(storage_name)
                        shared_inactive.discard(storage_name)
                        continue
                    if _deadline_hit(
                        deadline, errors, 'storage', node=node_name, storage=storage_name
                    ):
                        # Budget spent: don't re-error for this storage on every
                        # later node (the deadline is global once hit).
                        shared_done.add(storage_name)
                        shared_inactive.discard(storage_name)
                        continue
                    # Mark done only on a SUCCESSFUL listing, so a transient
                    # failure on this node lets the next ACTIVE node retry the
                    # same shared storage rather than freezing its guests unknown.
                    if self._merge_backup_volumes(
                        node_name, storage_name, None, latest, errors
                    ):
                        shared_done.add(storage_name)
                        shared_inactive.discard(storage_name)
                elif not active:
                    _backup_error(
                        errors,
                        'storage',
                        'storage not active on this node',
                        node=node_name,
                        storage=storage_name,
                    )
                elif not _has_backup_read_priv(perms, raw_sid):
                    _backup_error(
                        errors, 'storage', _NO_BACKUP_PRIV_MESSAGE,
                        node=node_name, storage=storage_name,
                    )
                elif not _deadline_hit(
                    deadline, errors, 'storage', node=node_name, storage=storage_name
                ):
                    self._merge_backup_volumes(
                        node_name, storage_name, node_name, latest, errors
                    )

        # Every name left here was never active on a node that was scanned
        # (an active sighting discards it), so the set itself is the guard.
        for storage_name in shared_inactive:
            _backup_error(
                errors, 'storage', 'shared storage not active on any node',
                storage=storage_name,
            )

        entries = sorted(
            latest.values(), key=lambda e: (e['vmid'], e['storage'], e['node'] or '')
        )
        return _cap_list(entries, MAX_GUEST_BACKUPS, errors, 'guest_backups')

    def _merge_backup_volumes(self, node_name, storage_name, entry_node, latest, errors):
        """List one storage's backup volumes and fold them into `latest`.

        Aggregated into a local dict and merged only on success, so a listing
        that fails mid-way leaves no half-counted entry behind -- the storage
        is then an `errors` entry and nothing else. Volumes without `vmid` or
        `ctime` (both optional in the schema) are skipped: they cannot feed a
        latest-per-guest computation and must not produce a latest_ctime:null
        entry the server would have to special-case. Returns True on a clean
        listing (so the caller can mark a shared storage done only on success),
        False when the content read failed or was malformed.
        """
        try:
            volumes = (
                self.proxmox.nodes(node_name).storage(storage_name).content.get(content='backup')
            )
            if not isinstance(volumes, list):
                _backup_error(
                    errors, 'storage', 'unexpected response shape (not a list)',
                    node=node_name, storage=storage_name,
                )
                return False
            per_guest = {}
            undated = 0
            for volume in volumes:
                if not isinstance(volume, dict):
                    continue
                vmid = _as_int(volume.get('vmid'))
                ctime = _as_int(volume.get('ctime'))
                if vmid is None or ctime is None:
                    # A backup volume we cannot attribute or date: skip the entry
                    # (never emit latest_ctime:null) but count it, so the storage
                    # is flagged incomplete below and its unmatched guests read
                    # unknown, never a false "never backed up".
                    undated += 1
                    continue
                entry = per_guest.get(vmid)
                if entry is None:
                    entry = {
                        'vmid': vmid,
                        'storage': storage_name,
                        'node': _scrub_str(entry_node),
                        'latest_ctime': None,
                        'latest_volid': None,
                        'latest_size': None,
                        'count': 0,
                    }
                    per_guest[vmid] = entry
                entry['count'] += 1
                if entry['latest_ctime'] is None or ctime > entry['latest_ctime']:
                    _set_latest_volume(entry, volume, ctime)
        except Exception as e:
            log(
                f"Error listing backups on {_log_safe(node_name)}/"
                f"{_log_safe(storage_name)}: {_log_safe(e)}",
                'error',
            )
            _backup_error(
                errors,
                'storage',
                f'content listing failed: {e}',
                node=node_name,
                storage=storage_name,
            )
            return False

        if undated:
            _backup_error(
                errors,
                'storage',
                f'{undated} backup volume(s) skipped (missing vmid or ctime)',
                node=node_name,
                storage=storage_name,
            )
        for vmid, entry in per_guest.items():
            latest[(vmid, storage_name, entry_node)] = entry
        return True

    def _collect_vzdump_tasks(self, node_names, errors, deadline=None):
        """Finished vzdump tasks per node, `status` verbatim (capped).

        `status` is a free string -- OK, "WARNINGS: <n>", or an error message
        -- and the server classifies it, not the agent. `id` is the vmid only
        when exactly one guest was backed up (pve-manager VZDump.pm forks the
        worker with $local_vmids->[0] iff there is one); a scheduled
        multi-guest job has an empty id, shipped as null. Tasks are therefore a
        JOB-level signal; the per-guest verdict is guest_backups.
        """
        tasks = []
        for node_name in node_names:
            if _deadline_hit(deadline, errors, 'tasks', node=node_name):
                continue
            try:
                # Ask PVE for one more than the cap: PVE applies `limit`
                # server-side, so requesting exactly MAX_TASKS_PER_NODE would
                # make the _cap_list overflow check below unreachable and a node
                # with more tasks would drop the excess with no cap error. With
                # +1, an over-cap node still yields a 'cap'-scope error (the
                # dropped count is a floor once PVE itself has trimmed).
                listing = self.proxmox.nodes(node_name).tasks.get(
                    typefilter='vzdump', limit=MAX_TASKS_PER_NODE + 1
                )
            except Exception as e:
                log(
                    f"Error listing vzdump tasks on {_log_safe(node_name)}: {_log_safe(e)}",
                    'error',
                )
                _backup_error(errors, 'tasks', f'task listing failed: {e}', node=node_name)
                continue
            listing = _as_list_or_error(listing, errors, 'tasks', node=node_name)
            if listing is None:
                continue
            rows = [t for t in listing if isinstance(t, dict)]
            rows = _cap_list(rows, MAX_TASKS_PER_NODE, errors, 'tasks', node=node_name)

            for task in rows:
                tasks.append({
                    'upid': _scrub_str(task.get('upid')),
                    'node': _scrub_str(node_name),
                    'id': _scrub_str(task.get('id')) or None,
                    'starttime': _as_int(task.get('starttime')),
                    'endtime': _as_int(task.get('endtime')),
                    'status': _scrub_str(task.get('status')),
                    'user': _scrub_str(task.get('user')),
                })
        return tasks

    def _collect_backup_jobs(self, errors, deadline=None):
        """Backup job definitions from /cluster/backup: display context ("VM
        101 is backed up by job X to storage Y on schedule Z") and the schedule
        the server can size a default threshold from. bwlimit/compress/mailto/
        hooks are dropped. /cluster/backup/{id}/included_volumes is deliberately
        not read: it is an ExtJS tree, and not_backed_up answers its question.
        """
        if _deadline_hit(deadline, errors, 'jobs'):
            return []
        try:
            listing = self.proxmox.cluster.backup.get()
        except Exception as e:
            log(f"Error listing backup jobs: {_log_safe(e)}", 'error')
            _backup_error(errors, 'jobs', f'backup job listing failed: {e}')
            return []
        listing = _as_list_or_error(listing, errors, 'jobs')
        if listing is None:
            return []
        rows = [j for j in listing if isinstance(j, dict)]
        rows = _cap_list(rows, MAX_BACKUP_JOBS, errors, 'jobs')

        jobs = []
        for job in rows:
            schedule = job.get('schedule')
            if schedule is None and job.get('starttime') is not None:
                # Pre-7.0 job format (dow + starttime), spelled the way PVE's
                # own converter does so both formats read alike downstream.
                dow = job.get('dow')
                schedule = f"{dow} {job['starttime']}" if dow else str(job['starttime'])
            jobs.append({
                'id': _scrub_str(job.get('id')),
                'enabled': _as_bool(job.get('enabled', 1)),
                'schedule': _scrub_str(schedule),
                'storage': _scrub_str(job.get('storage')),
                'vmid': _scrub_csv(job.get('vmid')),
                'all': _as_bool(job.get('all', 0)),
                'exclude': _scrub_csv(job.get('exclude')),
                'pool': _scrub_str(job.get('pool')),
                'node': _scrub_str(job.get('node')),
                'mode': _scrub_str(job.get('mode')),
                'comment': _scrub_str(job.get('comment')),
                'next_run': _as_int(job.get('next-run')),
            })
        return jobs

    def _collect_not_backed_up(self, errors, deadline=None):
        """Guests covered by no backup job (/cluster/backup-info/not-backed-up):
        the signal a job-level webhook can never produce -- a guest that
        quietly dropped out of every job."""
        if _deadline_hit(deadline, errors, 'not_backed_up'):
            return []
        try:
            listing = self.proxmox.cluster('backup-info')('not-backed-up').get()
        except Exception as e:
            log(f"Error listing not-backed-up guests: {_log_safe(e)}", 'error')
            _backup_error(errors, 'not_backed_up', f'not-backed-up listing failed: {e}')
            return []
        listing = _as_list_or_error(listing, errors, 'not_backed_up')
        if listing is None:
            return []
        rows = [g for g in listing if isinstance(g, dict) and _as_int(g.get('vmid')) is not None]

        rows = _cap_list(rows, MAX_NOT_BACKED_UP, errors, 'not_backed_up')

        return [
            {
                'vmid': _as_int(g.get('vmid')),
                'name': _scrub_str(g.get('name')),
                'type': _scrub_str(g.get('type')),
            }
            for g in rows
        ]


def _set_latest_volume(entry, volume, ctime):
    """Overwrite the entry's latest-* fields from a newer volume. The optional
    PBS-only keys are re-derived from the new volume, never inherited from the
    one it replaces."""
    entry['latest_ctime'] = ctime
    entry['latest_volid'] = _scrub_str(volume.get('volid'))
    size = _as_int(volume.get('size'))
    if size is None:
        size = _as_int(volume.get('approximate-size'))
    entry['latest_size'] = size
    for key in ('verification', 'protected', 'encrypted'):
        entry.pop(key, None)
    verification = volume.get('verification')
    if isinstance(verification, dict):
        # PBS SnapshotVerifyState: state serialized lowercase ("ok"/"failed").
        entry['verification'] = {
            'state': _scrub_str(verification.get('state')),
            'upid': _scrub_str(verification.get('upid')),
        }
    if 'protected' in volume:
        entry['protected'] = _as_bool(volume['protected'])
    if 'encrypted' in volume:
        entry['encrypted'] = _as_bool(volume['encrypted'])


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
