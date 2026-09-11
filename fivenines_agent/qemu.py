import os
import posixpath
import time
import xml.etree.ElementTree as ET
from urllib.parse import unquote, urlsplit

try:
    import libvirt
    _LibvirtError = libvirt.libvirtError
except ImportError:
    libvirt = None  # type: ignore[assignment]
    _LibvirtError = Exception

from fivenines_agent.debug import debug, log

STATE_MAP = {
    0: "nostate", 1: "running", 2: "blocked", 3: "paused",
    4: "shutdown", 5: "shutoff", 6: "crashed", 7: "pmsuspended", 8: "last"
}

# --- libvirt connection URI allowlist (agent #142) --------------------------
#
# A libvirt URI selects a TRANSPORT as well as a hypervisor, and several
# transports do far more than open a socket: `ext` runs an arbitrary local
# command (`?command=`), `ssh`/`libssh`/`libssh2` spawn ssh or link in an SSH
# client (with `command=`/`netcat=`/`proxy=` knobs of their own), and
# `tcp`/`tls` dial a network host. openReadOnly() only narrows the RPC surface
# once connected; it says nothing about how the connection is made. The backend
# restricts qemu_uri before sending it, but the agent must not stake its own
# process on a single upstream control, so the collector independently refuses
# to open anything but the local hypervisor socket:
#
#   accepted  qemu:///system, qemu:///session, qemu+unix:///system,
#             qemu+unix:///session -- optionally with ?socket=<path> and/or
#             ?mode=auto|direct|legacy, the only two parameters the unix
#             transport reads. socket= must be a normalized absolute path
#             inside a libvirt socket directory (LIBVIRT_SOCKET_DIRS): the
#             collector's open has no timeout, and a peer that reads and
#             waits (docker.sock, a socket-activated service) would stall
#             the tick past the systemd watchdog.
#   refused   every other scheme (qemu+ext, qemu+ssh, qemu+libssh[2],
#             qemu+tcp, qemu+tls, test, xen, lxc, ...); any URI with an
#             authority component (qemu://HOST/system is an implicit TLS
#             connection to HOST); qemu:///embed (runs the QEMU driver
#             in-process); any other query parameter (command=, netcat=,
#             proxy=, name=, ...); and an empty or non-string URI, which
#             would defer to LIBVIRT_DEFAULT_URI / libvirt.conf and could
#             resolve to any of the above.
#
# On refusal the collector never calls into libvirt at all and qemu_metrics
# reports None, which the server treats as a collection failure (no data,
# no pruning). The same None is reported when the connection or the domain
# enumeration fails; [] means libvirt answered and listed zero domains (the
# docker/zfs "report everything or null" contract). The refusal log names
# the REASON only, never the URI or any value taken from it: those lines
# reach the journal and the error telemetry sent back to the backend, a
# hostile URI can carry a credential anywhere (userinfo, path, a parameter
# value), and redacting it in place proved a losing game -- every rewrite
# opened a new hole or a quadratic regex. The one echoed token is the
# scheme, and only when it is a libvirt spelling (qemu, or qemu+<transport>,
# any case); anything else is reported as "(unrecognized)". The agent never
# echoes the URI on the ACCEPTED path either; libvirt's own connect-failure
# message is logged verbatim there because it is the only diagnostic an
# operator has, and it may quote the configured socket path.
#
# Query parsing is kept IDENTICAL to libvirt's rather than merely stricter:
# libvirt splits on "&" and treats ";" as a separator only when no "&"
# remains, so a query mixing the two is read differently by the two parsers
# (?mode=auto;mode=direct&socket=... is two valid modes to a naive splitter
# and one invalid mode to libvirt). Any ";" in the query is therefore
# refused outright; with "&" alone both parsers agree. Decoded parameter
# values must be printable with no whitespace, because libvirt decodes them
# too and its own connect error echoes the socket path.
#
# One more thing an accepted URI must not do: for a non-root agent, opening
# qemu:///session makes the libvirt client fork libvirt's own session daemon
# (virtqemud --timeout=120) whenever no socket is listening, and again each
# time it idles out. A monitoring agent connects or fails; it never spawns
# the hypervisor daemon, so LIBVIRT_AUTOSTART=0 is set once at import (on
# the main thread, before any libvirt thread exists; libvirt reads it at
# every open) unless the operator's service environment already sets it.
# User installs therefore need the session daemon running or
# socket-activated (systemctl --user enable --now virtqemud.socket).
LIBVIRT_ALLOWED_SCHEMES = ("qemu", "qemu+unix")
LIBVIRT_ALLOWED_PATHS = ("/system", "/session")
LIBVIRT_ALLOWED_PARAMS = ("socket", "mode")
LIBVIRT_ALLOWED_MODES = ("auto", "direct", "legacy")
# Every transport libvirt's remote driver knows. A refused scheme is echoed
# in the reason only when it spells qemu or qemu+<one of these> (in any
# case), so the echo is drawn from a fixed vocabulary, never from the URI.
LIBVIRT_TRANSPORTS = ("unix", "tcp", "tls", "ssh", "ext", "libssh", "libssh2")
_LIBVIRT_SCHEME_SPELLINGS = frozenset(
    ["qemu"] + ["qemu+" + transport for transport in LIBVIRT_TRANSPORTS]
)
# Where libvirt puts its sockets: the system daemons (monolithic
# libvirt-sock and modular virtqemud-sock alike) and, for session daemons,
# $XDG_RUNTIME_DIR/libvirt/ (resolved at check time).
LIBVIRT_SOCKET_DIRS = ("/run/libvirt/", "/var/run/libvirt/")
# Longest URI the allowlist will even parse. The longest acceptable URI is
# about 150 characters (qemu+unix:///session?socket=<107-char sun_path>
# &mode=legacy); the cap bounds every per-tick parse cost -- urlsplit's NFKC
# pass, per-parameter unquote -- to O(512) regardless of stdlib internals,
# so a hostile config cannot stretch the collection tick.
LIBVIRT_URI_MAX_CHARS = 512

# The collector's default, and the URI the permissions probe opens (it
# imports this name) -- one spelling, so the two cannot drift.
DEFAULT_LIBVIRT_URI = "qemu:///system"


def _disable_session_autostart():
    """LIBVIRT_AUTOSTART=0 unless the operator's environment already sets it
    (see the header). Called once at import, on the main thread, before any
    libvirt worker exists; the call in _connect is a no-op safety net that
    never reaches setenv while the variable is present."""
    os.environ.setdefault("LIBVIRT_AUTOSTART", "0")


_disable_session_autostart()


def _libvirt_socket_dirs():
    dirs = list(LIBVIRT_SOCKET_DIRS)
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    # posixpath on purpose (the cgroup.py precedent): a unix socket path is
    # always POSIX, and ntpath.normpath would rewrite every one of these with
    # backslashes when the suite runs on Windows.
    if xdg.startswith("/") and xdg == posixpath.normpath(xdg):
        dirs.append(xdg + "/libvirt/")
    return dirs


def libvirt_uri_rejection(uri):
    """Return why *uri* falls outside the local-socket allowlist, or None when
    it may be opened. Pure function: never touches libvirt."""
    if not isinstance(uri, str) or not uri:
        return (
            "URI must be a non-empty string (an empty URI defers to "
            "LIBVIRT_DEFAULT_URI / libvirt.conf)"
        )
    if len(uri) > LIBVIRT_URI_MAX_CHARS:
        return f"URI is longer than {LIBVIRT_URI_MAX_CHARS} characters"
    if " " in uri or not uri.isprintable():
        return "URI contains whitespace or control characters"
    try:
        parts = urlsplit(uri)
    except ValueError:
        # Never echo the parser's message: CPython builds it from the RAW
        # netloc, userinfo included.
        return "URI does not parse"
    # urlsplit lowercases the scheme, but libvirt matches the driver name
    # case-sensitively (only the transport after "+" is folded), so compare
    # the raw spelling: the agent must accept no spelling libvirt would not.
    scheme = uri[: len(parts.scheme)]
    if scheme not in LIBVIRT_ALLOWED_SCHEMES:
        if scheme.lower() in _LIBVIRT_SCHEME_SPELLINGS:
            shown = repr(scheme)
        else:
            shown = "(none)" if not scheme else "(unrecognized)"
        return (
            f"scheme {shown} is not a local qemu transport "
            f"(allowed: {', '.join(LIBVIRT_ALLOWED_SCHEMES)})"
        )
    # From here on nothing from the URI is echoed (see the header): the
    # authority, the path and every parameter can carry a credential.
    if parts.netloc:
        return (
            "URI carries an authority component (a remote host); only "
            f"{' and '.join(s + ':///' for s in LIBVIRT_ALLOWED_SCHEMES)} are allowed"
        )
    if parts.path not in LIBVIRT_ALLOWED_PATHS:
        return f"path is not one of {', '.join(LIBVIRT_ALLOWED_PATHS)}"
    if parts.fragment:
        return "URI carries a fragment"
    if ";" in parts.query:
        return "query contains ';' (libvirt and the agent would split it differently)"
    for name, value in _split_query(parts.query):
        if name not in LIBVIRT_ALLOWED_PARAMS:
            return (
                "query parameter is not one of "
                f"{', '.join(p + '=' for p in LIBVIRT_ALLOWED_PARAMS)}"
            )
        if " " in value or not value.isprintable():
            return "query parameter value contains whitespace or control characters"
        if name == "socket" and not _is_libvirt_socket_path(value):
            return (
                "socket= is not a normalized absolute path inside a libvirt "
                "socket directory"
            )
        if name == "mode" and value not in LIBVIRT_ALLOWED_MODES:
            return f"mode= is not one of {', '.join(LIBVIRT_ALLOWED_MODES)}"
    return None


def _is_libvirt_socket_path(value):
    """True when *value* is an absolute, already-normalized path (no "..",
    "//" or "." segments -- the kernel would resolve them past the directory)
    to a file inside one of the libvirt socket directories."""
    if not value.startswith("/") or value != posixpath.normpath(value):
        return False
    return any(
        value.startswith(d) and len(value) > len(d) for d in _libvirt_socket_dirs()
    )


def _split_query(query):
    """Yield (name, value) pairs the way libvirt's virURIParseParams reads a
    query that contains no ";" (the caller refuses one that does): "&"
    separates parameters, splitting happens before decoding, names and
    values are percent-decoded, and "+" is literal (no form decoding). A
    nameless "=value" segment is yielded with an empty name so the caller
    refuses it (libvirt would silently drop it: stricter, never looser)."""
    for part in query.split("&"):
        if not part:
            continue
        name, _, value = part.partition("=")
        yield unquote(name), unquote(value)


# The refused URI most recently logged at error level. A refused URI comes
# back on every tick (the collector is re-instantiated per tick and the
# config is level-triggered), so the error is logged once per CHANGE of
# refused URI and demoted to debug while it repeats; an accepted URI clears
# the register, so a bad URI that was fixed and later re-introduced is an
# error again. The per-tick signal is the None payload. The empty register
# is a private sentinel, not None: None is itself a refusable value (a
# backend can send {"uri": null}), and its first refusal must be an error.
_NEVER_REFUSED = object()
_last_refused_uri = _NEVER_REFUSED


def _log_refusal(uri, reason):
    """Log the reason -- never the URI (see the allowlist header). The raw
    URI is only ever compared for equality against the register."""
    global _last_refused_uri
    level = "debug" if uri == _last_refused_uri else "error"
    _last_refused_uri = uri
    log(
        f"Refusing configured libvirt URI: {reason}; not connecting, "
        "QEMU metrics report null",
        level,
    )


def _clear_refusal():
    global _last_refused_uri
    _last_refused_uri = _NEVER_REFUSED


class QEMUCollector:
    def __init__(self, uri=DEFAULT_LIBVIRT_URI):
        self.uri = uri
        self.conn = None
        # The allowlist is the one gate, before ANY libvirt call (not even
        # the global error-handler registration): a refused URI keeps its
        # reason here, no connection is attempted, and qemu_metrics reports
        # None instead of [] (zero VMs).
        self.refused = libvirt_uri_rejection(uri)
        if self.refused:
            _log_refusal(uri, self.refused)
        else:
            _clear_refusal()
            self._connect()
            self._setup_error_handler()

    def _setup_error_handler(self):
        """Setup custom error handler to suppress known cgroup v2 warnings."""
        def error_handler(ctx, error):
            if error and len(error) >= 2:
                msg = str(error[1]) if error[1] else ""
                if "getCpuacctPercpuUsage" in msg or "cgroup V2" in msg:
                    return
            log(f"libvirt error: {error}", 'debug')

        try:
            libvirt.registerErrorHandler(error_handler, None)
        except Exception:
            pass

    def _connect(self):
        try:
            # Log libvirt version and capabilities
            log(f"libvirt module version: {libvirt.getVersion()}", 'debug')

            # getLibVersion() is available in newer versions
            try:
                log(f"libvirt library version: {libvirt.getLibVersion()}", 'debug')
            except AttributeError:
                log("libvirt.getLibVersion() not available in this version", 'debug')

            # Connect or fail: never let libvirt fork a session daemon on the
            # agent's behalf (set at import; this is the no-op safety net).
            _disable_session_autostart()
            self.conn = libvirt.openReadOnly(self.uri)
            if self.conn is None:
                log("libvirt.openReadOnly returned None", 'error')
            else:
                # Log connection info
                try:
                    conn_version = self.conn.getVersion()
                    hypervisor_type = self.conn.getType()
                    log(f"Connected to {hypervisor_type} version: {conn_version}", 'debug')
                except Exception as e:
                    log(f"Error getting connection info: {e}", 'debug')
        except Exception as e:
            # The URI is never echoed (see the header). libvirt's own message
            # is kept -- it is THE diagnostic for a real connect failure --
            # and may quote the configured socket path.
            log(f"Cannot connect to libvirt: {e}", 'error')

    def _xml_devices(self, dom):
        disks, ifaces = [], []
        try:
            xml = dom.XMLDesc(0)
            root = ET.fromstring(xml)

            for d in root.findall(".//devices/disk"):
                tgt = d.find("target")
                if tgt is not None and tgt.get("dev"):
                    disks.append(tgt.get("dev"))

            for n in root.findall(".//devices/interface/target"):
                dev = n.get("dev")
                if dev:
                    ifaces.append(dev)
        except Exception as e:
            log(f"Error parsing XML for domain: {e}", 'error')
        return disks, ifaces

    def _get_vm_uptime(self, dom):
        try:
            state = int(dom.state()[0])
            if state != 1:  # Not running
                return 0

            info = dom.info()
            if info and len(info) >= 6:
                start_time = info[5]
                current_time = int(time.time())
                uptime = current_time - start_time
                return max(0, uptime)

        except Exception as e:
            log(f"Error getting VM uptime: {e}", 'error')
        return 0

    def _safe_append(self, data, metric_name, value, labels):
        try:
            data.append({
                'name': metric_name,
                'value': value,
                'labels': labels
            })
        except Exception as e:
            log(f"Error appending metric {metric_name}: {e}", 'error')

    def _collect_cpu_metrics(self, dom, labels, data):
        """Collect CPU metrics with proper cgroup v2 handling."""
        vcpus = max(1, int(dom.maxVcpus()))
        total_cpu_time_ns = 0
        per_vcpu_collected = False

        # Method 1: Try getCPUStats(False) for per-vCPU stats
        # This will fail on cgroup v2 systems
        try:
            per_vcpu = dom.getCPUStats(False)
            if per_vcpu and isinstance(per_vcpu, list):
                for idx, cpu_stats in enumerate(per_vcpu):
                    if isinstance(cpu_stats, dict) and 'cpu_time' in cpu_stats:
                        cpu_time = int(cpu_stats['cpu_time'])
                        self._safe_append(
                            data,
                            'vm_vcpu_time_nanoseconds_total',
                            cpu_time,
                            {**labels, 'vcpu': str(idx)}
                        )
                        total_cpu_time_ns += cpu_time
                        per_vcpu_collected = True
        except _LibvirtError as e:
            # Expected on cgroup v2 - silently ignore
            if "not supported" not in str(e).lower() and "cgroup" not in str(e).lower():
                log(f"Unexpected error in getCPUStats(False): {e}", 'debug')
        except Exception as e:
            log(f"Error getting per-vCPU stats: {e}", 'debug')

        # Method 2: Try dom.vcpus() as fallback
        # Note: This often returns current pinning info, not CPU time
        if not per_vcpu_collected:
            try:
                vcpu_info = dom.vcpus()
                if vcpu_info and len(vcpu_info) == 2:
                    # vcpu_info[0] contains the vCPU info list
                    # vcpu_info[1] contains CPU map info (not needed here)
                    vcpu_list = vcpu_info[0]
                    if vcpu_list:
                        for vcpu_data in vcpu_list:
                            # Format: (vcpu_number, state, cpu_time_ns, cpu_num)
                            if len(vcpu_data) >= 3:
                                vcpu_num = vcpu_data[0]
                                cpu_time = vcpu_data[2]  # CPU time in nanoseconds
                                if cpu_time > 0:  # Only record if we have actual data
                                    self._safe_append(
                                        data,
                                        'vm_vcpu_time_nanoseconds_total',
                                        cpu_time,
                                        {**labels, 'vcpu': str(vcpu_num)}
                                    )
                                    total_cpu_time_ns += cpu_time
                                    per_vcpu_collected = True
            except _LibvirtError as e:
                if "not implemented" not in str(e).lower():
                    log(f"vcpus() error: {e}", 'debug')
            except Exception as e:
                log(f"Error parsing vcpus() output: {e}", 'debug')

        # Method 3: Get aggregate CPU stats (usually works even on cgroup v2)
        if total_cpu_time_ns == 0:  # If we haven't collected any CPU time yet
            try:
                total_stats = dom.getCPUStats(True)
                if total_stats and isinstance(total_stats, list) and len(total_stats) > 0:
                    if isinstance(total_stats[0], dict) and 'cpu_time' in total_stats[0]:
                        total_cpu_time_ns = int(total_stats[0]['cpu_time'])
            except Exception as e:
                log(f"Error getting total CPU stats: {e}", 'debug')

        # Method 4: Ultimate fallback - use dom.info()
        if total_cpu_time_ns == 0:
            try:
                info = dom.info()
                # info[4] is CPU time in nanoseconds
                if info and len(info) > 4:
                    total_cpu_time_ns = int(info[4])
            except Exception as e:
                log(f"Error getting CPU time from info(): {e}", 'debug')

        self._safe_append(data, 'vm_cpu_time_nanoseconds_total', total_cpu_time_ns, labels)
        self._safe_append(data, 'vm_vcpu_count', vcpus, labels)

    def _collect_memory_metrics(self, dom, labels, data):
        try:
            mem = dom.memoryStats()

            # Log available keys only if RSS is missing (for debugging)
            if not mem.get('rss'):
                log(f"RSS metric unavailable. Available keys: {list(mem.keys())}", 'debug')

            memory_metrics = [
                ('vm_memory_assigned_bytes', 'actual'),
                ('vm_memory_balloon_bytes', 'usable'),
                ('vm_memory_rss_bytes', 'rss')
            ]

            for metric_name, mem_key in memory_metrics:
                if mem.get(mem_key):
                    self._safe_append(data, metric_name, int(mem[mem_key]) * 1024, labels)

            if mem.get('available'):
                self._safe_append(data, 'vm_memory_available_bytes', int(mem['available']) * 1024, labels)
            if mem.get('swap_in'):
                self._safe_append(data, 'vm_memory_swap_in_bytes', int(mem['swap_in']) * 1024, labels)
            if mem.get('swap_out'):
                self._safe_append(data, 'vm_memory_swap_out_bytes', int(mem['swap_out']) * 1024, labels)

        except Exception as e:
            log(f"Error collecting memory metrics: {e}", 'debug')

    def _collect_disk_metrics(self, dom, disks, labels, data):
        for dev in disks:
            try:
                if hasattr(dom, "blockStatsFlags"):
                    bs = dom.blockStatsFlags(dev, 0) or {}
                    rd_bytes = int(bs.get("rd_bytes", 0))
                    wr_bytes = int(bs.get("wr_bytes", 0))
                    rd_reqs = int(bs.get("rd_operations", 0))
                    wr_reqs = int(bs.get("wr_operations", 0))
                    rd_time_ns = int(bs.get("rd_total_time_ns", 0))
                    wr_time_ns = int(bs.get("wr_total_time_ns", 0))
                    flush_reqs = int(bs.get("flush_operations", 0))
                    flush_time_ns = int(bs.get("flush_total_time_ns", 0))
                else:
                    stats = dom.blockStats(dev)
                    rd_reqs, rd_bytes, wr_reqs, wr_bytes = map(int, stats[:4])
                    rd_time_ns = wr_time_ns = flush_reqs = flush_time_ns = 0

                device_labels = {**labels, 'device': dev}

                disk_metrics = [
                    ('vm_disk_read_bytes_total', rd_bytes),
                    ('vm_disk_write_bytes_total', wr_bytes),
                    ('vm_disk_read_operations_total', rd_reqs),
                    ('vm_disk_write_operations_total', wr_reqs)
                ]

                if rd_time_ns > 0:
                    disk_metrics.append(('vm_disk_read_time_nanoseconds_total', rd_time_ns))
                if wr_time_ns > 0:
                    disk_metrics.append(('vm_disk_write_time_nanoseconds_total', wr_time_ns))
                if flush_reqs > 0:
                    disk_metrics.append(('vm_disk_flush_operations_total', flush_reqs))
                if flush_time_ns > 0:
                    disk_metrics.append(('vm_disk_flush_time_nanoseconds_total', flush_time_ns))

                for metric_name, value in disk_metrics:
                    self._safe_append(data, metric_name, value, device_labels)

            except Exception as e:
                log(f"Error collecting disk metrics for device {dev}: {e}", 'debug')
                continue

    def _collect_network_metrics(self, dom, ifaces, labels, data):
        for iface in ifaces:
            try:
                stats = dom.interfaceStats(iface)
                rx_bytes = int(stats[0])
                rx_packets = int(stats[1])
                rx_errs = int(stats[2])
                rx_drops = int(stats[3])
                tx_bytes = int(stats[4])
                tx_packets = int(stats[5])
                tx_errs = int(stats[6])
                tx_drops = int(stats[7])

                device_labels = {**labels, 'device': iface}

                network_metrics = [
                    ('vm_network_receive_bytes_total', rx_bytes),
                    ('vm_network_transmit_bytes_total', tx_bytes),
                    ('vm_network_receive_packets_total', rx_packets),
                    ('vm_network_transmit_packets_total', tx_packets),
                    ('vm_network_receive_drops_total', rx_drops),
                    ('vm_network_transmit_drops_total', tx_drops),
                    ('vm_network_receive_errors_total', rx_errs),
                    ('vm_network_transmit_errors_total', tx_errs)
                ]

                for metric_name, value in network_metrics:
                    self._safe_append(data, metric_name, value, device_labels)

            except Exception as e:
                log(f"Error collecting network metrics for interface {iface}: {e}", 'debug')
                continue

    def _collect_domain_metrics(self, dom, data):
        try:
            uuid = dom.UUIDString()
            name = dom.name()
            state_num = int(dom.state()[0])
            state = STATE_MAP.get(state_num, str(state_num))

            labels = {'vm_uuid': uuid, 'vm_name': name}

            self._safe_append(data, 'vm_vm_info', 1, {**labels, 'state': state})
            self._safe_append(data, 'vm_vm_state_code', state_num, labels)
            self._safe_append(data, 'vm_vm_uptime_seconds_total', self._get_vm_uptime(dom), labels)

            # Only collect detailed metrics if VM is running
            if state_num == 1:  # running
                self._collect_cpu_metrics(dom, labels, data)
                self._collect_memory_metrics(dom, labels, data)

                disks, ifaces = self._xml_devices(dom)
                if disks:
                    self._collect_disk_metrics(dom, disks, labels, data)
                if ifaces:
                    self._collect_network_metrics(dom, ifaces, labels, data)

        except Exception as ex:
            log(f"Error collecting metrics for domain: {ex}", 'error')

    def collect(self):
        """The domain metric list; [] only when libvirt answered and listed
        zero domains. None -- a collection failure the server skips -- on a
        refused URI, a failed connection or a failed enumeration, so an
        outage never reads as "all VMs are gone"."""
        if self.refused:
            return None
        if not self.conn:
            log("No libvirt connection available", 'error')
            return None

        data = []

        try:
            doms = self.conn.listAllDomains()

            try:
                info = self.conn.getInfo()
                if info:
                    hypervisor_labels = {'hypervisor': 'kvm'}
                    self._safe_append(data, 'hypervisor_vcpus_total', info[2], hypervisor_labels)
                    self._safe_append(data, 'hypervisor_memory_bytes', info[1] * 1024 * 1024, hypervisor_labels)
                    self._safe_append(data, 'hypervisor_domains_total', len(doms), hypervisor_labels)

                    running_count = sum(1 for d in doms if d.state()[0] == 1)
                    self._safe_append(data, 'hypervisor_domains_running', running_count, hypervisor_labels)
            except Exception as e:
                log(f"Error collecting hypervisor metrics: {e}", 'debug')

        except Exception as e:
            log(f"listAllDomains failed: {e}", 'error')
            return None

        for dom in doms:
            self._collect_domain_metrics(dom, data)

        return data

    def close(self):
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None


@debug('qemu_metrics')
def qemu_metrics(uri=DEFAULT_LIBVIRT_URI):
    if libvirt is None:
        log("libvirt not available, skipping QEMU metrics", "debug")
        return None
    collector = QEMUCollector(uri)
    try:
        return collector.collect()
    finally:
        collector.close()
