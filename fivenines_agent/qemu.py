import os
import time
import libvirt
import xml.etree.ElementTree as ET

from fivenines_agent.debug import debug, log

STATE_MAP = {
    0: "nostate", 1: "running", 2: "blocked", 3: "paused",
    4: "shutdown", 5: "shutoff", 6: "crashed", 7: "pmsuspended", 8: "last"
}

class QEMUCollector:
    def __init__(self, uri="qemu:///system"):
        self.uri = uri
        self.conn = None
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
            self.conn = libvirt.openReadOnly(self.uri)
            if self.conn is None:
                log("libvirt.openReadOnly returned None", 'error')
        except Exception as e:
            log(f"Cannot connect to libvirt at {self.uri}: {e}", 'error')

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
        except libvirt.libvirtError as e:
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
            except libvirt.libvirtError as e:
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
        data = []

        if not self.conn:
            log("No libvirt connection available", 'error')
            return data

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
            return data

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
def qemu_metrics(uri="qemu:///system"):
    collector = QEMUCollector(uri)
    try:
        return collector.collect()
    finally:
        collector.close()
