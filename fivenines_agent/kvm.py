import os
import time
import libvirt
import xml.etree.ElementTree as ET

from fivenines_agent.debug import debug, log

STATE_MAP = {
    0: "nostate", 1: "running", 2: "blocked", 3: "paused",
    4: "shutdown", 5: "shutoff", 6: "crashed", 7: "pmsuspended", 8: "last"
}

class KVMCollector:
    def __init__(self, uri: "qemu:///system"):
        self.uri = uri
        self.conn = None
        self._connect()

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
        vcpus = max(1, int(dom.maxVcpus()))
        total_cpu_time_ns = 0
        per_vcpu_ok = False

        # Try per-vCPU stats via getCPUStats(False)
        try:
            per_vcpu = dom.getCPUStats(False) or []
            if per_vcpu:
                per_vcpu_ok = True
                for idx, row in enumerate(per_vcpu):
                    tns = int(row.get('cpu_time', 0)) or 0
                    self._safe_append(
                        data,
                        'kvm_vcpu_time_nanoseconds_total',
                        tns,
                        {**labels, 'vcpu': str(idx)}
                    )
                    total_cpu_time_ns += tns
        except Exception:
            per_vcpu_ok = False

        # Fallback: per-vCPU via dom.vcpus()
        if not per_vcpu_ok:
            try:
                vinfo = dom.vcpus()
                cpuinfo_list = vinfo[0] if isinstance(vinfo, tuple) else vinfo
                if cpuinfo_list:
                    per_vcpu_ok = True
                    total_cpu_time_ns = 0
                    for entry in cpuinfo_list:
                        if isinstance(entry, tuple) and len(entry) >= 3:
                            idx = entry[0]
                            tns = int(entry[2])
                        elif isinstance(entry, dict):
                            idx = int(entry.get('number', 0))
                            tns = int(entry.get('cpuTime', 0))
                        else:
                            continue
                        self._safe_append(
                            data,
                            'kvm_vcpu_time_nanoseconds_total',
                            tns,
                            {**labels, 'vcpu': str(idx)}
                        )
                        total_cpu_time_ns += tns
            except Exception:
                per_vcpu_ok = False

        # If still no per-vCPU data, get aggregate total
        if not per_vcpu_ok:
            try:
                total = dom.getCPUStats(True) or [{}]
                total_cpu_time_ns = int(total[0].get('cpu_time', 0)) or 0
            except Exception:
                try:
                    info = dom.info()
                    total_cpu_time_ns = int(info[4]) if info and len(info) >= 5 else 0
                except Exception:
                    total_cpu_time_ns = 0

        self._safe_append(data, 'kvm_cpu_time_nanoseconds_total', total_cpu_time_ns, labels)
        self._safe_append(data, 'kvm_vcpu_count', vcpus, labels)

    def _collect_memory_metrics(self, dom, labels, data):
        try:
            mem = dom.memoryStats()

            memory_metrics = [
                ('kvm_memory_assigned_bytes', 'actual'),      # Total assigned memory
                ('kvm_memory_balloon_bytes', 'usable'),       # Usable memory (after ballooning)
                ('kvm_memory_rss_bytes', 'rss')              # Resident set size
            ]

            for metric_name, mem_key in memory_metrics:
                if mem.get(mem_key):
                    self._safe_append(data, metric_name, int(mem[mem_key]) * 1024, labels)

            if mem.get('available'):
                self._safe_append(data, 'kvm_memory_available_bytes', int(mem['available']) * 1024, labels)
            if mem.get('swap_in'):
                self._safe_append(data, 'kvm_memory_swap_in_bytes', int(mem['swap_in']) * 1024, labels)
            if mem.get('swap_out'):
                self._safe_append(data, 'kvm_memory_swap_out_bytes', int(mem['swap_out']) * 1024, labels)

        except Exception as e:
            log(f"Error collecting memory metrics: {e}", 'debug')

    def _collect_disk_metrics(self, dom, disks, labels, data):
        for dev in disks:
            try:
                # Try the newer blockStatsFlags API first
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
                    if len(stats) > 4:
                        # Some versions have errs as 5th element
                        errs = int(stats[4]) if len(stats) > 4 else 0

                device_labels = {**labels, 'device': dev}

                disk_metrics = [
                    ('kvm_disk_read_bytes_total', rd_bytes),
                    ('kvm_disk_write_bytes_total', wr_bytes),
                    ('kvm_disk_read_operations_total', rd_reqs),
                    ('kvm_disk_write_operations_total', wr_reqs)
                ]

                if rd_time_ns > 0:
                    disk_metrics.append(('kvm_disk_read_time_nanoseconds_total', rd_time_ns))
                if wr_time_ns > 0:
                    disk_metrics.append(('kvm_disk_write_time_nanoseconds_total', wr_time_ns))
                if flush_reqs > 0:
                    disk_metrics.append(('kvm_disk_flush_operations_total', flush_reqs))
                if flush_time_ns > 0:
                    disk_metrics.append(('kvm_disk_flush_time_nanoseconds_total', flush_time_ns))

                for metric_name, value in disk_metrics:
                    self._safe_append(data, metric_name, value, device_labels)

            except Exception as e:
                log(f"Error collecting disk metrics for device {dev}: {e}", 'debug')
                continue

    def _collect_network_metrics(self, dom, ifaces, labels, data):
        for iface in ifaces:
            try:
                stats = dom.interfaceStats(iface)
                rx_bytes, rx_packets, rx_errs, rx_drops = int(stats[0]), int(stats[1]), int(stats[2]), int(stats[3])
                tx_bytes, tx_packets, tx_errs, tx_drops = int(stats[4]), int(stats[5]), int(stats[6]), int(stats[7])

                device_labels = {**labels, 'device': iface}

                network_metrics = [
                    ('kvm_network_receive_bytes_total', rx_bytes),
                    ('kvm_network_transmit_bytes_total', tx_bytes),
                    ('kvm_network_receive_packets_total', rx_packets),
                    ('kvm_network_transmit_packets_total', tx_packets),
                    ('kvm_network_receive_drops_total', rx_drops),
                    ('kvm_network_transmit_drops_total', tx_drops),
                    ('kvm_network_receive_errors_total', rx_errs),
                    ('kvm_network_transmit_errors_total', tx_errs)
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

            self._safe_append(data, 'kvm_vm_info', 1, {**labels, 'state': state})
            self._safe_append(data, 'kvm_vm_state_code', state_num, labels)
            self._safe_append(data, 'kvm_vm_uptime_seconds_total', self._get_vm_uptime(dom), labels)

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
                    self._safe_append(data, 'kvm_hypervisor_vcpus_total', info[2], hypervisor_labels)
                    self._safe_append(data, 'kvm_hypervisor_memory_bytes', info[1] * 1024 * 1024, hypervisor_labels)
                    self._safe_append(data, 'kvm_hypervisor_domains_total', len(doms), hypervisor_labels)

                    running_count = sum(1 for d in doms if d.state()[0] == 1)
                    self._safe_append(data, 'kvm_hypervisor_domains_running', running_count, hypervisor_labels)
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


@debug('kvm_metrics')
def kvm_metrics():
    collector = KVMCollector()
    try:
        return collector.collect()
    finally:
        collector.close()
