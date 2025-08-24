
import os
import time
import libvirt
import xml.etree.ElementTree as ET

from fivenines_agent.debug import debug, log

STATE_MAP = {
    0: "nostate", 1: "running", 2: "blocked", 3: "paused",
    4: "shutdown", 5: "shutoff", 6: "crashed", 7: "pmsuspended", 8: "last"
}

class LibvirtKVMCollector:
    def __init__(self, uri: str = "qemu:///system"):
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
        """Return (disks, ifaces) from domain XML."""
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
        except Exception:
            log("Error parsing XML", 'error')
        return disks, ifaces

    def _get_vm_uptime(self, dom):
        """Get VM uptime in seconds."""
        try:
            # Get VM state first
            state = int(dom.state()[0])
            if state != 1:  # Not running
                return 0

            # Get start time from dom.info()
            info = dom.info()
            if info and len(info) >= 6:
                start_time = info[5]  # Start time in seconds since epoch
                current_time = int(time.time())
                uptime = current_time - start_time
                return max(0, uptime)  # Ensure non-negative

        except Exception:
            log("Error getting VM uptime", 'error')
        return 0

    def _safe_append(self, data, metric_name, value, labels):
        """Safely append a metric to the data list."""
        try:
            data.append((metric_name, value, labels))
        except Exception as e:
            log(f"Error appending metric {metric_name}: {e}", 'error')

    def _collect_cpu_metrics(self, dom, labels, data):
        """Collect CPU-related metrics for a domain."""
        vcpus = max(1, int(dom.maxVcpus()))
        total_cpu_time_ns = 0
        per_vcpu_ok = False

        # Try per-vCPU via getCPUStats(False)
        try:
            per_vcpu = dom.getCPUStats(False) or []
            if per_vcpu:
                per_vcpu_ok = True
                for idx, row in enumerate(per_vcpu):
                    tns = int(row.get('cpu_time', 0)) or 0
                    self._safe_append(data, 'vm_vcpu_time_ns', tns, {**labels, 'vcpu': str(idx)})
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
                        self._safe_append(data, 'vm_vcpu_time_ns', tns, {**labels, 'vcpu': str(idx)})
                        total_cpu_time_ns += tns
            except Exception:
                per_vcpu_ok = False

        # If still no per-vCPU, get total
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

        self._safe_append(data, 'vm_cpu_time_ns', total_cpu_time_ns, labels)
        self._safe_append(data, 'vm_vcpu_count', vcpus, labels)

    def _collect_memory_metrics(self, dom, labels, data):
        """Collect memory-related metrics for a domain."""
        try:
            mem = dom.memoryStats()
            memory_metrics = [
                ('vm_mem_assigned_bytes', 'actual'),
                ('vm_mem_balloon_bytes', 'usable'),
                ('vm_mem_rss_bytes', 'rss')
            ]

            for metric_name, mem_key in memory_metrics:
                if mem.get(mem_key):
                    self._safe_append(data, metric_name, int(mem[mem_key]) * 1024, labels)
        except Exception:
            pass

    def _collect_disk_metrics(self, dom, disks, labels, data):
        """Collect disk-related metrics for a domain."""
        for dev in disks:
            try:
                if hasattr(dom, "blockStatsFlags"):
                    bs = dom.blockStatsFlags(dev, 0) or {}
                    rd_bytes = int(bs.get("rd_bytes", 0))
                    wr_bytes = int(bs.get("wr_bytes", 0))
                    rd_reqs = int(bs.get("rd_operations", 0))
                    wr_reqs = int(bs.get("wr_operations", 0))
                else:
                    rd_reqs, rd_bytes, wr_reqs, wr_bytes = map(int, dom.blockStats(dev)[:4])

                device_labels = {**labels, 'device': dev}
                disk_metrics = [
                    ('vm_disk_read_bytes', rd_bytes),
                    ('vm_disk_write_bytes', wr_bytes),
                    ('vm_disk_read_ops', rd_reqs),
                    ('vm_disk_write_ops', wr_reqs)
                ]

                for metric_name, value in disk_metrics:
                    self._safe_append(data, metric_name, value, device_labels)
            except Exception:
                continue

    def _collect_network_metrics(self, dom, ifaces, labels, data):
        """Collect network-related metrics for a domain."""
        for iface in ifaces:
            try:
                rx, rxp, tx, txp, rxerr, txerr, rxdrop, txdrop = dom.interfaceStats(iface)
                device_labels = {**labels, 'device': iface}
                network_metrics = [
                    ('vm_net_rx_bytes', int(rx)),
                    ('vm_net_tx_bytes', int(tx)),
                    ('vm_net_rx_packets', int(rxp)),
                    ('vm_net_tx_packets', int(txp)),
                    ('vm_net_rx_drop', int(rxdrop)),
                    ('vm_net_tx_drop', int(txdrop))
                ]

                for metric_name, value in network_metrics:
                    self._safe_append(data, metric_name, value, device_labels)
            except Exception:
                continue

    def _collect_domain_metrics(self, dom, data):
        """Collect all metrics for a single domain."""
        try:
            uuid = dom.UUIDString()
            name = dom.name()
            state_num = int(dom.state()[0])
            state = STATE_MAP.get(state_num, str(state_num))

            labels = {'vm_uuid': uuid, 'vm_name': name}

            # Basic metrics
            self._safe_append(data, 'vm_state', state, labels)
            self._safe_append(data, 'vm_uptime_seconds', self._get_vm_uptime(dom), labels)

            # Collect detailed metrics
            self._collect_cpu_metrics(dom, labels, data)
            self._collect_memory_metrics(dom, labels, data)

            # Discover devices and collect device metrics
            disks, ifaces = self._xml_devices(dom)
            self._collect_disk_metrics(dom, disks, labels, data)
            self._collect_network_metrics(dom, ifaces, labels, data)

        except Exception as ex:
            log(f"Domain metrics error: {ex}", 'error')

    # ---- public ----
    def collect(self):
        """
        Run one collection cycle and return ALL points as a list of tuples:
          [(metric_name, value, labels_dict), ...]
        """
        data = []

        try:
            doms = self.conn.listAllDomains()
        except Exception as e:
            log(f"listAllDomains failed: {e}", 'error')
            return data

        for dom in doms:
            self._collect_domain_metrics(dom, data)

        return data


@debug('libvirt_kvm_metrics')
def libvirt_kvm_metrics():
    return LibvirtKVMCollector().collect()
