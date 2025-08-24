
import os
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
            pass
        return disks, ifaces

    # ---- public ----
    def collect(self):
        """
        Run one collection cycle and return ALL points as a list of tuples:
          [(metric_name, value, labels_dict), ...]
        """
        out = []

        try:
            doms = self.conn.listAllDomains()
        except Exception as e:
            log(f"listAllDomains failed: {e}", 'error')
            return out

        for dom in doms:
            try:
                uuid = dom.UUIDString()
                name = dom.name()
                vcpus = max(1, int(dom.maxVcpus()))
                state = STATE_MAP.get(int(dom.state()[0]), str(dom.state()[0]))

                labels = {'vm_uuid': uuid, 'vm_name': name, 'vm_state': state}

                # Uptime placeholder (0 without guest agent)
                out.append(('vm_uptime_seconds', 0, labels))

                # ---- CPU cumulative times (ns): per-vCPU + total ----
                total_cpu_time_ns = 0
                per_vcpu_ok = False

                # 1) Preferred: per-vCPU via getCPUStats(False)
                try:
                    per_vcpu = dom.getCPUStats(False) or []
                    if per_vcpu:
                        per_vcpu_ok = True
                        for idx, row in enumerate(per_vcpu):
                            tns = int(row.get('cpu_time', 0)) or 0
                            out.append(('vm_vcpu_time_ns', tns, {**labels, 'vcpu': str(idx)}))
                            total_cpu_time_ns += tns
                except Exception:
                    per_vcpu_ok = False

                # 2) Fallback: per-vCPU via dom.vcpus()
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
                                    tns = int(entry[2])  # ns
                                elif isinstance(entry, dict):
                                    idx = int(entry.get('number', 0))
                                    tns = int(entry.get('cpuTime', 0))
                                else:
                                    continue
                                out.append(('vm_vcpu_time_ns', tns, {**labels, 'vcpu': str(idx)}))
                                total_cpu_time_ns += tns
                    except Exception:
                        per_vcpu_ok = False

                # 3) If still no per-vCPU, at least report total
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

                out.append(('vm_cpu_time_ns', total_cpu_time_ns, labels))
                out.append(('vm_vcpu_count', vcpus, labels))

                # ---- Memory (KiB -> bytes) ----
                try:
                    mem = dom.memoryStats()
                    if mem.get('actual'):
                        out.append(('vm_mem_assigned_bytes', int(mem['actual']) * 1024, labels))
                    if mem.get('usable'):
                        out.append(('vm_mem_balloon_bytes', int(mem['usable']) * 1024, labels))
                    if mem.get('rss'):
                        out.append(('vm_mem_rss_bytes', int(mem['rss']) * 1024, labels))
                except Exception:
                    pass

                # Discover devices once
                disks, ifaces = self._xml_devices(dom)

                # ---- Disk cumulative counters ----
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

                        lb = {**labels, 'device': dev}
                        out.append(('vm_disk_read_bytes', rd_bytes, lb))
                        out.append(('vm_disk_write_bytes', wr_bytes, lb))
                        out.append(('vm_disk_read_ops', rd_reqs, lb))
                        out.append(('vm_disk_write_ops', wr_reqs, lb))
                    except Exception:
                        continue

                # ---- Network cumulative counters ----
                for iface in ifaces:
                    try:
                        rx, rxp, tx, txp, rxerr, txerr, rxdrop, txdrop = dom.interfaceStats(iface)
                        lbn = {**labels, 'iface': iface}
                        out.append(('vm_net_rx_bytes', int(rx), lbn))
                        out.append(('vm_net_tx_bytes', int(tx), lbn))
                        out.append(('vm_net_rx_packets', int(rxp), lbn))
                        out.append(('vm_net_tx_packets', int(txp), lbn))
                        out.append(('vm_net_rx_drop', int(rxdrop), lbn))
                        out.append(('vm_net_tx_drop', int(txdrop), lbn))
                    except Exception:
                        continue

            except Exception as ex:
                log(f"Domain metrics error: {ex}", 'error')
                continue
        return out


@debug('libvirt_metrics')
def libvirt_metrics():
    return LibvirtKVMCollector().collect()
