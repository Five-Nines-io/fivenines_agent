import os
import time
from typing import Dict, Any, Optional

import libvirt
import xml.etree.ElementTree as ET

from fivenines_agent.debug import debug

STATE_MAP = {
    0: "nostate", 1: "running", 2: "blocked", 3: "paused",
    4: "shutdown", 5: "shutoff", 6: "crashed", 7: "pmsuspended", 8: "last"
}

def _state_to_str(code: int) -> str:
    return STATE_MAP.get(int(code), str(code))

class LibvirtKVMCollector:
    """
    Emits cumulative VM metrics from libvirt (no derived rates/percentages).
    Labels on all points: host, vm_uuid, vm_name, vm_state.
    Extra labels: device (disk metrics), iface (net metrics), vcpu (per-vCPU timers).
    """
    def __init__(self, uri: str = "qemu:///system", emit=None, logger=None, host_id: Optional[str] = None):
        self.uri = uri
        self.emit = emit or (lambda m, v, l: None)
        self.logger = logger
        self.host_id = host_id or os.uname().nodename
        self.conn = None
        self._connect()

    # -------------- internals --------------
    def _log(self, level: str, msg: str):
        if self.logger and hasattr(self.logger, level):
            getattr(self.logger, level)(msg)
        else:
            print(f"[{level.upper()}] {msg}")

    def _connect(self):
        try:
            self.conn = libvirt.openReadOnly(self.uri)
            if self.conn is None:
                raise RuntimeError("libvirt.openReadOnly returned None")
        except Exception as e:
            raise RuntimeError(f"Cannot connect to libvirt at {self.uri}: {e}")

    def _xml_devices(self, dom):
        """
        Parse domain XML to discover disk and interface device names.
        Returns (disks, ifaces)
        """
        disks, ifaces = [], []
        try:
            xml = dom.XMLDesc(0)
            root = ET.fromstring(xml)
            # Disks
            for d in root.findall(".//devices/disk"):
                tgt = d.find("target")
                if tgt is not None and tgt.get("dev"):
                    disks.append(tgt.get("dev"))
            # NICs
            for n in root.findall(".//devices/interface/target"):
                dev = n.get("dev")
                if dev:
                    ifaces.append(dev)
        except Exception:
            pass
        return disks, ifaces

    # -------------- public --------------
    def poll(self) -> int:
        """
        Collect once and emit cumulative values.
        Returns number of points emitted (for --dry-run/debug usefulness).
        """
        points = 0
        try:
            doms = self.conn.listAllDomains()
        except Exception as e:
            self._log("error", f"listAllDomains failed: {e}")
            return 0

        for dom in doms:
            try:
                uuid = dom.UUIDString()
                name = dom.name()
                vcpus = max(1, dom.maxVcpus() or 1)
                state = _state_to_str(dom.state()[0])

                labels = {'host': self.host_id, 'vm_uuid': uuid, 'vm_name': name, 'vm_state': state}

                # Uptime placeholder (0 without guest agent)
                self.emit('vm.uptime_seconds', 0, labels); points += 1

                # ---- CPU cumulative times (ns): total + per-vCPU ----
                total_cpu_time_ns = 0

                # Preferred: per-vCPU stats (list of dicts, one per vCPU)
                per_vcpu = []
                try:
                    per_vcpu = dom.getCPUStats(False) or []
                except Exception:
                    per_vcpu = []

                if per_vcpu:
                    for idx, row in enumerate(per_vcpu):
                        tns = int(row.get('cpu_time', 0)) or 0
                        self.emit('vm.vcpu.time_ns', tns, {**labels, 'vcpu': str(idx)}); points += 1
                        total_cpu_time_ns += tns
                else:
                    # Fallbacks: whole-domain CPU time
                    try:
                        total = dom.getCPUStats(True) or [{}]
                        total_cpu_time_ns = int(total[0].get('cpu_time', 0)) or 0
                    except Exception:
                        try:
                            info = dom.info()
                            # info[4] is cumulative CPU time (ns)
                            total_cpu_time_ns = int(info[4]) if info and len(info) >= 5 else 0
                        except Exception:
                            total_cpu_time_ns = 0

                self.emit('vm.cpu.time_ns', total_cpu_time_ns, labels); points += 1
                self.emit('vm.vcpu.count', vcpus, labels); points += 1

                # ---- Memory (normalize KiB -> bytes) ----
                try:
                    mem = dom.memoryStats()
                    if mem.get('actual'):
                        self.emit('vm.mem.assigned_bytes', int(mem['actual']) * 1024, labels); points += 1
                    if mem.get('usable'):
                        self.emit('vm.mem.balloon_bytes', int(mem['usable']) * 1024, labels); points += 1
                    if mem.get('rss'):
                        self.emit('vm.mem.rss_bytes', int(mem['rss']) * 1024, labels); points += 1
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
                        self.emit('vm.disk.read_bytes', rd_bytes, lb); points += 1
                        self.emit('vm.disk.write_bytes', wr_bytes, lb); points += 1
                        self.emit('vm.disk.read_ops', rd_reqs, lb); points += 1
                        self.emit('vm.disk.write_ops', wr_reqs, lb); points += 1
                    except Exception:
                        continue

                # ---- Network cumulative counters ----
                for iface in ifaces:
                    try:
                        rx, rxp, tx, txp, rxerr, txerr, rxdrop, txdrop = dom.interfaceStats(iface)
                        lbn = {**labels, 'iface': iface}
                        self.emit('vm.net.rx_bytes', int(rx), lbn); points += 1
                        self.emit('vm.net.tx_bytes', int(tx), lbn); points += 1
                        self.emit('vm.net.rx_packets', int(rxp), lbn); points += 1
                        self.emit('vm.net.tx_packets', int(txp), lbn); points += 1
                        self.emit('vm.net.rx_drop', int(rxdrop), lbn); points += 1
                        self.emit('vm.net.tx_drop', int(txdrop), lbn); points += 1
                    except Exception:
                        continue

            except Exception as ex:
                self._log('error', f"Domain metrics error: {ex}")
                continue

        return points


@debug('libvirt_metrics')
def libvirt_metrics():
    return LibvirtKVMCollector().poll()
