# fivenines_agent — VM monitoring via libvirt/KVM (Proxmox-compatible)
# Created: 2025-08-24 11:55:39 UTC
# from __future__ import annotations
import os, time
from typing import Dict, Any, Optional
# try:
import libvirt  # type: ignore
# except Exception as e:  # pragma: no cover
    # libvirt = None
import fivenines_agent.debug as debug

STATE_MAP = {0:"nostate",1:"running",2:"blocked",3:"paused",4:"shutdown",5:"shutoff",6:"crashed",7:"pmsuspended",8:"last"}
def _state_to_str(code:int)->str: return STATE_MAP.get(int(code), str(code))

class LibvirtKVMCollector:
    def __init__(self, uri: str="qemu:///system", emit=None, logger=None, host_id: Optional[str]=None):
        if libvirt is None: raise RuntimeError("libvirt-python not available.")
        self.uri=uri; self.emit=emit or (lambda m,v,l:None); self.logger=logger; self.host_id=host_id or os.uname().nodename
        self.prev: Dict[str, Dict[str, Any]] = {}
        self.conn=None; self._connect()
    def _log(self, level:str, msg:str):
        if self.logger and hasattr(self.logger, level): getattr(self.logger, level)(msg)
        else: print(f"[{level.upper()}] {msg}")
    def _connect(self):
        try:
            self.conn = libvirt.openReadOnly(self.uri)
            if self.conn is None: raise RuntimeError("libvirt.openReadOnly returned None")
        except Exception as e:
            raise RuntimeError(f"Cannot connect to libvirt at {self.uri}: {e}")
    def _get_all_stats(self):
        try:
            flags = (libvirt.VIR_CONNECT_GET_ALL_DOMAINS_STATS_ACTIVE |
                     libvirt.VIR_DOMAIN_STATS_CPU | libvirt.VIR_DOMAIN_STATS_BALLOON |
                     libvirt.VIR_DOMAIN_STATS_BLOCK | libvirt.VIR_DOMAIN_STATS_INTERFACE)
            return self.conn.getAllDomainStats([], flags)
        except Exception as e:
            self._log('warning', f"Bulk stats not available, falling back. ({e})")
            doms = self.conn.listAllDomains(); res=[]
            for dom in doms:
                stats={}
                try:
                    cpu_stats=dom.getCPUStats(False)
                    if cpu_stats: stats['cpu.time']=int(cpu_stats[0].get('cpu_time',0))
                except Exception: pass
                try:
                    mem=dom.memoryStats()
                    if mem:
                        if mem.get('actual'):  stats['balloon.maximum']=int(mem['actual'])*1024
                        if mem.get('rss'):     stats['balloon.rss']=int(mem['rss'])*1024
                        if mem.get('usable'):  stats['balloon.current']=int(mem['usable'])*1024
                except Exception: pass
                res.append((dom, stats))
            return res
    def poll(self):
        now=time.time()
        try: domstats=self._get_all_stats()
        except Exception as e:
            self._log('error', f"Failed to fetch domain stats: {e}")
            try: self._connect(); domstats=self._get_all_stats()
            except Exception as e2: self._log('error', f"Reconnect failed: {e2}"); return
        for dom, stats in domstats:
            try:
                uuid=dom.UUIDString(); name=dom.name(); vcpus=max(1, dom.maxVcpus() or 1); state=_state_to_str(dom.state()[0])
                labels={'host': self.host_id, 'vm_uuid': uuid, 'vm_name': name, 'vm_state': state}
                self.emit('vm.uptime_seconds', 0, labels)
                cpu_time_ns=int(stats.get('cpu.time',0)); prev=self.prev.get(uuid, {})
                if prev.get('ts'):
                    dt=max(0.001, now-float(prev['ts'])); dtime=max(0, cpu_time_ns-int(prev.get('cpu_time',0)))
                    cpu_pct=(dtime/(dt*1e9*vcpus))*100.0; cpu_pct=0.0 if cpu_pct<0 else min(cpu_pct,100.0)
                    self.emit('vm.cpu.pct', cpu_pct, labels)
                self.emit('vm.vcpu.count', vcpus, labels)
                mem_assigned=int(stats.get('balloon.maximum',0)); mem_balloon=int(stats.get('balloon.current',0)); rss=int(stats.get('balloon.rss',0))
                if mem_assigned: self.emit('vm.mem.assigned_bytes', mem_assigned, labels)
                if mem_balloon:  self.emit('vm.mem.balloon_bytes',  mem_balloon,  labels)
                if rss:          self.emit('vm.mem.rss_bytes',       rss,          labels)
                for i in range(int(stats.get('block.count',0))):
                    pfx=f'block.{i}'; dev=stats.get(f'{pfx}.name') or f'vd{i}'
                    rd_bytes=int(stats.get(f'{pfx}.rd.bytes',0)); wr_bytes=int(stats.get(f'{pfx}.wr.bytes',0))
                    rd_reqs=int(stats.get(f'{pfx}.rd.reqs',0));   wr_reqs=int(stats.get(f'{pfx}.wr.reqs',0))
                    lb={**labels,'device':dev}; self.emit('vm.disk.read_bytes',rd_bytes,lb); self.emit('vm.disk.write_bytes',wr_bytes,lb)
                    self.emit('vm.disk.read_ops',rd_reqs,lb); self.emit('vm.disk.write_ops',wr_reqs,lb)
                    if 'disk' in prev:
                        pdev=prev['disk'].get(dev,{}); dt=max(0.001, now-float(prev['ts']))
                        if 'rd_bytes' in pdev:
                            self.emit('vm.disk.read_bytes_per_s', max(0, rd_bytes-pdev['rd_bytes'])/dt, lb)
                            self.emit('vm.disk.write_bytes_per_s',max(0, wr_bytes-pdev['wr_bytes'])/dt, lb)
                for i in range(int(stats.get('net.count',0))):
                    pfx=f'net.{i}'; iface=stats.get(f'{pfx}.name') or f'eth{i}'
                    rxb=int(stats.get(f'{pfx}.rx.bytes',0)); txb=int(stats.get(f'{pfx}.tx.bytes',0))
                    rxp=int(stats.get(f'{pfx}.rx.pkts',0));  txp=int(stats.get(f'{pfx}.tx.pkts',0))
                    rxd=int(stats.get(f'{pfx}.rx.drop',0));  txd=int(stats.get(f'{pfx}.tx.drop',0))
                    lbn={**labels,'iface':iface}; self.emit('vm.net.rx_bytes',rxb,lbn); self.emit('vm.net.tx_bytes',txb,lbn)
                    self.emit('vm.net.rx_packets',rxp,lbn); self.emit('vm.net.tx_packets',txp,lbn); self.emit('vm.net.rx_drop',rxd,lbn); self.emit('vm.net.tx_drop',txd,lbn)
                    if 'net' in prev:
                        pn=prev['net'].get(iface,{}); dt=max(0.001, now-float(prev['ts']))
                        if 'rx_bytes' in pn:
                            self.emit('vm.net.rx_bytes_per_s', max(0, rxb-pn['rx_bytes'])/dt, lbn)
                            self.emit('vm.net.tx_bytes_per_s', max(0, txb-pn['tx_bytes'])/dt, lbn)
                snap={'ts':now,'cpu_time':cpu_time_ns,'disk':{},'net':{}}
                for i in range(int(stats.get('block.count',0))):
                    pfx=f'block.{i}'; dev=stats.get(f'{pfx}.name') or f'vd{i}'
                    snap['disk'][dev]={'rd_bytes':int(stats.get(f'{pfx}.rd.bytes',0)),'wr_bytes':int(stats.get(f'{pfx}.wr.bytes',0))}
                for i in range(int(stats.get('net.count',0))):
                    pfx=f'net.{i}'; iface=stats.get(f'{pfx}.name') or f'eth{i}'
                    snap['net'][iface]={'rx_bytes':int(stats.get(f'{pfx}.rx.bytes',0)),'tx_bytes':int(stats.get(f'{pfx}.tx.bytes',0))}
                self.prev[uuid]=snap
            except Exception as ex:
                self._log('error', f"Domain metrics error: {ex}"); continue

@debug('libvirt')
def libvirt():
  return LibvirtKVMCollector().poll()

# if __name__ == "__main__":/
    # def _emit(m,v,l): print(m,v,l)
    # c=LibvirtKVMCollector();
    # while True: c.poll(); time.sleep(5)
