package main

// Core collectors, ported from cpu.py / memory.py / load_average.py /
// network.py / partitions.py / io.py / files.py. The payload keys and shapes
// match the Python agent's; where gopsutil computes a value differently from
// psutil, the psutil formula is reproduced and the comment says so -- those
// are exactly the spots a port silently drifts on.

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

func round1(x float64) float64 { return math.Round(x*10) / 10 }

func clampPct(x float64) float64 { return math.Max(0, math.Min(100, round1(x))) }

// ---- cpu ----------------------------------------------------------------

// psutil keeps the previous per-CPU snapshot in module state (taken at
// import), and cpu_percent / cpu_times_percent are deltas against it.
var (
	cpuMu   sync.Mutex
	cpuPrev []cpu.TimesStat
)

func init() { cpuPrev, _ = cpu.Times(true) }

// psutil's _cpu_tot_time: guest time is already counted in user/nice on
// Linux, so it is subtracted from the total.
func cpuTotal(t cpu.TimesStat) float64 {
	return t.User + t.Nice + t.System + t.Idle + t.Iowait + t.Irq + t.Softirq + t.Steal
}

func cpuData() (any, error) {
	now, err := cpu.Times(true)
	if err != nil {
		return nil, err
	}
	cpuMu.Lock()
	prev := cpuPrev
	cpuPrev = now
	cpuMu.Unlock()

	cores := make([]map[string]float64, 0, len(now))
	for i, t := range now {
		var p cpu.TimesStat
		if i < len(prev) {
			p = prev[i]
		}
		all := cpuTotal(t) - cpuTotal(p)
		pct := func(cur, old float64) float64 {
			if all <= 0 {
				return 0
			}
			return clampPct((cur - old) / all * 100)
		}
		busy := (cpuTotal(t) - t.Idle - t.Iowait) - (cpuTotal(p) - p.Idle - p.Iowait)
		cores = append(cores, map[string]float64{
			"percentage": pct(busy, 0),
			"user":       pct(t.User, p.User),
			"nice":       pct(t.Nice, p.Nice),
			"system":     pct(t.System, p.System),
			"idle":       pct(t.Idle, p.Idle),
			"iowait":     pct(t.Iowait, p.Iowait),
			"irq":        pct(t.Irq, p.Irq),
			"softirq":    pct(t.Softirq, p.Softirq),
			"steal":      pct(t.Steal, p.Steal),
			"guest":      pct(t.Guest, p.Guest),
			"guest_nice": pct(t.GuestNice, p.GuestNice),
		})
	}
	return cores, nil
}

// psutil.cpu_times(percpu=True) is a list of namedtuples, which json.dumps
// writes as ARRAYS -- so the wire format is positional, not keyed.
func cpuUsage() (any, error) {
	times, err := cpu.Times(true)
	if err != nil {
		return nil, err
	}
	out := make([][10]float64, 0, len(times))
	for _, t := range times {
		out = append(out, [10]float64{t.User, t.Nice, t.System, t.Idle, t.Iowait,
			t.Irq, t.Softirq, t.Steal, t.Guest, t.GuestNice})
	}
	return out, nil
}

func cpuModel() (any, error) {
	model := "-"
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return model, nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "model name") {
			if _, v, ok := strings.Cut(line, ":"); ok {
				model = strings.TrimSpace(v)
			}
		}
	}
	return model, nil
}

func cpuCount() (any, error) { return cpu.Counts(true) }

// ---- memory -------------------------------------------------------------

func memory() (any, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	// psutil: percent is (total - available) / total, NOT gopsutil's
	// UsedPercent (used / total). Same field name, different metric.
	percent := 0.0
	if v.Total > 0 {
		percent = round1(float64(v.Total-v.Available) / float64(v.Total) * 100)
	}
	return map[string]any{
		"total": v.Total, "available": v.Available, "percent": percent,
		"used": v.Used, "free": v.Free, "active": v.Active, "inactive": v.Inactive,
		"buffers": v.Buffers, "cached": v.Cached, "shared": v.Shared, "slab": v.Slab,
	}, nil
}

func swap() (any, error) {
	s, err := mem.SwapMemory()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"total": s.Total, "used": s.Used, "free": s.Free,
		"percent": round1(s.UsedPercent), "sin": s.Sin, "sout": s.Sout,
	}, nil
}

func loadAverage() (any, error) {
	a, err := load.Avg()
	if err != nil {
		return nil, err
	}
	return [3]float64{a.Load1, a.Load5, a.Load15}, nil
}

// ---- files --------------------------------------------------------------

func fileHandles() ([3]int64, error) {
	var out [3]int64
	b, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err != nil {
		return out, err
	}
	for i, f := range strings.Fields(string(b)) {
		if i < 3 {
			out[i], _ = strconv.ParseInt(f, 10, 64)
		}
	}
	return out, nil
}

// ---- network ------------------------------------------------------------

const sysClassNet = "/sys/class/net"
const maxLinkSpeedMbps = 1_600_000

func readSysfsNet(iface, attr string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(sysClassNet, iface, attr))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

func interfaceType(iface string) string {
	if isDir(filepath.Join(sysClassNet, iface, "bridge")) {
		return "bridge"
	}
	if _, err := os.Stat(filepath.Join(sysClassNet, iface, "device")); err == nil {
		return "physical"
	}
	return "virtual"
}

func linkSpeedBps(iface string) any {
	raw, ok := readSysfsNet(iface, "speed")
	if !ok {
		return nil
	}
	mbps, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || mbps <= 0 || mbps > maxLinkSpeedMbps {
		return nil
	}
	return mbps * 1_000_000
}

func network() (any, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	up := map[string]bool{}
	for _, i := range ifaces {
		isUp := false
		for _, f := range i.Flags {
			if f == "up" {
				isUp = true
			}
		}
		lower := strings.ToLower(i.Name)
		// psutil.net_if_addrs() comes from getifaddrs(3), which also lists the
		// AF_PACKET (MAC) entry: an UP interface with a MAC but no IP -- a
		// bridge member, a veth -- counts as "having an address" in Python.
		// Go's net.Interfaces().Addrs is IP-only, so the MAC is checked too.
		hasAddr := len(i.Addrs) > 0 || i.HardwareAddr != ""
		if isUp && i.Name != "lo" && !strings.HasPrefix(lower, "loopback") && hasAddr {
			up[i.Name] = true
		}
	}

	types := map[string]string{}
	memberCount := map[string]int{}
	memberOf := map[string]string{}
	for name := range up {
		t := interfaceType(name)
		types[name] = t
		if t == "bridge" {
			members, _ := os.ReadDir(filepath.Join(sysClassNet, name, "brif"))
			memberCount[name] = len(members)
			for _, m := range members {
				memberOf[m.Name()] = name
			}
		}
	}

	counters, err := net.IOCounters(true)
	if err != nil {
		return nil, err
	}
	// make(), not `var result []...`: a nil slice marshals to null, and on
	// this wire null means "collection failed", [] means "zero interfaces".
	result := make([]map[string]map[string]any, 0, len(up))
	for _, c := range counters {
		if !up[c.Name] {
			continue
		}
		entry := map[string]any{
			"bytes_sent": c.BytesSent, "bytes_recv": c.BytesRecv,
			"packets_sent": c.PacketsSent, "packets_recv": c.PacketsRecv,
			"errin": c.Errin, "errout": c.Errout, "dropin": c.Dropin, "dropout": c.Dropout,
			"interface_type": types[c.Name], "network_link_speed_bps": linkSpeedBps(c.Name),
		}
		if n, ok := memberCount[c.Name]; ok {
			entry["bridge_member_count"] = n
		}
		if b, ok := memberOf[c.Name]; ok {
			entry["bridge"] = b
		}
		result = append(result, map[string]map[string]any{c.Name: entry})
	}
	return result, nil
}

// ---- partitions ---------------------------------------------------------

var ignoredFS = map[string]bool{
	"squashfs": true, "cagefs-skeleton": true, "overlay": true, "devtmpfs": true,
	"tmpfs": true, "loop": true, "nullfs": true, "cdfs": true, "udf": true, "iso9660": true,
}

func shouldIgnore(fstype, opts string) bool {
	return ignoredFS[strings.ToLower(fstype)] || strings.Contains(strings.ToLower(opts), "cdrom")
}

type partition struct{ Device, Mountpoint, Fstype, Opts string }

// psutil.disk_partitions(all=False), NOT gopsutil's disk.Partitions(false):
// gopsutil also drops every BIND mount, which inside a container (where each
// volume is a bind of a host directory) is every real mount -- the Go agent
// reported partitions_metadata: [] there, and the disk silently vanished
// from monitoring. psutil keeps them: a real filesystem type from
// /proc/filesystems (plus zfs) and a device is all it asks.
func partitions() ([]partition, error) {
	fstypes := map[string]bool{}
	fsList, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(fsList), "\n") {
		if nodev, fs, ok := strings.Cut(line, "\t"); ok && strings.TrimSpace(nodev) == "nodev" {
			if fs == "zfs" {
				fstypes["zfs"] = true
			}
		} else if t := strings.TrimSpace(line); t != "" {
			fstypes[t] = true
		}
	}
	mountsPath := "/proc/self/mounts"
	if st, err := os.Stat("/etc/mtab"); err == nil && st.Mode().IsRegular() {
		mountsPath = "/etc/mtab"
	} else if real, err := filepath.EvalSymlinks("/etc/mtab"); err == nil {
		mountsPath = real
	}
	mounts, err := os.ReadFile(mountsPath)
	if err != nil {
		return nil, err
	}
	// getmntent(3) decodes the octal escapes mount writes for these bytes.
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	var out []partition
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		p := partition{unescape.Replace(f[0]), unescape.Replace(f[1]), f[2], f[3]}
		if p.Device == "none" {
			p.Device = ""
		}
		if p.Device == "" || !fstypes[p.Fstype] {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func partitionsMetadata() (any, error) {
	parts, err := partitions()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(parts))
	for _, p := range parts {
		if shouldIgnore(p.Fstype, p.Opts) {
			continue
		}
		out = append(out, map[string]string{
			"device": p.Device, "mountpoint": p.Mountpoint, "fstype": p.Fstype, "opts": p.Opts,
		})
	}
	return out, nil
}

func partitionsUsage() (any, error) {
	parts, err := partitions()
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]any{}
	for _, p := range parts {
		if shouldIgnore(p.Fstype, p.Opts) {
			continue
		}
		u, err := disk.Usage(p.Mountpoint)
		if err != nil {
			logf("info", "Error getting disk usage for %s: %v", p.Mountpoint, err)
			continue
		}
		// psutil: used / (used + free), the space a non-root user can reach.
		percent := 0.0
		if u.Used+u.Free > 0 {
			percent = round1(float64(u.Used) / float64(u.Used+u.Free) * 100)
		}
		out[p.Mountpoint] = map[string]any{
			"total": u.Total, "used": u.Used, "free": u.Free, "percent": percent,
		}
	}
	return out, nil
}

// ---- io -----------------------------------------------------------------

// psutil.disk_io_counters(perdisk=True), read from /proc/diskstats directly:
// gopsutil's disk.IOCounters() skips every device whose counters are all
// zero (an idle loop device), and returns a map, losing the file order.
// Not reproduced: psutil's nowrap=True, which keeps a counter monotonic
// across a 32-bit wrap -- one more hidden semantic a real port must carry.
func ioCounters() (any, error) {
	raw, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	out := make([]map[string]map[string]uint64, 0, 64)
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 {
			continue
		}
		n := make([]uint64, 11)
		for i := range n {
			if n[i], err = strconv.ParseUint(f[3+i], 10, 64); err != nil {
				return nil, err
			}
		}
		out = append(out, map[string]map[string]uint64{f[2]: {
			"read_count": n[0], "read_merged_count": n[1], "read_bytes": n[2] * 512,
			"read_time": n[3], "write_count": n[4], "write_merged_count": n[5],
			"write_bytes": n[6] * 512, "write_time": n[7], "busy_time": n[9],
		}})
	}
	return out, nil
}
