//! Core collectors, ported from cpu.py / memory.py / load_average.py /
//! network.py / partitions.py / io.py / files.py by reading /proc and /sys the
//! way psutil does -- not through a crate. The Go prototype is why: gopsutil's
//! nearest function silently diverged from psutil twice (bind mounts, idle
//! disks), and Rust's `sysinfo` is further from psutil than gopsutil is.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use nix::sys::statvfs::statvfs;
use nix::unistd::{SysconfVar, sysconf};
use serde_json::{Map, Value, json};

pub type Collected = Result<Value, String>;

pub fn read(path: impl AsRef<Path>) -> Result<String, String> {
    fs::read_to_string(path.as_ref()).map_err(|e| format!("{}: {e}", path.as_ref().display()))
}

// c_long is i64 here but i32 on 32-bit targets (armv7, i386).
#[allow(clippy::useless_conversion)]
fn sysconf_or(var: SysconfVar, default: i64) -> i64 {
    sysconf(var)
        .ok()
        .flatten()
        .map(i64::from)
        .unwrap_or(default)
}

pub fn clk_tck() -> f64 {
    sysconf_or(SysconfVar::CLK_TCK, 100) as f64
}

pub fn page_size() -> u64 {
    sysconf_or(SysconfVar::PAGE_SIZE, 4096) as u64
}

pub fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn clamp_pct(x: f64) -> f64 {
    round1(x).clamp(0.0, 100.0)
}

// ---- cpu -------------------------------------------------------------------

/// user nice system idle iowait irq softirq steal guest guest_nice, seconds.
type CpuTimes = [f64; 10];
const CPU_FIELDS: [&str; 10] = [
    "user",
    "nice",
    "system",
    "idle",
    "iowait",
    "irq",
    "softirq",
    "steal",
    "guest",
    "guest_nice",
];

fn per_cpu_times() -> Result<Vec<CpuTimes>, String> {
    let tck = clk_tck();
    Ok(read("/proc/stat")?
        .lines()
        .filter(|l| l.starts_with("cpu") && l.as_bytes().get(3).is_some_and(u8::is_ascii_digit))
        .map(|l| {
            let mut t = [0.0; 10];
            for (i, v) in l.split_whitespace().skip(1).take(10).enumerate() {
                t[i] = v.parse::<f64>().unwrap_or(0.0) / tck;
            }
            t
        })
        .collect())
}

/// psutil's _cpu_tot_time: guest time is already counted in user/nice on
/// Linux, so it is left out of the total.
fn cpu_total(t: &CpuTimes) -> f64 {
    t[..8].iter().sum()
}

/// psutil keeps the previous per-CPU snapshot in module state, taken at
/// import; cpu_percent / cpu_times_percent are deltas against it.
static CPU_PREV: LazyLock<Mutex<Vec<CpuTimes>>> =
    LazyLock::new(|| Mutex::new(per_cpu_times().unwrap_or_default()));

pub fn init() {
    LazyLock::force(&CPU_PREV);
}

pub fn cpu_data() -> Collected {
    let now = per_cpu_times()?;
    let prev = std::mem::replace(&mut *CPU_PREV.lock().unwrap(), now.clone());
    let cores = now
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let p = prev.get(i).copied().unwrap_or([0.0; 10]);
            let all = cpu_total(t) - cpu_total(&p);
            let pct = |delta: f64| {
                if all <= 0.0 {
                    0.0
                } else {
                    clamp_pct(delta / all * 100.0)
                }
            };
            let busy = (cpu_total(t) - t[3] - t[4]) - (cpu_total(&p) - p[3] - p[4]);
            let mut core = Map::new();
            core.insert("percentage".into(), json!(pct(busy)));
            for (k, name) in CPU_FIELDS.iter().enumerate() {
                core.insert((*name).into(), json!(pct(t[k] - p[k])));
            }
            Value::Object(core)
        })
        .collect();
    Ok(Value::Array(cores))
}

/// psutil.cpu_times(percpu=True) is a list of namedtuples, which json.dumps
/// writes as ARRAYS -- the wire format is positional, not keyed.
pub fn cpu_usage() -> Collected {
    Ok(json!(per_cpu_times()?))
}

pub fn cpu_model() -> Collected {
    let model = read("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("model name"))
        .filter_map(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
        .next_back()
        .unwrap_or_else(|| "-".into());
    Ok(json!(model))
}

/// os.cpu_count(): the ONLINE processors, not the affinity mask that
/// std::thread::available_parallelism reports.
pub fn cpu_count() -> Collected {
    Ok(json!(sysconf_or(SysconfVar::_NPROCESSORS_ONLN, 1)))
}

pub fn boot_time() -> f64 {
    read("/proc/stat")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0.0)
}

// ---- memory ----------------------------------------------------------------

fn meminfo() -> Result<HashMap<String, u64>, String> {
    Ok(read("/proc/meminfo")?
        .lines()
        .filter_map(|l| {
            let (k, rest) = l.split_once(':')?;
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            Some((k.to_string(), kb * 1024))
        })
        .collect())
}

pub fn memory() -> Collected {
    let m = meminfo()?;
    let g = |k: &str| m.get(k).copied().unwrap_or(0);
    let (total, free, buffers) = (g("MemTotal"), g("MemFree"), g("Buffers"));
    let cached = g("Cached") + g("SReclaimable");
    // psutil 7: used = total - available. Before psutil 6 it was
    // total - free - cached - buffers -- the formula this port first shipped
    // with, 1.8 GB off on the bench host until the payload diff caught it. A
    // port freezes one psutil version's semantics; the Python agent gets the
    // next one by bumping a pin.
    let mut available = match m.get("MemAvailable") {
        // psutil estimates from /proc/zoneinfo when the kernel reports 0 or
        // nothing (calculate_avail_vmem); free + cached + buffers is a stand-in.
        Some(&a) if a > 0 => a,
        _ => free + cached + buffers,
    };
    if available > total {
        available = free; // an LXC container seeing host values, as psutil and procps do
    }
    let used = total - available;
    let percent = if total > 0 {
        round1(used as f64 / total as f64 * 100.0)
    } else {
        0.0
    };
    Ok(json!({
        "total": total, "available": available, "percent": percent, "used": used,
        "free": free, "active": g("Active"), "inactive": g("Inactive"), "buffers": buffers,
        "cached": cached, "shared": g("Shmem"), "slab": g("Slab"),
    }))
}

pub fn phys_mem_total() -> u64 {
    static TOTAL: LazyLock<u64> = LazyLock::new(|| {
        meminfo()
            .ok()
            .and_then(|m| m.get("MemTotal").copied())
            .unwrap_or(0)
    });
    *TOTAL
}

pub fn swap() -> Collected {
    let m = meminfo()?;
    let total = m.get("SwapTotal").copied().unwrap_or(0);
    let free = m.get("SwapFree").copied().unwrap_or(0);
    let used = total.saturating_sub(free);
    let percent = if total > 0 {
        round1(used as f64 / total as f64 * 100.0)
    } else {
        0.0
    };
    // psutil: pswpin/pswpout pages from /proc/vmstat, times 4 KiB.
    let vmstat = read("/proc/vmstat")?;
    let pages = |key: &str| {
        vmstat
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(' ')?.parse::<u64>().ok())
            .unwrap_or(0)
    };
    Ok(json!({
        "total": total, "used": used, "free": free, "percent": percent,
        "sin": pages("pswpin") * 4096, "sout": pages("pswpout") * 4096,
    }))
}

pub fn load_average() -> Collected {
    let raw = read("/proc/loadavg")?;
    let v: Vec<f64> = raw
        .split_whitespace()
        .take(3)
        .filter_map(|x| x.parse().ok())
        .collect();
    if v.len() != 3 {
        return Err(format!("unexpected /proc/loadavg: {raw:?}"));
    }
    Ok(json!(v))
}

pub fn file_handles() -> Result<[i64; 3], String> {
    let mut out = [0; 3];
    for (i, v) in read("/proc/sys/fs/file-nr")?
        .split_whitespace()
        .take(3)
        .enumerate()
    {
        out[i] = v.parse().map_err(|e| format!("file-nr: {e}"))?;
    }
    Ok(out)
}

// ---- network ---------------------------------------------------------------

const SYS_CLASS_NET: &str = "/sys/class/net";
const MAX_LINK_SPEED_MBPS: i64 = 1_600_000;

/// psutil's interfaces() for network.py: RUNNING (psutil's `isup` is IFF_RUNNING,
/// the link, not IFF_UP, the admin state), not loopback, and at least one
/// address -- getifaddrs(3) lists the AF_PACKET (MAC) entry too, so an
/// interface with a MAC and no IP counts.
fn interfaces() -> Result<HashSet<String>, String> {
    let mut running = HashSet::new();
    let mut has_addr = HashSet::new();
    for ifa in getifaddrs().map_err(|e| e.to_string())? {
        if ifa.flags.contains(InterfaceFlags::IFF_RUNNING) {
            running.insert(ifa.interface_name.clone());
        }
        if ifa.address.is_some() {
            has_addr.insert(ifa.interface_name);
        }
    }
    Ok(running
        .into_iter()
        .filter(|n| has_addr.contains(n) && n != "lo" && !n.to_lowercase().starts_with("loopback"))
        .collect())
}

fn sysfs_net(iface: &str, attr: &str) -> Option<String> {
    fs::read_to_string(Path::new(SYS_CLASS_NET).join(iface).join(attr))
        .ok()
        .map(|s| s.trim().to_string())
}

fn interface_type(iface: &str) -> &'static str {
    let base = Path::new(SYS_CLASS_NET).join(iface);
    if base.join("bridge").is_dir() {
        "bridge"
    } else if base.join("device").exists() {
        "physical"
    } else {
        "virtual"
    }
}

fn link_speed_bps(iface: &str) -> Value {
    match sysfs_net(iface, "speed").and_then(|s| s.parse::<i64>().ok()) {
        Some(mbps) if mbps > 0 && mbps <= MAX_LINK_SPEED_MBPS => json!(mbps * 1_000_000),
        _ => Value::Null,
    }
}

pub fn network() -> Collected {
    let up = interfaces()?;
    let mut types = HashMap::new();
    let mut member_count = HashMap::new();
    let mut member_of = HashMap::new();
    for name in &up {
        let t = interface_type(name);
        types.insert(name.clone(), t);
        if t == "bridge" {
            let members: Vec<String> =
                fs::read_dir(Path::new(SYS_CLASS_NET).join(name).join("brif"))
                    .map(|d| {
                        d.filter_map(|e| e.ok()?.file_name().into_string().ok())
                            .collect()
                    })
                    .unwrap_or_default();
            member_count.insert(name.clone(), members.len());
            for m in members {
                member_of.insert(m, name.clone());
            }
        }
    }

    // psutil.net_io_counters(pernic=True): /proc/net/dev, in file order.
    let mut out = Vec::new();
    for line in read("/proc/net/dev")?.lines().skip(2) {
        let Some((name, counters)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if !up.contains(name) {
            continue;
        }
        let f: Vec<u64> = counters
            .split_whitespace()
            .map(|v| v.parse().unwrap_or(0))
            .collect();
        if f.len() < 12 {
            continue;
        }
        let mut entry = json!({
            "bytes_sent": f[8], "bytes_recv": f[0], "packets_sent": f[9], "packets_recv": f[1],
            "errin": f[2], "errout": f[10], "dropin": f[3], "dropout": f[11],
            "interface_type": types[name], "network_link_speed_bps": link_speed_bps(name),
        });
        if let Some(n) = member_count.get(name) {
            entry["bridge_member_count"] = json!(n);
        }
        if let Some(b) = member_of.get(name) {
            entry["bridge"] = json!(b);
        }
        out.push(json!({ name: entry }));
    }
    Ok(Value::Array(out))
}

// ---- partitions ------------------------------------------------------------

const IGNORED_FS: [&str; 10] = [
    "squashfs",
    "cagefs-skeleton",
    "overlay",
    "devtmpfs",
    "tmpfs",
    "loop",
    "nullfs",
    "cdfs",
    "udf",
    "iso9660",
];

fn should_ignore(fstype: &str, opts: &str) -> bool {
    IGNORED_FS.contains(&fstype.to_lowercase().as_str()) || opts.to_lowercase().contains("cdrom")
}

struct Partition {
    device: String,
    mountpoint: String,
    fstype: String,
    opts: String,
}

/// getmntent(3) decodes the octal escapes mount writes for these bytes.
fn unescape(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

/// psutil.disk_partitions(all=False): a real filesystem type from
/// /proc/filesystems (plus zfs) and a device. Bind mounts are KEPT.
fn partitions() -> Result<Vec<Partition>, String> {
    let mut fstypes = HashSet::new();
    for line in read("/proc/filesystems")?.lines() {
        match line.split_once('\t') {
            Some((nodev, fs)) if nodev.trim() == "nodev" => {
                if fs.trim() == "zfs" {
                    fstypes.insert("zfs".to_string());
                }
            }
            _ if !line.trim().is_empty() => {
                fstypes.insert(line.trim().to_string());
            }
            _ => {}
        }
    }
    let mounts_path = if Path::new("/etc/mtab").is_file() {
        "/etc/mtab"
    } else {
        "/proc/self/mounts"
    };
    Ok(read(mounts_path)?
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                return None;
            }
            let device = match unescape(f[0]) {
                d if d == "none" => String::new(),
                d => d,
            };
            if device.is_empty() || !fstypes.contains(f[2]) {
                return None;
            }
            Some(Partition {
                device,
                mountpoint: unescape(f[1]),
                fstype: f[2].into(),
                opts: f[3].into(),
            })
        })
        .collect())
}

pub fn partitions_metadata() -> Collected {
    Ok(Value::Array(
        partitions()?
            .into_iter()
            .filter(|p| !should_ignore(&p.fstype, &p.opts))
            .map(|p| json!({"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype, "opts": p.opts}))
            .collect(),
    ))
}

/// psutil.disk_usage: free and percent are what a non-root user can reach.
pub fn partitions_usage() -> Collected {
    let mut out = Map::new();
    for p in partitions()?
        .into_iter()
        .filter(|p| !should_ignore(&p.fstype, &p.opts))
    {
        let st = match statvfs(p.mountpoint.as_str()) {
            Ok(st) => st,
            Err(e) => {
                crate::log(
                    "info",
                    &format!("Error getting disk usage for {}: {e}", p.mountpoint),
                );
                continue;
            }
        };
        let frsize = st.fragment_size() as u64;
        let total = st.blocks() as u64 * frsize;
        let used = total.saturating_sub(st.blocks_free() as u64 * frsize);
        let free = st.blocks_available() as u64 * frsize;
        let percent = if used + free > 0 {
            round1(used as f64 / (used + free) as f64 * 100.0)
        } else {
            0.0
        };
        out.insert(
            p.mountpoint,
            json!({"total": total, "used": used, "free": free, "percent": percent}),
        );
    }
    Ok(Value::Object(out))
}

// ---- io --------------------------------------------------------------------

/// psutil.disk_io_counters(perdisk=True): every /proc/diskstats row, in file
/// order, idle devices included. psutil's nowrap=True (counters kept
/// monotonic across a wrap) is NOT reproduced.
pub fn io() -> Collected {
    let mut out = Vec::new();
    for line in read("/proc/diskstats")?.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 14 {
            continue;
        }
        let n: Vec<u64> = f[3..14]
            .iter()
            .map(|v| v.parse().map_err(|e| format!("diskstats: {e}")))
            .collect::<Result<_, _>>()?;
        out.push(json!({ f[2]: {
            "read_count": n[0], "read_merged_count": n[1], "read_bytes": n[2] * 512, "read_time": n[3],
            "write_count": n[4], "write_merged_count": n[5], "write_bytes": n[6] * 512, "write_time": n[7],
            "busy_time": n[9],
        }}));
    }
    Ok(Value::Array(out))
}
