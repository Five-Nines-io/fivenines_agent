//! processes.py is 34 lines because psutil does the work; this is what
//! `proc.as_dict(attrs=[...])` means on Linux, spelled out.

use std::collections::HashMap;
use std::fs;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use nix::unistd::{Uid, User};
use serde_json::{Value, json};

use crate::collectors::{Collected, clk_tck, page_size, phys_mem_total, round1};

/// psutil's PROC_STATUSES (the state letter of /proc/<pid>/stat), '?' otherwise.
fn status(letter: u8) -> &'static str {
    match letter {
        b'R' => "running",
        b'S' => "sleeping",
        b'D' => "disk-sleep",
        b'T' => "stopped",
        b't' => "tracing-stop",
        b'Z' => "zombie",
        b'X' | b'x' => "dead",
        b'K' => "wake-kill",
        b'W' => "waking",
        b'I' => "idle",
        b'P' => "parked",
        _ => "?",
    }
}

/// process_iter() keeps each Process object between calls, and
/// cpu_percent(interval=None) is the delta against the previous call on that
/// object -- 0.0 the first time. Keyed by (pid, start time), as process_iter
/// is, so a recycled pid starts over.
type ProcKey = (u32, u64); // (pid, start time in ticks)
type ProcSample = (f64, Instant); // (user + system seconds, when)
static PREV: LazyLock<Mutex<HashMap<ProcKey, ProcSample>>> = LazyLock::new(Default::default);

/// psutil's cmdline(): NUL-separated, unless the process rewrote its title
/// (setproctitle), in which case psutil splits on spaces.
fn argv0(pid: u32) -> Option<String> {
    let data = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let data = String::from_utf8_lossy(&data);
    if data.is_empty() {
        return None;
    }
    let sep = if data.ends_with('\0') { '\0' } else { ' ' };
    let data = data.strip_suffix(sep).unwrap_or(&data);
    let mut args: Vec<&str> = data.split(sep).collect();
    if sep == '\0' && args.len() == 1 && data.contains(' ') {
        args = data.split(' ').collect();
    }
    args.first()
        .map(|a| a.rsplit('/').next().unwrap_or(a).to_string())
}

/// name() in psutil: the kernel truncates comm to 15 bytes, so a 15-byte
/// name is completed from argv[0] when argv[0]'s basename starts with it.
fn name(pid: u32, comm: String) -> String {
    if comm.len() < 15 {
        return comm;
    }
    match argv0(pid) {
        Some(extended) if extended.starts_with(&comm) => extended,
        _ => comm,
    }
}

pub fn processes() -> Collected {
    let mut pids: Vec<u32> = fs::read_dir("/proc")
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .filter(|&p| p > 0)
        .collect();
    pids.sort_unstable();

    let now = Instant::now();
    let (tck, page, total) = (clk_tck(), page_size(), phys_mem_total());
    let mut users: HashMap<u32, Value> = HashMap::new(); // per-tick uid -> name cache
    let mut prev = PREV.lock().unwrap();
    let mut seen = HashMap::with_capacity(pids.len());
    let mut out = Vec::with_capacity(pids.len());

    for pid in pids {
        let base = format!("/proc/{pid}");
        let Ok(stat) = fs::read(format!("{base}/stat")) else {
            continue;
        }; // gone: NoSuchProcess
        // comm may contain spaces and parens: it ends at the LAST ')'.
        let (Some(open), Some(close)) = (
            stat.iter().position(|&b| b == b'('),
            stat.iter().rposition(|&b| b == b')'),
        ) else {
            continue;
        };
        if close < open || close + 2 > stat.len() {
            continue;
        }
        let comm = String::from_utf8_lossy(&stat[open + 1..close]).into_owned();
        let rest = String::from_utf8_lossy(&stat[close + 2..]);
        let f: Vec<&str> = rest.split_whitespace().collect(); // f[0] is field 3 (state)
        if f.len() < 40 {
            continue;
        }
        let num = |i: usize| f[i - 3].parse::<u64>().unwrap_or(0);
        let ticks = |i: usize| num(i) as f64 / tck;

        let (user, system) = (ticks(14), ticks(15));
        let key = (pid, num(22));
        let cpu_percent = match prev.get(&key) {
            Some(&(cpu, when)) => {
                let dt = now.duration_since(when).as_secs_f64();
                if dt > 0.0 {
                    round1((user + system - cpu) / dt * 100.0)
                } else {
                    0.0
                }
            }
            None => 0.0,
        };
        seen.insert(key, (user + system, now));

        let memory_percent = fs::read_to_string(format!("{base}/statm"))
            .ok()
            .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
            .filter(|_| total > 0)
            .map_or(Value::Null, |rss| {
                json!((rss * page) as f64 / total as f64 * 100.0)
            });

        // username: the REAL uid, first column of "Uid:" in /proc/<pid>/status.
        let username = fs::read_to_string(format!("{base}/status"))
            .ok()
            .and_then(|s| {
                s.lines().find_map(|l| {
                    l.strip_prefix("Uid:")?
                        .split_whitespace()
                        .next()?
                        .parse::<u32>()
                        .ok()
                })
            })
            .map_or(Value::Null, |uid| {
                users
                    .entry(uid)
                    .or_insert_with(|| {
                        // psutil falls back to the uid as a string.
                        json!(
                            User::from_uid(Uid::from_raw(uid))
                                .ok()
                                .flatten()
                                .map_or(uid.to_string(), |u| u.name)
                        )
                    })
                    .clone()
            });

        out.push(json!({
            "pid": pid,
            "ppid": num(4),
            "name": name(pid, comm),
            "username": username,
            "memory_percent": memory_percent,
            "cpu_percent": cpu_percent,
            // pcputimes(user, system, children_user, children_system, iowait):
            // a namedtuple, so an ARRAY on the wire.
            "cpu_times": [user, system, ticks(16), ticks(17), ticks(42)],
            "num_threads": num(20),
            "status": status(f[0].as_bytes()[0]),
        }));
    }
    *prev = seen; // processes that exited are forgotten, as process_iter does
    Ok(Value::Array(out))
}
