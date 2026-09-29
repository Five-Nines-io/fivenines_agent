//! Prototype: the fivenines agent's collection loop and core collectors in
//! Rust, the sibling of experiments/go-agent. Not production code -- see
//! README.md.

mod bounded;
mod collectors;
mod contract;
mod docker;
mod processes;
mod sync;

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::unistd::{Gid, Group, Uid, User, geteuid, getgid, getgroups, getuid};
use serde_json::{Map, Value, json};
use signal_hook::consts::{SIGINT, SIGTERM};

use crate::collectors::Collected;
use crate::sync::{Event, Synchronizer, gzip_json};

const VERSION: &str = "0.0.0-rust-proto";

/// Per-collector wall-clock bound -- the TODOS.md P3 item.
const COLLECTOR_TIMEOUT: Duration = Duration::from_secs(10);

pub fn log(level: &str, msg: &str) {
    if level == "debug" && std::env::var("LOG_LEVEL").as_deref() != Ok("debug") {
        return;
    }
    eprintln!("[{}] {msg}", level.to_uppercase());
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

pub fn api_url() -> String {
    env_or("API_URL", "api.fivenines.io")
}

fn config_dir() -> String {
    env_or("CONFIG_DIR", "/etc/fivenines_agent")
}

/// platform.uname(). processor is `uname -p` in Python: "unknown" (-> "") on
/// Debian/Ubuntu, the architecture on RHEL. The Debian answer is hardcoded.
fn uname() -> Value {
    match nix::sys::utsname::uname() {
        Ok(u) => json!({
            "system": u.sysname().to_string_lossy(), "node": u.nodename().to_string_lossy(),
            "release": u.release().to_string_lossy(), "version": u.version().to_string_lossy(),
            "machine": u.machine().to_string_lossy(), "processor": "",
        }),
        Err(_) => Value::Null,
    }
}

fn group_name(gid: Gid) -> String {
    Group::from_gid(gid)
        .ok()
        .flatten()
        .map_or(gid.to_string(), |g| g.name)
}

fn user_context() -> Value {
    let (uid, gid) = (getuid(), getgid());
    let username = User::from_uid(uid)
        .ok()
        .flatten()
        .map_or(uid.to_string(), |u| u.name);
    let groups: Vec<String> = getgroups()
        .unwrap_or_default()
        .into_iter()
        .map(group_name)
        .collect();
    let home = std::env::var("HOME").unwrap_or_default();
    let cfg = config_dir();
    json!({
        "username": username, "uid": uid.as_raw(), "euid": geteuid().as_raw(), "gid": gid.as_raw(),
        "groupname": group_name(gid), "groups": groups, "is_root": uid == Uid::from_raw(0),
        "is_user_install": !home.is_empty() && cfg.starts_with(&home),
        "config_dir": cfg, "home_dir": home,
    })
}

/// machine_id.py: a persisted UUID4, created 0600.
fn machine_id() -> Value {
    let path = PathBuf::from(config_dir()).join("MACHINE_ID");
    if let Some(id) = fs::read_to_string(&path)
        .ok()
        .and_then(|s| uuid::Uuid::parse_str(s.trim()).ok())
    {
        return json!(id.to_string());
    }
    let id = uuid::Uuid::new_v4().to_string();
    let written = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(id.as_bytes()));
    written.map_or(Value::Null, |_| json!(id))
}

fn static_data() -> Map<String, Value> {
    let core = [
        "cpu",
        "memory",
        "load_average",
        "io",
        "network",
        "partitions",
        "file_handles",
    ];
    let Value::Object(m) = json!({
        "version": VERSION, "uname": uname(), "boot_time": collectors::boot_time(),
        "capabilities": core.iter().map(|k| (k.to_string(), json!(true))).collect::<Map<_, _>>(),
        "capability_reasons": {}, "pending_capabilities": [],
        "user_context": user_context(), "machine_id": machine_id(),
    }) else {
        unreachable!()
    };
    m
}

/// A collector gets config[config_key] -- the **kwargs of pass_kwargs=True.
type CollectFn = fn(&Value) -> Collected;

/// The COLLECTORS registry, restricted to what this prototype ports.
static REGISTRY: &[(&str, &[(&str, CollectFn)])] = &[
    (
        "cpu",
        &[
            ("cpu", |_| collectors::cpu_data()),
            ("cpu_usage", |_| collectors::cpu_usage()),
            ("cpu_model", |_| collectors::cpu_model()),
            ("cpu_count", |_| collectors::cpu_count()),
        ],
    ),
    (
        "memory",
        &[
            ("memory", |_| collectors::memory()),
            ("swap", |_| collectors::swap()),
        ],
    ),
    ("network", &[("network", |_| collectors::network())]),
    (
        "partitions",
        &[
            ("partitions_metadata", |_| collectors::partitions_metadata()),
            ("partitions_usage", |_| collectors::partitions_usage()),
        ],
    ),
    ("io", &[("io", |_| collectors::io())]),
    ("processes", &[("processes", |_| processes::processes())]),
    ("docker", &[("docker", docker::docker_metrics)]),
];

/// docker has its own 25s budget; the generic bound sits above it so the
/// collector reports its own failure first.
fn collector_timeout(key: &str) -> Duration {
    if key == "docker" {
        Duration::from_secs(30)
    } else {
        COLLECTOR_TIMEOUT
    }
}

/// Python truthiness of a config value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

fn run(
    key: &'static str,
    f: impl FnOnce() -> Collected + Send + 'static,
    data: &mut Map<String, Value>,
    telemetry: &mut Map<String, Value>,
) {
    let start = Instant::now();
    let result = bounded::call_bounded(key, collector_timeout(key), f);
    let mut entry = Map::new();
    entry.insert(
        "duration_ms".into(),
        json!(start.elapsed().as_secs_f64() * 1000.0),
    );
    let value = result.unwrap_or_else(|e| {
        log("error", &format!("{key}: {e}"));
        entry.insert("error".into(), json!(e));
        Value::Null // a failed collector reports null, never a partial value
    });
    telemetry.insert(key.into(), Value::Object(entry));
    data.insert(key.into(), value);
}

fn collect_metrics(cfg: &Map<String, Value>, data: &mut Map<String, Value>) {
    let mut telemetry = Map::new();
    run(
        "load_average",
        collectors::load_average,
        data,
        &mut telemetry,
    );
    let (used, limit) = match collectors::file_handles() {
        Ok(fh) => (json!(fh[0]), json!(fh[2])),
        Err(_) => (Value::Null, Value::Null),
    };
    data.insert("file_handles_used".into(), used);
    data.insert("file_handles_limit".into(), limit);
    for (config_key, group) in REGISTRY {
        if truthy(cfg.get(*config_key)) {
            let group_cfg = cfg.get(*config_key).cloned().unwrap_or(Value::Null);
            for (key, f) in *group {
                let (f, group_cfg) = (*f, group_cfg.clone());
                run(key, move || f(&group_cfg), data, &mut telemetry);
            }
        }
    }
    data.insert("_telemetry".into(), Value::Object(telemetry));
}

fn tick(cfg: &Map<String, Value>, static_data: &Map<String, Value>) -> Map<String, Value> {
    let mut data = static_data.clone();
    let start = Instant::now();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    data.insert("ts".into(), json!(ts));
    collect_metrics(cfg, &mut data);
    data.insert("running_time".into(), json!(start.elapsed().as_secs_f64()));
    data
}

fn dry_run_config() -> Map<String, Value> {
    let Value::Object(m) = json!({
        "enabled": true, "interval": 60, "cpu": true, "memory": true,
        "network": true, "partitions": true, "io": true, "processes": true,
    }) else {
        unreachable!()
    };
    m
}

fn main() {
    let arg = std::env::args().nth(1);
    if arg.as_deref() == Some("--version") {
        println!("{VERSION}");
        return;
    }
    let dry_run =
        std::env::var("DRY_RUN").as_deref() == Ok("true") || arg.as_deref() == Some("--dry-run");
    collectors::init();

    let exit = Event::default();
    {
        let exit = exit.clone();
        let mut signals =
            signal_hook::iterator::Signals::new([SIGTERM, SIGINT]).expect("signal handlers");
        std::thread::spawn(move || {
            if signals.forever().next().is_some() {
                exit.set();
            }
        });
    }

    let static_data = static_data();
    if dry_run {
        let data = Value::Object(tick(&dry_run_config(), &static_data));
        println!(
            "{}",
            serde_json::to_string_pretty(&data).expect("serializable")
        );
        return;
    }

    let token = match fs::read_to_string(PathBuf::from(config_dir()).join("TOKEN")) {
        Ok(t) => t.trim().to_string(),
        Err(_) => {
            log("error", &format!("TOKEN not found in {}", config_dir()));
            std::process::exit(2);
        }
    };
    let sync = Arc::new(Synchronizer::new(token, exit.clone()));

    let mut get_config = static_data.clone();
    get_config.insert("get_config".into(), json!(true));
    let blob = gzip_json(&Value::Object(get_config)).expect("serializable");
    while !sync.send(&blob) {
        if exit.is_set() {
            return;
        }
    }
    let drain = {
        let sync = Arc::clone(&sync);
        std::thread::spawn(move || sync.run())
    };
    log("info", "fivenines agent (Rust prototype) started");

    while !exit.is_set() {
        let cfg = sync.config();
        if !truthy(cfg.get("enabled")) {
            exit.wait(Duration::from_secs(25));
            continue;
        }
        let data = tick(&cfg, &static_data);
        let running = data["running_time"].as_f64().unwrap_or(0.0);
        match gzip_json(&Value::Object(data)) {
            Ok(blob) => sync.put(blob),
            Err(e) => log(
                "error",
                &format!("Payload serialization failed; dropping tick: {e}"),
            ),
        }
        let interval = cfg
            .get("interval")
            .and_then(Value::as_f64)
            .filter(|i| *i > 0.0)
            .unwrap_or(60.0);
        exit.wait(Duration::from_secs_f64((interval - running).max(0.1)));
    }
    sync.stop();
    let _ = drain.join();
    log("info", "fivenines agent shutting down");
}
