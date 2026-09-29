//! docker.py with bollard, the Docker client a real Rust port would take.
//! Same contract: {"containers": {}} is a genuinely empty host, null is a
//! collection failure the server never prunes on, and a partial container
//! map never ships.
//!
//! bollard is async (hyper on tokio). The agent is not, so one current-thread
//! runtime is built once and each tick blocks on it: no worker pool, no
//! extra threads.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use bollard::Docker;
use bollard::errors::Error as DockerError;
use bollard::models::ContainerStatsResponse;
use bollard::query_parameters::{InspectContainerOptions, ListContainersOptions, StatsOptions};
use futures_util::StreamExt;
use serde_json::{Map, Value, json};

use crate::collectors::Collected;
use crate::log;

const CLIENT_TIMEOUT_SECS: u64 = 10;
const COLLECT_DEADLINE: Duration = Duration::from_secs(25);
const MAX_CONTAINERS: usize = 500;
const ZERO_TIMESTAMP: &str = "0001-01-01T00:00:00Z";

struct State {
    runtime: tokio::runtime::Runtime,
    client: Option<(String, Docker)>,
    prev_stats: HashMap<String, ContainerStatsResponse>,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| {
    Mutex::new(State {
        runtime: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime"),
        client: None,
        prev_stats: HashMap::new(),
    })
});

/// Why one container produced no entry.
enum EntryError {
    /// The daemon answered; docker.py's `except Exception` -> skip it.
    Data(String),
    /// A Docker call failed. 404 (vanished) is skipped; anything else is a
    /// collection failure, because docker-py's APIError subclasses requests'
    /// RequestException: a 500 on one container ships None, never a partial map.
    Docker(DockerError),
}

impl From<DockerError> for EntryError {
    fn from(e: DockerError) -> Self {
        EntryError::Docker(e)
    }
}

fn data<T>(v: Option<T>, what: &str) -> Result<T, EntryError> {
    v.ok_or_else(|| EntryError::Data(format!("stats: missing {what}")))
}

fn is_not_found(e: &DockerError) -> bool {
    matches!(
        e,
        DockerError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

fn client(slot: &mut Option<(String, Docker)>, socket_url: &str) -> Result<Docker, DockerError> {
    if let Some((url, docker)) = slot
        && url == socket_url
    {
        return Ok(docker.clone());
    }
    let docker = if socket_url.is_empty() {
        Docker::connect_with_unix_defaults()?
    } else {
        Docker::connect_with_socket(
            socket_url,
            CLIENT_TIMEOUT_SECS,
            bollard::API_DEFAULT_VERSION,
        )?
    };
    *slot = Some((socket_url.to_string(), docker.clone()));
    Ok(docker)
}

fn cpu_usage_percent(
    stats: &ContainerStatsResponse,
    prev: &ContainerStatsResponse,
    key: fn(&bollard::models::ContainerCpuUsage) -> Option<u64>,
) -> Result<f64, EntryError> {
    // dict.get(key, 0) on the counters, a KeyError on system_cpu_usage.
    let usage = |s: &ContainerStatsResponse| {
        s.cpu_stats
            .as_ref()
            .and_then(|c| c.cpu_usage.as_ref())
            .and_then(key)
            .unwrap_or(0) as i128
    };
    let system = |s: &ContainerStatsResponse| {
        data(
            s.cpu_stats.as_ref().and_then(|c| c.system_cpu_usage),
            "cpu_stats.system_cpu_usage",
        )
    };
    let cpu_delta = usage(stats) - usage(prev);
    let system_delta = system(stats)? as i128 - system(prev)? as i128;
    Ok(if system_delta > 0 && cpu_delta > 0 {
        cpu_delta as f64 / system_delta as f64 * 100.0
    } else {
        0.0
    })
}

/// usage minus the page cache (total_inactive_file on cgroup v1,
/// inactive_file on v2) when that is non-zero.
fn memory_usage(stats: &ContainerStatsResponse) -> Result<i128, EntryError> {
    let mem = data(stats.memory_stats.as_ref(), "memory_stats")?;
    let usage = data(mem.usage, "memory_stats.usage")? as i128;
    let detail = data(mem.stats.as_ref(), "memory_stats.stats")?;
    for key in ["total_inactive_file", "inactive_file"] {
        if let Some(&v) = detail.get(key).filter(|&&v| v != 0) {
            return Ok(usage - v as i128);
        }
    }
    Ok(usage)
}

fn computed_stats(
    stats: &ContainerStatsResponse,
    prev: &ContainerStatsResponse,
) -> Result<Map<String, Value>, EntryError> {
    let cpu = stats.cpu_stats.as_ref();
    let usage = memory_usage(stats)?;
    let limit = data(
        stats.memory_stats.as_ref().and_then(|m| m.limit),
        "memory_stats.limit",
    )?;
    if limit == 0 {
        return Err(EntryError::Data("memory_stats.limit is 0".into()));
    }
    let mut out = Map::new();
    out.insert(
        "cpu_percent".into(),
        json!(cpu_usage_percent(stats, prev, |u| u.total_usage)?),
    );
    out.insert(
        "memory_percent".into(),
        json!(usage as f64 / limit as f64 * 100.0),
    );
    out.insert("memory_usage".into(), json!(usage));
    out.insert("memory_limit".into(), json!(limit));
    out.insert(
        "pids_stats".into(),
        stats.pids_stats.as_ref().map_or(json!({}), |p| json!(p)),
    );
    out.insert(
        "cpu_throttling".into(),
        cpu.and_then(|c| c.throttling_data.as_ref())
            .map_or(json!({}), |t| json!(t)),
    );
    out.insert("online_cpus".into(), json!(cpu.and_then(|c| c.online_cpus)));
    out.insert(
        "cpu_kernelmode_percent".into(),
        json!(cpu_usage_percent(stats, prev, |u| u.usage_in_kernelmode)?),
    );
    out.insert(
        "cpu_usermode_percent".into(),
        json!(cpu_usage_percent(stats, prev, |u| u.usage_in_usermode)?),
    );

    let entries = stats
        .blkio_stats
        .as_ref()
        .and_then(|b| b.io_service_bytes_recursive.as_ref());
    if let Some(entries) = entries.filter(|e| !e.is_empty()) {
        let (mut read, mut write) = (0u64, 0u64);
        for e in entries {
            match e.op.as_deref().map(str::to_lowercase).as_deref() {
                Some("read") => read += e.value.unwrap_or(0),
                Some("write") => write += e.value.unwrap_or(0),
                _ => {}
            }
        }
        out.insert("block_read_bytes".into(), json!(read));
        out.insert("block_write_bytes".into(), json!(write));
    }
    if let Some(networks) = stats.networks.as_ref().filter(|n| !n.is_empty()) {
        out.insert("networks".into(), json!(networks));
    }
    Ok(out)
}

fn normalize_timestamp(v: Option<&String>) -> Value {
    match v {
        Some(s) if !s.is_empty() && s != ZERO_TIMESTAMP => json!(s),
        _ => Value::Null,
    }
}

async fn image_tags_and_digests(
    docker: &Docker,
    image_id: &str,
    cache: &mut HashMap<String, (Value, Value)>,
) -> (Value, Value) {
    if let Some(hit) = cache.get(image_id) {
        return hit.clone();
    }
    let result = match docker.inspect_image(image_id).await {
        Ok(img) => {
            // docker-py's Image.tags drops the "<none>:<none>" placeholder.
            let tags: Vec<String> = img
                .repo_tags
                .unwrap_or_default()
                .into_iter()
                .filter(|t| t != "<none>:<none>")
                .collect();
            (json!(tags), json!(img.repo_digests.unwrap_or_default()))
        }
        Err(e) => {
            log(
                "error",
                &format!("Error fetching Docker image metadata for {image_id}: {e}"),
            );
            (json!([]), json!([]))
        }
    };
    cache.insert(image_id.to_string(), result.clone());
    result
}

async fn build_entry(
    docker: &Docker,
    id: &str,
    images: &mut HashMap<String, (Value, Value)>,
    prev_stats: &mut HashMap<String, ContainerStatsResponse>,
) -> Result<Value, EntryError> {
    let attrs = docker
        .inspect_container(id, None::<InspectContainerOptions>)
        .await?;
    let state = attrs.state.as_ref();
    let image_id = attrs.image.clone().unwrap_or_default();
    let (tags, digests) = image_tags_and_digests(docker, &image_id, images).await;
    let status = state.and_then(|s| s.status).map(|s| s.to_string());
    let mut entry = json!({
        "name": attrs.name.as_deref().filter(|n| !n.is_empty()).map(|n| n.trim_start_matches('/')),
        "image": attrs.config.as_ref().and_then(|c| c.image.clone()).filter(|i| !i.is_empty()).unwrap_or(image_id.clone()),
        "image_id": attrs.image,
        "image_tags": tags,
        "image_repo_digests": digests,
        "status": status,
        "exit_code": state.and_then(|s| s.exit_code).unwrap_or(0),
        "oom_killed": state.and_then(|s| s.oom_killed).unwrap_or(false),
        "restart_count": attrs.restart_count.unwrap_or(0),
        "started_at": normalize_timestamp(state.and_then(|s| s.started_at.as_ref())),
        "finished_at": normalize_timestamp(state.and_then(|s| s.finished_at.as_ref())),
        "health": state.and_then(|s| s.health.as_ref()).and_then(|h| h.status).map(|h| h.to_string()),
    });

    if status.as_deref() == Some("running") {
        let options = StatsOptions {
            stream: false,
            one_shot: true,
        };
        let stats = match docker.stats(id, Some(options)).next().await {
            Some(result) => result?,
            None => return Err(EntryError::Data("stats: empty response".into())),
        };
        if let Some(prev) = prev_stats.get(id) {
            let computed = computed_stats(&stats, prev)?;
            entry.as_object_mut().expect("object").extend(computed);
        }
        prev_stats.insert(id.to_string(), stats);
    }
    Ok(entry)
}

/// Ok(containers map) or Err(()) for a collection failure (-> null).
async fn collect(
    docker: &Docker,
    prev_stats: &mut HashMap<String, ContainerStatsResponse>,
) -> Result<Value, ()> {
    let options = ListContainersOptions {
        all: true,
        ..Default::default()
    };
    let mut containers = docker.list_containers(Some(options)).await.map_err(|e| {
        log("error", &format!("Error listing Docker containers: {e}"));
    })?;
    if containers.len() > MAX_CONTAINERS {
        // Running first, then the newest others.
        let running = |c: &bollard::models::ContainerSummary| {
            c.state.map(|s| s.to_string()).as_deref() == Some("running")
        };
        containers.sort_by_key(|c| (!running(c), std::cmp::Reverse(c.created.unwrap_or(0))));
        containers.truncate(MAX_CONTAINERS);
    }

    let mut entries = Map::new();
    let mut images = HashMap::new();
    for summary in containers {
        let Some(id) = summary.id else { continue };
        match build_entry(docker, &id, &mut images, prev_stats).await {
            Ok(entry) => {
                entries.insert(id, entry);
            }
            Err(EntryError::Docker(e)) if is_not_found(&e) => {
                log(
                    "debug",
                    &format!("Docker container {id} vanished during collection, skipping"),
                );
            }
            Err(EntryError::Data(e)) => log(
                "error",
                &format!("Error collecting Docker container {id}: {e}"),
            ),
            Err(EntryError::Docker(e)) => {
                log(
                    "error",
                    &format!("Docker error on container {id}: {e}; reporting collection failure"),
                );
                return Err(());
            }
        }
    }
    prev_stats.retain(|id, _| entries.contains_key(id));
    Ok(json!({ "containers": entries }))
}

pub fn docker_metrics(cfg: &Value) -> Collected {
    let socket_url = cfg.get("socket_url").and_then(Value::as_str).unwrap_or("");
    let mut guard = STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let State {
        runtime,
        client: slot,
        prev_stats,
    } = &mut *guard;

    let docker = match client(slot, socket_url) {
        Ok(d) => d,
        Err(e) => {
            log("error", &format!("Error connecting to Docker daemon: {e}"));
            return Ok(Value::Null);
        }
    };
    // The timeout is built INSIDE the runtime: tokio::time needs its reactor,
    // and evaluating it as block_on's argument panics ("no reactor running").
    let collected = runtime.block_on(async {
        tokio::time::timeout(COLLECT_DEADLINE, collect(&docker, prev_stats)).await
    });
    match collected {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(())) => {
            *slot = None; // rebuild the client next tick, as invalidate_docker_client does
            Ok(Value::Null)
        }
        Err(_) => {
            log(
                "error",
                &format!(
                    "Docker collection exceeded {COLLECT_DEADLINE:?} budget; reporting collection failure"
                ),
            );
            Ok(Value::Null)
        }
    }
}
