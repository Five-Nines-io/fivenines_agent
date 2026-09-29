//! Synchronizer + SynchronizationQueue: a bounded queue of pre-gzipped
//! payloads drained by one thread, linear retry backoff, one kept-alive
//! connection. ureq's timeout_global bounds the WHOLE request (connect,
//! headers and body), which is what http_body.read_capped_body adds on top of
//! requests' per-socket-operation timeout.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use flate2::{Compression, write::GzEncoder};
use serde_json::{Map, Value};

use crate::log;

const QUEUE_SIZE: usize = 100;
const GZIP_LEVEL: u32 = 6;

/// threading.Event.
#[derive(Clone, Default)]
pub struct Event(Arc<(Mutex<bool>, Condvar)>);

impl Event {
    pub fn set(&self) {
        let (m, c) = &*self.0;
        *m.lock().unwrap() = true;
        c.notify_all();
    }

    pub fn is_set(&self) -> bool {
        *self.0.0.lock().unwrap()
    }

    /// Sleeps up to `timeout`; true if the event was set.
    pub fn wait(&self, timeout: Duration) -> bool {
        let (m, c) = &*self.0;
        let (set, _) = c
            .wait_timeout_while(m.lock().unwrap(), timeout, |set| !*set)
            .unwrap();
        *set
    }
}

pub fn gzip_json(v: &Value) -> Result<Vec<u8>, String> {
    let raw = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    let mut enc = GzEncoder::new(
        Vec::with_capacity(raw.len() / 4),
        Compression::new(GZIP_LEVEL),
    );
    enc.write_all(&raw).map_err(|e| e.to_string())?;
    enc.finish().map_err(|e| e.to_string())
}

fn base_url() -> String {
    let url = crate::api_url();
    if url.starts_with("localhost") {
        format!("http://{url}")
    } else {
        format!("https://{url}")
    }
}

struct Queue {
    items: VecDeque<Vec<u8>>,
    closed: bool,
}

pub struct Synchronizer {
    token: String,
    agent: ureq::Agent,
    exit: Event,
    queue: Mutex<Queue>,
    ready: Condvar,
    config: Mutex<Map<String, Value>>,
}

impl Synchronizer {
    pub fn new(token: String, exit: Event) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            token,
            agent,
            exit,
            queue: Mutex::new(Queue {
                items: VecDeque::new(),
                closed: false,
            }),
            ready: Condvar::new(),
            config: Mutex::new(Map::new()),
        }
    }

    /// Drops the oldest payload when the queue is full, as the Python queue does.
    pub fn put(&self, blob: Vec<u8>) {
        let mut q = self.queue.lock().unwrap();
        if q.items.len() >= QUEUE_SIZE {
            q.items.pop_front();
            log("info", "Queue full, dropping oldest data");
        }
        q.items.push_back(blob);
        self.ready.notify_one();
    }

    pub fn stop(&self) {
        self.queue.lock().unwrap().closed = true;
        self.ready.notify_all();
    }

    pub fn config(&self) -> Map<String, Value> {
        self.config.lock().unwrap().clone()
    }

    fn post(&self, endpoint: &str, blob: &[u8]) -> Result<Value, String> {
        let mut res = self
            .agent
            .post(format!("{}{endpoint}", base_url()))
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .header("Authorization", format!("Bearer {}", self.token))
            .send(blob)
            .map_err(|e| e.to_string())?;
        let status = res.status();
        let body = res
            .body_mut()
            .with_config()
            .limit(16 << 20)
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        if status != 200 {
            return Err(format!("HTTP {status}: {}", String::from_utf8_lossy(&body)));
        }
        serde_json::from_slice(&body).map_err(|e| e.to_string())
    }

    /// Posts to /collect with retries and adopts the returned config.
    pub fn send(&self, blob: &[u8]) -> bool {
        const RETRIES: u64 = 3;
        const RETRY_INTERVAL: u64 = 5;
        for attempt in 1..=RETRIES {
            match self.post("/collect", blob) {
                Ok(res) => {
                    // A config is a Map: keys this agent does not know are simply
                    // never read -- no **kwargs splat, so no TypeError on a new key.
                    if let Some(Value::Object(cfg)) = res.get("config") {
                        *self.config.lock().unwrap() = cfg.clone();
                    }
                    return true;
                }
                Err(e) => {
                    let wait = RETRY_INTERVAL * attempt;
                    log(
                        "error",
                        &format!("Synchronizer Error: {e}; retrying in {wait}s"),
                    );
                    if self.exit.wait(Duration::from_secs(wait)) {
                        return false;
                    }
                }
            }
        }
        false
    }

    pub fn run(&self) {
        loop {
            let blob = {
                let mut q = self.queue.lock().unwrap();
                loop {
                    if q.closed {
                        return;
                    }
                    if let Some(b) = q.items.pop_front() {
                        break b;
                    }
                    q = self.ready.wait(q).unwrap();
                }
            };
            self.send(&blob);
        }
    }
}
