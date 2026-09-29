//! bounded.call_bounded in Rust. std has no abandonable task without an async
//! runtime, so this is the Python design unchanged: one OS thread per call,
//! abandoned at the deadline, single-flight per name so a stall leaks one
//! thread, not one per tick. (tokio would not change that: a blocking read
//! still has to go to spawn_blocking, which is this same thread.)

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex, mpsc};
use std::time::Duration;

use crate::collectors::Collected;

static STALLED: LazyLock<Mutex<HashSet<&'static str>>> = LazyLock::new(Default::default);

pub fn call_bounded<F>(name: &'static str, timeout: Duration, f: F) -> Collected
where
    F: FnOnce() -> Collected + Send + 'static,
{
    if STALLED.lock().unwrap().contains(name) {
        return Err(format!("{name}: previous call still blocked"));
    }
    let (tx, rx) = mpsc::sync_channel(1); // buffered: an abandoned worker never blocks on send
    let spawned = std::thread::Builder::new()
        .name(format!("bounded-{name}"))
        .spawn(move || {
            // A panic (an index past the end of an unexpected /proc line) ends
            // this worker only: the collector reports null, the agent lives.
            // This is why the release profile keeps panic = "unwind".
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
                .unwrap_or_else(|_| Err(format!("{name}: panicked")));
            let _ = tx.send(r);
        });
    if let Err(e) = spawned {
        return Err(format!("{name}: cannot start worker: {e}"));
    }
    match rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            STALLED.lock().unwrap().insert(name);
            std::thread::spawn(move || {
                let _ = rx.recv(); // the worker finally returned
                STALLED.lock().unwrap().remove(name);
            });
            Err(format!("{name}: blocked for {timeout:?}, abandoned"))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!("{name}: worker died")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::Condvar;

    static RELEASE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

    fn stuck() -> Collected {
        let (m, c) = &RELEASE;
        let _released = c.wait_while(m.lock().unwrap(), |r| !*r).unwrap();
        Ok(Value::Null)
    }

    fn never_runs() -> Collected {
        panic!("a second worker was started while the first was blocked")
    }

    fn boom() -> Collected {
        Ok(Value::from("not a number".parse::<u8>().unwrap()))
    }

    #[test]
    fn abandons_then_single_flights() {
        assert!(call_bounded("stuck", Duration::from_millis(10), stuck).is_err());
        let refused = call_bounded("stuck", Duration::from_millis(10), never_runs);
        assert!(refused.unwrap_err().contains("still blocked"));
        let (m, c) = &RELEASE;
        *m.lock().unwrap() = true;
        c.notify_all();
    }

    #[test]
    fn a_panicking_collector_is_an_error_not_a_crash() {
        let r = call_bounded("boom", Duration::from_secs(1), boom);
        assert!(r.unwrap_err().contains("panicked"));
    }
}
