"""Backend-pull capture coordinator: fire each capture_logs command exactly once.

The /collect response config is REPLACED every tick (Synchronizer.send_metrics),
so a capture_logs command left in config would re-fire every tick. This applies a
nonce (mirrors the permissions_recheck_token state machine in agent.py) PLUS disk
persistence, so a Restart=always agent never replays a capture it already served.

    config.capture_logs = {capture_id, unit, since, lines, max_bytes, expiry}
          |
          v  evaluate()
    capture_id == last_served (persisted) ?  -> None   (replay guard, survives restart)
    unit not in allowlist ?                  -> None   (default-deny)
    expiry set and now > expiry ?            -> None   (stale command)
    otherwise -> persist last_served = capture_id, return the JOB (enqueue once)

last_served is updated optimistically when the job is enqueued, not after the
upload acks. Tradeoff: a crash between enqueue and a successful POST drops that one
capture; the backend re-issues a NEW capture_id once `expiry` passes without an ack.
This keeps replay prevention simple and avoids an in-flight retry loop.
"""

import threading
import time

from fivenines_agent.debug import log


class CaptureCoordinator:
    def __init__(self, state_path, now_fn=time.time):
        self.state_path = state_path
        self._now = now_fn
        self._lock = threading.Lock()
        self._last_served = self._load()
        # capture_ids enqueued but not yet confirmed uploaded. Guards against
        # re-enqueuing a duplicate while an upload is in flight, while letting a
        # failed upload retry (last_served advances only after a real upload).
        self._in_flight = set()
        self._last_warned_id = None

    def _load(self):
        try:
            with open(self.state_path, "r") as f:
                return f.read().strip() or None
        except FileNotFoundError:
            return None
        except Exception as e:
            log(f"CaptureCoordinator: cannot read {self.state_path}: {e}", "error")
            return None

    def _persist(self, capture_id):
        try:
            with open(self.state_path, "w") as f:
                f.write(str(capture_id))
        except Exception as e:
            # Best-effort: a write failure must not break capture. The in-memory
            # _last_served still prevents replay within this process.
            log(f"CaptureCoordinator: cannot persist {self.state_path}: {e}", "error")

    def evaluate(self, capture_logs, allowed_units):
        """Return a capture job dict if this command should fire now, else None.

        On fire the capture_id is marked in-flight, NOT served: last_served (the
        no-replay-across-restart guard) advances only once mark_uploaded confirms
        a successful /logs POST, so a failed upload is retried on a later tick.
        mark_failed releases the in-flight slot. The lock guards state touched
        from both the collection loop (evaluate) and the uploader thread
        (mark_uploaded / mark_failed).
        """
        if not isinstance(capture_logs, dict):
            return None
        capture_id = capture_logs.get("capture_id")
        if not capture_id:
            return None
        unit = capture_logs.get("unit")
        expiry = capture_logs.get("expiry")
        with self._lock:
            if capture_id == self._last_served or capture_id in self._in_flight:
                return None  # already uploaded, or already in flight
            if unit not in allowed_units:
                # Default-deny. Warn once per capture_id to avoid per-tick spam.
                if self._last_warned_id != capture_id:
                    log(
                        f"CaptureCoordinator: unit {unit!r} not in allowlist, "
                        "refusing capture",
                        "error",
                    )
                    self._last_warned_id = capture_id
                return None
            if isinstance(expiry, (int, float)) and not isinstance(expiry, bool):
                if self._now() > expiry:
                    return None  # stale command
            self._in_flight.add(capture_id)
        return {
            "capture_id": capture_id,
            "unit": unit,
            "since": capture_logs.get("since"),
            "lines": capture_logs.get("lines"),
            "max_bytes": capture_logs.get("max_bytes"),
        }

    def mark_uploaded(self, capture_id):
        """Uploader callback on a successful /logs POST: persist the capture_id as
        served (no replay, survives restart) and free the in-flight slot."""
        if not capture_id:
            return
        with self._lock:
            self._last_served = capture_id
            self._in_flight.discard(capture_id)
            self._persist(capture_id)

    def mark_failed(self, capture_id):
        """Uploader callback when the capture/upload failed: free the in-flight
        slot so the command retries on a later tick (bounded by the backend's
        expiry). last_served is NOT advanced."""
        if not capture_id:
            return
        with self._lock:
            self._in_flight.discard(capture_id)


def evaluate_and_enqueue(coordinator, log_queue, config):
    """Glue: read capture_logs + allowlist from config; enqueue a job if it fires.

    Returns the job (also enqueued) or None. A free function so it is testable
    without constructing an Agent.
    """
    logs_cfg = config.get("logs")
    allowed = logs_cfg.get("units", []) if isinstance(logs_cfg, dict) else []
    job = coordinator.evaluate(config.get("capture_logs"), allowed)
    if job is not None:
        log_queue.put(job)
    return job
