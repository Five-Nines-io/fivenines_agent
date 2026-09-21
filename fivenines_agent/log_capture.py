"""Backend-pull capture coordinator: fire each capture_logs command exactly once.

The /collect response config is REPLACED every tick (Synchronizer.send_metrics),
so a capture_logs command left in config would re-fire every tick. This applies a
nonce (mirrors the permissions_recheck_token state machine in agent.py) PLUS disk
persistence, so a Restart=always agent never replays a capture it already served.

    config.capture_logs = {capture_id, unit, since, lines, max_bytes, expiry}
          |
          v  evaluate()
    capture_id already served or in flight ? -> None   (replay guard + no dup)
    unit not in allowlist ?                  -> None   (default-deny)
    expiry set and now > expiry ?            -> None   (stale command)
    otherwise -> mark in-flight, return the JOB (enqueue once)

last_served advances only AFTER a confirmed upload (mark_uploaded), not at enqueue
time, so a failed capture or upload is retried on a later tick instead of being
lost; mark_failed releases the in-flight slot. last_served is persisted to disk so
a Restart=always agent never replays a capture it already uploaded (a crash mid-
capture re-fires, which the idempotent backend dedupes on capture_id). max_bytes is
forward-plumbed into the job for the raw posture; V1 ships digest only, whose size
is already bounded by the fingerprint/excerpt caps in logs.py.
"""

import os
import threading
import time

from fivenines_agent import journal_policy
from fivenines_agent.debug import log
from fivenines_agent.env import restrict_to_owner


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
            # 0600 at creation (umask-independent), matching machine_id and the
            # TOKEN swap: state files under the config dir default to
            # owner-only rather than trusting the process umask.
            fd = os.open(self.state_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            # Heal a pre-existing file's mode too (os.open's mode applies only
            # at creation).
            restrict_to_owner(fd)
            with os.fdopen(fd, "w") as f:
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
                        f"CaptureCoordinator: unit {unit!r} not in the effective "
                        "unit allowlist (server units intersected with "
                        "journal_units.allow), refusing capture",
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
    capture_logs = config.get("capture_logs")
    # The host's own allowlist (journal_units.allow) can only narrow what the
    # server asked for. Only the ONE unit a capture command names is checked,
    # not the whole list: this runs every tick whether or not a capture is
    # pending (the feature is inert until the backend sends capture_logs), so
    # filtering the full list here would pay a stat plus up to MAX_PATTERNS
    # fnmatch calls per configured unit, per tick, for nothing. Emptying
    # `allowed` hands the refusal to the coordinator's existing warn-once
    # default-deny.
    requested = capture_logs.get("unit") if isinstance(capture_logs, dict) else None
    if requested is not None and not journal_policy.unit_allowed(requested):
        allowed = []
    job = coordinator.evaluate(capture_logs, allowed)
    if job is None:
        return None
    # evaluate() already marked this capture in-flight. The bounded log_queue
    # drops the OLDEST job silently on overflow, and a dropped job never reaches
    # the uploader -> its in-flight slot would leak forever. So when the queue is
    # full, shed THIS capture and release its slot instead; the backend re-mints a
    # fresh capture_id after expiry.
    if log_queue.full():
        log("evaluate_and_enqueue: log queue full, shedding capture", "error")
        coordinator.mark_failed(job.get("capture_id"))
        return None
    log_queue.put(job)
    return job
