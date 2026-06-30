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

import time

from fivenines_agent.debug import log


class CaptureCoordinator:
    def __init__(self, state_path, now_fn=time.time):
        self.state_path = state_path
        self._now = now_fn
        self._last_served = self._load()
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
        """Return a capture job dict if this command should fire now, else None."""
        if not isinstance(capture_logs, dict):
            return None
        capture_id = capture_logs.get("capture_id")
        if not capture_id:
            return None
        if capture_id == self._last_served:
            return None  # already served - replay guard, survives restart

        unit = capture_logs.get("unit")
        if unit not in allowed_units:
            # Default-deny. Warn once per capture_id to avoid per-tick log spam.
            if self._last_warned_id != capture_id:
                log(
                    f"CaptureCoordinator: unit {unit!r} not in allowlist, "
                    "refusing capture",
                    "error",
                )
                self._last_warned_id = capture_id
            return None

        expiry = capture_logs.get("expiry")
        if isinstance(expiry, (int, float)) and not isinstance(expiry, bool):
            if self._now() > expiry:
                return None  # stale command

        # Fire: mark served (optimistic) + persist so a restart never replays.
        self._last_served = capture_id
        self._persist(capture_id)
        return {
            "capture_id": capture_id,
            "unit": unit,
            "since": capture_logs.get("since"),
            "lines": capture_logs.get("lines"),
            "max_bytes": capture_logs.get("max_bytes"),
        }


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
