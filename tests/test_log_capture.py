"""Tests for the backend-pull capture coordinator (nonce + disk persistence).

Pure: no Agent, no journald, no network. The coordinator owns the replay guard
that Codex flagged (config is replaced each tick, so a command would re-fire), and
the disk persistence that makes it survive a Restart=always restart.
"""

import os

from fivenines_agent.log_capture import CaptureCoordinator, evaluate_and_enqueue
from fivenines_agent.synchronization_queue import SynchronizationQueue

ALLOW = ["nginx.service", "postgresql.service"]


def _cmd(**over):
    base = {"capture_id": "id-1", "unit": "nginx.service", "since": 1000, "lines": 500}
    base.update(over)
    return base


def _coord(tmp_path, **kw):
    return CaptureCoordinator(os.path.join(str(tmp_path), "last_capture_id"), **kw)


def test_new_capture_fires_and_returns_job(tmp_path):
    job = _coord(tmp_path).evaluate(_cmd(), ALLOW)
    assert job == {
        "capture_id": "id-1",
        "unit": "nginx.service",
        "since": 1000,
        "lines": 500,
        "max_bytes": None,
    }


def test_evaluate_does_not_persist_mark_uploaded_does(tmp_path):
    path = os.path.join(str(tmp_path), "last_capture_id")
    c = CaptureCoordinator(path)
    c.evaluate(_cmd(), ALLOW)
    assert not os.path.exists(path)  # in flight, not yet served
    c.mark_uploaded("id-1")
    with open(path) as f:
        assert f.read() == "id-1"


def test_same_capture_id_does_not_refire(tmp_path):
    c = _coord(tmp_path)
    assert c.evaluate(_cmd(), ALLOW) is not None
    assert c.evaluate(_cmd(), ALLOW) is None  # blocked while in flight


def test_absent_or_empty_capture_id_is_noop(tmp_path):
    c = _coord(tmp_path)
    assert c.evaluate({"unit": "nginx.service"}, ALLOW) is None
    assert c.evaluate(_cmd(capture_id=None), ALLOW) is None
    assert c.evaluate(_cmd(capture_id=""), ALLOW) is None


def test_non_dict_capture_logs_is_noop(tmp_path):
    c = _coord(tmp_path)
    assert c.evaluate(None, ALLOW) is None
    assert c.evaluate("nope", ALLOW) is None


def test_unit_not_in_allowlist_refused_and_not_persisted(tmp_path):
    path = os.path.join(str(tmp_path), "last_capture_id")
    c = CaptureCoordinator(path)
    assert c.evaluate(_cmd(unit="secret.service"), ALLOW) is None
    assert not os.path.exists(path)  # default-deny, nothing served


def test_expired_command_is_stale(tmp_path):
    c = _coord(tmp_path, now_fn=lambda: 2000)
    assert c.evaluate(_cmd(expiry=1500), ALLOW) is None  # now 2000 > 1500


def test_not_expired_command_fires(tmp_path):
    c = _coord(tmp_path, now_fn=lambda: 1000)
    assert c.evaluate(_cmd(expiry=1500), ALLOW) is not None


def test_bool_expiry_is_ignored(tmp_path):
    # bool is a subclass of int; True must not be treated as an epoch.
    c = _coord(tmp_path, now_fn=lambda: 1000)
    assert c.evaluate(_cmd(expiry=True), ALLOW) is not None


def test_persistence_survives_restart(tmp_path):
    path = os.path.join(str(tmp_path), "last_capture_id")
    c = CaptureCoordinator(path)
    c.evaluate(_cmd(), ALLOW)
    c.mark_uploaded("id-1")  # only an uploaded capture persists as served
    # "restart": a fresh coordinator loads the persisted id and must not replay.
    fresh = CaptureCoordinator(path)
    assert fresh.evaluate(_cmd(), ALLOW) is None


def test_persist_failure_in_mark_uploaded_is_best_effort(tmp_path):
    # state_path under a nonexistent dir -> write raises -> caught best-effort.
    bad = os.path.join(str(tmp_path), "missing", "last_capture_id")
    c = CaptureCoordinator(bad)
    assert c.evaluate(_cmd(), ALLOW) is not None  # fires (in flight)
    c.mark_uploaded("id-1")  # persist raises -> caught; in-memory served holds
    assert c.evaluate(_cmd(), ALLOW) is None  # last_served guard (in-memory)


def test_mark_failed_releases_for_retry(tmp_path):
    c = _coord(tmp_path)
    assert c.evaluate(_cmd(), ALLOW) is not None  # in flight
    assert c.evaluate(_cmd(), ALLOW) is None  # blocked while in flight
    c.mark_failed("id-1")  # upload failed -> release the slot
    assert c.evaluate(_cmd(), ALLOW) is not None  # retried on a later tick


def test_mark_uploaded_blocks_refire(tmp_path):
    c = _coord(tmp_path)
    assert c.evaluate(_cmd(), ALLOW) is not None
    c.mark_uploaded("id-1")
    assert c.evaluate(_cmd(), ALLOW) is None  # served, no replay


def test_mark_helpers_ignore_empty_capture_id(tmp_path):
    c = _coord(tmp_path)
    c.mark_uploaded(None)  # no-op, no crash
    c.mark_failed("")  # no-op
    assert c.evaluate(_cmd(), ALLOW) is not None  # state untouched


def test_enqueue_sheds_capture_when_queue_full(tmp_path):
    # A full bounded queue would drop-oldest silently, orphaning the dropped
    # job's in-flight slot; instead shed the NEW capture and release its slot so
    # it can retry (the backend re-mints after expiry) rather than leak.
    q = SynchronizationQueue(maxsize=1)
    q.put({"capture_id": "old"})  # queue now full
    c = _coord(tmp_path)
    job = evaluate_and_enqueue(c, q, {"logs": {"units": ALLOW}, "capture_logs": _cmd()})
    assert job is None
    assert q.qsize() == 1  # new capture not enqueued, old not evicted
    # in-flight was released -> the same capture_id can fire again (retry)
    assert c.evaluate(_cmd(), ALLOW) is not None


def test_load_error_when_state_path_is_dir(tmp_path):
    # An unreadable state path (a directory) degrades to no baseline, fires once.
    d = os.path.join(str(tmp_path), "as_dir")
    os.mkdir(d)
    assert CaptureCoordinator(d).evaluate(_cmd(), ALLOW) is not None


def test_warn_once_per_id_for_rejected_unit(tmp_path):
    c = _coord(tmp_path)
    bad = _cmd(unit="secret.service")
    assert c.evaluate(bad, ALLOW) is None
    assert c.evaluate(bad, ALLOW) is None  # second call: warn-once guard, still None
    assert c._last_warned_id == "id-1"


# --- evaluate_and_enqueue glue ---


def test_enqueue_puts_job_when_fired(tmp_path):
    q = SynchronizationQueue(maxsize=10)
    job = evaluate_and_enqueue(
        _coord(tmp_path), q, {"logs": {"units": ALLOW}, "capture_logs": _cmd()}
    )
    assert job is not None
    assert q.qsize() == 1
    assert q.get_nowait()["capture_id"] == "id-1"


def test_enqueue_noop_when_no_capture(tmp_path):
    q = SynchronizationQueue(maxsize=10)
    assert evaluate_and_enqueue(_coord(tmp_path), q, {"logs": {"units": ALLOW}}) is None
    assert q.qsize() == 0


def test_enqueue_defaults_empty_allowlist_when_logs_cfg_absent(tmp_path):
    q = SynchronizationQueue(maxsize=10)
    # No logs config -> allowlist defaults to [] -> default-deny.
    assert evaluate_and_enqueue(_coord(tmp_path), q, {"capture_logs": _cmd()}) is None
    assert q.qsize() == 0


def test_enqueue_handles_non_dict_logs_cfg(tmp_path):
    q = SynchronizationQueue(maxsize=10)
    cfg = {"logs": "garbage", "capture_logs": _cmd()}
    assert evaluate_and_enqueue(_coord(tmp_path), q, cfg) is None
    assert q.qsize() == 0
