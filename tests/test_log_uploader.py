"""Unit tests for the dedicated log-upload worker thread.

Pure dependency injection: build_fn / send_fn are stubs, so these exercise the
thread's drain / isolation / shutdown logic without journald, the network, or
the Synchronizer.
"""

from fivenines_agent.log_uploader import LogUploader
from fivenines_agent.synchronization_queue import SynchronizationQueue


def _run(build_fn, send_fn, jobs):
    """Start an uploader, feed it jobs + the shutdown sentinel, join it."""
    q = SynchronizationQueue(maxsize=50)
    up = LogUploader(q, build_fn, send_fn)
    up.start()
    for j in jobs:
        q.put(j)
    q.put(None)  # shutdown sentinel
    up.join(timeout=2)
    assert not up.is_alive()


def test_uploader_builds_then_sends():
    built, sent = [], []

    def build(job):
        built.append(job)
        return {"for": job["capture_id"]}

    def send(bundle):
        sent.append(bundle)
        return True

    _run(build, send, [{"capture_id": "X"}])
    assert built == [{"capture_id": "X"}]
    assert sent == [{"for": "X"}]


def test_uploader_skips_when_build_returns_none():
    sent = []
    _run(lambda job: None, lambda b: sent.append(b) or True, [{"capture_id": "Y"}])
    assert sent == []


def test_uploader_isolates_build_exception():
    processed = []

    def build(job):
        if job["capture_id"] == "bad":
            raise ValueError("boom")
        return {"ok": job["capture_id"]}

    _run(
        build,
        lambda b: processed.append(b) or True,
        [{"capture_id": "bad"}, {"capture_id": "good"}],
    )
    # The bad job is isolated; the good job is still processed.
    assert processed == [{"ok": "good"}]


def test_uploader_continues_on_send_failure():
    calls = []

    def send(b):
        calls.append(b)
        return False  # upload failed

    _run(
        lambda job: {"j": job["capture_id"]},
        send,
        [{"capture_id": "A"}, {"capture_id": "B"}],
    )
    assert len(calls) == 2  # both attempted, thread survived the failure


def test_uploader_isolates_send_exception():
    calls = []

    def send(b):
        calls.append(b)
        raise RuntimeError("net down")

    _run(
        lambda job: {"j": job["capture_id"]},
        send,
        [{"capture_id": "A"}, {"capture_id": "B"}],
    )
    assert len(calls) == 2  # raise isolated, both jobs processed


def test_stop_sets_event():
    up = LogUploader(SynchronizationQueue(), lambda j: None, lambda b: True)
    assert not up._stop_event.is_set()
    up.stop()
    assert up._stop_event.is_set()


# --- coordinator callbacks (B2 retry) ---


def _run_cb(build_fn, send_fn, jobs, **cbs):
    q = SynchronizationQueue(maxsize=50)
    up = LogUploader(q, build_fn, send_fn, **cbs)
    up.start()
    for j in jobs:
        q.put(j)
    q.put(None)
    up.join(timeout=2)


def test_on_success_called_with_capture_id():
    got = []
    _run_cb(
        lambda job: {"b": job["capture_id"]},
        lambda b: True,
        [{"capture_id": "X"}],
        on_success=lambda cid: got.append(("ok", cid)),
        on_failure=lambda cid: got.append(("fail", cid)),
    )
    assert got == [("ok", "X")]


def test_on_failure_called_on_send_false():
    got = []
    _run_cb(
        lambda job: {"b": 1},
        lambda b: False,
        [{"capture_id": "Y"}],
        on_failure=lambda cid: got.append(cid),
    )
    assert got == ["Y"]


def test_on_failure_called_on_send_exception():
    got = []

    def send(b):
        raise RuntimeError("net down")

    _run_cb(lambda job: {"b": 1}, send, [{"capture_id": "Z"}], on_failure=got.append)
    assert got == ["Z"]


def test_on_failure_called_on_build_none_and_exception():
    got = []

    def build(job):
        if job["capture_id"] == "boom":
            raise ValueError("x")
        return None  # capture failed -> retry

    _run_cb(
        build,
        lambda b: True,
        [{"capture_id": "none"}, {"capture_id": "boom"}],
        on_failure=got.append,
    )
    assert got == ["none", "boom"]
