"""Tests for bounded.call_bounded, the shared never-wait-past-a-deadline call."""

import threading
import time

import pytest

from fivenines_agent.bounded import WorkerTimeout, call_bounded
from fivenines_agent.debug import log, start_log_capture, stop_log_capture


def test_returns_the_value_of_a_call_that_finishes_in_time():
    assert call_bounded(lambda: 42, timeout=5) == 42


def test_reraises_the_calls_exception_on_the_callers_thread():
    """The dispatcher's telemetry and the caller's own `except` clauses only
    see what is raised on the calling thread."""
    boom = FileNotFoundError("no such command")
    raised_on = {}

    def fails():
        raised_on["thread"] = threading.current_thread()
        raise boom

    with pytest.raises(FileNotFoundError) as excinfo:
        call_bounded(fails, timeout=5)
    assert excinfo.value is boom
    assert raised_on["thread"] is not threading.current_thread()


def test_reraises_a_base_exception_rather_than_losing_it():
    """Not only Exception: a SystemExit in fn must not surface as a KeyError."""

    def exits():
        raise SystemExit(3)

    with pytest.raises(SystemExit):
        call_bounded(exits, timeout=5)


def test_errors_logged_inside_the_call_reach_the_callers_capture():
    """Log capture is thread-local; the dispatcher reads the caller's."""
    start_log_capture()
    try:
        call_bounded(lambda: log("sysfs said no", "error"), timeout=5)
        log("on the caller", "error")
    finally:
        captured = stop_log_capture()
    assert captured == ["sysfs said no", "on the caller"]


def test_a_call_past_its_deadline_is_abandoned_not_awaited():
    """THE reason the helper exists: the caller is freed at the deadline and is
    handed the still-running worker, a named daemon that cannot hold exit."""
    release = threading.Event()
    try:
        started = time.monotonic()
        with pytest.raises(WorkerTimeout) as excinfo:
            call_bounded(lambda: release.wait(30), timeout=0.05, name="probe-x")
        assert time.monotonic() - started < 5
        worker = excinfo.value.worker
        assert worker.is_alive()
        assert worker.daemon is True
        assert worker.name == "probe-x"
    finally:
        release.set()
    worker.join(5)
    assert not worker.is_alive()
