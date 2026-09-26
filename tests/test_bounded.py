"""Tests for bounded.call_bounded, the shared never-wait-past-a-deadline call."""

import threading
import time

import pytest

from fivenines_agent.bounded import WorkerTimeout, call_bounded


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
