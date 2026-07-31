"""Tests for the single-flight get_config fetch guard (_fetch_config_once).

Two call sites can request the config while self.token is still an
enrollment token: the synchronizer thread's startup fetch (run) and the main
loop (get_config). Without the guard both fire concurrently on every fresh
bulk install and enroll the same machine twice, minting a duplicate host.
These tests pin the guard's contract: exactly one fetch in flight, the
losing caller returns immediately (never stacks a second retry ladder in
front of the systemd watchdog), and a failed fetch can retry later (one in
flight, not one ever).
"""

import threading
import time
from threading import Event, Lock
from unittest.mock import MagicMock, patch

from fivenines_agent.synchronizer import Synchronizer


def make_synchronizer():
    """Create a Synchronizer with a mock queue, without starting the thread."""
    queue = MagicMock()
    sync = Synchronizer.__new__(Synchronizer)
    sync._stop_event = Event()
    sync.config_lock = Lock()
    sync._config_fetch_lock = Lock()
    sync.token = "enrollment-token"
    sync.config = {
        "enabled": None,
        "request_options": {"timeout": 5, "retry": 3, "retry_interval": 0},
    }
    sync.queue = queue
    sync.static_data = {"uname": {"node": "test"}}
    return sync


@patch.object(Synchronizer, "send_metrics")
def test_concurrent_fetches_send_one_request(mock_send):
    """While one fetch is in flight, a second caller returns without firing."""
    sync = make_synchronizer()
    in_flight = Event()
    release = Event()

    def slow_send(data):
        in_flight.set()
        release.wait(timeout=5)

    mock_send.side_effect = slow_send

    t = threading.Thread(target=sync._fetch_config_once)
    t.start()
    assert in_flight.wait(timeout=5)

    sync._fetch_config_once()
    assert mock_send.call_count == 1

    release.set()
    t.join(timeout=5)
    assert not t.is_alive()
    assert mock_send.call_count == 1


@patch.object(Synchronizer, "send_metrics")
def test_fetch_skipped_when_config_already_fetched(mock_send):
    """The recheck under config_lock skips the fetch once a config landed,
    even a disabled one (enabled False is a fetched config, None is not)."""
    sync = make_synchronizer()
    sync.config = {"enabled": False}
    sync._fetch_config_once()
    mock_send.assert_not_called()


@patch.object(Synchronizer, "send_metrics")
def test_failed_fetch_can_retry(mock_send):
    """One in flight, not one ever: a failed fetch releases the guard."""
    sync = make_synchronizer()
    sync._fetch_config_once()  # send_metrics no-op -> config stays None
    sync._fetch_config_once()
    assert mock_send.call_count == 2


@patch.object(Synchronizer, "send_metrics")
def test_fetch_sends_get_config_with_static_data(mock_send):
    sync = make_synchronizer()
    sync._fetch_config_once()
    mock_send.assert_called_once_with(
        {"get_config": True, "uname": {"node": "test"}}
    )


@patch.object(Synchronizer, "send_metrics")
def test_get_config_waits_for_inflight_fetch_but_never_fetches(mock_send):
    """With a fetch in flight elsewhere, get_config waits for it (so a
    healthy startup ticks as soon as the config lands) but NEVER runs its
    own fetch in the same call, even when the in-flight one failed --
    stacking a wait plus a fresh retry ladder in one loop iteration could
    outlast the systemd watchdog."""
    sync = make_synchronizer()
    assert sync._config_fetch_lock.acquire(blocking=False)
    results = []
    t = threading.Thread(target=lambda: results.append(sync.get_config()))
    t.start()
    t.join(timeout=0.2)
    assert t.is_alive()  # waiting on the in-flight fetch

    # The in-flight fetch finishes WITHOUT populating the config (failure):
    # the waiter must give up without firing a second request.
    sync._config_fetch_lock.release()
    t.join(timeout=5)
    assert not t.is_alive()
    assert results[0]["enabled"] is None
    mock_send.assert_not_called()


@patch.object(Synchronizer, "send_metrics")
def test_waiter_gives_up_after_bounded_timeout(mock_send):
    """A waiter with wait_timeout returns once the bound expires, without
    fetching, even while the other fetch is still in flight."""
    sync = make_synchronizer()
    assert sync._config_fetch_lock.acquire(blocking=False)
    try:
        start = time.monotonic()
        sync._fetch_config_once(wait_timeout=0.1)
        assert time.monotonic() - start < 5
        mock_send.assert_not_called()
    finally:
        sync._config_fetch_lock.release()


@patch.object(Synchronizer, "send_metrics")
def test_get_config_returns_config_fetched_by_inflight_winner(mock_send):
    """Happy path: while the startup fetch is in flight, get_config waits
    and returns the config that fetch produced -- exactly one request."""
    sync = make_synchronizer()
    started = Event()
    release = Event()

    def slow_send(data):
        started.set()
        release.wait(timeout=5)
        with sync.config_lock:
            sync.config = {"enabled": True, "interval": 60}

    mock_send.side_effect = slow_send

    t = threading.Thread(target=sync._fetch_config_once)
    t.start()
    assert started.wait(timeout=5)

    results = []
    waiter = threading.Thread(target=lambda: results.append(sync.get_config()))
    waiter.start()
    release.set()
    t.join(timeout=5)
    waiter.join(timeout=5)
    assert not waiter.is_alive()
    assert results[0] == {"enabled": True, "interval": 60}
    assert mock_send.call_count == 1


@patch.object(Synchronizer, "_fetch_config_once")
def test_run_startup_fetch_goes_through_the_guard(mock_fetch):
    """run() must not fire send_metrics directly: its startup fetch shares
    the single-flight guard with get_config."""
    sync = make_synchronizer()
    sync._stop_event.set()  # skip the queue drain loop
    sync.run()
    mock_fetch.assert_called_once()
