"""Tests for per-metric telemetry: _collect, log buffering, packages_sync telemetry."""

import sys
import threading
from unittest.mock import MagicMock, patch

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())


from fivenines_agent.agent import Agent  # noqa: E402
from fivenines_agent.debug import (  # noqa: E402
    _thread_local,
    log,
    start_log_capture,
    stop_log_capture,
)


def make_agent():
    """Create an Agent-like object with _collect attached."""
    agent = Agent.__new__(Agent)
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer = MagicMock()
    agent._telemetry = {}
    return agent


# --- _collect: success ---


def test_collect_returns_value():
    agent = make_agent()
    result = agent._collect("test_metric", lambda: 42)
    assert result == 42


def test_collect_records_duration():
    agent = make_agent()
    agent._collect("test_metric", lambda: "ok")
    entry = agent._telemetry["test_metric"]
    assert "duration_ms" in entry
    assert isinstance(entry["duration_ms"], float)
    assert entry["duration_ms"] >= 0


def test_collect_no_errors_key_on_success():
    agent = make_agent()
    agent._collect("test_metric", lambda: "ok")
    assert "errors" not in agent._telemetry["test_metric"]


# --- _collect: with args/kwargs ---


def test_collect_passes_args():
    agent = make_agent()

    def adder(a, b):
        return a + b

    result = agent._collect("adder", adder, 3, 7)
    assert result == 10


def test_collect_passes_kwargs():
    agent = make_agent()

    def greeter(greeting="world"):
        return f"hello {greeting}"

    result = agent._collect("greeter", greeter, greeting="alice")
    assert result == "hello alice"


# --- _collect: exception ---


def test_collect_exception_returns_none():
    agent = make_agent()

    def failing():
        raise ValueError("boom")

    result = agent._collect("fail_metric", failing)
    assert result is None


def test_collect_exception_records_error():
    agent = make_agent()

    def failing():
        raise ValueError("boom")

    agent._collect("fail_metric", failing)
    entry = agent._telemetry["fail_metric"]
    assert "duration_ms" in entry
    assert "errors" in entry
    assert "boom" in entry["errors"]


# --- _collect: collector that logs errors internally ---


@patch("fivenines_agent.debug.log_level", return_value="debug")
def test_collect_captures_logged_errors(mock_ll):
    agent = make_agent()

    def noisy_collector():
        log("something went wrong", "error")
        log("this is info", "info")
        log("another error", "error")
        return "partial"

    result = agent._collect("noisy", noisy_collector)
    assert result == "partial"
    entry = agent._telemetry["noisy"]
    assert entry["errors"] == ["something went wrong", "another error"]


# --- _collect: multiple metrics ---


def test_collect_multiple_metrics():
    agent = make_agent()
    agent._collect("m1", lambda: 1)
    agent._collect("m2", lambda: 2)
    agent._collect("m3", lambda: 3)
    assert set(agent._telemetry.keys()) == {"m1", "m2", "m3"}
    for key in ("m1", "m2", "m3"):
        assert "duration_ms" in agent._telemetry[key]


# --- Log buffering: basic lifecycle ---


@patch("fivenines_agent.debug.log_level", return_value="debug")
def test_log_capture_basic(mock_ll):
    start_log_capture()
    log("info msg", "info")
    log("err msg", "error")
    errors = stop_log_capture()
    assert errors == ["err msg"]


@patch("fivenines_agent.debug.log_level", return_value="debug")
def test_log_capture_only_errors(mock_ll):
    start_log_capture()
    log("debug msg", "debug")
    log("info msg", "info")
    log("warn msg", "warn")
    errors = stop_log_capture()
    assert errors == []


@patch("fivenines_agent.debug.log_level", return_value="debug")
def test_log_messages_still_print(mock_ll, capsys):
    start_log_capture()
    log("visible error", "error")
    errors = stop_log_capture()
    captured = capsys.readouterr()
    assert "visible error" in captured.out
    assert errors == ["visible error"]


def test_stop_without_start():
    """stop_log_capture without start returns empty list."""
    # Ensure no buffer is set
    _thread_local.log_buffer = None
    errors = stop_log_capture()
    assert errors == []


# --- Log buffering: errors captured regardless of log level ---


@patch("fivenines_agent.debug.log_level", return_value="critical")
def test_errors_captured_even_when_log_level_high(mock_ll, capsys):
    """Error messages are buffered even when log level suppresses printing."""
    start_log_capture()
    log("suppressed error", "error")
    errors = stop_log_capture()
    # Not printed (log level is critical)
    captured = capsys.readouterr()
    assert "suppressed error" not in captured.out
    # But still captured in buffer
    assert errors == ["suppressed error"]


# --- Log buffering: thread isolation ---


@patch("fivenines_agent.debug.log_level", return_value="debug")
def test_log_capture_thread_isolation(mock_ll):
    """Buffer on one thread does not capture logs from another."""
    other_thread_errors = []

    def other_thread_work():
        log("other thread error", "error")
        # This thread has no buffer, so nothing captured
        buf = getattr(_thread_local, "log_buffer", None)
        other_thread_errors.append(buf)

    start_log_capture()
    t = threading.Thread(target=other_thread_work)
    t.start()
    t.join()
    log("main thread error", "error")
    errors = stop_log_capture()

    # Main thread only captured its own error
    assert errors == ["main thread error"]
    # Other thread had no buffer
    assert other_thread_errors == [None]


# --- packages_sync telemetry ---


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_packages_sync_telemetry_early_return(mock_hash, mock_distro, mock_pkgs):
    """Telemetry recorded even on early return (no packages config)."""
    agent = make_agent()
    agent.config = {"enabled": True}

    agent._packages_sync_with_telemetry()

    assert "packages_sync" in agent._telemetry
    entry = agent._telemetry["packages_sync"]
    assert "duration_ms" in entry
    assert "errors" not in entry


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_packages_sync_telemetry_success(mock_hash, mock_distro, mock_pkgs, mock_dry):
    """Telemetry recorded on successful send."""
    agent = make_agent()
    agent.config = {
        "enabled": True,
        "packages": {"scan": True, "last_package_hash": "old"},
    }
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new"
    agent.synchronizer.send_packages.return_value = {"status": "queued"}

    agent._packages_sync_with_telemetry()

    assert "packages_sync" in agent._telemetry
    entry = agent._telemetry["packages_sync"]
    assert "duration_ms" in entry


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_packages_sync_telemetry_on_exception(mock_hash, mock_distro, mock_pkgs):
    """Telemetry with errors recorded when exception occurs."""
    agent = make_agent()
    agent.config = {
        "enabled": True,
        "packages": {"scan": True, "last_package_hash": None},
    }
    mock_distro.side_effect = RuntimeError("distro exploded")

    agent._packages_sync_with_telemetry()

    entry = agent._telemetry["packages_sync"]
    assert "duration_ms" in entry
    assert "errors" in entry
    assert "distro exploded" in entry["errors"]


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_packages_sync_telemetry_captures_logged_error(
    mock_hash, mock_distro, mock_pkgs, mock_dry
):
    """Telemetry captures error logged by packages_sync (send failure)."""
    agent = make_agent()
    agent.config = {
        "enabled": True,
        "packages": {"scan": True, "last_package_hash": "old"},
    }
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new"
    agent.synchronizer.send_packages.return_value = None  # failure

    agent._packages_sync_with_telemetry()

    entry = agent._telemetry["packages_sync"]
    assert "duration_ms" in entry
    assert "errors" in entry
    assert "Packages synchronization failed, will retry" in entry["errors"]
