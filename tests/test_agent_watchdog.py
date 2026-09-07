"""Tests for optional systemd-watchdog support in agent.run()."""

import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402
from fivenines_agent.agent import Agent  # noqa: E402


def make_agent():
    """Create an Agent-like object without __init__ side effects."""
    agent = Agent.__new__(Agent)
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer = MagicMock()
    agent.log_uploader = None
    agent.image_inventory_uploader = None
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {}
    agent.permissions.refresh_due.return_value = False
    agent._last_recheck_token = agent_module._RECHECK_UNSET
    agent.queue = MagicMock()
    agent.static_data = {"version": "test"}
    agent._telemetry = {}
    return agent


@patch("fivenines_agent.agent.dry_run", return_value=True)
@patch("fivenines_agent.agent.collect_metrics")
@patch("fivenines_agent.agent.packages_sync")
def test_run_with_watchdog_none(mock_ps, mock_cm, mock_dr):
    """When systemd_watchdog is None, agent.run() works without calling watchdog."""
    agent = make_agent()
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer.get_config.return_value = agent.config

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        with pytest.raises(SystemExit) as exc_info:
            agent.run()
        assert exc_info.value.code == 0
    finally:
        agent_module.systemd_watchdog = original


@patch("fivenines_agent.agent.dry_run", return_value=True)
@patch("fivenines_agent.agent.collect_metrics")
@patch("fivenines_agent.agent.packages_sync")
def test_run_with_watchdog_present(mock_ps, mock_cm, mock_dr):
    """When systemd_watchdog is available, agent.run() calls wd.ready() and wd.notify()."""
    agent = make_agent()
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer.get_config.return_value = agent.config

    mock_wd_module = MagicMock()
    mock_wd_instance = MagicMock()
    mock_wd_module.watchdog.return_value = mock_wd_instance

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = mock_wd_module
        agent_module.exit_event.clear()
        with pytest.raises(SystemExit) as exc_info:
            agent.run()
        assert exc_info.value.code == 0

        mock_wd_module.watchdog.assert_called_once()
        mock_wd_instance.ready.assert_called_once()
        mock_wd_instance.notify.assert_called()
    finally:
        agent_module.systemd_watchdog = original


@patch("fivenines_agent.agent.systemd_inventory_sync", return_value=True)
@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.collect_metrics")
@patch("fivenines_agent.agent.packages_sync")
def test_run_enqueues_precompressed_payload(mock_ps, mock_cm, mock_dr, mock_sis):
    """The metric payload is gzip-compressed at enqueue time (small blobs in
    the outage buffer, not full object graphs) and round-trips to JSON."""
    import gzip
    import json

    agent = make_agent()
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer.get_config.return_value = agent.config
    agent._systemd_force_resend = False
    # Everything landing in the payload must be JSON-serializable.
    agent.permissions.get_reasons.return_value = {}

    def stop_loop(_running_time):
        agent_module.exit_event.set()

    agent._wait_interval = stop_loop

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        with pytest.raises(SystemExit):
            agent.run()
    finally:
        agent_module.systemd_watchdog = original

    # One enqueue from the loop, then the shutdown sentinel from _cleanup.
    payload_calls = [
        c for c in agent.queue.put.call_args_list if c.args[0] is not None
    ]
    assert len(payload_calls) == 1
    blob = payload_calls[0].args[0]
    assert isinstance(blob, bytes)
    decoded = json.loads(gzip.decompress(blob).decode("utf-8"))
    assert decoded["version"] == "test"
    assert "ts" in decoded and "running_time" in decoded
