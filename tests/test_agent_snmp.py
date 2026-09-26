"""The agent hands the SNMP collector the start of its collection tick, so a
device's polls are timed tick to tick (#161)."""

import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402

TARGETS = [{"device_id": "dev-1", "ip": "192.0.2.1"}]


def _agent():
    agent = agent_module.Agent.__new__(agent_module.Agent)
    agent.config = {"enabled": True, "snmp_targets": TARGETS}
    agent._telemetry = {}
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {}
    return agent


def test_collect_metrics_passes_the_tick_start_to_snmp():
    with patch.object(agent_module, "collect_metrics"), patch.object(
        agent_module, "mqtt_metrics", return_value=None
    ), patch.object(agent_module, "is_windows", return_value=True), patch(
        "fivenines_agent.snmp.snmp_metrics", return_value={"devices": []}
    ) as snmp:
        data = {}
        _agent()._collect_metrics(data, 1000.0)
    snmp.assert_called_once_with(TARGETS, tick_started=1000.0)
    assert data["snmp_metrics"] == {"devices": []}


def test_run_passes_the_start_of_its_tick():
    """The value run() hands over is its own tick start: taken before any
    collector ran, so the stage SNMP runs at within the tick is irrelevant."""
    agent = _agent()
    agent.synchronizer = None
    agent.log_uploader = None
    agent.image_inventory_uploader = None
    agent.permissions.refresh_due.return_value = False
    agent._last_recheck_token = agent_module._RECHECK_UNSET
    agent.queue = MagicMock()
    agent.static_data = {"version": "test"}
    seen = []

    def collect(data, tick_started=None):
        seen.append((tick_started, time.monotonic()))

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        before = time.monotonic()
        with patch.object(agent_module, "dry_run", return_value=True), patch.object(
            agent, "_collect_metrics", side_effect=collect
        ), patch.object(agent_module, "packages_sync"), pytest.raises(SystemExit):
            agent.run()
    finally:
        agent_module.systemd_watchdog = original
    [(tick_started, called_at)] = seen
    assert before <= tick_started <= called_at


def test_no_targets_reconciles_the_snmp_state():
    """snmp_metrics is not called with no targets, so the removal of the
    last device must be handed to the collector another way."""
    agent = _agent()
    agent.config = {"enabled": True, "snmp_targets": []}
    with patch.object(agent_module, "collect_metrics"), patch.object(
        agent_module, "mqtt_metrics", return_value=None
    ), patch.object(agent_module, "is_windows", return_value=True), patch(
        "fivenines_agent.snmp.forget_targets"
    ) as forget, patch("fivenines_agent.snmp.snmp_metrics") as snmp:
        data = {}
        agent._collect_metrics(data, 1000.0)
    forget.assert_called_once_with()
    snmp.assert_not_called()
    assert "snmp_metrics" not in data
    # Housekeeping, not a collector: no telemetry entry of its own.
    assert not [k for k in agent._telemetry if "snmp" in k]


def test_failed_snmp_reconcile_does_not_stop_the_tick():
    agent = _agent()
    agent.config = {"enabled": True, "snmp_targets": []}
    with patch.object(agent_module, "collect_metrics"), patch.object(
        agent_module, "mqtt_metrics", return_value={"brokers": []}
    ), patch.object(agent_module, "is_windows", return_value=True), patch(
        "fivenines_agent.snmp.forget_targets", side_effect=RuntimeError("boom")
    ), patch.object(agent_module, "log") as log:
        data = {}
        agent._collect_metrics(data, 1000.0)
    assert data["mqtt"] == {"brokers": []}  # collection went on
    assert any("SNMP state reset failed: boom" in c.args[0] for c in log.call_args_list)
