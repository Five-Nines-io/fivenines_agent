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
