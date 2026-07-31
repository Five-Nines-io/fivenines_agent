"""Tests for the disabled-host branch of agent.run().

The queued get_config poll must only fire once a config fetch has succeeded
(enabled is False, not still None): while enabled is None the token may
still be an enrollment token, and a queued request drains on the
synchronizer thread OUTSIDE the single-flight fetch guard -- during an API
outage at install time it could race the direct fetch and enroll the host
twice.
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402
from fivenines_agent.agent import Agent  # noqa: E402


def make_agent(config):
    """Create an Agent-like object without __init__ side effects."""
    agent = Agent.__new__(Agent)
    agent.config = config
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


def run_one_tick(agent, config):
    """Drive agent.run() through exactly one loop iteration then shut down."""

    def get_config():
        agent_module.exit_event.set()
        return config

    agent.synchronizer.get_config.side_effect = get_config

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        with pytest.raises(SystemExit):
            agent.run()
    finally:
        agent_module.systemd_watchdog = original
        agent_module.exit_event.clear()


def queued_get_config_calls(queue):
    """The queue.put calls that carry a get_config payload (excludes the
    shutdown sentinel None enqueued by _cleanup)."""
    return [
        c
        for c in queue.put.call_args_list
        if isinstance(c.args[0], dict) and c.args[0].get("get_config")
    ]


@patch("fivenines_agent.agent.dry_run", return_value=False)
def test_disabled_host_polls_config_through_queue(mock_dr):
    """enabled False (a fetched config): the 25s queue poll fires; by then
    the token is a per-host token, so the queued request is safe."""
    config = {"enabled": False}
    agent = make_agent(config)
    run_one_tick(agent, config)
    assert len(queued_get_config_calls(agent.queue)) == 1


@patch("fivenines_agent.agent.dry_run", return_value=False)
def test_no_queued_poll_before_first_successful_fetch(mock_dr):
    """enabled None (startup fetch failed): no get_config payload may reach
    the queue -- get_config() on the next pass is the only retry path."""
    config = {
        "enabled": None,
        "request_options": {"timeout": 5, "retry": 3, "retry_interval": 5},
    }
    agent = make_agent(config)
    run_one_tick(agent, config)
    assert queued_get_config_calls(agent.queue) == []
