"""Tests verifying capability_reasons is threaded through Agent.static_data."""

import sys
from unittest.mock import MagicMock, patch

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402
from fivenines_agent.agent import Agent  # noqa: E402


def _make_agent():
    agent = Agent.__new__(Agent)
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {"nvidia_gpu": False, "cpu": True}
    agent.permissions.get_reasons.return_value = {
        "nvidia_gpu": "nvmlInit failed: NVML Shared Library Not Found"
    }
    agent.permissions.refresh_due.return_value = False
    agent._last_recheck_token = agent_module._RECHECK_UNSET
    agent.static_data = {
        "capabilities": agent.permissions.get_all(),
        "capability_reasons": agent.permissions.get_reasons(),
        "pending_capabilities": [],
    }
    return agent


def test_sighup_triggers_force_refresh_and_banner():
    """SIGHUP does a full reprobe + banner. static_data is republished by
    _apply_config_driven_refresh (always runs later the same tick), so the
    handler itself no longer writes capabilities/reasons (dead store removed)."""
    agent = _make_agent()
    before = dict(agent.static_data)

    agent_module.refresh_permissions_event.set()
    with patch("fivenines_agent.agent.print_capabilities_banner") as banner:
        agent._handle_sighup_refresh()

    agent.permissions.force_refresh.assert_called_once()
    banner.assert_called_once()
    # The handler does not touch static_data itself anymore.
    assert agent.static_data == before


def test_config_driven_refresh_updates_capability_reasons():
    """The config-driven (timed/gap) refresh writes capabilities and reasons to static_data."""
    agent = _make_agent()
    agent.permissions.get_all.return_value = {"nvidia_gpu": False, "cpu": True}
    agent.permissions.get_reasons.return_value = {
        "nvidia_gpu": "nvmlInit failed: driver removed"
    }

    agent_module.refresh_permissions_event.clear()
    agent._apply_config_driven_refresh({"interval": 60})

    agent.permissions.refresh_due.assert_called_once()
    assert (
        agent.static_data["capability_reasons"]["nvidia_gpu"]
        == "nvmlInit failed: driver removed"
    )


def test_no_sighup_leaves_static_data_unchanged():
    """When the SIGHUP event is not set, the sighup handler does not touch static_data."""
    agent = _make_agent()
    snapshot_before = dict(agent.static_data)

    agent_module.refresh_permissions_event.clear()
    agent._handle_sighup_refresh()

    agent.permissions.force_refresh.assert_not_called()
    assert agent.static_data == snapshot_before
