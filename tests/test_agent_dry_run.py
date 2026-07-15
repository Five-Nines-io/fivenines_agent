"""Tests for --dry-run mode in Agent.

In dry-run we skip the Synchronizer entirely (it's a non-daemon Thread that
would otherwise block on API config-fetch retries with an invalid token,
hanging the process after the main loop exits). Instead the agent uses a
static permissive config (_DRY_RUN_CONFIG) so every collector runs.
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402
from fivenines_agent.agent import Agent, _DRY_RUN_CONFIG  # noqa: E402


def make_dry_run_agent():
    """Build an Agent in the post-__init__ state that --dry-run produces:
    synchronizer is None, config will be set from _DRY_RUN_CONFIG in run()."""
    agent = Agent.__new__(Agent)
    agent.synchronizer = None
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
def test_dry_run_uses_static_config_when_synchronizer_is_none(mock_ps, mock_cm, mock_dr):
    """With synchronizer=None, agent.run() uses _DRY_RUN_CONFIG and exits cleanly."""
    agent = make_dry_run_agent()

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        with pytest.raises(SystemExit) as exc_info:
            agent.run()
        assert exc_info.value.code == 0
        # collect_metrics should have been called with the static config
        # (not with whatever a synchronizer would have returned).
        assert mock_cm.called
        called_config = mock_cm.call_args[0][0]
        assert called_config is _DRY_RUN_CONFIG
        # packages_sync MUST NOT be called - it would attempt an HTTP POST to
        # /packages and there's no synchronizer to dispatch through.
        assert not mock_ps.called
    finally:
        agent_module.systemd_watchdog = original


def test_dry_run_config_includes_systemd():
    """F5: systemd is a host-level collector (no external service config needed,
    like cpu/disk_health), so --dry-run must exercise its per-tick health
    surface. Regression: the key was omitted when the collector was added, so
    collect_metrics' `if not config_value` gate silently skipped it."""
    assert _DRY_RUN_CONFIG.get("systemd")  # present and truthy


def test_dry_run_config_includes_zfs():
    """ZFS is a host-level collector (generic zpool, no external config), so
    --dry-run must exercise it. Same regression class as systemd: without the
    key, collect_metrics' `if not config_value` gate silently skips it."""
    assert _DRY_RUN_CONFIG.get("zfs")  # present and truthy


@patch("fivenines_agent.agent.dry_run", return_value=True)
def test_dry_run_cleanup_skips_synchronizer(mock_dr):
    """_cleanup() must not crash when synchronizer is None."""
    agent = make_dry_run_agent()
    with pytest.raises(SystemExit) as exc_info:
        agent._cleanup()
    assert exc_info.value.code == 0
    # The queue is cleared in cleanup even when there's no synchronizer.
    agent.queue.clear.assert_called_once()
