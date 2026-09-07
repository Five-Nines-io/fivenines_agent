"""Tests for the per-tick ping target cap (config is server-pushed and each
tcp_ping blocks up to 5s sequentially on the watchdog-bounded loop)."""

import sys
from unittest.mock import MagicMock, patch

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402
from fivenines_agent.agent import MAX_PING_TARGETS, _capped_ping_targets  # noqa: E402


def test_small_ping_map_passes_through():
    agent_module._ping_capped_warned = False
    ping = {"eu": "a.example", "us": "b.example"}
    assert _capped_ping_targets(ping) == list(ping.items())


def test_oversized_ping_map_is_capped_and_warned_once():
    agent_module._ping_capped_warned = False
    ping = {f"r{i}": f"h{i}.example" for i in range(MAX_PING_TARGETS + 15)}
    with patch("fivenines_agent.agent.log") as mock_log:
        first = _capped_ping_targets(ping)
        second = _capped_ping_targets(ping)
    assert len(first) == len(second) == MAX_PING_TARGETS
    warnings = [c for c in mock_log.call_args_list if "ping config" in c.args[0]]
    assert len(warnings) == 1  # warn once, not per tick


def test_collect_metrics_routes_ping_through_the_cap():
    """The cap must hold on the real tick path (_collect_metrics), not just in
    the helper: reverting the call site to config["ping"].items() would pass
    the unit tests above while an oversized map still ran unbounded."""
    from fivenines_agent.agent import Agent

    agent_module._ping_capped_warned = True  # capping, not the warn, is under test
    agent = Agent.__new__(Agent)
    agent._telemetry = None
    agent.config = {
        "ping": {f"r{i}": f"h{i}.example" for i in range(MAX_PING_TARGETS + 5)}
    }
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {}
    data = {}
    with patch("fivenines_agent.agent.is_windows", return_value=False), \
         patch("fivenines_agent.agent.load_average", return_value=[0.0, 0.0, 0.0]), \
         patch("fivenines_agent.agent.file_handles_used", return_value=1), \
         patch("fivenines_agent.agent.file_handles_limit", return_value=2), \
         patch("fivenines_agent.agent.ubuntu_pro_status", return_value=None), \
         patch("fivenines_agent.agent.collect_metrics"), \
         patch("fivenines_agent.agent.mqtt_metrics", return_value=None), \
         patch("fivenines_agent.agent.tcp_ping", return_value=1.23) as ping:
        agent._collect_metrics(data)
    assert ping.call_count == MAX_PING_TARGETS
    assert sum(1 for k in data if k.startswith("ping_")) == MAX_PING_TARGETS
