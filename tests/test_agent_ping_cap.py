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
