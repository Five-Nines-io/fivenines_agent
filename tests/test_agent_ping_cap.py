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


def test_non_dict_ping_config_yields_empty():
    """REGRESSION: `ping: true` (the plain-boolean shape other config keys
    use) or garbage must yield [] -- an AttributeError here escapes the
    collection loop and exits the agent into a Restart=always crash loop
    against the same config."""
    for bad in (True, "host", ["a"], 3, None):
        assert _capped_ping_targets(bad) == []


def test_oversized_entries_are_dropped():
    agent_module._ping_capped_warned = False
    ping = {"ok": "h.example", "big" * 100: "h2.example", "r": "x" * 500}
    assert _capped_ping_targets(ping) == [("ok", "h.example")]


def test_over_cap_rotation_gives_every_target_a_turn():
    """The cap must not starve the same config-order tail every tick: the
    window rotates so skipped targets get probed on later ticks."""
    agent_module._ping_capped_warned = False
    agent_module._ping_rotation = 0
    ping = {f"r{i:02d}": f"h{i}.example" for i in range(MAX_PING_TARGETS * 2)}
    first = {r for r, _ in _capped_ping_targets(ping)}
    second = {r for r, _ in _capped_ping_targets(ping)}
    assert first != second
    assert first | second == set(ping.keys())


def test_ping_loop_deadline_skips_remaining_targets():
    """Targets past the wall-clock deadline are skipped for the tick (the
    per-target timeout cannot preempt a hung getaddrinfo). A negative
    deadline makes the very first check trip deterministically."""
    from unittest.mock import patch as patch_fn

    agent = agent_module.Agent.__new__(agent_module.Agent)
    agent.config = {"enabled": True, "ping": {"a": "h1", "b": "h2"}}
    agent._telemetry = {}
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {}

    ping_fn = MagicMock(return_value=1.0)
    with patch_fn.object(agent_module, "PING_LOOP_DEADLINE", -1), \
         patch_fn.object(agent_module, "collect_metrics"), \
         patch_fn.object(agent_module, "mqtt_metrics", return_value=None), \
         patch_fn.object(agent_module, "tcp_ping", ping_fn), \
         patch_fn.object(agent_module, "is_windows", return_value=True):
        data = {}
        agent._collect_metrics(data)
    assert ping_fn.call_count == 0  # every target past the (elapsed) deadline
    assert "ping_a" not in data and "ping_b" not in data
