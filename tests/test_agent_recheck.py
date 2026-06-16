"""Tests for the backend-controlled recheck additions to Agent:
recheck-token state machine, interval/throttle clamping, pending computation,
and the config-driven refresh dispatch.
"""

import sys
from unittest.mock import MagicMock, patch

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402
from fivenines_agent.agent import Agent  # noqa: E402


def _agent(caps=None, reasons=None):
    agent = Agent.__new__(Agent)
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = caps if caps is not None else {}
    agent.permissions.get_reasons.return_value = reasons or {}
    agent.permissions.refresh_due.return_value = False
    agent._last_recheck_token = agent_module._RECHECK_UNSET
    agent.static_data = {}
    return agent


# --- _recheck_token_changed (nonce state machine) ---


def test_token_first_observation_none_baselines():
    agent = _agent()
    assert agent._recheck_token_changed(None) is False
    assert agent._last_recheck_token is None


def test_token_first_observation_value_baselines_no_fire():
    """A token already set when the agent (re)starts must not trigger a reprobe."""
    agent = _agent()
    assert agent._recheck_token_changed("abc") is False
    assert agent._last_recheck_token == "abc"


def test_token_change_after_baseline_fires():
    agent = _agent()
    agent._recheck_token_changed(None)  # baseline
    assert agent._recheck_token_changed("abc") is True


def test_token_unchanged_no_fire():
    agent = _agent()
    agent._recheck_token_changed("abc")  # baseline
    assert agent._recheck_token_changed("abc") is False


def test_token_changes_to_different_value_fires():
    agent = _agent()
    agent._recheck_token_changed("abc")  # baseline
    assert agent._recheck_token_changed("def") is True


def test_token_null_resets_then_same_value_fires():
    """abc -> null -> abc fires, because null resets the baseline."""
    agent = _agent()
    agent._recheck_token_changed("abc")  # baseline
    assert agent._recheck_token_changed(None) is False
    assert agent._last_recheck_token is None
    assert agent._recheck_token_changed("abc") is True


# --- _collection_interval ---


def test_collection_interval_default_when_absent():
    assert _agent()._collection_interval({}) == 60


def test_collection_interval_allows_low_warmup_value():
    assert _agent()._collection_interval({"interval": 5}) == 5


def test_collection_interval_blocks_zero_and_negative():
    agent = _agent()
    assert agent._collection_interval({"interval": 0}) == 60
    assert agent._collection_interval({"interval": -3}) == 60


def test_collection_interval_rejects_non_numeric_and_bool():
    agent = _agent()
    assert agent._collection_interval({"interval": "x"}) == 60
    assert agent._collection_interval({"interval": True}) == 60


def test_collection_interval_passes_normal_value():
    assert _agent()._collection_interval({"interval": 60}) == 60


# --- _gap_probe_interval ---


def test_gap_interval_absent_means_every_tick():
    assert _agent()._gap_probe_interval({}, 60) == 0


def test_gap_interval_throttle_above_interval():
    assert (
        _agent()._gap_probe_interval({"permissions_recheck_interval": 120}, 60) == 120
    )


def test_gap_interval_floored_at_interval():
    assert _agent()._gap_probe_interval({"permissions_recheck_interval": 30}, 60) == 60


def test_gap_interval_capped_at_3600():
    assert (
        _agent()._gap_probe_interval({"permissions_recheck_interval": 99999}, 60)
        == 3600
    )


def test_gap_interval_rejects_zero_negative_bool_and_nonint():
    agent = _agent()
    assert agent._gap_probe_interval({"permissions_recheck_interval": 0}, 60) == 0
    assert agent._gap_probe_interval({"permissions_recheck_interval": -5}, 60) == 0
    assert agent._gap_probe_interval({"permissions_recheck_interval": True}, 60) == 0
    assert agent._gap_probe_interval({"permissions_recheck_interval": "x"}, 60) == 0


def test_gap_interval_accepts_float():
    # A float permissions_recheck_interval (e.g. 300.0 from JSON) must throttle,
    # not silently fall back to every-tick; consistent with _collection_interval.
    assert (
        _agent()._gap_probe_interval({"permissions_recheck_interval": 300.0}, 60)
        == 300.0
    )


def test_gap_interval_float_floored_at_interval():
    assert (
        _agent()._gap_probe_interval({"permissions_recheck_interval": 30.0}, 60) == 60
    )


# --- _pending_capabilities ---


def test_pending_includes_enabled_missing_and_override():
    agent = _agent({"qemu": False, "docker": True, "smart_storage": False})
    config = {"qemu": True, "docker": True, "smart_storage_health": True}
    pending = agent._pending_capabilities(config)
    assert "qemu" in pending  # enabled + missing
    assert "smart_storage" in pending  # override: smart_storage_health -> smart_storage
    assert "docker" not in pending  # enabled but present


def test_pending_excludes_disabled():
    agent = _agent({"qemu": False})
    assert agent._pending_capabilities({}) == []


def test_pending_includes_snmp_targets():
    agent = _agent({"snmp": False})
    pending = agent._pending_capabilities({"snmp_targets": [{"host": "h"}]})
    assert pending == ["snmp"]


def test_pending_snmp_not_added_when_available():
    agent = _agent({"snmp": True})
    assert agent._pending_capabilities({"snmp_targets": [{"host": "h"}]}) == []


def test_pending_includes_packages_scan():
    agent = _agent({"packages": False})
    assert agent._pending_capabilities({"packages": {"scan": True}}) == ["packages"]


def test_pending_packages_not_added_when_available():
    agent = _agent({"packages": True})
    assert agent._pending_capabilities({"packages": {"scan": True}}) == []


def test_pending_packages_not_added_when_scan_off():
    agent = _agent({"packages": False})
    assert agent._pending_capabilities({"packages": {"scan": False}}) == []


def test_pending_packages_ignores_non_dict_config():
    agent = _agent({"packages": False})
    assert agent._pending_capabilities({"packages": True}) == []


def test_pending_includes_software_inventory_for_windows_packages_scan():
    # On Windows the package scan reads the Uninstall registry (software_inventory
    # cap); there is no 'packages' cap in the Windows capability set.
    agent = _agent({"software_inventory": False})
    assert agent._pending_capabilities({"packages": {"scan": True}}) == [
        "software_inventory"
    ]


def test_pending_software_inventory_not_added_when_available():
    agent = _agent({"software_inventory": True})
    assert agent._pending_capabilities({"packages": {"scan": True}}) == []


def test_pending_includes_systemd_when_enabled_and_missing():
    # systemd is a regular COLLECTORS config key, so it gap-reprobes like any
    # other service.
    agent = _agent({"systemd": False})
    assert "systemd" in agent._pending_capabilities({"systemd": True})


def test_pending_includes_cgroup_when_systemd_enabled_and_cgroup_missing():
    # cgroup has no config key of its own; it gates per-unit metrics inside the
    # systemd collector, so it is gap-reprobed alongside systemd.
    agent = _agent({"systemd": True, "cgroup": None})
    assert "cgroup" in agent._pending_capabilities({"systemd": True})


def test_pending_cgroup_not_added_when_present():
    agent = _agent({"systemd": True, "cgroup": "v2"})
    assert "cgroup" not in agent._pending_capabilities({"systemd": True})


def test_pending_cgroup_not_added_when_systemd_disabled():
    agent = _agent({"systemd": True, "cgroup": None})
    assert agent._pending_capabilities({}) == []


# --- _apply_config_driven_refresh ---


def test_apply_token_change_forces_full_reprobe():
    agent = _agent({"qemu": True})
    agent._last_recheck_token = "old"
    agent._apply_config_driven_refresh({"permissions_recheck_token": "new"})
    agent.permissions.force_refresh.assert_called_once()
    agent.permissions.refresh_due.assert_not_called()
    assert agent.static_data["capabilities"] == {"qemu": True}
    assert agent.static_data["pending_capabilities"] == []


def test_apply_no_token_runs_gap_refresh_and_publishes_state():
    agent = _agent({"qemu": False}, reasons={"qemu": "libvirt probe timed out"})
    agent._apply_config_driven_refresh({"interval": 60, "qemu": True})
    agent.permissions.force_refresh.assert_not_called()
    agent.permissions.refresh_due.assert_called_once_with(["qemu"], 0)
    assert agent.static_data["capabilities"] == {"qemu": False}
    assert agent.static_data["capability_reasons"] == {
        "qemu": "libvirt probe timed out"
    }
    assert agent.static_data["pending_capabilities"] == ["qemu"]


def test_apply_recomputes_pending_only_when_gap_probe_flips():
    # refresh_due flips qemu available -> pending must be recomputed so the
    # payload reflects the post-probe state (empty), not the stale pre-probe set.
    agent = _agent()
    state = {"flipped": False}

    def fake_get_all():
        return {"qemu": True} if state["flipped"] else {"qemu": False}

    def fake_refresh_due(pending, gap_interval):
        state["flipped"] = True
        return True

    agent.permissions.get_all.side_effect = fake_get_all
    agent.permissions.refresh_due.side_effect = fake_refresh_due

    agent._apply_config_driven_refresh({"interval": 60, "qemu": True})

    assert agent.static_data["pending_capabilities"] == []


# --- _wait_interval (uses the clamped collection interval) ---


def test_wait_interval_uses_clamped_interval():
    agent = _agent()
    agent.config = {"interval": 60}
    with patch.object(agent_module, "exit_event") as fake_event:
        agent._wait_interval(0.5)
    fake_event.wait.assert_called_once()
    assert abs(fake_event.wait.call_args[0][0] - 59.5) < 0.01


def test_wait_interval_floors_sleep_at_minimum():
    """A 5s warmup interval with longer running_time floors the sleep at 0.1s."""
    agent = _agent()
    agent.config = {"interval": 5}
    with patch.object(agent_module, "exit_event") as fake_event:
        agent._wait_interval(10.0)
    assert fake_event.wait.call_args[0][0] == 0.1
