"""Tests for the agent's signal handlers, the TOKEN load at startup and the
public-IP dispatch in _collect_metrics."""

import signal as real_signal
import sys
from threading import Event
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

# Mock libvirt before any fivenines_agent imports that transitively need it.
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402
from fivenines_agent.agent import Agent, setup_signals  # noqa: E402


@pytest.fixture
def fresh_events(monkeypatch):
    """Private exit/refresh events, so a handler under test never sets the
    module-level ones other tests (and the real loop) read."""
    exit_event, refresh_event = Event(), Event()
    monkeypatch.setattr(agent_module, "exit_event", exit_event)
    monkeypatch.setattr(agent_module, "refresh_permissions_event", refresh_event)
    return SimpleNamespace(exit=exit_event, refresh=refresh_event)


def _registered_handlers():
    """Run setup_signals against a fake signal module; return {signum: handler}."""
    fake = SimpleNamespace(
        SIGTERM=real_signal.SIGTERM,
        SIGINT=real_signal.SIGINT,
        SIGHUP=getattr(real_signal, "SIGHUP", 1),
        signal=MagicMock(),
    )
    with patch("fivenines_agent.agent.signal", fake):
        setup_signals()
    return fake, {c.args[0]: c.args[1] for c in fake.signal.call_args_list}


@pytest.mark.parametrize("signame", ["SIGTERM", "SIGINT"])
def test_exit_signals_set_the_exit_event_only(fresh_events, signame):
    fake, handlers = _registered_handlers()
    signum = getattr(fake, signame)

    handlers[signum](signum, None)

    assert fresh_events.exit.is_set()
    assert not fresh_events.refresh.is_set()


def test_sighup_requests_a_capability_refresh_without_exiting(fresh_events):
    fake, handlers = _registered_handlers()

    with patch("fivenines_agent.agent.log") as mock_log:
        handlers[fake.SIGHUP](fake.SIGHUP, None)

    assert fresh_events.refresh.is_set()
    assert not fresh_events.exit.is_set()
    mock_log.assert_called_once_with(
        "Received SIGHUP - will refresh capabilities", "info"
    )


# --- _load_file (TOKEN at startup) ---


def test_load_file_sets_the_stripped_content(monkeypatch, tmp_path):
    monkeypatch.setattr(agent_module, "CONFIG_DIR", str(tmp_path))
    (tmp_path / "TOKEN").write_text("  abc123\n")
    agent = Agent.__new__(Agent)

    agent._load_file("TOKEN")

    assert agent.token == "abc123"


def test_load_file_missing_exits_with_status_2(monkeypatch, tmp_path):
    """No TOKEN, no agent: it logs why and exits 2 instead of running
    unauthenticated."""
    monkeypatch.setattr(agent_module, "CONFIG_DIR", str(tmp_path))
    agent = Agent.__new__(Agent)

    with patch("fivenines_agent.agent.log") as mock_log, pytest.raises(
        SystemExit
    ) as exc:
        agent._load_file("TOKEN")

    assert exc.value.code == 2
    mock_log.assert_called_once_with("TOKEN file is missing", "error")
    assert not hasattr(agent, "token")


# --- public IP dispatch in _collect_metrics ---


def _collect_with_config(config):
    agent = Agent.__new__(Agent)
    agent._telemetry = None
    agent.config = config
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {}
    data = {}

    def fake_get_ip(ipv6=False):
        return "2001:db8::10" if ipv6 else "192.0.2.10"

    with patch("fivenines_agent.agent.is_windows", return_value=False), patch(
        "fivenines_agent.agent.load_average", return_value=[0.0, 0.0, 0.0]
    ), patch("fivenines_agent.agent.file_handles_used", return_value=1), patch(
        "fivenines_agent.agent.file_handles_limit", return_value=2
    ), patch(
        "fivenines_agent.agent.ubuntu_pro_status", return_value=None
    ), patch(
        "fivenines_agent.agent.collect_metrics"
    ), patch(
        "fivenines_agent.agent.mqtt_metrics", return_value=None
    ), patch(
        "fivenines_agent.snmp.forget_targets"
    ), patch(
        "fivenines_agent.agent.get_ip", side_effect=fake_get_ip
    ) as get_ip:
        agent._collect_metrics(data)
    return data, get_ip


def test_ipv4_and_ipv6_are_collected_when_enabled():
    data, get_ip = _collect_with_config({"ipv4": True, "ipv6": True})

    assert data["ipv4"] == "192.0.2.10"
    assert data["ipv6"] == "2001:db8::10"
    assert get_ip.call_args_list == [call(ipv6=False), call(ipv6=True)]


def test_each_ip_family_follows_its_own_flag():
    data, get_ip = _collect_with_config({"ipv4": False, "ipv6": True})

    assert "ipv4" not in data
    assert data["ipv6"] == "2001:db8::10"
    get_ip.assert_called_once_with(ipv6=True)

    data, get_ip = _collect_with_config({"ipv4": True})

    assert data["ipv4"] == "192.0.2.10"
    assert "ipv6" not in data
    get_ip.assert_called_once_with(ipv6=False)
