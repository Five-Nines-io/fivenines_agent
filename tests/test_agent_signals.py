"""Tests for setup_signals() and its handlers, the TOKEN load at startup and the
OS-aware collector dispatch.

SIGHUP must be guarded so the agent imports and runs on Windows. The
_collect_file_handles dispatch (D2 + D10) emits Linux file-nr keys on Linux
and the Windows handle-count key on Windows - never both. The Ubuntu Pro
block rides the same Linux-only branch. Each public-IP family is looked up
only when its own config flag is on."""

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


def _run_setup_signals(sighup=True):
    """Run setup_signals against a fake signal module (the real signal numbers,
    a mock signal()); return it and the {signum: handler} it registered.
    sighup=False models Windows, whose signal module has no SIGHUP at all."""
    fake = SimpleNamespace(
        SIGTERM=real_signal.SIGTERM, SIGINT=real_signal.SIGINT, signal=MagicMock()
    )
    if sighup:
        fake.SIGHUP = getattr(real_signal, "SIGHUP", 1)
    with patch("fivenines_agent.agent.signal", fake):
        setup_signals()
    return fake, {c.args[0]: c.args[1] for c in fake.signal.call_args_list}


def test_setup_signals_registers_sigterm_and_sigint():
    """SIGTERM and SIGINT exist on all OSes and must be registered."""
    fake, _ = _run_setup_signals()

    registered = [c.args[0] for c in fake.signal.call_args_list]
    assert fake.SIGTERM in registered
    assert fake.SIGINT in registered


def test_setup_signals_skips_sighup_when_unavailable():
    """When signal lacks SIGHUP (Windows), setup_signals must NOT raise."""
    fake, _ = _run_setup_signals(sighup=False)  # must not raise AttributeError

    # Only SIGTERM and SIGINT were registered; SIGHUP skipped.
    assert fake.signal.call_count == 2


def test_setup_signals_registers_sighup_when_available():
    """When signal has SIGHUP (Linux/macOS), it's registered alongside the others."""
    fake, _ = _run_setup_signals()

    assert fake.signal.call_count == 3


# --- the registered handlers ---


@pytest.fixture
def fresh_events(monkeypatch):
    """Private exit/refresh events, so a handler under test never sets the
    module-level ones other tests (and the real loop) read."""
    exit_event, refresh_event = Event(), Event()
    monkeypatch.setattr(agent_module, "exit_event", exit_event)
    monkeypatch.setattr(agent_module, "refresh_permissions_event", refresh_event)
    return SimpleNamespace(exit=exit_event, refresh=refresh_event)


@pytest.mark.parametrize("signame", ["SIGTERM", "SIGINT"])
def test_exit_signals_set_the_exit_event_only(fresh_events, signame):
    fake, handlers = _run_setup_signals()
    signum = getattr(fake, signame)

    handlers[signum](signum, None)

    assert fresh_events.exit.is_set()
    assert not fresh_events.refresh.is_set()


def test_sighup_requests_a_capability_refresh_without_exiting(fresh_events):
    fake, handlers = _run_setup_signals()

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


# --- T6: OS-aware file-handles dispatch (_collect_file_handles) ---


def _bare_agent():
    """An Agent instance bypassing __init__, with just what the dispatch needs."""
    agent = Agent.__new__(Agent)
    agent._telemetry = None
    return agent


def test_collect_file_handles_linux_emits_used_and_limit():
    """On Linux, the dispatch emits file_handles_used and file_handles_limit only."""
    agent = _bare_agent()
    data = {}
    with patch("fivenines_agent.agent.is_windows", return_value=False), \
         patch("fivenines_agent.agent.file_handles_used", return_value=42), \
         patch("fivenines_agent.agent.file_handles_limit", return_value=65536):
        agent._collect_file_handles(data)

    assert data["file_handles_used"] == 42
    assert data["file_handles_limit"] == 65536
    assert "handle_count" not in data


def test_collect_file_handles_windows_emits_handle_count_only():
    """On Windows, the dispatch emits handle_count - not the Linux file_handles_*."""
    agent = _bare_agent()
    data = {}
    with patch("fivenines_agent.agent.is_windows", return_value=True), \
         patch("fivenines_agent.agent.handle_count", return_value=12345):
        agent._collect_file_handles(data)

    assert data["handle_count"] == 12345
    assert "file_handles_used" not in data
    assert "file_handles_limit" not in data


# --- _collect_metrics dispatch: Ubuntu Pro (server #746), public IPs ---


def _run_collect_metrics(windows, reading, config=None, get_ip=None):
    """Run _collect_metrics with every other collector stubbed out. config
    defaults to {}; get_ip is the public-IP lookup double to install, which
    only a config enabling ipv4/ipv6 reaches."""
    agent = _bare_agent()
    agent.config = {} if config is None else config
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {}
    data = {}
    with patch("fivenines_agent.agent.is_windows", return_value=windows), patch(
        "fivenines_agent.agent.load_average", return_value=[0.0, 0.0, 0.0]
    ), patch("fivenines_agent.agent.handle_count", return_value=1), patch(
        "fivenines_agent.agent.file_handles_used", return_value=1
    ), patch(
        "fivenines_agent.agent.file_handles_limit", return_value=2
    ), patch(
        "fivenines_agent.agent.collect_metrics"
    ), patch(
        "fivenines_agent.agent.mqtt_metrics", return_value=None
    ), patch(
        "fivenines_agent.agent.ubuntu_pro_status", return_value=reading
    ), patch(
        "fivenines_agent.agent.get_ip", get_ip or MagicMock()
    ):
        agent._collect_metrics(data)
    return data


def test_ubuntu_pro_is_collected_unconditionally_on_linux():
    """No config key, no capability gate, no version gate: an empty config must
    still produce the block, or the feature is silently off fleet-wide."""
    reading = {"attached": True, "services": ["esm-infra"]}
    assert _run_collect_metrics(windows=False, reading=reading)["ubuntu_pro"] == reading


def test_ubuntu_pro_collection_failure_travels_as_null():
    """null is the documented "could not determine" the server PRESERVES on. It
    must reach the payload rather than being swallowed, so a host that stops
    being readable is distinguishable from one that was never checked."""
    data = _run_collect_metrics(windows=False, reading=None)
    assert "ubuntu_pro" in data
    assert data["ubuntu_pro"] is None


def test_ubuntu_pro_is_absent_on_windows():
    """`pro` is an Ubuntu tool; a Windows agent must not carry the key at all."""
    assert "ubuntu_pro" not in _run_collect_metrics(windows=True, reading=None)


def _collect_ips(config):
    """Run _collect_metrics on Linux with this config and a get_ip answering one
    documentation address per family; return the data and the get_ip mock."""
    get_ip = MagicMock(
        side_effect=lambda ipv6=False: "2001:db8::10" if ipv6 else "192.0.2.10"
    )
    data = _run_collect_metrics(
        windows=False, reading=None, config=config, get_ip=get_ip
    )
    return data, get_ip


def test_ipv4_and_ipv6_are_collected_when_enabled():
    data, get_ip = _collect_ips({"ipv4": True, "ipv6": True})

    assert data["ipv4"] == "192.0.2.10"
    assert data["ipv6"] == "2001:db8::10"
    assert get_ip.call_args_list == [call(ipv6=False), call(ipv6=True)]


def test_each_ip_family_follows_its_own_flag():
    data, get_ip = _collect_ips({"ipv4": False, "ipv6": True})

    assert "ipv4" not in data
    assert data["ipv6"] == "2001:db8::10"
    get_ip.assert_called_once_with(ipv6=True)

    data, get_ip = _collect_ips({"ipv4": True})

    assert data["ipv4"] == "192.0.2.10"
    assert "ipv6" not in data
    get_ip.assert_called_once_with(ipv6=False)
