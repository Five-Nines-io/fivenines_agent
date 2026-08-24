"""Tests for setup_signals() and the OS-aware collector dispatch.

SIGHUP must be guarded so the agent imports and runs on Windows. The
_collect_file_handles dispatch (D2 + D10) emits Linux file-nr keys on Linux
and the Windows handle-count key on Windows - never both. The Ubuntu Pro
block rides the same Linux-only branch."""

import signal as real_signal
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# Mock libvirt before any fivenines_agent imports that transitively need it.
sys.modules.setdefault("libvirt", MagicMock())

from fivenines_agent.agent import Agent, setup_signals  # noqa: E402


def test_setup_signals_registers_sigterm_and_sigint():
    """SIGTERM and SIGINT exist on all OSes and must be registered."""
    fake = SimpleNamespace(
        SIGTERM=real_signal.SIGTERM,
        SIGINT=real_signal.SIGINT,
        SIGHUP=getattr(real_signal, "SIGHUP", 1),
        signal=MagicMock(),
    )
    with patch("fivenines_agent.agent.signal", fake):
        setup_signals()

    registered = [c.args[0] for c in fake.signal.call_args_list]
    assert fake.SIGTERM in registered
    assert fake.SIGINT in registered


def test_setup_signals_skips_sighup_when_unavailable():
    """When signal lacks SIGHUP (Windows), setup_signals must NOT raise."""
    fake = SimpleNamespace(
        SIGTERM=real_signal.SIGTERM,
        SIGINT=real_signal.SIGINT,
        # no SIGHUP attribute - hasattr(fake, "SIGHUP") returns False
        signal=MagicMock(),
    )
    with patch("fivenines_agent.agent.signal", fake):
        setup_signals()  # must not raise AttributeError

    # Only SIGTERM and SIGINT were registered; SIGHUP skipped.
    assert fake.signal.call_count == 2


def test_setup_signals_registers_sighup_when_available():
    """When signal has SIGHUP (Linux/macOS), it's registered alongside the others."""
    fake = SimpleNamespace(
        SIGTERM=real_signal.SIGTERM,
        SIGINT=real_signal.SIGINT,
        SIGHUP=getattr(real_signal, "SIGHUP", 999),
        signal=MagicMock(),
    )
    with patch("fivenines_agent.agent.signal", fake):
        setup_signals()

    assert fake.signal.call_count == 3


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


# --- Ubuntu Pro dispatch (server #746) ---


def _run_collect_metrics(windows, reading):
    """Run _collect_metrics with every other collector stubbed out."""
    agent = _bare_agent()
    agent.config = {}
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {}
    data = {}
    with patch("fivenines_agent.agent.is_windows", return_value=windows), \
         patch("fivenines_agent.agent.load_average", return_value=[0.0, 0.0, 0.0]), \
         patch("fivenines_agent.agent.handle_count", return_value=1), \
         patch("fivenines_agent.agent.file_handles_used", return_value=1), \
         patch("fivenines_agent.agent.file_handles_limit", return_value=2), \
         patch("fivenines_agent.agent.collect_metrics"), \
         patch("fivenines_agent.agent.mqtt_metrics", return_value=None), \
         patch("fivenines_agent.agent.ubuntu_pro_status", return_value=reading):
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
