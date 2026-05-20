"""Tests for setup_signals() and the OS-aware file-handles dispatch.

SIGHUP must be guarded so the agent imports and runs on Windows. The
_collect_file_handles dispatch (D2 + D10) emits Linux file-nr keys on Linux
and the Windows handle-count key on Windows - never both."""

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
