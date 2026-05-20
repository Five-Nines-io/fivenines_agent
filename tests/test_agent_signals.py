"""Tests for setup_signals(): SIGHUP must be guarded so the agent imports
and runs on Windows (which lacks SIGHUP entirely)."""

import signal as real_signal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fivenines_agent.agent import setup_signals


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
