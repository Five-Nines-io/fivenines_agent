"""Tests for optional systemd-watchdog support in agent.run()."""

import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())

import fivenines_agent.agent as agent_module  # noqa: E402
from fivenines_agent.agent import Agent  # noqa: E402
from fivenines_agent.synchronizer import QueuedPayload  # noqa: E402


def make_agent():
    """Create an Agent-like object without __init__ side effects."""
    agent = Agent.__new__(Agent)
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer = MagicMock()
    agent.log_uploader = None
    agent.image_inventory_uploader = None
    agent.permissions = MagicMock()
    agent.permissions.get_all.return_value = {}
    agent.permissions.refresh_due.return_value = False
    # Everything landing in the payload must be JSON-serializable.
    agent.permissions.get_reasons.return_value = {}
    agent._last_recheck_token = agent_module._RECHECK_UNSET
    agent._systemd_force_resend = False
    agent.queue = MagicMock()
    agent.static_data = {"version": "test"}
    agent._telemetry = {}
    return agent


@patch("fivenines_agent.agent.dry_run", return_value=True)
@patch("fivenines_agent.agent.collect_metrics")
@patch("fivenines_agent.agent.packages_sync")
def test_run_with_watchdog_none(mock_ps, mock_cm, mock_dr):
    """When systemd_watchdog is None, agent.run() works without calling watchdog."""
    agent = make_agent()
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer.get_config.return_value = agent.config

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        with pytest.raises(SystemExit) as exc_info:
            agent.run()
        assert exc_info.value.code == 0
    finally:
        agent_module.systemd_watchdog = original


@patch("fivenines_agent.agent.dry_run", return_value=True)
@patch("fivenines_agent.agent.collect_metrics")
@patch("fivenines_agent.agent.packages_sync")
def test_run_with_watchdog_present(mock_ps, mock_cm, mock_dr):
    """When systemd_watchdog is available, agent.run() calls wd.ready() and wd.notify()."""
    agent = make_agent()
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer.get_config.return_value = agent.config

    mock_wd_module = MagicMock()
    mock_wd_instance = MagicMock()
    mock_wd_module.watchdog.return_value = mock_wd_instance

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = mock_wd_module
        agent_module.exit_event.clear()
        with pytest.raises(SystemExit) as exc_info:
            agent.run()
        assert exc_info.value.code == 0

        mock_wd_module.watchdog.assert_called_once()
        mock_wd_instance.ready.assert_called_once()
        mock_wd_instance.notify.assert_called()
    finally:
        agent_module.systemd_watchdog = original


@patch("fivenines_agent.agent.systemd_inventory_sync", return_value=True)
@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.collect_metrics")
@patch("fivenines_agent.agent.packages_sync")
def test_run_enqueues_precompressed_payload(mock_ps, mock_cm, mock_dr, mock_sis):
    """The metric payload is gzip-compressed at enqueue time (small blobs in
    the outage buffer, not full object graphs) and round-trips to JSON. It is
    queued with its tick's start, taken BEFORE any collector reads the clock:
    every age in the payload is taken after it, so the wait reported from it
    makes an age read older than it is, not fresher (#246)."""
    import gzip
    import itertools
    import json

    agent = make_agent()
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer.get_config.return_value = agent.config
    agent._systemd_force_resend = False
    # Everything landing in the payload must be JSON-serializable.
    agent.permissions.get_reasons.return_value = {}

    def stop_loop(_running_time):
        agent_module.exit_event.set()

    agent._wait_interval = stop_loop
    # A clock that moves on every read: each stamp is strictly ordered.
    ticks = itertools.count(1000.0)
    # Value: protects=the stamp is the tick's start, before any collector
    # reads the clock, as the contract fixtures name it; fails_when=the payload
    # is queued with a stamp taken during or after the collection (its end, or
    # the enqueue), which makes an age read fresher than it is;
    # why_new=synchronizer tests feed literal waiting_since values, no other
    # agent test checks where the stamp is taken; seam=none; no_claim=reads of
    # the clock before the tick's start (none in the loop today).
    collected_at = []
    mock_cm.side_effect = lambda *args, **kwargs: collected_at.append(time.monotonic())

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        with patch.object(agent_module.time, "monotonic", lambda: next(ticks)):
            with pytest.raises(SystemExit):
                agent.run()
    finally:
        agent_module.systemd_watchdog = original

    # One enqueue from the loop, then the shutdown sentinel from _cleanup.
    payload_calls = [c for c in agent.queue.put.call_args_list if c.args[0] is not None]
    assert len(payload_calls) == 1
    queued = payload_calls[0].args[0]
    assert isinstance(queued, QueuedPayload)
    assert len(collected_at) == 1
    assert queued.waiting_since < collected_at[0]
    blob = queued.body
    assert isinstance(blob, bytes)
    decoded = json.loads(gzip.decompress(blob).decode("utf-8"))
    assert decoded["version"] == "test"
    assert "ts" in decoded and "running_time" in decoded


@patch("fivenines_agent.agent.systemd_inventory_sync", return_value=True)
@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.collect_metrics")
@patch("fivenines_agent.agent.packages_sync")
def test_run_dumps_payload_only_at_debug_level(
    mock_ps, mock_cm, mock_dr, mock_sis, capsys
):
    """The per-tick pretty-printed payload dump (json.dumps, indent=2) is gated
    on debug_enabled(): emitted at debug level, skipped at the default level
    (where it would burn CPU building a message log() then discards)."""
    agent = make_agent()
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer.get_config.return_value = agent.config
    agent._systemd_force_resend = False
    agent.permissions.get_reasons.return_value = {}

    def stop_loop(_running_time):
        agent_module.exit_event.set()

    agent._wait_interval = stop_loop

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        with patch("fivenines_agent.debug.log_level", return_value="debug"):
            with pytest.raises(SystemExit):
                agent.run()
    finally:
        agent_module.systemd_watchdog = original

    out = capsys.readouterr().out
    assert '"version": "test"' in out  # the indent=2 payload dump made it out


@patch("fivenines_agent.agent.systemd_inventory_sync", return_value=True)
@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.collect_metrics")
@patch("fivenines_agent.agent.packages_sync")
def test_run_survives_unserializable_payload(mock_ps, mock_cm, mock_dr, mock_sis):
    """A collector that leaks a non-JSON-serializable value must cost one
    dropped tick, not the whole agent (serialization moved onto the main loop
    with compress-at-enqueue)."""
    agent = make_agent()
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer.get_config.return_value = agent.config
    agent._systemd_force_resend = False
    agent.permissions.get_reasons.return_value = {}

    def poison(config, data, telemetry=None, permissions=None):
        data["bad"] = object()  # not JSON-serializable

    mock_cm.side_effect = poison

    def stop_loop(_running_time):
        agent_module.exit_event.set()

    agent._wait_interval = stop_loop

    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        with pytest.raises(SystemExit) as exc_info:
            agent.run()
        assert exc_info.value.code == 0  # clean shutdown, not a crash
    finally:
        agent_module.systemd_watchdog = original

    payload_calls = [c for c in agent.queue.put.call_args_list if c.args[0] is not None]
    assert payload_calls == []  # tick dropped, nothing enqueued


# --- the exit code after an unexpected error (#272) ---


def _run_until_exit(agent):
    """Run the loop with no watchdog; return the SystemExit code and every
    log() call."""
    original = agent_module.systemd_watchdog
    try:
        agent_module.systemd_watchdog = None
        agent_module.exit_event.clear()
        with patch.object(agent_module, "log") as mock_log:
            with pytest.raises(SystemExit) as exc_info:
                agent.run()
    finally:
        agent_module.systemd_watchdog = original
    return exc_info.value.code, mock_log.call_args_list


# Value: protects=an agent ended by an unexpected error exits non-zero, which
# is what makes WinSW leave the restart to the SCM's failure actions; with
# exit code 0 WinSW reports the service stopped and a Windows host stayed
# silent until someone started it; fails_when=Agent.run exits 0 after an
# exception, skips _cleanup, or logs the raw message (unredacted, and with a
# character the stdout may not encode); why_new=every run() test ended the
# loop through exit_event; seam=collect_metrics raises; no_claim=that WinSW
# and the SCM restart the service (the Windows E2E kills the agent for that).
@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.collect_metrics")
def test_run_exits_non_zero_after_an_unexpected_error(mock_cm, mock_dr):
    agent = make_agent()
    agent.synchronizer.get_config.return_value = agent.config
    mock_cm.side_effect = RuntimeError("boom \u63a5 password=hunter2hunter2\nforged")

    code, logged = _run_until_exit(agent)

    assert code == 1
    errors = [c.args[0] for c in logged if c.args[1:] == ("error",)]
    assert errors == ["Error: RuntimeError: boom \\u63a5 password=[REDACTED] forged"]
    # _cleanup still ran: the synchronizer was stopped and woken.
    agent.synchronizer.stop.assert_called_once_with()
    agent.queue.put.assert_called_with(None)


@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.collect_metrics")
def test_run_exits_non_zero_when_a_base_exception_ends_the_loop(mock_cm, mock_dr):
    """Not an Exception, so no "Error:" line, but still a crash: _cleanup's
    sys.exit replaces it with a non-zero code, never 0."""

    class _NotAnException(BaseException):
        pass

    agent = make_agent()
    agent.synchronizer.get_config.return_value = agent.config
    mock_cm.side_effect = _NotAnException()

    code, logged = _run_until_exit(agent)

    assert code == 1
    assert [c for c in logged if c.args[1:] == ("error",)] == []
