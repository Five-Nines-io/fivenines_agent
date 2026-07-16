"""Tests for the incident log-capture wiring in Agent (_handle_capture_request).

The nonce + persistence + allowlist live in CaptureCoordinator (see
test_log_capture); this checks the thin Agent glue: no-op when uploading is
disabled, enqueue once when a new capture command fires, no duplicate on replay.
"""

import sys
from unittest.mock import MagicMock

# libvirt-python cannot build on macOS; mock it before importing the agent
# (mirrors test_agent_recheck). The other service libs install normally.
sys.modules.setdefault("libvirt", MagicMock())

from fivenines_agent.agent import Agent  # noqa: E402
from fivenines_agent.log_capture import CaptureCoordinator  # noqa: E402
from fivenines_agent.synchronization_queue import SynchronizationQueue  # noqa: E402


def _agent(tmp_path, uploader):
    agent = Agent.__new__(Agent)
    agent.log_uploader = uploader
    agent.log_queue = SynchronizationQueue(maxsize=10)
    agent.capture_coordinator = CaptureCoordinator(str(tmp_path / "last_capture_id"))
    return agent


def _cfg(capture_id="id-1", unit="nginx.service"):
    return {
        "logs": {"units": ["nginx.service"]},
        "capture_logs": {"capture_id": capture_id, "unit": unit, "since": 1000},
    }


def test_handle_capture_noop_when_uploader_disabled(tmp_path):
    agent = _agent(tmp_path, uploader=None)
    agent._handle_capture_request(_cfg())  # valid command, but no uploader
    assert agent.log_queue.qsize() == 0


def test_handle_capture_enqueues_on_new_command(tmp_path):
    agent = _agent(tmp_path, uploader=MagicMock())
    agent._handle_capture_request(_cfg())
    assert agent.log_queue.qsize() == 1
    assert agent.log_queue.get_nowait()["capture_id"] == "id-1"


def test_handle_capture_no_duplicate_on_replay(tmp_path):
    agent = _agent(tmp_path, uploader=MagicMock())
    agent._handle_capture_request(_cfg())
    agent._handle_capture_request(_cfg())  # same capture_id -> replay guard
    assert agent.log_queue.qsize() == 1


def test_handle_capture_refuses_unit_outside_allowlist(tmp_path):
    agent = _agent(tmp_path, uploader=MagicMock())
    agent._handle_capture_request(_cfg(unit="secret.service"))  # default-deny
    assert agent.log_queue.qsize() == 0


def test_cleanup_stops_uploader_with_sentinel_then_join(tmp_path):
    """_cleanup must stop the uploader thread: stop(), push the None sentinel
    (unblocks the queue.get), then join. A wrong order would hang agent exit."""
    import pytest

    from fivenines_agent.agent import Agent as _Agent

    agent = _Agent.__new__(_Agent)
    agent.queue = MagicMock()
    agent.synchronizer = None
    agent.log_uploader = MagicMock()
    agent.log_queue = MagicMock()

    with pytest.raises(SystemExit) as exc_info:
        agent._cleanup()

    assert exc_info.value.code == 0
    agent.log_uploader.stop.assert_called_once()
    agent.log_queue.put.assert_called_once_with(None)
    agent.log_uploader.join.assert_called_once()
