"""Tests for synchronizer _post() and send_packages() methods."""

import json
from threading import Event
from unittest.mock import MagicMock, patch

from fivenines_agent.synchronizer import Synchronizer


def make_synchronizer():
    """Create a Synchronizer with a mock queue, without starting the thread."""
    queue = MagicMock()
    sync = Synchronizer.__new__(Synchronizer)
    sync._stop_event = Event()
    sync.config_lock = __import__("threading").Lock()
    sync.token = "test-token"
    sync.config = {
        "enabled": True,
        "request_options": {"timeout": 5, "retry": 3, "retry_interval": 0},
    }
    sync.queue = queue
    return sync


# --- _post ---


@patch.object(Synchronizer, "get_conn")
def test_post_success(mock_get_conn):
    sync = make_synchronizer()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = json.dumps({"ok": True}).encode("utf-8")
    mock_conn.getresponse.return_value = mock_response
    mock_get_conn.return_value = mock_conn

    result = sync._post("/test", {"data": 1})
    assert result == {"ok": True}
    mock_conn.request.assert_called_once()
    args = mock_conn.request.call_args[0]
    assert args[0] == "POST"
    assert args[1] == "/test"


@patch.object(Synchronizer, "get_conn")
def test_post_http_error_retries(mock_get_conn):
    sync = make_synchronizer()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 500
    mock_response.read.return_value = b"Internal Server Error"
    mock_conn.getresponse.return_value = mock_response
    mock_get_conn.return_value = mock_conn

    result = sync._post("/test", {"data": 1})
    assert result is None
    assert mock_get_conn.call_count == 3  # retried 3 times


@patch.object(Synchronizer, "get_conn", return_value=None)
def test_post_connection_failure(mock_get_conn):
    sync = make_synchronizer()
    result = sync._post("/test", {"data": 1})
    assert result is None


@patch.object(Synchronizer, "get_conn")
def test_post_stops_on_stop_event(mock_get_conn):
    sync = make_synchronizer()
    sync._stop_event.set()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 500
    mock_response.read.return_value = b"error"
    mock_conn.getresponse.return_value = mock_response
    mock_get_conn.return_value = mock_conn

    result = sync._post("/test", {"data": 1})
    assert result is None
    # Should break after first retry since stop_event is set
    assert mock_get_conn.call_count == 1


# --- send_metrics ---


@patch.object(Synchronizer, "_post")
def test_send_metrics_updates_config(mock_post):
    sync = make_synchronizer()
    mock_post.return_value = {"config": {"enabled": True, "interval": 30}}

    sync.send_metrics({"test": True})
    assert sync.config == {"enabled": True, "interval": 30}


@patch.object(Synchronizer, "_post")
def test_send_metrics_no_update_on_none(mock_post):
    sync = make_synchronizer()
    original_config = sync.config.copy()
    mock_post.return_value = None

    sync.send_metrics({"test": True})
    assert sync.config == original_config


# --- send_packages ---


@patch.object(Synchronizer, "_post")
def test_send_packages_success(mock_post):
    sync = make_synchronizer()
    mock_post.return_value = {"status": "queued"}

    scan_data = {
        "distro": "debian",
        "packages_hash": "abc123",
        "packages": [{"name": "openssl", "version": "3.0"}],
    }
    result = sync.send_packages(scan_data)
    assert result == {"status": "queued"}
    mock_post.assert_called_once_with("/packages", scan_data)


@patch.object(Synchronizer, "_post")
def test_send_packages_failure(mock_post):
    sync = make_synchronizer()
    mock_post.return_value = None

    result = sync.send_packages({"distro": "debian", "packages": []})
    assert result is None
