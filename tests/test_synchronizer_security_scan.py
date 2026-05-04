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
    sync.static_data = {}
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


# --- _swap_token ---


@patch("fivenines_agent.synchronizer.config_dir", return_value="/tmp/test-config")
def test_swap_token_success(mock_config_dir, tmp_path):
    sync = make_synchronizer()
    token_file = tmp_path / "TOKEN"
    mock_config_dir.return_value = str(tmp_path)

    sync._swap_token("new-token-123")
    assert sync.token == "new-token-123"
    assert token_file.read_text() == "new-token-123"


@patch("fivenines_agent.synchronizer.config_dir", return_value="/nonexistent/path")
def test_swap_token_permission_error(mock_config_dir):
    sync = make_synchronizer()
    with patch("builtins.open", side_effect=PermissionError("denied")):
        sync._swap_token("new-token-456")
    # Token should still be updated in memory
    assert sync.token == "new-token-456"


@patch("fivenines_agent.synchronizer.config_dir", return_value="/tmp/test-config")
def test_swap_token_generic_error(mock_config_dir):
    sync = make_synchronizer()
    with patch("builtins.open", side_effect=OSError("disk full")):
        sync._swap_token("new-token-789")
    # Token should still be updated in memory
    assert sync.token == "new-token-789"


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


# --- send_systemd_inventory ---


@patch.object(Synchronizer, "_post")
def test_send_systemd_inventory_success(mock_post):
    sync = make_synchronizer()
    mock_post.return_value = {"status": "queued"}

    inventory = {
        "inventory_hash": "deadbeef",
        "units": {"nginx.service": {"FragmentPath": "/etc/foo"}},
        "version": 252,
        "cgroup": "v2",
    }
    result = sync.send_systemd_inventory(inventory)
    assert result == {"status": "queued"}
    mock_post.assert_called_once_with("/systemd_inventory", inventory)


@patch.object(Synchronizer, "_post")
def test_send_systemd_inventory_failure(mock_post):
    sync = make_synchronizer()
    mock_post.return_value = None

    result = sync.send_systemd_inventory({"inventory_hash": "x", "units": {}})
    assert result is None


# --- get_config ---


def test_get_config_returns_config_when_enabled():
    sync = make_synchronizer()
    sync.config = {"enabled": True, "interval": 60}
    result = sync.get_config()
    assert result == {"enabled": True, "interval": 60}


@patch.object(Synchronizer, "send_metrics")
def test_get_config_fetches_when_enabled_is_none(mock_send):
    sync = make_synchronizer()
    sync.config = {
        "enabled": None,
        "request_options": {"timeout": 5, "retry": 3, "retry_interval": 0},
    }

    def update_config(data):
        with sync.config_lock:
            sync.config = {"enabled": True, "interval": 30}

    mock_send.side_effect = update_config

    result = sync.get_config()
    mock_send.assert_called_once_with({"get_config": True})
    assert result == {"enabled": True, "interval": 30}


@patch.object(Synchronizer, "send_metrics")
def test_get_config_reads_under_lock(mock_send):
    """get_config always reads config under the lock, not outside it."""
    sync = make_synchronizer()
    sync.config = {"enabled": False, "interval": 60}

    # Acquire the lock to prove get_config waits for it
    sync.config_lock.acquire()
    import threading

    results = []

    def call_get_config():
        results.append(sync.get_config())

    t = threading.Thread(target=call_get_config)
    t.start()
    # Give the thread a moment to block
    t.join(timeout=0.1)
    assert t.is_alive()  # Thread should be blocked on the lock

    sync.config_lock.release()
    t.join(timeout=1)
    assert not t.is_alive()
    assert results[0] == {"enabled": False, "interval": 60}


# --- get_conn certifi fallback ---


@patch("fivenines_agent.synchronizer.api_url", return_value="api.fivenines.io")
@patch("fivenines_agent.synchronizer.certifi")
@patch("fivenines_agent.synchronizer.os.path.exists", return_value=False)
@patch("fivenines_agent.synchronizer.ssl.create_default_context")
@patch("fivenines_agent.synchronizer.DNSResolver")
def test_get_conn_certifi_fallback(mock_resolver, mock_ssl, mock_exists, mock_certifi, mock_api_url):
    """When certifi bundle file doesn't exist, fall back to system CAs."""
    sync = make_synchronizer()
    mock_certifi.where.return_value = "/nonexistent/cacert.pem"
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = []
    mock_resolver.return_value = mock_resolver_instance

    sync.get_conn()

    # ssl.create_default_context should be called without cafile
    mock_ssl.assert_called_once_with()


@patch("fivenines_agent.synchronizer.api_url", return_value="api.fivenines.io")
@patch("fivenines_agent.synchronizer.certifi")
@patch("fivenines_agent.synchronizer.os.path.exists", return_value=True)
@patch("fivenines_agent.synchronizer.ssl.create_default_context")
@patch("fivenines_agent.synchronizer.DNSResolver")
def test_get_conn_certifi_exists(mock_resolver, mock_ssl, mock_exists, mock_certifi, mock_api_url):
    """When certifi bundle exists, use it as cafile."""
    sync = make_synchronizer()
    mock_certifi.where.return_value = "/path/to/cacert.pem"
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = []
    mock_resolver.return_value = mock_resolver_instance

    sync.get_conn()

    # ssl.create_default_context should be called with cafile
    mock_ssl.assert_called_once_with(cafile="/path/to/cacert.pem")
