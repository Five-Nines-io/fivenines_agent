"""Tests for synchronizer _post() and send_packages() methods."""

import gzip
import json
from threading import Event
from unittest.mock import MagicMock, patch

import fivenines_agent.synchronizer as synchronizer_module
from fivenines_agent.synchronizer import Synchronizer, serialize_payload


def make_synchronizer():
    """Create a Synchronizer with a mock queue, without starting the thread."""
    queue = MagicMock()
    sync = Synchronizer.__new__(Synchronizer)
    sync._stop_event = Event()
    sync.config_lock = __import__("threading").Lock()
    sync._config_fetch_lock = __import__("threading").Lock()
    sync.token = "test-token"
    sync.config = {
        "enabled": True,
        "request_options": {"timeout": 5, "retry": 3, "retry_interval": 0},
    }
    sync.queue = queue
    sync.static_data = {}
    sync._conn_local = __import__("threading").local()
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


# --- send_image_packages ---


@patch.object(Synchronizer, "_post")
def test_send_image_packages_success(mock_post):
    sync = make_synchronizer()
    mock_post.return_value = {"status": "ok", "accepted": True}

    image_data = {
        "image_id": "sha256:abc",
        "distro": "debian:12",
        "packages_hash": "deadbeef",
        "packages": [{"name": "openssl", "version": "3.0", "ecosystem": None}],
        "errors": [],
    }
    result = sync.send_image_packages(image_data)
    assert result == {"status": "ok", "accepted": True}
    mock_post.assert_called_once_with("/image_packages", image_data)


@patch.object(Synchronizer, "_post")
def test_send_image_packages_failure(mock_post):
    sync = make_synchronizer()
    mock_post.return_value = None

    result = sync.send_image_packages({"image_id": "sha256:x", "packages": []})
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
    synchronizer_module._ssl_context = None  # reset the process-wide cache
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
    synchronizer_module._ssl_context = None  # reset the process-wide cache
    sync = make_synchronizer()
    mock_certifi.where.return_value = "/path/to/cacert.pem"
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = []
    mock_resolver.return_value = mock_resolver_instance

    sync.get_conn()

    # ssl.create_default_context should be called with cafile
    mock_ssl.assert_called_once_with(cafile="/path/to/cacert.pem")


# --- connection reuse / pre-compressed payloads ---


def _ok_conn(body=None):
    conn = MagicMock()
    response = MagicMock()
    response.status = 200
    response.read.return_value = json.dumps(body or {"ok": True}).encode("utf-8")
    conn.getresponse.return_value = response
    return conn


@patch.object(Synchronizer, "get_conn")
def test_post_reuses_connection_across_requests(mock_get_conn):
    """A successful request leaves the connection cached; the next _post on the
    same thread must NOT redial (no second get_conn call)."""
    sync = make_synchronizer()
    mock_get_conn.return_value = _ok_conn()

    assert sync._post("/a", {"x": 1}) == {"ok": True}
    assert sync._post("/b", {"x": 2}) == {"ok": True}
    assert mock_get_conn.call_count == 1


@patch.object(Synchronizer, "get_conn")
def test_post_stale_reused_connection_rebuilds_for_free(mock_get_conn):
    """A transport error on a REUSED connection (server closed the kept-alive
    socket) rebuilds once without consuming a retry: the request still succeeds
    with retry=1 configured."""
    sync = make_synchronizer()
    sync.config["request_options"]["retry"] = 1
    stale = MagicMock()
    stale.request.side_effect = BrokenPipeError("stale socket")
    sync._conn_local.conn = stale  # simulate a kept-alive conn from a past POST
    mock_get_conn.return_value = _ok_conn()

    assert sync._post("/test", {"x": 1}) == {"ok": True}
    stale.close.assert_called_once()
    assert mock_get_conn.call_count == 1


@patch.object(Synchronizer, "get_conn")
def test_post_http_error_on_reused_connection_counts_as_retry(mock_get_conn):
    """A non-200 on a reused connection is a REAL server-side error: it must
    consume a retry (no free rebuild), or an erroring API would see every
    request doubled."""
    sync = make_synchronizer()
    sync.config["request_options"]["retry"] = 1
    reused = MagicMock()
    response = MagicMock()
    response.status = 500
    response.read.return_value = b"boom"
    reused.getresponse.return_value = response
    sync._conn_local.conn = reused

    assert sync._post("/test", {"x": 1}) is None
    mock_get_conn.assert_not_called()  # retry=1: the reused attempt was the only one


@patch.object(Synchronizer, "get_conn")
def test_post_sends_precompressed_bytes_verbatim(mock_get_conn):
    """bytes input (serialize_payload output) is sent as-is: no re-serialization,
    and the body decompresses back to the original payload."""
    sync = make_synchronizer()
    conn = _ok_conn()
    mock_get_conn.return_value = conn

    payload = {"ts": 123, "cpu": [1, 2, 3]}
    blob = serialize_payload(payload)
    assert sync._post("/collect", blob) == {"ok": True}

    body = conn.request.call_args[0][2]
    assert body == blob
    assert json.loads(gzip.decompress(body).decode("utf-8")) == payload
    headers = conn.request.call_args[0][3]
    assert headers["Content-Length"] == str(len(blob))


def test_discard_conn_swallows_close_errors():
    sync = make_synchronizer()
    conn = MagicMock()
    conn.close.side_effect = OSError("already closed")
    sync._conn_local.conn = conn
    sync._discard_conn()  # must not raise
    assert sync._has_cached_conn() is False


@patch("fivenines_agent.synchronizer.api_url", return_value="api.fivenines.io")
@patch("fivenines_agent.synchronizer.socket.socket")
@patch("fivenines_agent.synchronizer.DNSResolver")
def test_get_conn_closes_socket_on_failed_connect(mock_resolver, mock_socket, mock_api_url):
    """A socket whose connect fails is closed instead of leaked to the GC."""
    synchronizer_module._ssl_context = None
    sync = make_synchronizer()
    answer = MagicMock()
    answer.address = "192.0.2.1"
    resolver_instance = MagicMock()
    resolver_instance.resolve.return_value = [answer]
    mock_resolver.return_value = resolver_instance
    sock = MagicMock()
    sock.connect.side_effect = OSError("unreachable")
    mock_socket.return_value = sock

    with patch("fivenines_agent.synchronizer._get_ssl_context"):
        assert sync.get_conn() is None
    assert sock.close.call_count == 2  # once per address family attempt
