"""Tests for the Synchronizer's queue drain, token swap on /collect, the
pre-compressed debug line and get_conn's api_url handling (custom port,
plain-HTTP localhost)."""

import http.client
import json
import threading
from threading import Event, Lock
from unittest.mock import MagicMock, call, patch

from fivenines_agent.synchronizer import Synchronizer, serialize_payload


def make_synchronizer():
    """Create a Synchronizer with a mock queue, without starting the thread."""
    sync = Synchronizer.__new__(Synchronizer)
    sync._stop_event = Event()
    sync.config_lock = Lock()
    sync._config_fetch_lock = Lock()
    sync.token = "enroll"
    sync.config = {
        "enabled": True,
        "request_options": {"timeout": 5, "retry": 3, "retry_interval": 0},
    }
    sync.queue = MagicMock()
    sync.static_data = {}
    sync._conn_local = threading.local()
    return sync


def _conn_answering(*bodies):
    """A connection whose successive responses are 200s with these bodies."""
    conn = MagicMock()
    responses = []
    for body in bodies:
        response = MagicMock()
        response.status = 200
        response.read.return_value = json.dumps(body).encode("utf-8")
        responses.append(response)
    conn.getresponse.side_effect = responses
    return conn


# --- run(): the queue drain ---


@patch.object(Synchronizer, "_fetch_config_once")
@patch.object(Synchronizer, "send_metrics")
def test_run_sends_each_payload_and_skips_the_wakeup_sentinel(mock_send, mock_fetch):
    """run() fetches the config, then sends every queued payload in order and
    marks it done. None (what _cleanup puts to wake a blocked get()) is not a
    payload: it is neither sent nor marked done. stop() ends the loop at the
    next check."""
    sync = make_synchronizer()
    first, second = serialize_payload({"tick": 1}), serialize_payload({"tick": 2})
    # A list side effect: one get() too many raises StopIteration instead of
    # blocking the test forever.
    sync.queue.get.side_effect = [first, None, second]

    def send(data):
        if data == second:
            sync.stop()

    mock_send.side_effect = send

    sync.run()

    mock_fetch.assert_called_once_with()
    assert mock_send.call_args_list == [call(first), call(second)]
    assert sync.queue.get.call_count == 3
    assert sync.queue.task_done.call_count == 2
    assert sync._stop_event.is_set()


# --- send_metrics(): per-host token handed back by /collect ---


@patch("fivenines_agent.synchronizer.config_dir")
@patch.object(Synchronizer, "get_conn")
def test_collect_response_token_is_persisted_and_used_next(
    mock_get_conn, mock_config_dir, tmp_path
):
    """The enrollment answer carries the per-host token: it is written to
    TOKEN, the new config is applied, and the NEXT request authenticates with
    the new token."""
    mock_config_dir.return_value = str(tmp_path)
    new_config = {
        "enabled": True,
        "interval": 30,
        "request_options": {"timeout": 5, "retry": 3, "retry_interval": 0},
    }
    conn = _conn_answering(
        {"token": "per-host-token", "config": new_config},
        {"config": new_config},
    )
    mock_get_conn.return_value = conn
    sync = make_synchronizer()

    sync.send_metrics({"get_config": True})

    assert sync.token == "per-host-token"
    assert (tmp_path / "TOKEN").read_text() == "per-host-token"
    assert sync.config == new_config
    first_headers = conn.request.call_args_list[0].args[3]
    assert first_headers["Authorization"] == "Bearer enroll"

    sync.send_metrics(serialize_payload({"tick": 1}))

    second_headers = conn.request.call_args_list[1].args[3]
    assert second_headers["Authorization"] == "Bearer per-host-token"


@patch.object(Synchronizer, "_swap_token")
@patch.object(Synchronizer, "_post")
def test_collect_response_without_token_keeps_the_token(mock_post, mock_swap):
    mock_post.return_value = {"config": {"enabled": False}}
    sync = make_synchronizer()
    sync.send_metrics({"x": 1})
    mock_swap.assert_not_called()
    assert sync.token == "enroll"
    assert sync.config == {"enabled": False}


# --- _post(): the pre-compressed debug line ---


@patch.object(Synchronizer, "get_conn")
def test_precompressed_post_logs_its_size_only_at_debug_level(mock_get_conn, capsys):
    """A pre-compressed /collect body is announced by its size at debug level
    (it is never decompressed to be printed), and not at all otherwise."""
    blob = serialize_payload({"marker": "xyz123"})

    mock_get_conn.return_value = _conn_answering({"ok": True})
    sync = make_synchronizer()
    with patch("fivenines_agent.debug.log_level", return_value="info"):
        assert sync._post("/collect", blob) == {"ok": True}
    assert "Sending request" not in capsys.readouterr().out

    mock_get_conn.return_value = _conn_answering({"ok": True})
    sync = make_synchronizer()
    with patch("fivenines_agent.debug.log_level", return_value="debug"):
        assert sync._post("/collect", blob) == {"ok": True}
    out = capsys.readouterr().out
    assert f"Sending request to /collect: <precompressed {len(blob)} bytes>" in out
    assert "xyz123" not in out


# --- get_conn(): api_url forms ---


@patch("fivenines_agent.synchronizer.api_url", return_value="api.example.test:8443")
@patch("fivenines_agent.synchronizer.socket.socket")
@patch("fivenines_agent.synchronizer.DNSResolver")
def test_get_conn_dials_the_port_named_in_api_url(
    mock_resolver, mock_socket, mock_api_url
):
    """host:port in API_URL resolves the HOST alone and dials the given port
    (the default is 443), with the host name kept for SNI."""
    answer = MagicMock()
    answer.address = "192.0.2.1"
    mock_resolver.return_value.resolve.return_value = [answer]
    sock = MagicMock()
    mock_socket.return_value = sock
    sync = make_synchronizer()

    with patch("fivenines_agent.synchronizer._get_ssl_context") as ctx:
        ctx.return_value.wrap_socket.return_value = sock
        conn = sync.get_conn()

    mock_resolver.assert_called_once_with("api.example.test")
    sock.connect.assert_called_once_with(("192.0.2.1", 8443))
    ctx.return_value.wrap_socket.assert_called_once_with(
        sock, server_hostname="api.example.test"
    )
    assert isinstance(conn, http.client.HTTPSConnection)
    assert conn.sock is sock


@patch("fivenines_agent.synchronizer.api_url", return_value="localhost:3000")
@patch("fivenines_agent.synchronizer.socket.socket")
@patch("fivenines_agent.synchronizer.DNSResolver")
def test_get_conn_localhost_is_plain_http(mock_resolver, mock_socket, mock_api_url):
    """A localhost API_URL (development) gets a plain HTTP connection with the
    configured timeout: no DNS resolver, no hand-built socket, no TLS. The
    connection is created unconnected (nothing is dialed here)."""
    sync = make_synchronizer()
    sync.config["request_options"]["timeout"] = 7

    conn = sync.get_conn()

    assert type(conn) is http.client.HTTPConnection
    assert (conn.host, conn.port, conn.timeout) == ("localhost", 3000, 7)
    assert conn.sock is None
    mock_resolver.assert_not_called()
    mock_socket.assert_not_called()
