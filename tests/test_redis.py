"""Tests for redis_metrics collector and RESP protocol encoding."""

from unittest.mock import MagicMock, patch

from fivenines_agent.redis import _resp_command, redis_metrics


# Minimal INFO response: +OK for AUTH, bulk INFO data, +OK for QUIT
SAMPLE_INFO = (
    "+OK\r\n"
    "$600\r\n"
    "# Server\r\n"
    "redis_version:7.0.12\r\n"
    "uptime_in_seconds:12345\r\n"
    "# Clients\r\n"
    "connected_clients:3\r\n"
    "blocked_clients:0\r\n"
    "evicted_clients:0\r\n"
    "maxclients:10000\r\n"
    "total_connections_received:100\r\n"
    "total_commands_processed:500\r\n"
    "# Stats\r\n"
    "evicted_keys:0\r\n"
    "expired_keys:10\r\n"
    "# Keyspace\r\n"
    "db0:keys=42,expires=5,avg_ttl=1000\r\n"
    "\r\n"
    "+OK\r\n"
)


# --- _resp_command ---


def test_resp_command_single_arg():
    assert _resp_command("INFO") == "*1\r\n$4\r\nINFO\r\n"


def test_resp_command_multiple_args():
    assert _resp_command("AUTH", "secret") == "*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n"


def test_resp_command_crlf_in_arg_is_length_prefixed():
    """CRLF inside an argument is embedded in a bulk string, not a new command."""
    result = _resp_command("AUTH", "x\r\nFLUSHALL")
    # The $11 length prefix tells Redis to read exactly 11 bytes as one argument
    assert "*2\r\n$4\r\nAUTH\r\n$11\r\nx\r\nFLUSHALL\r\n" == result
    # FLUSHALL must not appear as a standalone RESP command
    assert "*1\r\n$8\r\nFLUSHALL\r\n" not in result


# --- redis_metrics ---


@patch("fivenines_agent.redis.socket.create_connection")
def test_redis_metrics_no_password(mock_conn):
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.side_effect = [SAMPLE_INFO.encode(), b""]

    result = redis_metrics()

    assert result["redis_version"] == "7.0.12"
    assert result["uptime_in_seconds"] == 12345.0
    assert result["connected_clients"] == 3.0
    assert result["db0"] == {"keys": 42.0, "expires": 5.0, "avg_ttl": 1000.0}

    sent = mock_sock.sendall.call_args[0][0].decode("utf-8")
    assert "AUTH" not in sent
    assert "*1\r\n$4\r\nINFO\r\n" in sent
    assert "*1\r\n$4\r\nQUIT\r\n" in sent


@patch("fivenines_agent.redis.socket.create_connection")
def test_redis_metrics_with_password(mock_conn):
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.side_effect = [SAMPLE_INFO.encode(), b""]

    result = redis_metrics(password="secretpass")

    assert result["redis_version"] == "7.0.12"

    sent = mock_sock.sendall.call_args[0][0].decode("utf-8")
    assert "*2\r\n$4\r\nAUTH\r\n$10\r\nsecretpass\r\n" in sent


@patch("fivenines_agent.redis.socket.create_connection")
def test_redis_metrics_crlf_password_no_injection(mock_conn):
    """CRLF in password must not become a separate command on the wire."""
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.side_effect = [SAMPLE_INFO.encode(), b""]

    redis_metrics(password="x\r\nFLUSHALL")

    sent = mock_sock.sendall.call_args[0][0].decode("latin-1")
    assert "*1\r\n$8\r\nFLUSHALL\r\n" not in sent
    assert "$11\r\nx\r\nFLUSHALL\r\n" in sent


@patch("fivenines_agent.redis.socket.create_connection")
def test_redis_metrics_custom_port(mock_conn):
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.side_effect = [SAMPLE_INFO.encode(), b""]

    redis_metrics(port=6380)

    mock_conn.assert_called_once_with(("localhost", 6380), timeout=5)


@patch("fivenines_agent.redis.socket.create_connection")
def test_redis_metrics_empty_response_returns_empty_dict(mock_conn):
    """No matching lines in response returns an empty metrics dict."""
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.side_effect = [b""]

    result = redis_metrics()

    assert result == {}


@patch("fivenines_agent.redis.socket.create_connection")
def test_redis_metrics_connection_error_returns_none(mock_conn):
    """Connection failure is caught and returns None."""
    mock_conn.side_effect = OSError("Connection refused")

    result = redis_metrics()

    assert result is None
