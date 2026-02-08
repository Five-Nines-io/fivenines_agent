"""Tests for tcp_ping utility."""

from unittest.mock import MagicMock, patch

from fivenines_agent.ping import tcp_ping


@patch("fivenines_agent.ping.socket.create_connection")
def test_tcp_ping_success(mock_conn):
    mock_conn.return_value.__enter__ = MagicMock()
    mock_conn.return_value.__exit__ = MagicMock(return_value=False)

    result = tcp_ping("example.com", port=80, timeout=5)
    assert result is not None
    assert isinstance(result, float)
    assert result >= 0


@patch("fivenines_agent.ping.socket.create_connection")
def test_tcp_ping_failure(mock_conn):
    mock_conn.side_effect = OSError("Connection refused")

    result = tcp_ping("example.com", port=80, timeout=5)
    assert result is None


@patch("fivenines_agent.ping.socket.create_connection")
def test_tcp_ping_timeout(mock_conn):
    mock_conn.side_effect = TimeoutError("timed out")

    result = tcp_ping("example.com", port=80, timeout=1)
    assert result is None
