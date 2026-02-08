"""Tests for IP detection and caching."""

import time
from unittest.mock import MagicMock, patch

import fivenines_agent.ip as ip_module
from fivenines_agent.ip import get_ip


def _reset_caches():
    """Reset module-level caches between tests."""
    ip_module._ip_v4_cache["timestamp"] = 0
    ip_module._ip_v4_cache["ip"] = None
    ip_module._ip_v6_cache["timestamp"] = 0
    ip_module._ip_v6_cache["ip"] = None


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_v4_success(mock_conn_cls):
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"1.2.3.4\n"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    result = get_ip(ipv6=False)
    assert result == "1.2.3.4"


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_v6_success(mock_conn_cls):
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"::1\n"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    result = get_ip(ipv6=True)
    assert result == "::1"


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_caches_result(mock_conn_cls):
    """Second call within TTL should return cached value without HTTP request."""
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"1.2.3.4\n"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    result1 = get_ip(ipv6=False)
    result2 = get_ip(ipv6=False)

    assert result1 == "1.2.3.4"
    assert result2 == "1.2.3.4"
    # Only one HTTP connection should have been made
    assert mock_conn_cls.call_count == 1


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_v6_caches_result(mock_conn_cls):
    """IPv6 cache works independently from IPv4."""
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"::1\n"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    result1 = get_ip(ipv6=True)
    result2 = get_ip(ipv6=True)

    assert result1 == "::1"
    assert result2 == "::1"
    assert mock_conn_cls.call_count == 1


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_cache_expired(mock_conn_cls):
    """After TTL expires, a new HTTP request should be made."""
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"1.2.3.4\n"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    # First call populates the cache
    get_ip(ipv6=False)
    # Expire the cache
    ip_module._ip_v4_cache["timestamp"] = time.time() - 120

    get_ip(ipv6=False)
    assert mock_conn_cls.call_count == 2


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_http_error(mock_conn_cls):
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 500
    mock_response.read.return_value = b"error"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    result = get_ip(ipv6=False)
    assert result is None


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_connection_error(mock_conn_cls):
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("refused")

    result = get_ip(ipv6=False)
    assert result is None


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_generic_exception(mock_conn_cls):
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = Exception("something broke")

    result = get_ip(ipv6=False)
    assert result is None
