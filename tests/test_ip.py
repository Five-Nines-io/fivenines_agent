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


# --- Negative cache (issue #42) ---


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_negative_cache_suppresses_retry_after_connection_error(mock_conn_cls):
    """First failure attempts and logs; subsequent calls within TTL return None silently."""
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError(
        "Network is unreachable"
    )

    with patch("fivenines_agent.ip.log") as mock_log:
        first = get_ip(ipv6=True)
        second = get_ip(ipv6=True)
        third = get_ip(ipv6=True)

    assert first is None
    assert second is None
    assert third is None
    # Only one HTTP attempt; the cache absorbs the others.
    assert mock_conn_cls.call_count == 1
    # And only one error log line, not three.
    error_logs = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert len(error_logs) == 1


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_negative_cache_suppresses_retry_after_generic_exception(mock_conn_cls):
    """Generic exceptions also populate the negative cache."""
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = Exception("something broke")

    get_ip(ipv6=False)
    get_ip(ipv6=False)

    assert mock_conn_cls.call_count == 1


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_negative_cache_suppresses_retry_after_http_non_200(mock_conn_cls):
    """HTTP non-200 responses populate the negative cache."""
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 503
    mock_response.read.return_value = b"unavailable"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    get_ip(ipv6=False)
    get_ip(ipv6=False)

    assert mock_conn_cls.call_count == 1


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_negative_cache_expires(mock_conn_cls):
    """After NEGATIVE_CACHE_TTL elapses, a new attempt is made."""
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")

    get_ip(ipv6=True)
    # Force the negative cache to expire (TTL is 300s; jump back 400s).
    ip_module._ip_v6_cache["timestamp"] = time.time() - 400

    get_ip(ipv6=True)
    assert mock_conn_cls.call_count == 2


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_negative_cache_per_family(mock_conn_cls):
    """An IPv6 failure does not poison the IPv4 cache."""
    _reset_caches()

    # IPv6 fails, populates negative cache.
    mock_conn_cls.return_value.request.side_effect = ConnectionError("v6 unreachable")
    assert get_ip(ipv6=True) is None

    # IPv4 path is independent and should still be attempted.
    mock_conn_cls.reset_mock()
    mock_conn_cls.return_value.request.side_effect = None
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"1.2.3.4\n"
    mock_conn_cls.return_value.getresponse.return_value = mock_response

    assert get_ip(ipv6=False) == "1.2.3.4"


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_negative_cache_clears_on_recovery(mock_conn_cls):
    """When connectivity recovers after the TTL, the new IP is cached."""
    _reset_caches()
    # First call: fails.
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")
    assert get_ip(ipv6=True) is None
    assert ip_module._ip_v6_cache["ip"] is None

    # Force the negative cache to expire.
    ip_module._ip_v6_cache["timestamp"] = time.time() - 400

    # Second call: succeeds.
    mock_conn_cls.return_value.request.side_effect = None
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"::1\n"
    mock_conn_cls.return_value.getresponse.return_value = mock_response

    assert get_ip(ipv6=True) == "::1"
    assert ip_module._ip_v6_cache["ip"] == "::1"


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_negative_cache_does_not_log_on_cache_hit(mock_conn_cls):
    """A cache hit should produce zero error logs (the noise fix)."""
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")

    # Prime the negative cache (one attempt, one error log).
    get_ip(ipv6=True)

    # Subsequent calls hit the cache and must be completely silent.
    with patch("fivenines_agent.ip.log") as mock_log:
        for _ in range(60):  # simulate one hour of ticks
            get_ip(ipv6=True)

    error_logs = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert error_logs == []
    # No additional HTTP attempts.
    assert mock_conn_cls.call_count == 1
