"""Tests for IP detection and caching."""

import time
from unittest.mock import MagicMock, patch

import fivenines_agent.ip as ip_module
from fivenines_agent.ip import get_ip


def _reset_caches():
    """Reset module-level caches between tests."""
    for cache in (ip_module._ip_v4_cache, ip_module._ip_v6_cache):
        cache["timestamp"] = 0
        cache["ip"] = None
        cache["failures"] = 0


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
    ip_module._ip_v4_cache["timestamp"] = time.monotonic() - 120

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


# --- Negative-cache backoff (issue #42) ---


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_first_failure_does_not_cache(mock_conn_cls):
    """A single transient failure must NOT engage the negative cache.

    On main, transients self-heal next tick; the negative cache must not
    regress that. So failure #1 is logged and re-attempted on the next call.
    """
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")

    assert get_ip(ipv6=True) is None
    assert get_ip(ipv6=True) is None
    # Both calls attempted the network (no cache yet).
    assert mock_conn_cls.call_count == 2


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_second_consecutive_failure_caches_for_60s(mock_conn_cls):
    """After 2 consecutive failures, a third call within 60s hits the cache."""
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")

    get_ip(ipv6=True)  # failures=1, no cache
    get_ip(ipv6=True)  # failures=2, caches for 60s
    assert mock_conn_cls.call_count == 2

    with patch("fivenines_agent.ip.log") as mock_log:
        assert get_ip(ipv6=True) is None  # cache hit, silent

    assert mock_conn_cls.call_count == 2  # no new HTTP call
    assert [c for c in mock_log.call_args_list if c.args[1] == "error"] == []


def test_negative_backoff_schedule():
    """The backoff schedule starts at 0, then 60, 120, 240, 300, capped."""
    assert ip_module._negative_backoff(0) == 0
    assert ip_module._negative_backoff(1) == 0
    assert ip_module._negative_backoff(2) == 60
    assert ip_module._negative_backoff(3) == 120
    assert ip_module._negative_backoff(4) == 240
    assert ip_module._negative_backoff(5) == 300
    assert ip_module._negative_backoff(50) == 300  # cap


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_backoff_grows_with_consecutive_failures(mock_conn_cls):
    """Each retry after the cached window starts a longer suppression."""
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")

    # 1st: no cache
    get_ip(ipv6=True)
    # 2nd: caches for 60s
    get_ip(ipv6=True)
    assert ip_module._ip_v6_cache["failures"] == 2

    # Skip past the 60s window and retry: 3rd failure caches for 120s.
    ip_module._ip_v6_cache["timestamp"] = time.monotonic() - 70
    get_ip(ipv6=True)
    assert ip_module._ip_v6_cache["failures"] == 3
    assert ip_module._negative_backoff(3) == 120

    # Skip past the 120s window: 4th caches for 240s.
    ip_module._ip_v6_cache["timestamp"] = time.monotonic() - 130
    get_ip(ipv6=True)
    assert ip_module._ip_v6_cache["failures"] == 4
    assert ip_module._negative_backoff(4) == 240


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_success_resets_failure_counter(mock_conn_cls):
    """A successful fetch must reset the failure counter to 0."""
    _reset_caches()

    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")
    get_ip(ipv6=False)
    get_ip(ipv6=False)
    assert ip_module._ip_v4_cache["failures"] == 2

    # Skip past the cache window and switch the mock to success.
    ip_module._ip_v4_cache["timestamp"] = time.monotonic() - 70
    mock_conn_cls.return_value.request.side_effect = None
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"1.2.3.4\n"
    mock_conn_cls.return_value.getresponse.return_value = mock_response

    assert get_ip(ipv6=False) == "1.2.3.4"
    assert ip_module._ip_v4_cache["failures"] == 0
    assert ip_module._ip_v4_cache["ip"] == "1.2.3.4"


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_backoff_per_family(mock_conn_cls):
    """An IPv6 failure streak does not back off the IPv4 path."""
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("v6 unreachable")
    get_ip(ipv6=True)
    get_ip(ipv6=True)
    assert ip_module._ip_v6_cache["failures"] == 2

    # IPv4 should still attempt with no suppression.
    mock_conn_cls.reset_mock()
    mock_conn_cls.return_value.request.side_effect = None
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"1.2.3.4\n"
    mock_conn_cls.return_value.getresponse.return_value = mock_response

    assert get_ip(ipv6=False) == "1.2.3.4"
    assert ip_module._ip_v4_cache["failures"] == 0


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_persistent_failure_steady_state_quiet(mock_conn_cls):
    """A permanently broken host hits the 300s cap and stays mostly quiet.

    Simulates 60 minutes of ticks (3600s) for a host with no IPv6.
    Expectation: ~12 HTTP attempts (1 every 5 min once steady state), not 60.
    """
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")

    attempts = 0
    for _ in range(60):
        # Pretend the agent ticked once per minute.
        if ip_module._ip_v6_cache["timestamp"] != 0:
            ip_module._ip_v6_cache["timestamp"] -= 60
        before = mock_conn_cls.call_count
        get_ip(ipv6=True)
        if mock_conn_cls.call_count > before:
            attempts += 1

    # Backoff schedule for 60 ticks (1/min):
    # tick 1: attempt (failures=1, no cache)
    # tick 2: attempt (failures=2, cache 60s)
    # tick 3: attempt (failures=3, cache 120s)
    # tick 5: attempt (failures=4, cache 240s)
    # tick 9: attempt (failures=5, cache 300s)
    # ticks 14, 19, 24, ...: attempt every 5 min after that
    # Expected attempts in 60 ticks: ~14 (well under one-per-tick).
    assert attempts < 20, f"too many attempts: {attempts}"
    assert attempts > 5, f"backoff suppressed too aggressively: {attempts}"


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_recovery_after_long_failure_streak(mock_conn_cls):
    """When a permanently-broken host comes back online, the next probe succeeds."""
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")

    # Force a long streak.
    for _ in range(5):
        get_ip(ipv6=True)
        ip_module._ip_v6_cache["timestamp"] = time.monotonic() - 400

    assert ip_module._ip_v6_cache["failures"] >= 2

    # Network recovers.
    mock_conn_cls.return_value.request.side_effect = None
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"::1\n"
    mock_conn_cls.return_value.getresponse.return_value = mock_response
    ip_module._ip_v6_cache["timestamp"] = time.monotonic() - 400

    assert get_ip(ipv6=True) == "::1"
    assert ip_module._ip_v6_cache["failures"] == 0


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_failures_counted_for_http_non_200(mock_conn_cls):
    """HTTP non-200 responses count as failures for backoff purposes."""
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 503
    mock_response.read.return_value = b"unavailable"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    get_ip(ipv6=False)
    get_ip(ipv6=False)
    assert ip_module._ip_v4_cache["failures"] == 2


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_failures_counted_for_generic_exception(mock_conn_cls):
    """Generic exceptions count as failures for backoff purposes."""
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = Exception("something broke")

    get_ip(ipv6=False)
    get_ip(ipv6=False)
    assert ip_module._ip_v4_cache["failures"] == 2


# --- Response validation ---


def test_validate_ip_accepts_valid_ipv4():
    assert ip_module._validate_ip("1.2.3.4\n", ipv6=False) == "1.2.3.4"


def test_validate_ip_accepts_valid_ipv6():
    assert ip_module._validate_ip("2001:db8::1\n", ipv6=True) == "2001:db8::1"


def test_validate_ip_rejects_empty_body():
    assert ip_module._validate_ip("", ipv6=False) is None
    assert ip_module._validate_ip("   \n", ipv6=False) is None


def test_validate_ip_rejects_html_body():
    assert ip_module._validate_ip("<html>error</html>", ipv6=False) is None


def test_validate_ip_rejects_garbage():
    assert ip_module._validate_ip("not an ip", ipv6=False) is None


def test_validate_ip_rejects_wrong_family_v4_for_v6():
    """An IPv4 address returned for an IPv6 request is rejected."""
    assert ip_module._validate_ip("1.2.3.4", ipv6=True) is None


def test_validate_ip_rejects_wrong_family_v6_for_v4():
    """An IPv6 address returned for an IPv4 request is rejected."""
    assert ip_module._validate_ip("::1", ipv6=False) is None


def test_validate_ip_rejects_oversized_body():
    """A body larger than MAX_RESPONSE_BODY chars is rejected even if it starts with a valid IP."""
    body = "1.2.3.4" + "X" * 500
    assert ip_module._validate_ip(body, ipv6=False) is None


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_invalid_response_body_does_not_cache(mock_conn_cls):
    """A 200 response with garbage body counts as a failure, not a value to cache."""
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"<html>upstream error</html>"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    with patch("fivenines_agent.ip.log") as mock_log:
        result = get_ip(ipv6=False)

    assert result is None
    assert ip_module._ip_v4_cache["ip"] is None
    assert ip_module._ip_v4_cache["failures"] == 1
    error_logs = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert len(error_logs) == 1
    assert "non-IPv4 body" in error_logs[0].args[0]


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_get_ip_wrong_family_response_does_not_cache(mock_conn_cls):
    """If ip.fivenines.io returns an IPv6 for an IPv4 request, treat as failure."""
    _reset_caches()
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"::1\n"
    mock_conn.getresponse.return_value = mock_response
    mock_conn_cls.return_value = mock_conn

    assert get_ip(ipv6=False) is None
    assert ip_module._ip_v4_cache["ip"] is None
    assert ip_module._ip_v4_cache["failures"] == 1


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_invalid_response_does_not_reset_failure_counter(mock_conn_cls):
    """Garbage response must NOT clear an existing failure streak."""
    _reset_caches()

    # First fail with ConnectionError to get failures=1.
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")
    get_ip(ipv6=False)
    assert ip_module._ip_v4_cache["failures"] == 1

    # Then a 200 with garbage body. Must keep counter incrementing, not reset.
    mock_conn_cls.return_value.request.side_effect = None
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"<html>error</html>"
    mock_conn_cls.return_value.getresponse.return_value = mock_response

    get_ip(ipv6=False)
    assert ip_module._ip_v4_cache["failures"] == 2
    assert ip_module._ip_v4_cache["ip"] is None


# --- Monotonic clock ---


@patch("fivenines_agent.ip.CustomHTTPSConnection")
def test_clock_rollback_does_not_extend_suppression(mock_conn_cls):
    """A wall-clock backward jump (NTP, suspend, VM restore) cannot keep the cache suppressed past the cap.

    With monotonic timestamps the age math is rollback-immune by construction.
    A negative wall-clock skew would have made `age < backoff` true forever
    on the previous (time.time()-based) version. We simulate the rollback by
    forcing the cache timestamp into the future and verifying the next call
    still re-attempts after the backoff window.
    """
    _reset_caches()
    mock_conn_cls.return_value.request.side_effect = ConnectionError("unreachable")

    # Establish 2 consecutive failures (cache active for 60s).
    get_ip(ipv6=True)
    get_ip(ipv6=True)
    assert ip_module._ip_v6_cache["failures"] == 2
    attempts_so_far = mock_conn_cls.call_count

    # Force the timestamp >300s in the past on the monotonic clock. Any
    # cap-respecting implementation should attempt again.
    ip_module._ip_v6_cache["timestamp"] = time.monotonic() - 1000

    get_ip(ipv6=True)
    assert mock_conn_cls.call_count == attempts_so_far + 1
