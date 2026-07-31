"""Tests for the Memcached stats-snapshot collector (server issue #497).

Only socket.create_connection is mocked; each scenario feeds a canned ``stats``
reply back through the real read loop + parser, so the whole
config-in -> parse -> payload-out pipeline is exercised. Mirrors test_redis.py's
cross-repo fixture assertion.
"""

import json
import os
import socket
from unittest.mock import MagicMock, patch

from fivenines_agent import memcached


def _fake_socket(reply_bytes, chunks=None):
    """A socket whose recv() drains a reply then returns b'' to end the loop.

    Pass ``chunks`` (a list of byte chunks) to model a reply split across
    multiple recv() calls; otherwise the whole reply lands in one recv().
    """
    sock = MagicMock()
    sock.recv.side_effect = (chunks if chunks is not None else [reply_bytes]) + [b""]
    return sock


_HEALTHY_REPLY = (
    b"STAT pid 2080\r\n"
    b"STAT uptime 86400\r\n"
    b"STAT time 1699564800\r\n"
    b"STAT version 1.6.29\r\n"
    b"STAT curr_connections 12\r\n"
    b"STAT total_connections 1450\r\n"
    b"STAT cmd_get 993566\r\n"
    b"STAT cmd_set 44210\r\n"
    b"STAT get_hits 981221\r\n"
    b"STAT get_misses 12345\r\n"
    b"STAT bytes 5242880\r\n"
    b"STAT limit_maxbytes 67108864\r\n"
    b"STAT evictions 17\r\n"
    b"STAT expired_unfetched 90\r\n"
    b"END\r\n"
)

_HEALTHY_PAYLOAD = {
    "version": "1.6.29",
    "uptime": 86400,
    "curr_connections": 12,
    "bytes": 5242880,
    "limit_maxbytes": 67108864,
    "get_hits_total": 981221,
    "get_misses_total": 12345,
    "cmd_get_total": 993566,
    "cmd_set_total": 44210,
    "evictions_total": 17,
    "expired_unfetched_total": 90,
}


# --- happy path ------------------------------------------------------------


def test_healthy_snapshot_and_whitelist():
    """A full reply parses to the snapshot; extra STATs (pid/time/...) drop, and
    keys come out in the fixed contract order."""
    sock = _fake_socket(_HEALTHY_REPLY)
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        out = memcached.memcached_metrics(host="127.0.0.1", port=11211)
    assert out == _HEALTHY_PAYLOAD
    assert list(out.keys()) == list(memcached._FIELD_MAP.values())
    # The `stats` command was issued, the recv timeout was armed, and the
    # connection closed. (settimeout is also re-armed per recv with the
    # remaining deadline budget, so assert the initial full-timeout arm.)
    sock.sendall.assert_called_once_with(b"stats\r\n")
    sock.settimeout.assert_any_call(memcached._TIMEOUT)
    sock.close.assert_called_once()


def test_default_host_port_used_when_unset():
    sock = _fake_socket(_HEALTHY_REPLY)
    with patch(
        "fivenines_agent.memcached.socket.create_connection", return_value=sock
    ) as conn:
        memcached.memcached_metrics()
    conn.assert_called_once_with(("127.0.0.1", 11211), timeout=memcached._TIMEOUT)


def test_value_with_spaces_is_kept_intact():
    # A version string is single-token in practice, but the split(" ", 2) must
    # keep any spaces in a value rather than truncating at the first one.
    reply = b"STAT version 1.6.29 (custom build)\r\nEND\r\n"
    sock = _fake_socket(reply)
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        out = memcached.memcached_metrics()
    assert out == {"version": "1.6.29 (custom build)"}


def test_reply_split_across_recv_calls():
    # END is split across two recv() chunks; the loop must accumulate and only
    # terminate once the full "\r\nEND\r\n" line has arrived.
    chunks = [b"STAT version 1.6.29\r\nEN", b"D\r\n"]
    sock = _fake_socket(None, chunks=chunks)
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        out = memcached.memcached_metrics()
    assert out == {"version": "1.6.29"}


def test_bare_end_reply_returns_none():
    # A reply that is just the terminator (startswith("END\r\n") branch) carries
    # no version -> collection failure (None), not an empty-but-reachable {}.
    # Per the null contract there is no empty-reachable sentinel.
    sock = _fake_socket(b"END\r\n")
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        assert memcached.memcached_metrics() is None


def test_version_less_reply_returns_none():
    # An END-terminated reply that carries stats but no `version` is not a
    # trustworthy memcached response (e.g. a non-memcached endpoint) -> None.
    reply = b"STAT curr_connections 5\r\nSTAT bytes 100\r\nEND\r\n"
    sock = _fake_socket(reply)
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        assert memcached.memcached_metrics() is None


def test_partial_stats_omit_absent_keys():
    # A reachable reply missing some whitelisted STATs omits those keys rather
    # than fabricating zeros; present ones still ship.
    reply = b"STAT version 1.6.29\r\nSTAT curr_connections 3\r\nEND\r\n"
    sock = _fake_socket(reply)
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        out = memcached.memcached_metrics()
    assert out == {"version": "1.6.29", "curr_connections": 3}


# --- collection failure (null) ---------------------------------------------


def test_missing_end_terminator_returns_none():
    # A truncated reply (no END line) is a collection failure, not a partial
    # snapshot: the connection dropped mid-read or the endpoint is not memcached.
    reply = b"STAT pid 2080\r\nSTAT uptime 86400\r\nSTAT version 1.6.29\r\n"
    sock = _fake_socket(reply)
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        assert memcached.memcached_metrics() is None


def test_socket_error_returns_none():
    # Connection refused / unreachable -> None via the except path (the server
    # sees no 'memcached' key and skips the tick).
    with patch(
        "fivenines_agent.memcached.socket.create_connection",
        side_effect=OSError("connection refused"),
    ):
        assert memcached.memcached_metrics() is None


def test_send_error_closes_and_returns_none():
    sock = MagicMock()
    sock.sendall.side_effect = OSError("broken pipe")
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        assert memcached.memcached_metrics() is None
    # The socket is still closed on the error path.
    sock.close.assert_called_once()


def test_bad_port_returns_none():
    # A non-numeric port raises ValueError before any connection is attempted.
    assert memcached.memcached_metrics(port="notaport") is None


def test_close_error_is_swallowed():
    # A failing close() must not sink an otherwise-good snapshot.
    sock = _fake_socket(_HEALTHY_REPLY)
    sock.close.side_effect = OSError("close failed")
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        assert memcached.memcached_metrics() == _HEALTHY_PAYLOAD


def test_none_port_returns_none():
    # A mis-typed pushed port (None) makes int() raise TypeError, which the
    # collector must turn into None per its contract -- not let it escape.
    assert memcached.memcached_metrics(port=None) is None


# --- read-loop robustness --------------------------------------------------


def test_end_break_exits_on_terminator_not_eof():
    # Real memcached holds the connection open after `stats`, so the loop MUST
    # exit on the END line, not by reaching EOF. recv() returns the terminated
    # reply, then a sentinel that raises if the loop ever reads again -- the
    # snapshot must come back without that second read happening (regression
    # guard: without the END-break every tick would block until the timeout).
    sock = MagicMock()
    sock.recv.side_effect = [_HEALTHY_REPLY, AssertionError("read past END terminator")]
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        assert memcached.memcached_metrics() == _HEALTHY_PAYLOAD
    sock.recv.assert_called_once()


def test_recv_timeout_mid_read_returns_none():
    # A wedged endpoint that stalls mid-reply raises socket.timeout on recv;
    # this is the exact "must never hang the collect tick" guard -> None + close.
    sock = MagicMock()
    sock.recv.side_effect = [b"STAT version 1.6.29\r\n", socket.timeout("timed out")]
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        assert memcached.memcached_metrics() is None
    sock.close.assert_called_once()


def test_read_cap_without_end_returns_none(monkeypatch):
    # An endpoint streaming past the byte ceiling without ever sending END must
    # stop the read (bounded memory / no hang) and report a collection failure.
    monkeypatch.setattr(memcached, "_MAX_REPLY_BYTES", 8)
    sock = _fake_socket(
        b"STAT version 1.6.29 and a great deal more with no terminator\r\n"
    )
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        assert memcached.memcached_metrics() is None


def test_post_end_data_cannot_override_counters():
    # END is a hard parse boundary: STAT lines arriving after it (a misbehaving
    # or hostile endpoint) must NOT override the real values before it.
    reply = (
        b"STAT version 1.6.29\r\nSTAT evictions 1\r\nEND\r\nSTAT evictions 999999\r\n"
    )
    sock = _fake_socket(reply)
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        out = memcached.memcached_metrics()
    assert out == {"version": "1.6.29", "evictions_total": 1}


def test_output_ordered_by_field_map_regardless_of_input_order():
    # STATs arrive in reverse-contract order; the snapshot must still emit keys
    # in _FIELD_MAP order (the server/fixture rely on it), proving _build_snapshot
    # re-orders rather than echoing input order.
    reply = (
        b"STAT evictions 17\r\n"
        b"STAT bytes 5242880\r\n"
        b"STAT uptime 86400\r\n"
        b"STAT version 1.6.29\r\n"
        b"END\r\n"
    )
    sock = _fake_socket(reply)
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        out = memcached.memcached_metrics()
    assert list(out.keys()) == ["version", "uptime", "bytes", "evictions_total"]


def test_read_deadline_bounds_slow_trickle(monkeypatch):
    # A slow-trickle endpoint dribbles non-END chunks that never trip the
    # per-recv timeout; the total-read deadline MUST stop it (else the
    # synchronous collect tick hangs past the systemd watchdog -> restart loop).
    seq = iter([1000.0, 1000.0, 2000.0])  # deadline calc, 1st check (ok), 2nd (past)
    monkeypatch.setattr(memcached.time, "monotonic", lambda: next(seq, 9999.0))
    sock = MagicMock()
    sock.recv.return_value = b"STAT junk 1\r\n"  # never sends END, never EOFs
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        assert memcached.memcached_metrics() is None
    sock.close.assert_called_once()


def test_crlf_only_split_blocks_phantom_end_injection():
    # A hostile STAT value carrying a bare "\n" + "END" would, under
    # str.splitlines(), manufacture a phantom END line that truncates the real
    # counters after it. Splitting on "\r\n" only must ignore the bare-\n and
    # preserve the trailing real counter.
    reply = b"STAT version 1.6.29\r\nSTAT x bad\nEND\r\nSTAT evictions 5\r\nEND\r\n"
    sock = _fake_socket(reply)
    with patch("fivenines_agent.memcached.socket.create_connection", return_value=sock):
        out = memcached.memcached_metrics()
    assert out == {"version": "1.6.29", "evictions_total": 5}


# --- unit-level parser / helpers -------------------------------------------


def test_parse_stats_skips_non_stat_lines():
    lines = ["STAT version 1.6.29", "END", "", "ERROR", "STAT curr_connections 3"]
    assert memcached._parse_stats(lines) == {
        "version": "1.6.29",
        "curr_connections": "3",
    }


def test_build_snapshot_omits_absent_and_non_numeric():
    stats = {
        "version": "1.6.29",
        "uptime": "100",
        "curr_connections": "notanumber",  # non-numeric numeric field -> dropped
        # bytes / limit_maxbytes / counters absent -> omitted
    }
    assert memcached._build_snapshot(stats) == {"version": "1.6.29", "uptime": 100}


def test_as_int_variants():
    assert memcached._as_int("42") == 42
    assert memcached._as_int("notanumber") is None
    assert memcached._as_int(None) is None  # TypeError branch


# --- cross-repo contract (fivenines-server) --------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "memcached_contract_payload.json"
)


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


def test_contract_fixture_round_trip():
    """SHARED FIXTURE (cross-repo contract): fixtures/memcached_contract_payload.json.

    Asserted on both sides:
    - here: memcached_metrics(**fixture["config"]) must equal each scenario's
      "payload" with only socket.create_connection mocked (the scenario's raw
      "reply" is fed back as the socket reply), pinning parse -> payload;
    - fivenines-server: spec/requests/api_collect_memcached_spec.rb posts each
      "payload" under data["memcached"] and asserts Ingesters::Agent handles the
      snapshot / null shapes.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    fixture = _load_fixture()
    config = fixture["config"]
    for name, scenario in fixture["scenarios"].items():
        sock = _fake_socket(scenario["reply"].encode())
        with patch(
            "fivenines_agent.memcached.socket.create_connection", return_value=sock
        ):
            out = memcached.memcached_metrics(**config)
        assert out == scenario["payload"], "scenario '{}' drifted".format(name)


def test_fixture_healthy_payload_keys_match_field_map():
    payload = _load_fixture()["scenarios"]["healthy"]["payload"]
    assert list(payload.keys()) == list(memcached._FIELD_MAP.values())


def test_fixture_collection_failure_is_null():
    assert _load_fixture()["scenarios"]["collection_failure"]["payload"] is None


def test_fixture_config_is_the_documented_shape():
    fixture = _load_fixture()
    assert set(fixture["config"]) == {"host", "port"}
    assert fixture["agent_min_version"] == "1.14.4"
