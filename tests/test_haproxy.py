"""Tests for the HAProxy stats collector (server issue #494).

Only the transport is mocked. The socket path drives a FakeSocket through the
real ``show stat`` write + EOF read; the HTTP path mocks ``requests.get``; the
contract round-trip mocks the ``_socket_show_stat`` / ``_http_show_stat`` seams,
feeding each scenario's ``raw_lines`` back as the CSV body. Mirrors
test_php_fpm.py's cross-repo fixture assertion.
"""

import json
import os

import pytest
import requests

from fivenines_agent import haproxy


# --- socket test double ----------------------------------------------------


class FakeSocket:
    """Minimal stand-in for a connected AF_UNIX stream socket.

    ``recv`` drains a preloaded byte buffer (returning b"" at EOF); ``sendall``
    accumulates what the client wrote so the ``show stat`` command can be
    asserted.
    """

    def __init__(self, to_read=b""):
        self._buf = bytearray(to_read)
        self.sent = bytearray()
        self.closed = False
        self.timeout = None
        self.connect_addr = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        if not self._buf:
            return b""
        chunk = bytes(self._buf[:n])
        del self._buf[:n]
        return chunk

    def connect(self, addr):
        self.connect_addr = addr

    def close(self):
        self.closed = True


def _http_response(text="", status=200):
    body = text.encode("utf-8") if isinstance(text, str) else text

    class _Resp:
        def __init__(self):
            self.status_code = status
            self.closed = False

        def iter_content(self, chunk_size=65536):
            for i in range(0, len(body), chunk_size):
                yield body[i : i + chunk_size]

        def close(self):
            self.closed = True

    return _Resp()


_HEADER = (
    "# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,wretr,status,"
    "weight,type,rate,check_status,check_duration,hrsp_4xx,hrsp_5xx,"
)


def _csv(*rows):
    return "\n".join((_HEADER,) + rows)


# --- transport selection (_read_stats) -------------------------------------


def test_read_stats_prefers_socket(monkeypatch):
    monkeypatch.setattr(haproxy, "_socket_show_stat", lambda p: f"sock:{p}")
    monkeypatch.setattr(haproxy, "_http_show_stat", lambda *a: "http")
    assert haproxy._read_stats("/s.sock", "http://h/stats", None, None) == "sock:/s.sock"


def test_read_stats_falls_back_to_url(monkeypatch):
    monkeypatch.setattr(haproxy, "_http_show_stat", lambda u, un, pw: f"http:{u}:{un}:{pw}")
    assert haproxy._read_stats(None, "http://h/stats", "admin", "pw") == "http:http://h/stats:admin:pw"


def test_read_stats_default_socket(monkeypatch):
    captured = {}
    monkeypatch.setattr(haproxy, "_socket_show_stat", lambda p: captured.setdefault("path", p))
    haproxy._read_stats(None, None, None, None)
    assert captured["path"] == haproxy._DEFAULT_STATS_SOCKET


def test_read_stats_no_socket_to_url_failover(monkeypatch):
    # A configured socket that FAILS (returns None) must NOT silently fall back
    # to stats_url -- a broken socket surfaces honestly. Guards the documented
    # no-failover invariant against a failover-adding mutation.
    monkeypatch.setattr(haproxy, "_socket_show_stat", lambda p: None)
    called = {"http": False}

    def http(*a):
        called["http"] = True
        return "http-body"

    monkeypatch.setattr(haproxy, "_http_show_stat", http)
    assert haproxy._read_stats("/s.sock", "http://h/stats", None, None) is None
    assert called["http"] is False


# --- socket transport (_socket_show_stat) ----------------------------------


def test_socket_show_stat_success(monkeypatch):
    sock = FakeSocket(_csv("web_back,BACKEND,0,0,0,0,,0,0,0,0,UP,1,1,0,,,0,0,").encode())
    monkeypatch.setattr(haproxy.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(haproxy.socket, "socket", lambda family, kind: sock)
    out = haproxy._socket_show_stat("/run/haproxy/admin.sock")
    assert "BACKEND" in out
    assert bytes(sock.sent) == b"show stat\n"
    assert sock.connect_addr == "/run/haproxy/admin.sock"
    # Each recv's timeout is the remaining wall-clock budget: >0 and <= _TIMEOUT.
    assert sock.timeout is not None and 0 < sock.timeout <= haproxy._TIMEOUT
    assert sock.closed


def test_socket_show_stat_no_af_unix(monkeypatch):
    monkeypatch.delattr(haproxy.socket, "AF_UNIX", raising=False)
    assert haproxy._socket_show_stat("/s.sock") is None


def test_socket_show_stat_connect_error(monkeypatch):
    class BadSock(FakeSocket):
        def connect(self, addr):
            raise OSError("connection refused")

    sock = BadSock()
    monkeypatch.setattr(haproxy.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(haproxy.socket, "socket", lambda family, kind: sock)
    assert haproxy._socket_show_stat("/s.sock") is None


def test_socket_show_stat_factory_error_leaves_sock_none(monkeypatch):
    def boom(family, kind):
        raise OSError("cannot create socket")

    monkeypatch.setattr(haproxy.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(haproxy.socket, "socket", boom)
    # sock stays None -> the finally block must not attempt close.
    assert haproxy._socket_show_stat("/s.sock") is None


def test_socket_show_stat_close_error_swallowed(monkeypatch):
    class BadClose(FakeSocket):
        def close(self):
            raise OSError("close failed")

    sock = BadClose(_csv().encode())
    monkeypatch.setattr(haproxy.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(haproxy.socket, "socket", lambda family, kind: sock)
    assert haproxy._socket_show_stat("/s.sock") is not None


def test_socket_show_stat_max_bytes_returns_none(monkeypatch):
    class InfiniteSock(FakeSocket):
        def recv(self, n):
            return b"x" * 1024  # never EOF: only the size cap can end the loop

    monkeypatch.setattr(haproxy, "_MAX_RESPONSE_BYTES", 2048)
    sock = InfiniteSock()
    monkeypatch.setattr(haproxy.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(haproxy.socket, "socket", lambda family, kind: sock)
    # A truncated (over-cap) read is a collection failure, not partial data:
    # shipping the truncated CSV would prune the untransmitted tail and
    # false-resolve open backend-down incidents.
    assert haproxy._socket_show_stat("/s.sock") is None


def _fake_clock(values):
    """A time.monotonic() stub yielding `values` in order, then repeating last."""
    seq = list(values)
    state = {"i": 0}

    def clock():
        i = state["i"]
        if i < len(seq) - 1:
            state["i"] = i + 1
        return seq[i]

    return clock


def test_socket_show_stat_wall_clock_deadline(monkeypatch):
    # A trickle socket that never EOFs. settimeout is per-recv and would reset
    # forever; the WALL-CLOCK deadline must end the read and return None. The
    # clock: [deadline-setup=0, then 1,2,3, then 100 (past the 5s deadline)].
    monkeypatch.setattr(haproxy.time, "monotonic", _fake_clock([0, 1, 2, 3, 100]))

    class TrickleSock(FakeSocket):
        def recv(self, n):
            return b"x"  # one byte at a time, never EOF

    sock = TrickleSock()
    monkeypatch.setattr(haproxy.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(haproxy.socket, "socket", lambda family, kind: sock)
    assert haproxy._socket_show_stat("/s.sock") is None


def test_socket_show_stat_empty_read_returns_none(monkeypatch):
    # Immediate EOF (HAProxy sent nothing) -> None, not "".
    sock = FakeSocket(b"")
    monkeypatch.setattr(haproxy.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(haproxy.socket, "socket", lambda family, kind: sock)
    assert haproxy._socket_show_stat("/s.sock") is None


def test_socket_show_stat_recv_timeout_shrinks_to_remaining(monkeypatch):
    # The per-recv timeout must be the REMAINING wall-clock budget, not a constant
    # _TIMEOUT reset each chunk. Under a deterministic clock (elapsed 2s of the 5s
    # budget), the recv timeout must be strictly < _TIMEOUT -- catches a
    # settimeout(_TIMEOUT)-constant mutation.
    monkeypatch.setattr(haproxy.time, "monotonic", _fake_clock([0, 2, 2, 3]))
    sock = FakeSocket(_csv().encode())
    monkeypatch.setattr(haproxy.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(haproxy.socket, "socket", lambda family, kind: sock)
    haproxy._socket_show_stat("/s.sock")
    assert sock.timeout is not None and sock.timeout < haproxy._TIMEOUT


# --- HTTP transport (_http_show_stat) --------------------------------------


def test_http_show_stat_success(monkeypatch):
    captured = {}
    resp = _http_response(_csv())

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return resp

    monkeypatch.setattr(haproxy.requests, "get", fake_get)
    out = haproxy._http_show_stat("http://127.0.0.1:8404/stats", "admin", "secret")
    assert "pxname" in out
    assert captured["url"] == "http://127.0.0.1:8404/stats;csv"
    assert captured["timeout"] == haproxy._TIMEOUT
    assert captured["auth"] == ("admin", "secret")
    assert captured["stream"] is True  # streamed, not buffered whole
    assert captured["allow_redirects"] is False  # no redirect-following (SSRF guard)
    assert captured["headers"]["Accept-Encoding"] == "identity"  # no decompression bomb
    assert resp.closed  # response released even on the success path


def test_http_show_stat_no_auth(monkeypatch):
    captured = {}

    def fake_get(url, **kwargs):
        captured["auth"] = kwargs["auth"]
        return _http_response(_csv())

    monkeypatch.setattr(haproxy.requests, "get", fake_get)
    haproxy._http_show_stat("http://h/stats;csv", None, None)
    assert captured["auth"] is None


def test_http_show_stat_username_without_password(monkeypatch):
    captured = {}

    def fake_get(url, **kwargs):
        captured["auth"] = kwargs["auth"]
        return _http_response(_csv())

    monkeypatch.setattr(haproxy.requests, "get", fake_get)
    haproxy._http_show_stat("http://h/stats;csv", "user", None)
    assert captured["auth"] == ("user", "")


def test_http_show_stat_non_200(monkeypatch):
    monkeypatch.setattr(
        haproxy.requests, "get", lambda *a, **k: _http_response("nope", 503)
    )
    assert haproxy._http_show_stat("http://h/stats", None, None) is None


def test_http_show_stat_exception(monkeypatch):
    def boom(*a, **k):
        raise requests.exceptions.Timeout("timed out")

    monkeypatch.setattr(haproxy.requests, "get", boom)
    assert haproxy._http_show_stat("http://h/stats", None, None) is None


def test_http_show_stat_byte_cap_returns_none(monkeypatch):
    # An over-cap body is a truncated read -> None, mirroring the socket path
    # (shipping partial CSV would prune the tail and false-resolve).
    monkeypatch.setattr(haproxy, "_MAX_RESPONSE_BYTES", 8)
    monkeypatch.setattr(
        haproxy.requests, "get", lambda *a, **k: _http_response("x" * 64)
    )
    assert haproxy._http_show_stat("http://h/stats;csv", None, None) is None


def test_http_show_stat_wall_clock_deadline(monkeypatch):
    # A trickle body read one byte per chunk whose read runs past the wall-clock
    # deadline -> None. Clock: [deadline-setup=0, 1, 2, then 100 (past 5s)].
    monkeypatch.setattr(haproxy, "_RECV_CHUNK_BYTES", 1)
    monkeypatch.setattr(haproxy.time, "monotonic", _fake_clock([0, 1, 2, 100]))
    monkeypatch.setattr(
        haproxy.requests, "get", lambda *a, **k: _http_response("x" * 10)
    )
    assert haproxy._http_show_stat("http://h/stats;csv", None, None) is None


def test_http_show_stat_iter_content_error_returns_none(monkeypatch):
    class BadStream:
        status_code = 200

        def iter_content(self, chunk_size=65536):
            raise requests.exceptions.ChunkedEncodingError("stream broke")

        def close(self):
            pass

    monkeypatch.setattr(haproxy.requests, "get", lambda *a, **k: BadStream())
    assert haproxy._http_show_stat("http://h/stats;csv", None, None) is None


def test_http_show_stat_empty_body_returns_none(monkeypatch):
    # A 200 with an empty body -> None, not "".
    monkeypatch.setattr(haproxy.requests, "get", lambda *a, **k: _http_response(""))
    assert haproxy._http_show_stat("http://h/stats;csv", None, None) is None


def test_http_show_stat_skips_empty_keepalive_chunks(monkeypatch):
    # requests.iter_content can yield empty keep-alive chunks; they are skipped
    # and the real body still assembles intact.
    payload = _csv("web,BACKEND,0,0,1,0,0,0,0,0,0,UP,1,1,0,,,0,0,").encode("utf-8")

    class KeepAliveStream:
        status_code = 200

        def iter_content(self, chunk_size=65536):
            yield b""
            yield payload
            yield b""

        def close(self):
            pass

    monkeypatch.setattr(haproxy.requests, "get", lambda *a, **k: KeepAliveStream())
    out = haproxy._http_show_stat("http://h/stats;csv", None, None)
    assert out is not None and "BACKEND" in out


def test_ensure_csv():
    assert haproxy._ensure_csv("http://h/stats") == "http://h/stats;csv"
    assert haproxy._ensure_csv("http://h/haproxy?stats") == "http://h/haproxy?stats;csv"
    assert haproxy._ensure_csv("http://h/stats;csv") == "http://h/stats;csv"
    assert haproxy._ensure_csv("http://h/stats;csv;norefresh") == "http://h/stats;csv;norefresh"


# --- CSV parsing (_parse_stat_csv) -----------------------------------------


def test_parse_no_header_returns_none():
    assert haproxy._parse_stat_csv("some error text\nnot csv") is None


def test_parse_header_without_pxname_returns_none():
    assert haproxy._parse_stat_csv("# foo,bar,baz\n1,2,3") is None


def test_parse_header_with_pxname_but_no_svname_returns_none():
    # pxname present but svname absent -> still None. Isolates the svname guard,
    # which the pxname-absent case can't reach (short-circuits on pxname first).
    assert haproxy._parse_stat_csv("# pxname,foo,bar\nweb,1,2") is None


def test_parse_header_without_type_column_returns_none():
    # pxname + svname present but NO 'type' column -> None (collection failure),
    # NOT [] (prune-all). Without 'type' every row would be dropped by _build_row
    # and the tick would collapse to [], false-resolving open backend-down
    # incidents -- the exact catastrophe the null-vs-empty contract prevents.
    assert haproxy._parse_stat_csv("# pxname,svname,status\nweb,BACKEND,UP") is None


def test_parse_zero_rows_returns_empty_list():
    assert haproxy._parse_stat_csv(_csv()) == []


def test_parse_maps_by_name_not_index():
    # The mapped columns are scattered through the header; an index-based reader
    # would mangle them. status sits at index 11, type at 13, hrsp_4xx at 17.
    rows = haproxy._parse_stat_csv(
        _csv("web,BACKEND,1,9,7,9,2000,0,111,222,3,UP,1,1,0,,,50,4,")
    )
    assert rows == [
        {
            "proxy": "web", "server": "BACKEND", "type": "backend", "status": "UP",
            "sessions_current": 7, "sessions_limit": 2000, "queue_current": 1,
            "http_4xx_total": 50, "http_5xx_total": 4, "retries_total": 3,
            "bytes_in_total": 111, "bytes_out_total": 222,
            "check_status": None, "check_duration_ms": None,
        }
    ]


def test_parse_skips_blank_lines():
    text = _csv("web,BACKEND,0,0,0,0,,0,0,0,0,UP,1,1,0,,,0,0,") + "\n\n   \n"
    rows = haproxy._parse_stat_csv(text)
    assert len(rows) == 1


def test_parse_splits_only_on_newline_not_exotic_whitespace():
    # A vertical-tab (\x0b) inside a field must NOT split the row. str.splitlines
    # would break on it and inject a phantom row; str.split("\n") does not.
    row = "web,srv\x0bweird,0,0,3,8,,5000,200000,400000,1,UP,1,2,1,L4OK,2,600,15,"
    rows = haproxy._parse_stat_csv(_csv(row))
    assert len(rows) == 1
    assert rows[0]["type"] == "server"


def test_parse_tolerates_crlf_line_endings():
    # A CRLF body: split("\n") leaves a trailing \r on each line, absorbed by the
    # per-cell strip(). Rows parse intact with clean values.
    text = _csv("web,BACKEND,0,0,5,0,2000,0,10,20,0,UP,1,1,0,,,0,0,").replace("\n", "\r\n")
    rows = haproxy._parse_stat_csv(text)
    assert len(rows) == 1
    assert rows[0]["status"] == "UP"
    assert rows[0]["sessions_current"] == 5


def test_parse_drops_listener_and_unknown_types():
    rows = haproxy._parse_stat_csv(
        _csv(
            "web,FRONTEND,,,0,0,2000,0,0,0,,OPEN,,0,0,,,0,0,",   # type 0 kept
            "web,sock1,,,0,0,,0,0,0,,OPEN,,3,0,,,0,0,",          # type 3 listener dropped
            "web,weird,,,0,0,,0,0,0,,UP,,9,0,,,0,0,",            # type 9 unknown dropped
        )
    )
    assert [r["type"] for r in rows] == ["frontend"]


def test_parse_drops_empty_type():
    rows = haproxy._parse_stat_csv(
        _csv("web,notype,,,0,0,,0,0,0,,UP,,,0,,,0,0,")  # type column empty
    )
    assert rows == []


def test_parse_short_row_fills_missing_with_none():
    # A row truncated before the check/hrsp columns still yields all keys, with
    # None where the columns are missing.
    rows = haproxy._parse_stat_csv(_csv("web,web1,0,0,2,,,,,,,UP,,2"))
    assert rows[0]["type"] == "server"
    assert rows[0]["status"] == "UP"
    assert rows[0]["check_status"] is None
    assert rows[0]["http_4xx_total"] is None


# --- cell conversion -------------------------------------------------------


def test_as_int():
    assert haproxy._as_int("42") == 42
    assert haproxy._as_int(" 42 ") == 42
    assert haproxy._as_int("3.9") == 3  # float-string tolerated, truncated
    assert haproxy._as_int("") is None
    assert haproxy._as_int(None) is None
    assert haproxy._as_int("abc") is None
    assert haproxy._as_int("inf") is None  # non-finite -> None (OverflowError guard)
    assert haproxy._as_int("nan") is None


def test_as_str():
    assert haproxy._as_str(" UP ") == "UP"
    assert haproxy._as_str("") is None
    assert haproxy._as_str(None) is None


# --- server cap (_apply_cap) -----------------------------------------------


def _row(server, row_type="server", status="UP"):
    return {"server": server, "type": row_type, "status": status}


def test_apply_cap_under_cap_returns_list():
    rows = [_row("FRONTEND", "frontend"), _row("s1"), _row("BACKEND", "backend")]
    assert haproxy._apply_cap(rows) is rows


def test_apply_cap_at_exact_cap_returns_list(monkeypatch):
    # Boundary: len(servers) == _SERVER_CAP is still within cap (the <= edge) --
    # no wrapper, the list is returned unchanged.
    monkeypatch.setattr(haproxy, "_SERVER_CAP", 2)
    rows = [_row("s1"), _row("s2")]
    assert haproxy._apply_cap(rows) is rows


def test_apply_cap_over_cap_wraps_and_orders_problems_first(monkeypatch):
    monkeypatch.setattr(haproxy, "_SERVER_CAP", 2)
    rows = [
        _row("FRONTEND", "frontend"),
        _row("up1", status="UP"),
        _row("down1", status="DOWN"),
        _row("up2", status="UP"),
        _row("BACKEND", "backend"),
    ]
    out = haproxy._apply_cap(rows)
    assert out["servers_capped"] is True
    # frontend + backend always first (CSV order), then problems-first servers.
    assert [r["server"] for r in out["rows"]] == ["FRONTEND", "BACKEND", "down1", "up1"]


def test_apply_cap_keeps_all_frontend_backend(monkeypatch):
    monkeypatch.setattr(haproxy, "_SERVER_CAP", 1)
    rows = [_row(f"s{i}") for i in range(5)] + [
        _row("FE", "frontend"),
        _row("BE", "backend"),
    ]
    out = haproxy._apply_cap(rows)
    kept_non_server = [r["server"] for r in out["rows"] if r["type"] != "server"]
    assert kept_non_server == ["FE", "BE"]
    assert sum(1 for r in out["rows"] if r["type"] == "server") == 1


def test_is_problem_status():
    assert haproxy._is_problem_status("DOWN")
    assert haproxy._is_problem_status("MAINT")
    assert haproxy._is_problem_status("DRAIN")
    assert haproxy._is_problem_status("DOWN 1/2")
    assert haproxy._is_problem_status("NOLB")  # taken out of load-balancing = problem
    assert haproxy._is_problem_status("")
    assert haproxy._is_problem_status(None)  # None coerces to "" -> problem
    assert not haproxy._is_problem_status("UP")
    assert not haproxy._is_problem_status("UP 1/3")
    assert not haproxy._is_problem_status("OPEN")
    assert not haproxy._is_problem_status("no check")


# --- top-level haproxy_metrics ---------------------------------------------


def test_metrics_socket_success(monkeypatch):
    monkeypatch.setattr(
        haproxy, "_socket_show_stat",
        lambda p: _csv("web,BACKEND,0,0,5,0,2000,0,10,20,0,UP,1,1,0,,,0,0,"),
    )
    out = haproxy.haproxy_metrics(stats_socket="/s.sock")
    assert out == [
        {
            "proxy": "web", "server": "BACKEND", "type": "backend", "status": "UP",
            "sessions_current": 5, "sessions_limit": 2000, "queue_current": 0,
            "http_4xx_total": 0, "http_5xx_total": 0, "retries_total": 0,
            "bytes_in_total": 10, "bytes_out_total": 20,
            "check_status": None, "check_duration_ms": None,
        }
    ]


def test_metrics_transport_failure_returns_none(monkeypatch):
    monkeypatch.setattr(haproxy, "_socket_show_stat", lambda p: None)
    assert haproxy.haproxy_metrics(stats_socket="/s.sock") is None


def test_metrics_malformed_csv_returns_none(monkeypatch):
    monkeypatch.setattr(haproxy, "_socket_show_stat", lambda p: "garbage, not a stat page")
    assert haproxy.haproxy_metrics(stats_socket="/s.sock") is None


def test_metrics_read_exception_returns_none(monkeypatch):
    def boom(*a):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(haproxy, "_read_stats", boom)
    assert haproxy.haproxy_metrics(stats_socket="/s.sock") is None


def test_metrics_absorbs_unknown_config_keys(monkeypatch):
    # The server echoes the haproxy config block every /collect; an added key
    # must not turn the whole tick into a spurious collection failure.
    monkeypatch.setattr(haproxy, "_socket_show_stat", lambda p: _csv())
    out = haproxy.haproxy_metrics(stats_socket="/s.sock", future_option="x")
    assert out == []


# --- cross-repo contract (fivenines-server) --------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "haproxy_contract_payload.json"
)


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


def _run_scenario(scenario, monkeypatch):
    lines = scenario.get("raw_lines")
    raw = None if lines is None else "\n".join(lines)
    monkeypatch.setattr(haproxy, "_socket_show_stat", lambda *a, **k: raw)
    monkeypatch.setattr(haproxy, "_http_show_stat", lambda *a, **k: raw)
    if "server_cap" in scenario:
        monkeypatch.setattr(haproxy, "_SERVER_CAP", scenario["server_cap"])
    return haproxy.haproxy_metrics(**scenario["config"])


@pytest.mark.parametrize(
    "name",
    ["healthy", "backend_down_server_maint", "zero_proxies", "collection_failure", "capped_tick"],
)
def test_contract_fixture_round_trip(name, monkeypatch):
    """SHARED FIXTURE (cross-repo contract): fixtures/haproxy_contract_payload.json.

    Asserted on both sides:
    - here: haproxy_metrics(**scenario["config"]) must equal scenario["payload"]
      with only the socket/HTTP transport mocked (raw_lines fed as the CSV body,
      _SERVER_CAP shrunk to server_cap for the capped scenario);
    - fivenines-server: spec/requests/api_collect_haproxy_spec.rb posts
      scenario["payload"] under data["haproxy"] and asserts Ingesters::Agent
      handles the list / capped-wrapper / [] / null shapes.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    fixture = _load_fixture()
    scenario = fixture["scenarios"][name]
    assert _run_scenario(scenario, monkeypatch) == scenario["payload"]


def test_fixture_agent_min_version():
    assert _load_fixture()["agent_min_version"] == "1.14.3"


def test_fixture_row_keys_match_contract():
    row_keys = list(_load_fixture()["row_contract"].keys())
    expected = [
        "proxy", "server", "type", "status", "sessions_current", "sessions_limit",
        "queue_current", "http_4xx_total", "http_5xx_total", "retries_total",
        "bytes_in_total", "bytes_out_total", "check_status", "check_duration_ms",
    ]
    # row_contract documents every payload key (plus trailing _-prefixed notes).
    assert [k for k in row_keys if not k.startswith("_")] == expected
    # Every healthy-scenario row carries exactly those keys in order.
    for row in _load_fixture()["scenarios"]["healthy"]["payload"]:
        assert list(row.keys()) == expected


def test_fixture_config_is_documented_shape():
    for scenario in _load_fixture()["scenarios"].values():
        assert set(scenario["config"]) == {"stats_socket", "stats_url", "username", "password"}
