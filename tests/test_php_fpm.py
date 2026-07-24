"""Tests for the PHP-FPM per-pool status collector (server issue #490).

Only the transport is mocked. The HTTP path mocks requests.get; the FastCGI
path drives a FakeSocket through the real BEGIN_REQUEST/PARAMS/STDIN encode and
STDOUT/END_REQUEST decode; the contract round-trip mocks the _fetch_status_body
seam and, for auto-discovery scenarios, points discovery at a temp dir of real
pool.d configs. Mirrors test_apache.py's cross-repo fixture assertion.
"""

import json
import os
import struct
from unittest.mock import MagicMock

import pytest
import requests

from fivenines_agent import php_fpm


# --- FastCGI test doubles --------------------------------------------------


class FakeSocket:
    """A minimal stand-in for a connected stream socket.

    ``recv`` drains a preloaded byte buffer (returning b"" at EOF); ``sendall``
    accumulates what the client wrote so request framing can be asserted.
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


def _fcgi_record(rec_type, content, pad=0, request_id=1):
    header = struct.pack("!BBHHBB", 1, rec_type, request_id, len(content), pad, 0)
    return header + content + (b"\x00" * pad)


_END_REQUEST = _fcgi_record(3, struct.pack("!IB3x", 0, 0))


def _fcgi_stream(body, header="Content-type: application/json\r\n\r\n", split=None):
    """Build a well-formed FPM FastCGI STDOUT+END_REQUEST response byte stream."""
    payload = (header + body).encode("utf-8")
    if split:
        records = b"".join(
            _fcgi_record(6, payload[i:][:split]) for i in range(0, len(payload), split)
        )
    else:
        records = _fcgi_record(6, payload)
    return records + _END_REQUEST


def _http_response(text="", status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    return resp


_RAW_WWW = {
    "pool": "www",
    "process manager": "dynamic",
    "start time": 1721815200,
    "start since": 3600,
    "accepted conn": 100,
    "listen queue": 0,
    "max listen queue": 5,
    "listen queue len": 128,
    "idle processes": 8,
    "active processes": 2,
    "total processes": 10,
    "max active processes": 3,
    "max children reached": 0,
    "slow requests": 0,
}

_NORM_WWW = {
    "name": "www",
    "process_manager": "dynamic",
    "active_processes": 2,
    "idle_processes": 8,
    "total_processes": 10,
    "listen_queue": 0,
    "max_listen_queue": 5,
    "max_children_reached": 0,
    "slow_requests": 0,
    "accepted_connections": 100,
}


# --- HTTP transport (Phase A) ----------------------------------------------


def test_http_single_pool(monkeypatch):
    monkeypatch.setattr(
        php_fpm.requests, "get", lambda url, timeout: _http_response(json.dumps(_RAW_WWW))
    )
    assert php_fpm.php_fpm_metrics(status_page_url="http://127.0.0.1/status?json") == [_NORM_WWW]


def test_http_non_200_returns_null(monkeypatch):
    monkeypatch.setattr(
        php_fpm.requests, "get", lambda url, timeout: _http_response("x", status=500)
    )
    assert php_fpm.php_fpm_metrics(status_page_url="http://127.0.0.1/status?json") is None


def test_http_exception_returns_null(monkeypatch):
    def boom(url, timeout):
        raise requests.exceptions.Timeout("timed out")

    monkeypatch.setattr(php_fpm.requests, "get", boom)
    assert php_fpm.php_fpm_metrics(status_page_url="http://127.0.0.1/status?json") is None


def test_http_malformed_json_returns_null(monkeypatch):
    monkeypatch.setattr(php_fpm.requests, "get", lambda url, timeout: _http_response("not json"))
    assert php_fpm.php_fpm_metrics(status_page_url="http://127.0.0.1/status?json") is None


def test_http_non_dict_json_returns_null(monkeypatch):
    monkeypatch.setattr(php_fpm.requests, "get", lambda url, timeout: _http_response("[1, 2]"))
    assert php_fpm.php_fpm_metrics(status_page_url="http://127.0.0.1/status?json") is None


def test_default_url_used_when_unset(monkeypatch):
    captured = {}

    def cap(url, timeout):
        captured["url"] = url
        captured["timeout"] = timeout
        return _http_response(json.dumps(_RAW_WWW))

    monkeypatch.setattr(php_fpm.requests, "get", cap)
    php_fpm.php_fpm_metrics()
    assert captured["url"] == "http://127.0.0.1/status?json"
    assert captured["timeout"] == php_fpm._TIMEOUT


def test_json_query_appended_through_metrics(monkeypatch):
    captured = {}

    def cap(url, timeout):
        captured["url"] = url
        return _http_response(json.dumps(_RAW_WWW))

    monkeypatch.setattr(php_fpm.requests, "get", cap)
    php_fpm.php_fpm_metrics(status_page_url="http://127.0.0.1/status")
    assert captured["url"] == "http://127.0.0.1/status?json"


# --- json query flag (parse-based, not substring) --------------------------


def test_ensure_json_query_variants():
    assert php_fpm._ensure_json_query("http://h/status") == "http://h/status?json"
    assert php_fpm._ensure_json_query("http://h/status?refresh=5") == "http://h/status?refresh=5&json"
    assert php_fpm._ensure_json_query("http://h/status?json") == "http://h/status?json"
    assert php_fpm._ensure_json_query("http://h/status?json=1") == "http://h/status?json=1"
    # A path that merely contains "json" must still get the flag appended.
    assert php_fpm._ensure_json_query("http://h/jsonstatus") == "http://h/jsonstatus?json"


# --- scheme dispatch -------------------------------------------------------


def test_unknown_scheme_returns_null():
    assert php_fpm.php_fpm_metrics(status_page_url="ftp://h/status") is None


def test_no_scheme_returns_null():
    assert php_fpm.php_fpm_metrics(status_page_url="127.0.0.1/status") is None


def test_resolution_exception_returns_null(monkeypatch):
    def boom(url):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(php_fpm, "_resolve_endpoints", boom)
    assert php_fpm.php_fpm_metrics(status_page_url="http://h/status?json") is None


# --- unix:// URL parsing ---------------------------------------------------


def test_unix_url_sock_split():
    assert php_fpm._endpoint_from_url("unix:///run/php/php8.2-fpm.sock/status") == {
        "kind": "unix",
        "address": "/run/php/php8.2-fpm.sock",
        "script_name": "/status",
    }


def test_unix_url_sock_no_trailing_script():
    assert php_fpm._endpoint_from_url("unix:///run/php.sock") == {
        "kind": "unix",
        "address": "/run/php.sock",
        "script_name": "/status",
    }


def test_unix_url_fallback_without_sock_marker():
    assert php_fpm._endpoint_from_url("unix:///run/php/fpm/status") == {
        "kind": "unix",
        "address": "/run/php/fpm",
        "script_name": "/status",
    }


def test_unix_url_two_slash_authority_folded():
    # Malformed two-slash form: the socket path's first segment lands in the URL
    # authority; it must be folded back into the (absolute) path, not dropped.
    assert php_fpm._endpoint_from_url("unix://run/php/fpm.sock/status") == {
        "kind": "unix",
        "address": "/run/php/fpm.sock",
        "script_name": "/status",
    }


def test_unix_url_unparseable_returns_none():
    assert php_fpm._endpoint_from_url("unix://") is None
    assert php_fpm._endpoint_from_url("unix:///") is None


# --- tcp:// URL parsing ----------------------------------------------------


def test_tcp_url():
    assert php_fpm._endpoint_from_url("tcp://127.0.0.1:9000/status") == {
        "kind": "tcp",
        "host": "127.0.0.1",
        "port": 9000,
        "script_name": "/status",
    }


def test_tcp_url_default_script():
    assert php_fpm._endpoint_from_url("tcp://127.0.0.1:9000") == {
        "kind": "tcp",
        "host": "127.0.0.1",
        "port": 9000,
        "script_name": "/status",
    }


def test_tcp_url_ipv6():
    assert php_fpm._endpoint_from_url("tcp://[::1]:9000/status") == {
        "kind": "tcp",
        "host": "::1",
        "port": 9000,
        "script_name": "/status",
    }


def test_tcp_url_bad_port_returns_none():
    assert php_fpm._endpoint_from_url("tcp://127.0.0.1:notaport/status") is None


def test_tcp_url_missing_port_returns_none():
    assert php_fpm._endpoint_from_url("tcp://127.0.0.1/status") is None


# --- listen address parsing ------------------------------------------------


def test_split_host_port_variants():
    assert php_fpm._split_host_port("127.0.0.1:9000") == ("127.0.0.1", 9000)
    assert php_fpm._split_host_port(":9000") == ("127.0.0.1", 9000)
    assert php_fpm._split_host_port("9000") == ("127.0.0.1", 9000)
    assert php_fpm._split_host_port("[::1]:9000") == ("::1", 9000)
    assert php_fpm._split_host_port("localhost:9000") == ("localhost", 9000)


def test_split_host_port_invalid():
    assert php_fpm._split_host_port("notaport") is None
    assert php_fpm._split_host_port("host:notaport") is None
    assert php_fpm._split_host_port("[::1]") is None
    assert php_fpm._split_host_port("[::1]nocolon") is None
    assert php_fpm._split_host_port(":0") is None
    assert php_fpm._split_host_port("host:70000") is None


def test_safe_port_type_error():
    assert php_fpm._safe_port(None) is None


def test_endpoint_from_listen():
    assert php_fpm._endpoint_from_listen("/run/php.sock", "/status") == {
        "kind": "unix",
        "address": "/run/php.sock",
        "script_name": "/status",
    }
    # status_path without a leading slash is normalised.
    assert php_fpm._endpoint_from_listen("127.0.0.1:9000", "status") == {
        "kind": "tcp",
        "host": "127.0.0.1",
        "port": 9000,
        "script_name": "/status",
    }


def test_endpoint_from_listen_missing_parts():
    assert php_fpm._endpoint_from_listen(None, "/status") is None
    assert php_fpm._endpoint_from_listen("/run/php.sock", None) is None


def test_endpoint_from_listen_bad_tcp():
    assert php_fpm._endpoint_from_listen("host:bad", "/status") is None


# --- pool.d config parsing -------------------------------------------------


def test_parse_pool_file():
    text = (
        "; a comment\n"
        "orphan = 1\n"  # before any [section]: no current pool
        "\n"
        "[global]\n"
        "pid = /run/php-fpm.pid\n"
        "[www]\n"
        "listen = /run/php/www.sock  ; inline comment\n"
        'pm.status_path = "/status"\n'
        "no_equals_line\n"
        "[api]\n"
        "listen = '127.0.0.1:9000'\n"
        "pm.status_path = /api\n"
    )
    assert php_fpm._parse_pool_file(text) == [
        {"name": "global", "listen": None, "status_path": None},
        {"name": "www", "listen": "/run/php/www.sock", "status_path": "/status"},
        {"name": "api", "listen": "127.0.0.1:9000", "status_path": "/api"},
    ]


def test_clean_value():
    assert php_fpm._clean_value(" /run/x.sock ; a comment ") == "/run/x.sock"
    assert php_fpm._clean_value(' "/status" ') == "/status"
    assert php_fpm._clean_value(" '/status' ") == "/status"
    assert php_fpm._clean_value('"') == '"'  # single char: nothing to strip
    assert php_fpm._clean_value('"mismatch') == '"mismatch'  # unmatched quote


# --- discovery -------------------------------------------------------------


def _write(tmp_path, name, content):
    (tmp_path / name).write_text(content)


def test_discover_multi_file(tmp_path, monkeypatch):
    _write(tmp_path, "a.conf", "[www]\nlisten = /run/www.sock\npm.status_path = /status\n")
    _write(tmp_path, "b.conf", "[api]\nlisten = 127.0.0.1:9000\npm.status_path = /status\n")
    monkeypatch.setattr(php_fpm, "_POOL_CONFIG_GLOBS", [str(tmp_path / "*.conf")])
    eps = php_fpm._discover_pools()
    assert eps is not None
    assert len(eps) == 2
    assert {e["kind"] for e in eps} == {"unix", "tcp"}


def test_endpoint_key_and_label_all_kinds():
    http = {"kind": "http", "url": "http://h/status?json"}
    unix = {"kind": "unix", "address": "/run/x.sock", "script_name": "/status"}
    tcp = {"kind": "tcp", "host": "127.0.0.1", "port": 9000, "script_name": "/status"}
    assert php_fpm._endpoint_key(http) == ("http", "http://h/status?json")
    assert php_fpm._endpoint_key(unix) == ("unix", "/run/x.sock", "/status")
    assert php_fpm._endpoint_key(tcp) == ("tcp", "127.0.0.1", 9000, "/status")
    assert php_fpm._endpoint_label(http) == "http://h/status?json"
    assert php_fpm._endpoint_label(unix) == "unix:/run/x.sock/status"
    assert php_fpm._endpoint_label(tcp) == "tcp:127.0.0.1:9000/status"


def test_discover_dedups_identical_endpoints(tmp_path, monkeypatch):
    _write(tmp_path, "a.conf", "[www]\nlisten = /run/www.sock\npm.status_path = /status\n")
    _write(tmp_path, "b.conf", "[dup]\nlisten = /run/www.sock\npm.status_path = /status\n")
    monkeypatch.setattr(php_fpm, "_POOL_CONFIG_GLOBS", [str(tmp_path / "*.conf")])
    eps = php_fpm._discover_pools()
    assert eps is not None
    assert len(eps) == 1


def test_discover_skips_incomplete_pools(tmp_path, monkeypatch):
    _write(
        tmp_path,
        "a.conf",
        "[nolisten]\npm.status_path = /status\n[nostatus]\nlisten = /run/x.sock\n",
    )
    monkeypatch.setattr(php_fpm, "_POOL_CONFIG_GLOBS", [str(tmp_path / "*.conf")])
    assert php_fpm._discover_pools() == []


def test_discover_zero_files(tmp_path, monkeypatch):
    monkeypatch.setattr(php_fpm, "_POOL_CONFIG_GLOBS", [str(tmp_path / "*.conf")])
    assert php_fpm._discover_pools() == []


def test_discover_unreadable_file_returns_none(monkeypatch):
    # An unreadable matched config sinks discovery to None (collection failure),
    # NOT [] -- otherwise a pool that merely can't be read would false-resolve
    # as "operator removed it" and the server would prune its rows.
    monkeypatch.setattr(php_fpm, "_pool_config_files", lambda: ["/no/such/path.conf"])
    assert php_fpm._discover_pools() is None


def test_discover_partial_unreadable_returns_none(tmp_path, monkeypatch):
    # One readable pollable pool + one unreadable file -> None, never a short
    # [www] array that would drop (and prune) whatever the unreadable file held.
    good = tmp_path / "www.conf"
    good.write_text("[www]\nlisten = /run/www.sock\npm.status_path = /status\n")
    monkeypatch.setattr(
        php_fpm, "_pool_config_files", lambda: [str(good), "/no/such/path.conf"]
    )
    assert php_fpm._discover_pools() is None


# --- top-level auto-discovery outcomes -------------------------------------


def test_auto_zero_pools_returns_empty_list(monkeypatch):
    monkeypatch.setattr(php_fpm, "_discover_pools", lambda: [])
    assert php_fpm.php_fpm_metrics(status_page_url="auto") == []


def test_auto_all_success_returns_array(monkeypatch):
    eps = [
        {"kind": "unix", "address": "/a.sock", "script_name": "/status"},
        {"kind": "tcp", "host": "h", "port": 9000, "script_name": "/status"},
    ]
    monkeypatch.setattr(php_fpm, "_discover_pools", lambda: eps)
    monkeypatch.setattr(
        php_fpm,
        "_fetch_status_body",
        lambda ep: json.dumps({"pool": ep.get("address") or ep.get("host")}),
    )
    out = php_fpm.php_fpm_metrics(status_page_url="AUTO")  # case-insensitive sentinel
    assert [p["name"] for p in out] == ["/a.sock", "h"]


def test_auto_partial_failure_returns_null(monkeypatch):
    eps = [
        {"kind": "unix", "address": "/a.sock", "script_name": "/status"},
        {"kind": "tcp", "host": "h", "port": 9000, "script_name": "/status"},
    ]
    monkeypatch.setattr(php_fpm, "_discover_pools", lambda: eps)

    def fetch(ep):
        return json.dumps({"pool": "a"}) if ep["kind"] == "unix" else None

    monkeypatch.setattr(php_fpm, "_fetch_status_body", fetch)
    assert php_fpm.php_fpm_metrics(status_page_url="auto") is None


# --- normalisation ---------------------------------------------------------


def test_normalize_drops_extra_and_fills_missing():
    raw = {"pool": "w", "process manager": "dynamic", "active processes": 2, "junk": "x"}
    out = php_fpm._normalize_pool(raw)
    assert out["name"] == "w"
    assert out["active_processes"] == 2
    assert "junk" not in out
    assert out["accepted_connections"] is None  # absent FPM key -> None
    assert list(out.keys()) == list(php_fpm._FIELD_MAP.values())


# --- FastCGI wire protocol -------------------------------------------------


def test_fcgi_roundtrip_and_request_framing(monkeypatch):
    body = json.dumps(_RAW_WWW)
    sock = FakeSocket(_fcgi_stream(body))
    monkeypatch.setattr(php_fpm, "_fcgi_connect", lambda ep: sock)
    out = php_fpm._fcgi_status_body({"kind": "unix", "address": "/x.sock", "script_name": "/status"})
    assert out == body
    assert sock.closed
    # First record is a BEGIN_REQUEST (version=1, type=1).
    assert sock.sent[0] == 1 and sock.sent[1] == 1
    # The status request carries QUERY_STRING=json.
    assert b"QUERY_STRING" in sock.sent
    assert b"json" in sock.sent


def test_fcgi_default_script_name(monkeypatch):
    sock = FakeSocket(_fcgi_stream(json.dumps(_RAW_WWW)))
    monkeypatch.setattr(php_fpm, "_fcgi_connect", lambda ep: sock)
    php_fpm._fcgi_status_body({"kind": "unix", "address": "/x.sock"})  # no script_name
    assert b"/status" in sock.sent


def test_fcgi_multi_record_stdout(monkeypatch):
    body = json.dumps(_RAW_WWW)
    sock = FakeSocket(_fcgi_stream(body, split=7))
    monkeypatch.setattr(php_fpm, "_fcgi_connect", lambda ep: sock)
    assert php_fpm._fcgi_status_body({"kind": "unix", "address": "/x", "script_name": "/s"}) == body


def test_fcgi_ignores_stderr_and_reads_padding(monkeypatch):
    body = json.dumps(_RAW_WWW)
    payload = ("Content-type: application/json\r\n\r\n" + body).encode()
    stream = _fcgi_record(7, b"a warning") + _fcgi_record(6, payload, pad=5) + _END_REQUEST
    sock = FakeSocket(stream)
    monkeypatch.setattr(php_fpm, "_fcgi_connect", lambda ep: sock)
    assert php_fpm._fcgi_status_body({"kind": "unix", "address": "/x", "script_name": "/s"}) == body


def test_fcgi_empty_stdout_record(monkeypatch):
    body = json.dumps(_RAW_WWW)
    payload = ("H: 1\r\n\r\n" + body).encode()
    stream = _fcgi_record(6, payload) + _fcgi_record(6, b"") + _END_REQUEST
    sock = FakeSocket(stream)
    monkeypatch.setattr(php_fpm, "_fcgi_connect", lambda ep: sock)
    assert php_fpm._fcgi_status_body({"kind": "unix", "address": "/x", "script_name": "/s"}) == body


def test_fcgi_truncated_header_returns_empty(monkeypatch):
    sock = FakeSocket(b"\x01\x06")  # 2 bytes, short of an 8-byte header
    monkeypatch.setattr(php_fpm, "_fcgi_connect", lambda ep: sock)
    assert php_fpm._fcgi_status_body({"kind": "unix", "address": "/x", "script_name": "/s"}) == ""


def test_fcgi_max_body_cap(monkeypatch):
    monkeypatch.setattr(php_fpm, "_FCGI_MAX_BODY", 4)
    payload = ("H: 1\r\n\r\n" + "0123456789").encode()
    sock = FakeSocket(_fcgi_record(6, payload))  # no END_REQUEST: cap must break the loop
    monkeypatch.setattr(php_fpm, "_fcgi_connect", lambda ep: sock)
    out = php_fpm._fcgi_status_body({"kind": "unix", "address": "/x", "script_name": "/s"})
    assert out == "0123456789"


def test_fcgi_connect_error_returns_none(monkeypatch):
    def boom(ep):
        raise OSError("connection refused")

    monkeypatch.setattr(php_fpm, "_fcgi_connect", boom)
    assert php_fpm._fcgi_status_body({"kind": "unix", "address": "/x", "script_name": "/s"}) is None


def test_fcgi_close_error_is_swallowed(monkeypatch):
    class BadClose(FakeSocket):
        def close(self):
            raise OSError("close failed")

    sock = BadClose(_fcgi_stream(json.dumps(_RAW_WWW)))
    monkeypatch.setattr(php_fpm, "_fcgi_connect", lambda ep: sock)
    assert php_fpm._fcgi_status_body({"kind": "unix", "address": "/x", "script_name": "/s"}) is not None


def test_fcgi_body_separators():
    assert php_fpm._fcgi_body(b"H: 1\r\n\r\nBODY") == "BODY"
    assert php_fpm._fcgi_body(b"H: 1\n\nBODY") == "BODY"
    assert php_fpm._fcgi_body(b"rawbody") == "rawbody"


def test_fcgi_pair_length_encoding():
    out = php_fpm._fcgi_pair("N" * 200, "V" * 5)
    assert out[0] & 0x80  # 200 >= 128 -> 4-byte length, high bit set
    assert struct.unpack("!I", out[0:4])[0] & 0x7FFFFFFF == 200
    assert out[4] == 5  # 5 < 128 -> single byte


def test_recv_exact_eof():
    assert php_fpm._recv_exact(FakeSocket(b"abc"), 5) == b"abc"


def test_fcgi_connect_unix(monkeypatch):
    made = {}

    def fake_socket(family, kind):
        made["family"] = family
        made["kind"] = kind
        return FakeSocket()

    monkeypatch.setattr(php_fpm.socket, "socket", fake_socket)
    sock = php_fpm._fcgi_connect({"kind": "unix", "address": "/run/x.sock", "script_name": "/s"})
    assert made["family"] == php_fpm.socket.AF_UNIX
    assert made["kind"] == php_fpm.socket.SOCK_STREAM
    assert sock.connect_addr == "/run/x.sock"
    assert sock.timeout == php_fpm._TIMEOUT


def test_fcgi_connect_unix_without_af_unix(monkeypatch):
    monkeypatch.delattr(php_fpm.socket, "AF_UNIX", raising=False)
    assert php_fpm._fcgi_status_body({"kind": "unix", "address": "/x", "script_name": "/s"}) is None


def test_fcgi_connect_tcp(monkeypatch):
    captured = {}
    fake = FakeSocket()

    def fake_create(addr, timeout):
        captured["addr"] = addr
        captured["timeout"] = timeout
        return fake

    monkeypatch.setattr(php_fpm.socket, "create_connection", fake_create)
    sock = php_fpm._fcgi_connect({"kind": "tcp", "host": "127.0.0.1", "port": 9000, "script_name": "/s"})
    assert captured["addr"] == ("127.0.0.1", 9000)
    assert captured["timeout"] == php_fpm._TIMEOUT
    assert sock.timeout == php_fpm._TIMEOUT


def test_fcgi_transport_end_to_end_via_metrics(monkeypatch):
    """A unix:// URL flows through the real FastCGI encode/decode to a payload."""
    sock = FakeSocket(_fcgi_stream(json.dumps(_RAW_WWW)))
    monkeypatch.setattr(php_fpm, "_fcgi_connect", lambda ep: sock)
    out = php_fpm.php_fpm_metrics(status_page_url="unix:///run/php/php8.2-fpm.sock/status")
    assert out == [_NORM_WWW]


# --- cross-repo contract (fivenines-server) --------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "php_fpm_contract_payload.json"
)


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


def _run_scenario(scenario, tmp_path, monkeypatch):
    raw = scenario.get("raw_status", {})

    def fake_fetch(endpoint):
        body = raw.get(php_fpm._endpoint_label(endpoint))
        return None if body is None else json.dumps(body)

    monkeypatch.setattr(php_fpm, "_fetch_status_body", fake_fetch)
    if "pool_configs" in scenario:
        for fname, content in scenario["pool_configs"].items():
            (tmp_path / fname).write_text(content)
        monkeypatch.setattr(php_fpm, "_POOL_CONFIG_GLOBS", [str(tmp_path / "*.conf")])
    return php_fpm.php_fpm_metrics(**scenario["config"])


@pytest.mark.parametrize(
    "name", ["healthy_multi_pool", "zero_pools", "collection_failure", "partial_failure"]
)
def test_contract_fixture_round_trip(name, tmp_path, monkeypatch):
    """SHARED FIXTURE (cross-repo contract): fixtures/php_fpm_contract_payload.json.

    Asserted on both sides:
    - here: php_fpm_metrics(**scenario["config"]) must equal scenario["payload"]
      with only the transport mocked (raw_status fed per endpoint, pool.d configs
      written to a temp dir for auto-discovery);
    - fivenines-server: spec/requests/api_collect_php_fpm_spec.rb posts
      scenario["payload"] under data["php_fpm"] and asserts Ingesters::Agent
      handles the array / [] / null shapes.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    fixture = _load_fixture()
    scenario = fixture["scenarios"][name]
    assert _run_scenario(scenario, tmp_path, monkeypatch) == scenario["payload"]


def test_fixture_agent_min_version():
    assert _load_fixture()["agent_min_version"] == "1.13.1"


def test_fixture_payload_keys_match_field_map():
    payload = _load_fixture()["scenarios"]["healthy_multi_pool"]["payload"]
    for pool in payload:
        assert list(pool.keys()) == list(php_fpm._FIELD_MAP.values())


def test_fixture_config_is_documented_shape():
    fixture = _load_fixture()
    for scenario in fixture["scenarios"].values():
        assert set(scenario["config"]) == {"status_page_url"}
