"""Tests for the Apache mod_status ?auto collector (server issue #489).

Only requests.get is mocked; each case feeds a canned ?auto body back through
the real parse -> payload pipeline. Mirrors the Nginx integration but parses by
key name (MPM/version-tolerant) instead of positional index, so mpm_prefork and
mpm_event both yield the same payload keys.
"""

import json
import os
from typing import Optional
from unittest.mock import MagicMock, patch

import requests

from fivenines_agent.apache import apache_metrics


def _response(text="", status=200, server: Optional[str] = "Apache/2.4.52 (Ubuntu)"):
    """A stand-in requests.Response: status_code, text, and a real headers dict.

    server=None models a response with no Server header (headers.get returns
    None).
    """
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = {} if server is None else {"Server": server}
    return resp


# Realistic mpm_prefork ?auto: no event-only fields, single worker lines. The
# scoreboard is internally consistent (8 idle _, 2 busy W) but the collector
# never depends on that.
PREFORK_AUTO = "\n".join(
    [
        "127.0.0.1",
        "ServerVersion: Apache/2.4.41 (Ubuntu)",
        "ServerMPM: prefork",
        "ServerUptimeSeconds: 7200",
        "Total Accesses: 500",
        "Total kBytes: 2048",
        "CPULoad: .00972222",
        "Uptime: 7200",
        "ReqPerSec: .0694444",
        "BytesPerSec: 291.271",
        "BytesPerReq: 4194.3",
        "BusyWorkers: 2",
        "IdleWorkers: 8",
        "Scoreboard: ________WW..",
        "",
    ]
)

_PREFORK_EMPTY_STATES = {
    "starting": 0,
    "reading": 0,
    "keepalive": 0,
    "dns_lookup": 0,
    "closing": 0,
    "logging": 0,
    "graceful": 0,
    "idle_cleanup": 0,
}


def test_prefork_full_payload_no_none():
    resp = _response(text=PREFORK_AUTO, server="Apache/2.4.41 (Ubuntu)")
    with patch("fivenines_agent.apache.requests.get", return_value=resp):
        out = apache_metrics()

    assert out == {
        "apache_version": "Apache/2.4.41 (Ubuntu)",
        "requests_per_second": 0.0694444,
        "bytes_per_second": 291.271,
        "busy_workers": 2,
        "idle_workers": 8,
        "total_accesses": 500,
        "total_kbytes": 2048,
        "scoreboard": {"waiting": 8, "sending": 2, "open": 2, **_PREFORK_EMPTY_STATES},
    }
    # A healthy scrape has no None among the seven read fields.
    for key in (
        "requests_per_second",
        "bytes_per_second",
        "busy_workers",
        "idle_workers",
        "total_accesses",
        "total_kbytes",
    ):
        assert out[key] is not None


# Realistic mpm_event ?auto: event-only fields the collector must ignore, and
# the duplicated BusyWorkers/IdleWorkers pair mpm_event emits. Distinct values
# are used across the two blocks to pin the "last occurrence wins" behaviour
# (real Apache emits identical values, so the choice is harmless either way).
EVENT_AUTO = "\n".join(
    [
        "127.0.0.1",
        "ServerVersion: Apache/2.4.52 (Ubuntu)",
        "ServerMPM: event",
        "Total Accesses: 1250",
        "Total kBytes: 8945",
        "ReqPerSec: .345304",
        "BytesPerSec: 2529.71",
        "BusyWorkers: 5",
        "IdleWorkers: 45",
        "Processes: 2",
        "Stopping: 0",
        "BusyWorkers: 1",
        "IdleWorkers: 49",
        "ConnsTotal: 3",
        "ConnsAsyncWriting: 0",
        "ConnsAsyncKeepAlive: 1",
        "ConnsAsyncClosing: 0",
        "Scoreboard: __W_K.C",
        "",
    ]
)


def test_event_duplicate_workers_last_wins_and_event_fields_ignored():
    resp = _response(text=EVENT_AUTO)
    with patch("fivenines_agent.apache.requests.get", return_value=resp):
        out = apache_metrics()

    # Last occurrence of the duplicated worker lines wins.
    assert out["busy_workers"] == 1
    assert out["idle_workers"] == 49
    assert out["requests_per_second"] == 0.345304
    assert out["bytes_per_second"] == 2529.71
    assert out["total_accesses"] == 1250
    assert out["total_kbytes"] == 8945

    # Event-only fields never leak into the payload: the key set is fixed and
    # identical to prefork's.
    assert set(out) == {
        "apache_version",
        "requests_per_second",
        "bytes_per_second",
        "busy_workers",
        "idle_workers",
        "total_accesses",
        "total_kbytes",
        "scoreboard",
    }

    # "__W_K.C" -> three waiting (_), one each of sending/keepalive/open/closing.
    assert out["scoreboard"] == {
        "waiting": 3,
        "sending": 1,
        "keepalive": 1,
        "open": 1,
        "closing": 1,
        "starting": 0,
        "reading": 0,
        "dns_lookup": 0,
        "logging": 0,
        "graceful": 0,
        "idle_cleanup": 0,
    }


def test_scoreboard_counts_every_state():
    # Two waiting plus exactly one of each remaining state, in scoreboard-char
    # order: _ _ S R W K D C L G I .
    resp = _response(text="Scoreboard: __SRWKDCLGI.\n")
    with patch("fivenines_agent.apache.requests.get", return_value=resp):
        out = apache_metrics()

    assert out["scoreboard"] == {
        "waiting": 2,
        "starting": 1,
        "reading": 1,
        "sending": 1,
        "keepalive": 1,
        "dns_lookup": 1,
        "closing": 1,
        "logging": 1,
        "graceful": 1,
        "idle_cleanup": 1,
        "open": 1,
    }


def test_scoreboard_ignores_unknown_chars_and_absence():
    # An unmapped character (Z, whitespace) is dropped, not bucketed; an absent
    # Scoreboard line yields an all-zero board rather than a crash.
    resp = _response(text="Scoreboard: __Z W\n")
    with patch("fivenines_agent.apache.requests.get", return_value=resp):
        board = apache_metrics()["scoreboard"]
    assert board["waiting"] == 2
    assert board["sending"] == 1
    assert sum(board.values()) == 3  # Z and the space contribute nothing

    resp = _response(text="BusyWorkers: 1\n")  # no Scoreboard line at all
    with patch("fivenines_agent.apache.requests.get", return_value=resp):
        board = apache_metrics()["scoreboard"]
    assert set(board.values()) == {0}
    assert len(board) == 11


def test_missing_and_unparsable_fields_return_none():
    # BusyWorkers is non-numeric (ValueError path); every other read field is
    # absent (KeyError path). Both coerce to None without sinking the payload,
    # and the scoreboard is still computed.
    resp = _response(text="BusyWorkers: notanumber\nScoreboard: __\n")
    with patch("fivenines_agent.apache.requests.get", return_value=resp):
        out = apache_metrics()

    assert out["busy_workers"] is None
    assert out["idle_workers"] is None
    assert out["requests_per_second"] is None
    assert out["bytes_per_second"] is None
    assert out["total_accesses"] is None
    assert out["total_kbytes"] is None
    assert out["scoreboard"]["waiting"] == 2


def test_present_but_unparsable_float_returns_none():
    # A present-but-non-numeric ReqPerSec must hit the as_float ValueError arm
    # (-> None) without sinking the payload; a sibling field still parses. Pins
    # the float branch independently of the int branch (which shares the
    # except clause), so narrowing as_float to `except KeyError` would fail here.
    resp = _response(text="ReqPerSec: n/a\nBusyWorkers: 3\n")
    with patch("fivenines_agent.apache.requests.get", return_value=resp):
        out = apache_metrics()
    assert out["requests_per_second"] is None
    assert out["busy_workers"] == 3


def test_non_200_returns_none():
    resp = _response(text=PREFORK_AUTO, status=500)
    with patch("fivenines_agent.apache.requests.get", return_value=resp):
        assert apache_metrics() is None


def test_timeout_returns_none():
    with patch(
        "fivenines_agent.apache.requests.get",
        side_effect=requests.exceptions.Timeout("timed out"),
    ):
        assert apache_metrics() is None


def test_connection_error_returns_none():
    with patch(
        "fivenines_agent.apache.requests.get",
        side_effect=requests.exceptions.ConnectionError("refused"),
    ):
        assert apache_metrics() is None


def test_missing_server_header_yields_none_version():
    resp = _response(text=PREFORK_AUTO, server=None)
    with patch("fivenines_agent.apache.requests.get", return_value=resp):
        out = apache_metrics()
    assert out["apache_version"] is None
    assert out["busy_workers"] == 2  # the rest still parses


def test_auto_appended_to_bare_url():
    resp = _response(text=PREFORK_AUTO)
    with patch("fivenines_agent.apache.requests.get", return_value=resp) as mock_get:
        apache_metrics(status_page_url="http://localhost/server-status")
    assert mock_get.call_args[0][0] == "http://localhost/server-status?auto"
    assert mock_get.call_args.kwargs["timeout"] == 5


def test_auto_appended_with_ampersand_when_query_present():
    resp = _response(text=PREFORK_AUTO)
    with patch("fivenines_agent.apache.requests.get", return_value=resp) as mock_get:
        apache_metrics(status_page_url="http://localhost/server-status?refresh=5")
    assert mock_get.call_args[0][0] == "http://localhost/server-status?refresh=5&auto"


def test_url_already_machine_readable_is_unchanged():
    resp = _response(text=PREFORK_AUTO)
    url = "http://127.0.0.1/server-status?auto"
    with patch("fivenines_agent.apache.requests.get", return_value=resp) as mock_get:
        apache_metrics(status_page_url=url)
    assert mock_get.call_args[0][0] == url


def test_auto_appended_when_host_or_path_contains_auto_substring():
    # The "already machine-readable" check is scoped to the query string, so a
    # host (autoconfig.internal) or path (/auto-status) carrying the substring
    # "auto" must still get ?auto appended -- otherwise Apache serves HTML and
    # the collector silently returns a mostly-None payload.
    resp = _response(text=PREFORK_AUTO)
    for url, expected in (
        ("http://autoconfig.internal/server-status", "http://autoconfig.internal/server-status?auto"),
        ("http://localhost/auto-status", "http://localhost/auto-status?auto"),
    ):
        with patch("fivenines_agent.apache.requests.get", return_value=resp) as mock_get:
            apache_metrics(status_page_url=url)
        assert mock_get.call_args[0][0] == expected


# --- cross-repo contract (fivenines-server) -------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "apache_contract_payload.json"
)

# The exact keys the server ingester reads. A rename or drop must fail loudly
# here, not silently zero the server-side metrics.
_PAYLOAD_KEYS = {
    "apache_version",
    "requests_per_second",
    "bytes_per_second",
    "busy_workers",
    "idle_workers",
    "total_accesses",
    "total_kbytes",
    "scoreboard",
}
_SCOREBOARD_STATES = {
    "waiting",
    "starting",
    "reading",
    "sending",
    "keepalive",
    "dns_lookup",
    "closing",
    "logging",
    "graceful",
    "idle_cleanup",
    "open",
}


def test_contract_fixture_round_trip():
    """SHARED FIXTURE (cross-repo contract): fixtures/apache_contract_payload.json.

    Asserted on both sides:
    - here: apache_metrics(**fixture["config"]["apache"]) must equal
      fixture["payload"]["apache"] with only requests.get mocked (the fixture's
      raw "?auto" body fed back as response.text, "server_header" as the Server
      header), pinning parse -> payload;
    - fivenines-server: spec/requests/api_collect_apache_spec.rb posts
      payload["apache"] under data["apache"] and asserts Ingesters::Agent
      ingests it.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)

    config = fixture["config"]["apache"]
    resp = _response(text=fixture["raw_auto"], server=fixture["server_header"])
    with patch("fivenines_agent.apache.requests.get", return_value=resp) as mock_get:
        out = apache_metrics(**config)

    assert out == fixture["payload"]["apache"]
    # The URL is scraped verbatim (it already carries ?auto).
    assert mock_get.call_args[0][0] == config["status_page_url"]
    assert set(out) == _PAYLOAD_KEYS
    assert set(out["scoreboard"]) == _SCOREBOARD_STATES


def test_fixture_config_is_the_documented_shape():
    """The agent receives config["apache"] == {status_page_url}; the fixture's
    config pins that contract shape (no extra keys)."""
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)
    assert set(fixture["config"]["apache"]) == {"status_page_url"}
    assert fixture["agent_min_version"] == "1.11.5"
