"""Tests for the Proxmox Backup Server collector.

Only the HTTP transport is mocked: a FakeSession routes each request path to a
recorded response, feeding status codes and JSON bodies through the real
classification, privilege check and group/snapshot merge. The contract
round-trip replays responses captured from a real PBS 4.2
(tests/fixtures/pbs_contract_payload.json).
"""

import contextlib
import gzip
import hashlib
import http.server
import importlib.util
import json
import math
import os
import random
import re
import shutil
import ssl
import subprocess
import threading
import time
import tracemalloc
import warnings
from unittest.mock import MagicMock
from urllib.parse import unquote, urlencode

import pytest
import requests

from fivenines_agent import pbs
from fivenines_agent.cache import TTLCache
from fivenines_agent.http_body import BodyOverBudget

FINGERPRINT = "b7:24:5c:7a:78:c1:25:6c:0d:a9:ff:4a:6c:30:2e:10:03:ce:82:2c:00:d7:e9:82:1e:fc:00:93:f4:de:85:4f"
SECRET = "0000-secret"
TOKEN = {"token_id": "fivenines@pbs!monitoring", "token_secret": SECRET}
LOOPBACK = {"host": "localhost", "verify_ssl": False, **TOKEN}
GC_UPID = "UPID:n:00000025:000023D8:0000000A:0000000B:garbage_collection:ds:root@pam:"


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    monkeypatch.setattr(pbs, "_cache", TTLCache())
    monkeypatch.setattr(pbs, "_rotation", None)
    monkeypatch.setattr(pbs, "_local_nodes", set())
    monkeypatch.setattr(pbs, "_stalled_worker", None)
    monkeypatch.setattr(pbs, "_stalled_progress", {})
    monkeypatch.setattr(pbs, "_timeout_backoff", {})
    monkeypatch.setattr(pbs, "_auth_backoff", None)
    monkeypatch.setattr(pbs, "_last_logged_failure", None)
    monkeypatch.setattr(pbs, "_store_rotation", None)
    monkeypatch.setattr(pbs, "_read_failures", {"previous": set(), "current": set()})
    monkeypatch.setattr(pbs, "_read_failure_lines", {"error": 0, "quieted": 0})


# --- test doubles ----------------------------------------------------------


class FakeResponse:
    """A streamed requests.Response stand-in (the collector reads bodies via
    iter_content under a byte cap, never .json())."""

    def __init__(self, status=200, json_body=None, body=""):
        self.status_code = status
        if json_body is not None:
            self._raw = json.dumps(json_body).encode("utf-8")
        else:
            self._raw = body.encode("utf-8")
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for i in range(0, len(self._raw), chunk_size):
            yield self._raw[i:][:chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, handler):
        self._handler = handler
        self.calls = []
        self.timeouts = []
        self.closed = False

    def get(self, url, params=None, timeout=None, stream=None, allow_redirects=None):
        # The host is server-pushed: every request is streamed, refuses
        # redirects, and is bounded -- never an unbounded wait on the
        # watchdog-bounded collection loop.
        assert stream is True and allow_redirects is False
        connect, read = timeout
        assert 0 < connect <= 5 and 0 < read <= 10
        if params:
            url += "?" + urlencode(params)
        self.calls.append(url)
        self.timeouts.append(timeout)
        try:
            return self._handler(url)
        except requests.exceptions.ReadTimeout as e:
            # The wait a real timeout takes: the whole read timeout for a
            # request sent and left unanswered; only the connect timeout for a
            # TLS handshake that stalled (urllib3 reports it as a read one).
            if isinstance(pbs.time, Clock):
                pbs.time.now += connect if isinstance(e, HandshakeStall) else read
            raise

    def close(self):
        self.closed = True


class Clock:
    """A monotonic clock for pbs.time (and optionally the cache) only, so no
    other module's reads consume the budget under test."""

    def __init__(self, now=1000.0):
        self.now = now

    def monotonic(self):
        return self.now

    def time(self):
        # The wall clock (a block's built_at) moves with the monotonic one.
        return 1_790_000_000.0 + self.now


def use_clock(monkeypatch, clock, cache_too=False):
    monkeypatch.setattr(pbs, "time", clock)
    if cache_too:
        monkeypatch.setattr("fivenines_agent.cache.time", clock)
    return clock


_BASE_RE = re.compile(r"^https://[^/]+/api2/json")


class HandshakeStall(requests.exceptions.ReadTimeout):
    """A TLS handshake that stalled: urllib3 raises a read timeout for it."""


_TRANSPORT_ERRORS = {
    "connection_refused": requests.exceptions.ConnectionError,
    "handshake_timeout": HandshakeStall,
    # A request sent and not answered in time (PBS may still be running it).
    "timeout": requests.exceptions.ReadTimeout,
    "connect_timeout": requests.exceptions.ConnectTimeout,
    "tls_error": requests.exceptions.SSLError,
    "request_error": requests.exceptions.RequestException,
}


def route(url):
    """The fixture key of a request: its path and decoded query."""
    return unquote(_BASE_RE.sub("", url))


def responses_handler(responses):
    def handler(url):
        key = route(url)
        desc = responses.get(key)
        if desc is None:
            # pytest.fail is a BaseException: the collector's `except
            # Exception` cannot turn an unexpected request into a passing
            # http_error envelope.
            pytest.fail(f"no recorded response for {key}")
        if "error" in desc:
            raise _TRANSPORT_ERRORS[desc["error"]](desc.get("message", ""))
        if "json" in desc:
            return FakeResponse(desc["status"], json_body=desc["json"])
        return FakeResponse(desc["status"], body=desc.get("body", ""))

    return handler


def install(monkeypatch, responses, peer_fingerprint=None, presented=None):
    session = FakeSession(responses_handler(responses))
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: peer_fingerprint)
    monkeypatch.setattr(
        pbs, "_presented_fingerprint", lambda target, deadline: presented
    )
    return session


def scenario_responses(fixture, scenario):
    """A scenario's recorded responses: its own, over those of the scenario
    named by `responses_base` (a derived scenario states only its delta)."""
    base = scenario.get("responses_base")
    responses = dict(fixture["scenarios"][base]["responses"]) if base else {}
    responses.update(scenario.get("responses", {}))
    return responses


# Frozen in the fixture: every scenario's block was "built" at this epoch.
FIXTURE_BUILT_AT = 1790640000


def run_scenario(fixture, scenario, monkeypatch, sessions=None):
    # A simulated clock, so a replayed read timeout takes its read timeout
    # (as on the wire) and a timed-out walk arms the hold.
    use_clock(monkeypatch, Clock())
    monkeypatch.setattr(pbs, "_epoch", lambda: FIXTURE_BUILT_AT)
    if scenario.get("agent_state", {}).get("walks_held"):
        # An earlier build of this agent armed the walk hold.
        failure = ("namespaces", "store1", None, "armed by an earlier build")
        pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    session = install(
        monkeypatch,
        scenario_responses(fixture, scenario),
        scenario.get("peer_fingerprint"),
        scenario.get("presented_fingerprint"),
    )
    if sessions is not None:
        sessions.append(session)
    return pbs.pbs_metrics(**scenario["config"]["pbs"])


def ok(data):
    return {"status": 200, "json": {"data": data}}


def fail(status, body=""):
    return {"status": status, "body": body}


# A small, fully-read PBS used by the unit tests: one datastore, the root
# namespace only, one group with two finished snapshots.
PERMS_FULL = {
    "/datastore": {"Datastore.Audit": True},
    "/remote": {"Remote.Audit": True},
}


def snapshot(
    btype, bid, when, size=100, files=None, verification=None, protected=False
):
    snap = {
        "backup-type": btype,
        "backup-id": bid,
        "backup-time": when,
        "owner": "u@pbs",
    }
    snap["files"] = (
        files
        if files is not None
        else [
            {"filename": "root.pxar.didx", "crypt-mode": "none", "size": size},
            {"filename": "index.json.blob", "crypt-mode": "none", "size": 300},
        ]
    )
    if size is not None:
        snap["size"] = size
        snap["protected"] = protected
    if verification is not None:
        snap["verification"] = verification
    return snap


VERIFY_OK = {"state": "ok", "upid": "UPID:n:1:2:3:0000000A:verify:ds:root@pam:"}


def verified(state, store="ds"):
    """A verification that ran on `store` of this PBS (node n, as GC_UPID)."""
    return {"state": state, "upid": f"UPID:n:1:2:3:0000000A:verify:{store}:root@pam:"}


# What a PBS older than 3.3 answers to sync-direction=all (older_pbs scenario).
_NO_SYNC_DIRECTION = (
    "parameter verification failed - 'sync-direction': "
    "schema does not allow additional properties."
)


def minimal_responses(**overrides):
    responses = {
        "/version": ok({"release": "0", "repoid": "x", "version": "4.2"}),
        "/access/permissions": ok(PERMS_FULL),
        "/admin/datastore": ok(
            [
                {
                    "store": "ds",
                    "backend-type": "filesystem",
                    "mount-status": "nonremovable",
                }
            ]
        ),
        "/status/datastore-usage": ok(
            [
                {
                    "store": "ds",
                    "total": 1000,
                    "used": 400,
                    "avail": 600,
                    "estimated-full-date": 1900000000,
                }
            ]
        ),
        "/admin/sync?sync-direction=all": ok([]),
        "/admin/verify": ok([]),
        "/admin/prune": ok([]),
        # Read only when the listing names no backend (PBS < 4.1.7): no
        # backend property means a filesystem datastore.
        "/config/datastore": ok(
            [{"name": n} for n in ("ds", "a", "b", "c", "d", "zz", "s0", "s1")]
        ),
        "/admin/datastore/ds/gc": ok(
            {"store": "ds", "last-run-state": "OK", "disk-bytes": 10, "upid": GC_UPID}
        ),
        "/admin/datastore/ds/namespace": ok([{"ns": ""}]),
        "/admin/datastore/ds/groups": ok(
            [
                {
                    "backup-type": "vm",
                    "backup-id": "100",
                    "backup-count": 2,
                    "last-backup": 200,
                }
            ]
        ),
        "/admin/datastore/ds/snapshots": ok(
            [
                snapshot("vm", "100", 100, verification=VERIFY_OK),
                snapshot("vm", "100", 200),
            ]
        ),
    }
    responses.update(overrides)
    return responses


def collect(monkeypatch, responses, keep_cache=False, **config):
    """One tick. The block cache is reset first unless keep_cache, so a test
    can collect several variants back to back."""
    if not keep_cache:
        monkeypatch.setattr(pbs, "_cache", TTLCache())
    session = install(monkeypatch, responses)
    out = pbs.pbs_metrics(**{**LOOPBACK, **config})
    return out, session


def capture_logs(monkeypatch):
    logged = []
    monkeypatch.setattr(
        pbs, "log", lambda message, level="info": logged.append((level, message))
    )
    return logged


def _target(**overrides):
    config = {
        "host": "localhost",
        "port": 8007,
        "token_id": "a@pbs!t",
        "token_secret": SECRET,
        "verify_ssl": False,
        "fingerprint": None,
    }
    config.update(overrides)
    return pbs._Target(**config)


# --- cross-repo contract (fivenines-server) --------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "pbs_contract_payload.json"
)

_SUCCESS_KEYS = {
    "scope",
    "reachable",
    "version",
    "release",
    "fingerprint",
    "age_s",
    "built_at",
    "walks_held",
    "datastores",
    "groups",
    "sync_jobs",
    "verify_jobs",
    "prune_jobs",
    "errors",
}
_FAILURE_KEYS = {"reachable", "error_type", "error_message"}
_DATASTORE_KEYS = {
    "store",
    "backend_type",
    "mount_status",
    "maintenance_mode",
    "maintenance_message",
    "total",
    "used",
    "avail",
    "estimated_full_date",
    "gc",
    "namespaces",
    "unread_namespaces",
}
_GROUP_KEYS = {
    "store",
    "ns",
    "type",
    "id",
    "last_backup",
    "count",
    "in_progress",
    "in_progress_since",
    "size",
    "crypt_mode",
    "protected",
    "verify_state",
    "verify_time",
    "last_verified_ok",
    "verify_failed_count",
}
_CONFIG_KEYS = {"host", "port", "token_id", "token_secret", "verify_ssl", "fingerprint"}
_ERROR_TYPES = {
    "config_error",
    "connection_refused",
    "timeout",
    "tls_error",
    "auth_failed",
    "http_error",
    "over_privileged",
    "no_datastore_access",
}


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


_SCENARIOS = [
    "healthy",
    "scoped_token",
    "offline_datastore",
    "over_privileged",
    "no_datastore_access",
    "auth_failed",
    "unreachable",
    "tls_fingerprint_mismatch",
    "remote_unverified_refused",
    "snapshots_unreadable",
    "older_pbs",
    "first_backup_in_progress",
    "namespace_walk_held",
    "namespace_walk_held_steady",
]


def test_fixture_scenarios_are_all_asserted():
    assert sorted(_load_fixture()["scenarios"]) == sorted(_SCENARIOS)


@pytest.mark.parametrize("name", _SCENARIOS)
def test_contract_fixture_round_trip(name, monkeypatch):
    """SHARED FIXTURE (cross-repo contract): fixtures/pbs_contract_payload.json.

    pbs_metrics(**scenario["config"]["pbs"]) must equal
    scenario["payload"]["pbs"] with only the HTTP transport mocked: the
    recorded responses (captured from a real PBS 4.2, except the scenarios
    marked synthetic) replay through the real classification, privilege check
    and merge. The server keeps a byte-identical copy and posts each payload
    under data["pbs"]; change the shape only in lockstep with it.
    """
    fixture = _load_fixture()
    scenario = fixture["scenarios"][name]
    assert run_scenario(fixture, scenario, monkeypatch) == scenario["payload"]["pbs"]


# Responses a scenario records on purpose although the agent never asks for
# them.
_UNREQUESTED_ON_PURPOSE = {
    # The privilege check refuses the token first; the listing PBS would
    # answer (empty) is recorded to show it.
    ("no_datastore_access", "/admin/datastore"),
    # Captured to show PBS omitting the keys for a namespace-scoped token,
    # which never reads it (it would walk every other datastore).
    ("scoped_token", "/status/datastore-usage"),
}


# Value: protects=every response a scenario records is one the agent asks
#   for (the server reads them as the evidence behind each payload);
#   fails_when=the agent stops reading an endpoint and the fixture keeps
#   describing it (scoped_token kept its usage status capture after scoped
#   tokens stopped reading it); why_new=nothing compared what a scenario
#   records with what the agent requests; seam=none
@pytest.mark.parametrize("name", _SCENARIOS)
def test_every_recorded_response_is_requested(name, monkeypatch):
    fixture = _load_fixture()
    scenario = fixture["scenarios"][name]
    sessions = []
    run_scenario(fixture, scenario, monkeypatch, sessions)
    requested = {route(u) for u in sessions[0].calls}
    unused = {(name, key) for key in scenario.get("responses", {})} - {
        (name, key) for key in requested
    }
    assert unused == {e for e in _UNREQUESTED_ON_PURPOSE if e[0] == name}


# Value: protects=every 'skipped: ...' message errors_contract quotes is one
#   the agent ships, and every one it ships is quoted (the server matches
#   them); fails_when=a message is reworded on one side only; why_new=the
#   tests compared each constant with itself; seam=none
def test_every_skip_message_the_contract_quotes_is_the_one_the_agent_ships():
    texts = _load_fixture()["errors_contract"].values()
    quoted = [q for text in texts for q in re.findall(r"'(skipped:[^']*)'", text)]
    shipped = {
        pbs._DEADLINE_MESSAGE,
        pbs._TIMEOUT_BACKOFF_MESSAGE,
        pbs._TIMEOUT_HOLD_MESSAGE,
    }
    matched = set()
    for quote in quoted:
        # '(...)' in a quote stands for an elided part.
        pattern = ".*".join(re.escape(p) for p in quote.split("(...)"))
        hits = {m for m in shipped if re.fullmatch(pattern, m)}
        assert hits, quote
        matched |= hits
    assert matched == shipped


def test_fixture_agent_min_version():
    # A frozen literal, never the live pyproject version (a release bump must
    # not break this test).
    assert _load_fixture()["agent_min_version"] == "1.21.0"


def test_every_build_has_its_own_built_at_and_re_emissions_share_it(
    monkeypatch,
):
    """built_at is the build's identity: the server's two-absences prune rule
    counts builds, and a cached block is re-emitted ~5 times per TTL."""
    clock = use_clock(monkeypatch, Clock(), cache_too=True)
    first, _ = collect(monkeypatch, minimal_responses())
    clock.now += 60
    again, _ = collect(monkeypatch, minimal_responses(), keep_cache=True)
    clock.now += pbs.PBS_CACHE_TTL
    rebuilt, _ = collect(monkeypatch, minimal_responses(), keep_cache=True)
    assert first["built_at"] == again["built_at"] == 1_790_001_000
    assert again["age_s"] == 60
    assert rebuilt["built_at"] == first["built_at"] + 60 + pbs.PBS_CACHE_TTL


def test_fixture_shapes():
    for name, scenario in _load_fixture()["scenarios"].items():
        assert set(scenario["config"]["pbs"]) == _CONFIG_KEYS, name
        payload = scenario["payload"]["pbs"]
        if "error_type" in payload:
            expected = set(_FAILURE_KEYS)
            if payload["error_type"] == "tls_error":
                expected.add("presented_fingerprint")
            assert set(payload) == expected, name
            assert payload["error_type"] in _ERROR_TYPES, name
            assert "datastores" not in payload  # the server keys ingestion off this
            continue
        assert set(payload) == _SUCCESS_KEYS, name
        for datastore in payload["datastores"]:
            assert set(datastore) == _DATASTORE_KEYS, name
        for group in payload["groups"]:
            assert set(group) == _GROUP_KEYS, name


def test_fixture_is_ascii():
    with open(_FIXTURE_PATH, "rb") as f:
        f.read().decode("ascii")


# --- config validation -----------------------------------------------------


@pytest.mark.parametrize(
    "host, bare, url_host, loopback",
    [
        ("localhost", "localhost", "localhost", True),
        ("LOCALHOST", "LOCALHOST", "LOCALHOST", True),
        ("127.0.0.1", "127.0.0.1", "127.0.0.1", True),
        (" 127.0.0.2 ", "127.0.0.2", "127.0.0.2", True),
        ("::1", "::1", "[::1]", True),
        ("[::1]", "::1", "[::1]", True),
        ("10.0.0.5", "10.0.0.5", "10.0.0.5", False),
        ("2001:db8::1", "2001:db8::1", "[2001:db8::1]", False),
        ("pbs.example.com", "pbs.example.com", "pbs.example.com", False),
    ],
)
def test_url_host_accepts_hostnames_and_ip_literals(host, bare, url_host, loopback):
    assert pbs._url_host(host) == (bare, url_host, loopback)


@pytest.mark.parametrize(
    "host",
    [
        None,
        12,
        "",
        "pbs/evil",
        "user@pbs",
        "pbs:8007",
        "pbs example",
        "fe80::1%eth0",
        "-pbs",
    ],
)
def test_url_host_refuses_anything_that_could_reshape_the_url(host):
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._url_host(host)
    assert excinfo.value.error_type == "config_error"


@pytest.mark.parametrize("unset", [None, ""])
def test_null_or_blank_host_and_port_mean_the_defaults(unset):
    # The server may send null, or a form may post "", for an unset field;
    # neither is a config error.
    target = _target(host=unset, port=unset)
    assert target.base == "https://127.0.0.1:8007/api2/json"
    assert target.verify is False  # localhost is loopback


def test_valid_port():
    assert pbs._valid_port("8007") == 8007
    for bad in (0, 65536, True, "x", None):
        with pytest.raises(pbs._PbsError):
            pbs._valid_port(bad)


def test_authorization_header():
    assert pbs._authorization("a@pbs!t", "s3cret") == "PBSAPIToken=a@pbs!t:s3cret"
    assert (
        pbs._authorization("first.last@pam!mon-1", "x")
        == "PBSAPIToken=first.last@pam!mon-1:x"
    )


@pytest.mark.parametrize(
    "token_id, secret",
    [
        (None, "s"),
        ("a@pbs!t", None),
        ("", "s"),
        (5, "s"),
        ("a@pbs!t", 5),
        ("a@pbs", "s"),  # a user, not a token
        ("a b@pbs!t", "s"),
        ("a@pbs!t\r\nX: y", "s"),
        ("\xe9@pbs!t", "s"),
        ("a\x00@pbs!t", "s"),
        ("a\x7f@pbs!t", "s"),
        ("a\x1b[31m@pbs!t", "s"),
        ("a@pbs!t", "has space"),
        ("a@pbs!t", "line\nbreak"),
        ("a@pbs!t", "x" * 257),
    ],
)
def test_authorization_refuses_malformed_tokens(token_id, secret):
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._authorization(token_id, secret)
    assert excinfo.value.error_type == "config_error"


def test_normalize_fingerprint():
    assert pbs._normalize_fingerprint(None) is None
    assert pbs._normalize_fingerprint("") is None
    assert pbs._normalize_fingerprint(FINGERPRINT.upper()) == FINGERPRINT
    assert (
        pbs._normalize_fingerprint(" " + FINGERPRINT.replace(":", "") + " ")
        == FINGERPRINT
    )
    for bad in (12, "b7:24", "zz" * 32, FINGERPRINT + ":00"):
        with pytest.raises(pbs._PbsError):
            pbs._normalize_fingerprint(bad)


@pytest.mark.parametrize(
    "value, expected",
    [
        (False, False),
        (0, False),
        ("false", False),
        (" OFF ", False),
        ("no", False),
        ("0", False),
        (True, True),
        (None, True),
        (1, True),
        ("yes", True),
        ("garbage", True),
        ([], True),
    ],
)
def test_config_bool_only_explicit_false_disables_verification(value, expected):
    assert pbs._config_bool(value) is expected


def test_target_tls_policy():
    pinned = _target(host="pbs.example", fingerprint=FINGERPRINT)
    assert pinned.verify is False and pinned.fingerprint == FINGERPRINT
    verified = _target(host="pbs.example", verify_ssl=True)
    assert verified.verify is True and verified.fingerprint is None
    local = _target(host="127.0.0.1")
    assert local.verify is False
    assert local.base == "https://127.0.0.1:8007/api2/json"
    with pytest.raises(pbs._PbsError) as excinfo:
        _target(host="pbs.example")
    assert excinfo.value.error_type == "config_error"
    assert excinfo.value.reachable is False


def test_target_cache_key_never_holds_the_secret():
    target = _target(token_secret="sup3r-secret")
    assert "sup3r-secret" not in repr(target.cache_key)
    assert target.secret_digest == hashlib.sha256(b"sup3r-secret").hexdigest()


def test_target_redacts_its_secret():
    target = _target()
    assert target.redact(RuntimeError(f"PBSAPIToken=a@pbs!t:{SECRET}")) == (
        "PBSAPIToken=a@pbs!t:[REDACTED]"
    )


def test_config_error_never_contacts_the_host(monkeypatch):
    def forbidden(target):
        raise AssertionError("no session may be opened")

    monkeypatch.setattr(pbs, "_new_session", forbidden)
    out = pbs.pbs_metrics(host="pbs.example", verify_ssl=False, **TOKEN)
    assert out["error_type"] == "config_error"


# --- transport -------------------------------------------------------------


def test_new_session_posture():
    target = _target()
    session = pbs._new_session(target)
    assert session.trust_env is False  # no proxy / netrc may see the token
    assert session.headers["Authorization"] == f"PBSAPIToken=a@pbs!t:{SECRET}"
    assert session.verify is False
    assert not isinstance(session.get_adapter("https://localhost"), pbs._PinnedAdapter)
    session.close()


def test_new_session_pins_the_fingerprint():
    target = _target(host="pbs.example", verify_ssl=True, fingerprint=FINGERPRINT)
    session = pbs._new_session(target)
    adapter = session.get_adapter("https://pbs.example:8007/api2/json")
    assert isinstance(adapter, pbs._PinnedAdapter)
    assert adapter.poolmanager.connection_pool_kw["assert_fingerprint"] == FINGERPRINT
    assert session.verify is False
    session.close()


def _colon(digest_bytes):
    return ":".join(format(byte, "02x") for byte in digest_bytes)


def test_peer_fingerprint():
    der = b"certificate-bytes"
    response = MagicMock()
    response.raw.connection.sock.getpeercert.return_value = der
    assert pbs._peer_fingerprint(response) == _colon(hashlib.sha256(der).digest())
    response.raw.connection.sock.getpeercert.assert_called_once_with(binary_form=True)
    response.raw.connection.sock.getpeercert.return_value = None
    assert pbs._peer_fingerprint(response) is None
    assert pbs._peer_fingerprint(object()) is None  # no .raw at all


def test_presented_fingerprint_is_a_bare_handshake(monkeypatch):
    der = b"certificate-bytes"
    seen = []

    def fake(addr, timeout=None):
        seen.append((addr, timeout))
        return ssl.DER_cert_to_PEM_cert(der)

    monkeypatch.setattr(pbs.ssl, "get_server_certificate", fake)
    clock = use_clock(monkeypatch, Clock())
    target = _target(host="::1", port=18007)
    assert pbs._presented_fingerprint(target, clock.now + 2) == _colon(
        hashlib.sha256(der).digest()
    )
    # The bare host (no brackets), and the budget left, floored.
    pbs._presented_fingerprint(target, clock.now - 5)
    assert seen == [(("::1", 18007), 2), (("::1", 18007), 0.1)]

    def broken(addr, timeout=None):
        raise OSError("handshake failed")

    monkeypatch.setattr(pbs.ssl, "get_server_certificate", broken)
    assert pbs._presented_fingerprint(target, clock.now + 2) is None


def test_error_body_is_bounded_and_never_raises():
    assert (
        pbs._error_body(FakeResponse(403, body=" permission check failed \n"))
        == "permission check failed"
    )
    assert pbs._error_body(FakeResponse(500, body="x" * 10000)) == ""


@pytest.mark.parametrize(
    "exc, error_type",
    [
        (requests.exceptions.SSLError("bad cert " + SECRET), "tls_error"),
        (requests.exceptions.Timeout("slow " + SECRET), "timeout"),
        (
            requests.exceptions.ConnectionError("refused " + SECRET),
            "connection_refused",
        ),
        (requests.exceptions.RequestException("other " + SECRET), "http_error"),
    ],
)
def test_get_classifies_transport_failures(exc, error_type):
    def handler(url):
        raise exc

    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(FakeSession(handler), _target(), "/version")
    assert excinfo.value.error_type == error_type
    assert excinfo.value.reachable is False
    assert SECRET not in excinfo.value.message


def test_get_classifies_http_status():
    session = FakeSession(lambda url: FakeResponse(401, body="authentication failed"))
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(session, _target(), "/version")
    assert (
        excinfo.value.error_type,
        excinfo.value.status,
        excinfo.value.reachable,
    ) == ("auth_failed", 401, True)
    assert excinfo.value.message == "HTTP 401: authentication failed"
    session = FakeSession(lambda url: FakeResponse(500, body=f"boom {SECRET}"))
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(session, _target(), "/version")
    assert (excinfo.value.error_type, excinfo.value.status) == ("http_error", 500)
    assert excinfo.value.message == "HTTP 500: boom [REDACTED]"


def test_get_passes_params_and_calls_on_response():
    seen = []
    session = FakeSession(lambda url: FakeResponse(200, json_body={"data": [1]}))
    data = pbs._get(
        session, _target(), "/admin/x", {"ns": "a/b c"}, on_response=seen.append
    )
    assert data == [1]
    assert session.calls == ["https://127.0.0.1:8007/api2/json/admin/x?ns=a%2Fb+c"]
    assert session.timeouts == [(5, 10)]
    assert len(seen) == 1


@pytest.mark.parametrize(
    "response, message",
    [
        (FakeResponse(200, body="not json"), "invalid JSON response"),
        # Nested far past the interpreter's recursion limit, well under the
        # byte cap: json.loads raises RecursionError, not ValueError.
        (
            FakeResponse(200, body="[" * 100000 + "]" * 100000),
            "invalid JSON response",
        ),
        (FakeResponse(200, json_body=[1, 2]), "unexpected response envelope"),
        (FakeResponse(200, json_body={"errors": {}}), "unexpected response envelope"),
    ],
)
def test_get_refuses_malformed_bodies(response, message):
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(FakeSession(lambda url: response), _target(), "/access/permissions")
    assert excinfo.value.message == message
    assert excinfo.value.error_type == "http_error"


def test_get_decodes_bodies_as_json_loads_would():
    """The body is decoded before parsing (so its bytes can be dropped first):
    invalid UTF-8 is still one failed read, and a UTF-16 body still parses."""
    response = FakeResponse(200)
    response._raw = b'{"data": "\xff"}'
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(FakeSession(lambda url: response), _target(), "/version")
    assert excinfo.value.message == "invalid JSON response"
    response = FakeResponse(200)
    response._raw = '{"data": "ok"}'.encode("utf-16")
    assert pbs._get(FakeSession(lambda url: response), _target(), "/version") == "ok"


@pytest.mark.parametrize(
    "cap, path",
    [
        ("_MAX_RESPONSE_BYTES", "/admin/datastore/ds/groups"),
        ("_MAX_RESPONSE_BYTES", "/admin/datastore/ds/snapshots"),
        ("_SMALL_MAX_BYTES", "/access/permissions"),
        ("_SMALL_MAX_BYTES", "/admin/datastore/ds/namespace"),
    ],
)
def test_get_caps_the_body(cap, path, monkeypatch):
    monkeypatch.setattr(pbs, cap, 16)
    session = FakeSession(lambda url: FakeResponse(200, json_body={"data": "x" * 100}))
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(session, _target(), path)
    assert excinfo.value.message.startswith("body read failed")


def test_get_clamps_every_bound_to_the_deadline(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    bodies = []
    real = pbs.read_capped_body

    def recording(response, max_bytes, timeout_s):
        bodies.append(timeout_s)
        return real(response, max_bytes, timeout_s)

    monkeypatch.setattr(pbs, "read_capped_body", recording)
    session = FakeSession(lambda url: FakeResponse(200, json_body={"data": {}}))
    pbs._get(session, _target(), "/version", deadline=clock.now + 3)
    assert session.timeouts == [(3, 3)] and bodies == [3]


def test_get_never_starts_past_the_deadline(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    session = FakeSession(lambda url: FakeResponse(200, json_body={"data": {}}))
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(session, _target(), "/version", deadline=clock.now)
    assert excinfo.value.error_type == "timeout"
    assert excinfo.value.message == pbs._DEADLINE_MESSAGE
    assert session.calls == []


def test_budget_constants_are_pinned():
    # Literals, not the constants themselves: these bound a tick on the
    # WatchdogSec=90 collection loop, so changing one must be deliberate.
    assert pbs.PBS_COLLECT_DEADLINE == 20
    # The hard bound abandons the whole collection: it must leave the soft
    # budget room to finish a slow-but-answering tick (its requests are
    # clamped to it) and stay well under WatchdogSec=90.
    assert pbs.PBS_HARD_DEADLINE == 30
    assert pbs.PBS_CACHE_TTL == 300
    assert (pbs._CONNECT_TIMEOUT, pbs._READ_TIMEOUT, pbs._BODY_READ_DEADLINE_S) == (
        5,
        10,
        10,
    )
    assert pbs._MAX_RESPONSE_BYTES == 16 * 1024 * 1024
    assert (pbs._ERROR_BODY_MAX_BYTES, pbs._ERROR_BODY_DEADLINE_S) == (4096, 2)
    assert pbs._VERSION_MAX_BYTES == 64 * 1024
    assert pbs._SMALL_MAX_BYTES == 4 * 1024 * 1024
    assert pbs._MAX_BLOCK_JSON_BYTES == 8 * 1024 * 1024
    assert pbs._MAX_BLOCK_GZIP_BYTES == 1024 * 1024
    assert pbs._TIMEOUT_BACKOFF_MAX == 6 * 3600
    assert pbs._TIMEOUT_BACKOFF_MIN_WAIT == 5
    assert pbs._MAX_READ_FAILURE_LINES == 20
    # Every read one build can back off -- a status per datastore, a /groups
    # and a /snapshots per namespace -- plus the one walk hold.
    assert pbs._TIMEOUT_BACKOFF_ENTRIES == 100 + 2 * 1000 + 1


# --- pbs_metrics -----------------------------------------------------------


def test_minimal_success(monkeypatch):
    out, session = collect(monkeypatch, minimal_responses())
    assert out["reachable"] is True and out["version"] == "4.2"
    assert out["release"] == "0"
    assert out["errors"] == []
    datastore = out["datastores"][0]
    assert (datastore["total"], datastore["estimated_full_date"]) == (1000, 1900000000)
    assert (datastore["namespaces"], datastore["unread_namespaces"]) == ([""], [])
    assert datastore["gc"]["last_run_state"] == "OK"
    assert datastore["gc"]["last_run_starttime"] == 11
    assert out["groups"] == [
        {
            "store": "ds",
            "ns": "",
            "type": "vm",
            "id": "100",
            "last_backup": 200,
            "count": 2,
            "in_progress": False,
            "in_progress_since": None,
            "size": 100,
            "crypt_mode": "none",
            "protected": False,
            "verify_state": None,
            "verify_time": None,
            "last_verified_ok": 100,
            "verify_failed_count": 0,
        }
    ]
    assert session.closed


def test_block_is_cached_but_version_is_read_every_tick(monkeypatch):
    clock = use_clock(monkeypatch, Clock(), cache_too=True)
    out, session = collect(monkeypatch, minimal_responses())
    first = len(session.calls)
    clock.now += 42
    out2, session2 = collect(monkeypatch, minimal_responses(), keep_cache=True)
    assert [route(u) for u in session2.calls] == ["/version"]
    assert out2["age_s"] == 42 and out["age_s"] == 0
    assert first > 1


def test_block_is_rebuilt_after_the_ttl(monkeypatch):
    """The privilege check runs on every rebuild: a token escalated while a
    block was cached is refused once the TTL (300s, a literal) runs out."""
    clock = use_clock(monkeypatch, Clock(), cache_too=True)
    collect(monkeypatch, minimal_responses())
    clock.now += 299
    _, session = collect(monkeypatch, minimal_responses(), keep_cache=True)
    assert [route(u) for u in session.calls] == ["/version"]
    clock.now += 1
    admin = {"/": {"Datastore.Audit": True, "Datastore.Read": True}}
    out, session = collect(
        monkeypatch,
        minimal_responses(**{"/access/permissions": ok(admin)}),
        keep_cache=True,
    )
    assert "/access/permissions" in [route(u) for u in session.calls]
    assert out["error_type"] == "over_privileged"


def test_down_pbs_reads_unreachable_even_with_a_cached_block(monkeypatch):
    collect(monkeypatch, minimal_responses())
    out, _ = collect(
        monkeypatch, {"/version": {"error": "connection_refused"}}, keep_cache=True
    )
    assert out["reachable"] is False and out["error_type"] == "connection_refused"


def test_build_failure_is_not_cached(monkeypatch):
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore": fail(500, "boom")})
    )
    assert out["error_type"] == "http_error" and out["reachable"] is True
    out, _ = collect(monkeypatch, minimal_responses(), keep_cache=True)
    assert "datastores" in out


def test_unexpected_exception_is_an_envelope(monkeypatch):
    def broken(target):
        raise RuntimeError("no session")

    monkeypatch.setattr(pbs, "_new_session", broken)
    out = pbs.pbs_metrics(**LOOPBACK)
    assert out == {
        "reachable": False,
        "error_type": "http_error",
        "error_message": "no session",
    }


def test_unexpected_exception_never_carries_the_secret(monkeypatch):
    logged = capture_logs(monkeypatch)

    def broken(target):
        raise RuntimeError(f"PBSAPIToken=x:{SECRET}\nFORGED")

    monkeypatch.setattr(pbs, "_new_session", broken)
    out = pbs.pbs_metrics(**LOOPBACK)
    assert SECRET not in out["error_message"]
    assert logged and all(SECRET not in m and "\n" not in m for _, m in logged)
    assert logged[0][0] == "error"


def test_non_dict_version_and_unknown_config_keys(monkeypatch):
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/version": ok("4.2")}), future_key=1
    )
    assert out["version"] is None and out["release"] is None


def test_configured_fingerprint_is_reported_when_the_socket_is_unreadable(monkeypatch):
    out, _ = collect(
        monkeypatch, minimal_responses(), host="pbs.example", fingerprint=FINGERPRINT
    )
    assert out["fingerprint"] == FINGERPRINT


def test_cache_is_keyed_on_the_target(monkeypatch):
    """A config change inside the TTL (another host, another token, a pinned
    certificate) must rebuild, never re-emit the block another PBS or another
    token produced."""
    collect(monkeypatch, minimal_responses())
    for change in (
        {"host": "127.0.0.2"},
        {"token_id": "other@pbs!t"},
        {"fingerprint": FINGERPRINT},
    ):
        _, session = collect(
            monkeypatch, minimal_responses(), keep_cache=True, **change
        )
        assert "/access/permissions" in [route(u) for u in session.calls], change


def test_wrong_secret_reads_auth_failed_even_with_a_cached_block(monkeypatch):
    """The secret is not part of the cache key, so a rotated secret reuses the
    block -- but /version goes out with the CURRENT secret every tick, so a
    wrong one surfaces at once instead of hiding behind the cache."""
    collect(monkeypatch, minimal_responses())
    out, session = collect(
        monkeypatch,
        {"/version": fail(401, "authentication failed")},
        keep_cache=True,
        token_secret="rotated-but-wrong",
    )
    assert out == {
        "reachable": True,
        "error_type": "auth_failed",
        "error_message": "HTTP 401: authentication failed",
    }
    assert [route(u) for u in session.calls] == ["/version"]


def test_auth_failure_backs_off_until_the_secret_changes(monkeypatch):
    """After a 401 the PBS is left alone for the TTL: each attempt would write
    one more authentication failure to its auth log (and cost its 3s
    penalty). A NEW secret is tried at once, and success clears the backoff."""
    clock = use_clock(monkeypatch, Clock())
    denied = {"/version": fail(401, "authentication failed")}
    out, session = collect(monkeypatch, denied)
    assert out["error_type"] == "auth_failed" and len(session.calls) == 1
    clock.now += 60
    out, session = collect(monkeypatch, denied)
    assert out == {
        "reachable": True,
        "error_type": "auth_failed",
        "error_message": "HTTP 401: authentication failed",
    }
    assert session.calls == []
    out, session = collect(monkeypatch, minimal_responses(), token_secret="new-secret")
    assert "datastores" in out and pbs._auth_backoff is None
    collect(monkeypatch, denied)
    clock.now += 300
    _, session = collect(monkeypatch, minimal_responses())
    assert [route(u) for u in session.calls][0] == "/version"
    other = ("https://elsewhere:8007/api2/json", "x", False, None)
    pbs._auth_backoff = (other, "digest", clock.now + 999, "denied")
    assert pbs._auth_backoff_message(_target()) is None  # another PBS's backoff


@pytest.mark.parametrize(
    "overrides",
    [
        {"/version": {"error": "timeout"}},
        {"/access/permissions": ok({"/": {"Datastore.Audit": True, "Sys.Modify": 1}})},
        {"/admin/datastore": fail(500, "boom")},
    ],
)
def test_session_is_closed_on_every_failure_envelope(overrides, monkeypatch):
    """One keep-alive session per tick: a failure envelope must not leak it
    (a socket per tick on a long-lived daemon)."""
    out, session = collect(monkeypatch, minimal_responses(**overrides))
    assert "error_type" in out and "datastores" not in out
    assert session.closed


def test_failure_envelope_message_is_redacted_capped_and_log_safe(monkeypatch):
    """The top-level envelope carries a PBS error body verbatim-ish: it must be
    redacted and capped on the wire, and a newline in it must not forge a
    journal line."""
    logged = capture_logs(monkeypatch)
    body = "denied\nFAKE LOG LINE token=" + "A" * 40 + " " + "word " * 700
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/access/permissions": fail(403, body)})
    )
    assert out["error_type"] == "http_error" and out["reachable"] is True
    assert "A" * 40 not in out["error_message"]
    assert len(out["error_message"]) == 500
    assert logged
    assert all("A" * 40 not in line and "\n" not in line for _, line in logged)


def test_a_steady_failure_logs_at_error_once_then_debug(monkeypatch):
    logged = capture_logs(monkeypatch)
    down = {"/version": {"error": "timeout", "message": "slow"}}
    for _ in range(3):
        collect(monkeypatch, down)
    assert [level for level, _ in logged] == ["error", "debug", "debug"]
    collect(monkeypatch, minimal_responses())  # a success resets it
    collect(monkeypatch, down)
    assert logged[-1][0] == "error"


def test_tls_failure_ships_the_presented_fingerprint(monkeypatch):
    session = FakeSession(responses_handler({"/version": {"error": "tls_error"}}))
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    seen = []

    def presented(target, deadline):
        seen.append(target.host)
        return FINGERPRINT

    monkeypatch.setattr(pbs, "_presented_fingerprint", presented)
    out = pbs.pbs_metrics(host="pbs.example", fingerprint="00" * 32, **TOKEN)
    assert out["error_type"] == "tls_error"
    assert out["presented_fingerprint"] == FINGERPRINT and seen == ["pbs.example"]


def test_an_echoed_token_is_never_logged_or_shipped(monkeypatch):
    """An error body that echoes the request headers (a proxy or WAF debug
    page) must not carry the secret into the journal or the payload: the
    generic redaction does not know the PBSAPIToken form."""
    secret = "c9b7e5b5-3e4f-4d3e-9d2a-1f2e3d4c5b6a"
    body = '{"headers":{"Authorization":"PBSAPIToken=fivenines@pbs!monitoring:%s"}}' % (
        secret
    )
    logged = capture_logs(monkeypatch)
    out, _ = collect(monkeypatch, {"/version": fail(400, body)}, token_secret=secret)
    assert secret not in out["error_message"]
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/datastore/ds/gc": fail(500, body)}),
        token_secret=secret,
    )
    assert secret not in json.dumps(out)
    assert logged and all(secret not in line for _, line in logged)


# --- privileges ------------------------------------------------------------


def test_check_privileges():
    assert pbs._check_privileges(PERMS_FULL)[:2] == (True, True)
    # A grant on / as PBS reports it: inherited at /datastore (list_permissions
    # always evaluates the default paths /datastore and /remote).
    root = {"/": {"Datastore.Audit": True}, "/datastore": {"Datastore.Audit": True}}
    assert pbs._check_privileges(root)[:2] == (False, True)
    scoped = {
        "/datastore/ds/ns1": {"Datastore.Audit": True},
        "/remote/r1": {"Remote.Audit": True},
        "/x": "junk",
    }
    remote_audit, full_scope, grants = pbs._check_privileges(scoped)
    assert (remote_audit, full_scope) == (False, False)
    # The map the deep-ACL checks then read: a row that is not a privilege
    # map is dropped.
    assert grants == {
        "/datastore/ds/ns1": {"Datastore.Audit": True},
        "/remote/r1": {"Remote.Audit": True},
    }
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._check_privileges(["not", "a", "map"])
    assert excinfo.value.error_type == "http_error"


@pytest.mark.parametrize(
    "privilege",
    [
        "Datastore.Read",
        "Datastore.Backup",
        "Datastore.Prune",
        "Datastore.Modify",
        "Datastore.Verify",
        "Sys.Modify",
        "Permissions.Modify",
        "Remote.Read",
        # Audit privileges beyond the two the collector needs: Sys.Audit reads
        # the PBS system journal and syslog.
        "Sys.Audit",
        "Tape.Audit",
    ],
)
def test_any_privilege_beyond_the_allowlist_is_refused(privilege):
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._check_privileges(
            {"/datastore/ds": {"Datastore.Audit": True, privilege: False}}
        )
    assert excinfo.value.error_type == "over_privileged"
    assert privilege in excinfo.value.message


@pytest.mark.parametrize(
    "perms",
    [
        {},
        {"/remote": {"Remote.Audit": True}},
        # Measured: a grant that does not propagate reaches no datastore.
        {"/datastore": {"Datastore.Audit": False}},
        {"/": {"Datastore.Audit": False}},
    ],
)
def test_no_reachable_datastore_audit_is_refused(perms):
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._check_privileges(perms)
    assert excinfo.value.error_type == "no_datastore_access"


def test_a_non_propagated_remote_grant_hides_sync_jobs():
    perms = {
        "/datastore": {"Datastore.Audit": True},
        "/remote": {"Remote.Audit": False},
    }
    assert pbs._check_privileges(perms)[:2] == (False, True)


def test_over_privileged_wins_over_missing_datastore_audit():
    """A token that can RESTORE backups but not audit them is refused for the
    privilege it holds, never reported as merely lacking access."""
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._check_privileges({"/datastore": {"Datastore.Read": True}})
    assert excinfo.value.error_type == "over_privileged"


def test_root_grants_count_for_both_scopes():
    both = {"Datastore.Audit": True, "Remote.Audit": True}
    as_reported = {"/": both, "/datastore": both, "/remote": both}
    assert pbs._check_privileges(as_reported)[:2] == (True, True)


def test_a_root_grant_with_datastore_absent_is_not_full_scope(monkeypatch):
    """PBS leaves /datastore (or /remote) out of the map only when the token
    has NO privilege there: with a grant on /, that means an entry AT
    /datastore replaced it (a DatastoreBackup the reused user holds, say) and
    hides every datastore. An empty listing then proves nothing."""
    grant = {"Datastore.Audit": True, "Remote.Audit": True}
    perms = {path: grant for path in ("/", "/access", "/remote", "/system")}
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/access/permissions": ok(perms),
                "/admin/datastore": ok([]),
                "/status/datastore-usage": ok([]),
            }
        ),
    )
    assert "datastores" not in out and out["error_type"] == "no_datastore_access"
    # /remote overridden the same way: sync jobs unknown, not "none".
    perms = {path: grant for path in ("/", "/access", "/datastore", "/system")}
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/access/permissions": ok(perms)})
    )
    assert out["sync_jobs"] is None and out["scope"] == "full"


def test_over_privileged_token_is_used_for_nothing_else_and_never_cached(monkeypatch):
    """Refused on its first tick: no listing is requested with a token that can
    read or delete backups, and the refusal is not cached, so the tick after the
    operator fixes the ACL builds normally."""
    admin = {"/": {"Datastore.Audit": True, "Datastore.Read": True}}
    out, session = collect(
        monkeypatch, minimal_responses(**{"/access/permissions": ok(admin)})
    )
    assert out["error_type"] == "over_privileged" and out["reachable"] is True
    assert [route(u) for u in session.calls] == ["/version", "/access/permissions"]
    out, _ = collect(monkeypatch, minimal_responses(), keep_cache=True)
    assert out["errors"] == [] and len(out["groups"]) == 1


def test_scoped_token_marks_every_job_list_partial(monkeypatch):
    perms = {
        "/datastore/ds": {"Datastore.Audit": True},
        "/remote": {"Remote.Audit": True},
    }
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/access/permissions": ok(perms),
                "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
            }
        ),
    )
    assert [e["scope"] for e in out["errors"]] == [
        "sync_jobs",
        "verify_jobs",
        "prune_jobs",
    ]
    assert all(e["message"].startswith("partial:") for e in out["errors"])


def test_a_scoped_token_reaching_no_datastore_is_no_access(monkeypatch):
    perms = {"/datastore/gone": {"Datastore.Audit": True}}
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/access/permissions": ok(perms), "/admin/datastore": ok([])}
        ),
    )
    assert out["error_type"] == "no_datastore_access"


def test_a_full_scope_token_trusts_an_empty_pbs(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore": ok([]), "/status/datastore-usage": ok([])}
        ),
    )
    assert out["datastores"] == [] and out["groups"] == [] and out["errors"] == []


# --- datastore-level reads -------------------------------------------------


def test_store_names_cannot_reshape_the_request_path():
    """A datastore name comes from the PBS response and lands in a URL path: it
    is percent-encoded whole, so a '/', '?' or '#' cannot reach another
    endpoint or smuggle a query."""
    assert (
        pbs._store_path("a/../b?x=1#f", "gc")
        == "/admin/datastore/a%2F..%2Fb%3Fx%3D1%23f/gc"
    )


@pytest.mark.parametrize("listing", [{}, "", {"store": "ds"}])
def test_datastore_listing_must_be_a_list(listing, monkeypatch):
    """An EMPTY non-list body proves nothing: it must not pass as 'zero
    datastores' (the prune-all)."""
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore": ok(listing), "/status/datastore-usage": ok([])}
        ),
    )
    assert "datastores" not in out and out["error_type"] == "http_error"


@pytest.mark.parametrize("junk", [{"store": ""}, {"store": 5}, "junk", {}])
def test_one_unparseable_datastore_row_makes_the_listing_untrustworthy(
    junk, monkeypatch
):
    # A datastore silently dropped would read as removed.
    listing = [{"store": "ds"}, junk]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore": ok(listing)})
    )
    assert out["error_type"] == "http_error" and "datastores" not in out
    assert out["error_message"] == "unexpected datastore listing shape"


def test_datastores_are_sorted_and_capped(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_DATASTORES", 1)
    listing = [{"store": "zz"}, {"store": "ds"}]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore": ok(listing)})
    )
    assert [d["store"] for d in out["datastores"]] == ["ds"]
    assert out["errors"][0] == {
        "scope": "cap",
        "store": None,
        "ns": None,
        "message": "datastores capped at 1: 1 dropped",
    }


def test_usage_failures(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/status/datastore-usage": fail(500, "boom"),
                "/admin/datastore/ds/status": fail(500, "boom"),
            }
        ),
    )
    assert out["datastores"][0]["total"] is None
    assert out["errors"] == [
        {"scope": "usage", "store": None, "ns": None, "message": "HTTP 500: boom"},
        {"scope": "usage", "store": "ds", "ns": None, "message": "HTTP 500: boom"},
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/status/datastore-usage": ok({})}),
    )
    assert out["errors"][0]["message"] == "unexpected response shape (not a list)"
    assert out["datastores"][0]["total"] is None


def test_usage_without_numbers_is_null_never_zero(monkeypatch):
    rows = [{"store": "ds", "mount-status": "nonremovable"}, "junk", {"store": 1}]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/status/datastore-usage": ok(rows)})
    )
    ds = out["datastores"][0]
    assert (ds["total"], ds["used"], ds["avail"], ds["estimated_full_date"]) == (
        None,
        None,
        None,
        None,
    )


def test_estimated_full_date_sentinel_ships_verbatim(monkeypatch):
    # PBS sends 0 as its "no fill expected" sentinel; the agent passes it on
    # verbatim (documented in the contract), never as null.
    rows = [
        {"store": "ds", "total": 1, "used": 1, "avail": 0, "estimated-full-date": 0}
    ]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/status/datastore-usage": ok(rows)})
    )
    assert out["datastores"][0]["estimated_full_date"] == 0


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, (None, None)),
        ("", (None, None)),
        (5, (None, None)),
        ("read-only", ("read-only", None)),
        ("type=offline,message=disk swap tonight", ("offline", "disk swap tonight")),
        ('offline,message="quoted, with comma"', ("offline", "quoted, with comma")),
        ("offline,message=", ("offline", None)),
        # A property string: any key order (PBS 2.2-3.1 store it as sent)...
        ("message=disk swap,type=offline", ("offline", "disk swap")),
        ("message=x,offline", ("offline", "x")),
        # ...and a quoted value is unescaped (PBS >= 3.2 quotes a '"').
        ('offline,message="say \\"hi\\""', ("offline", 'say "hi"')),
        ("message=only a message", (None, "only a message")),
        # As the PBS UI writes it: the message always quoted.
        ('type=offline,message="3.5\\" disk, bay 2"', ("offline", '3.5" disk, bay 2')),
        ('message="3.5\\" disk, bay 2",type=offline', ("offline", '3.5" disk, bay 2')),
        ('type=offline,message="nightly swap"', ("offline", "nightly swap")),
        ('type=offline,message=""', ("offline", None)),
        # A quote opens a quoted value only at its START (PBS's parser).
        ('message=5" disk,type=offline', ("offline", '5" disk')),
        ("message=a\\,type=offline", ("offline", "a\\")),
    ],
)
def test_maintenance(value, expected):
    assert pbs._maintenance(value) == expected


def test_maintenance_message_is_capped():
    assert pbs.MAINTENANCE_MESSAGE_MAX_LEN == 200
    _, message = pbs._maintenance("offline,message=" + "m" * 1000)
    assert message == "m" * 200


def test_gc_failures(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore/ds/gc": fail(403, "permission check failed")}
        ),
    )
    assert out["datastores"][0]["gc"] is None
    assert out["errors"][0]["scope"] == "gc" and out["errors"][0]["store"] == "ds"
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/gc": ok([])})
    )
    assert out["errors"][0]["message"] == "unexpected response shape (not an object)"


def test_gc_on_an_older_pbs_reads_state_not_reported(monkeypatch):
    """A PBS older than ~3.2 reports only the last GC's task id and counters:
    a start time with a null state is 'not reported', unlike a GC that never
    ran (no task id at all)."""
    legacy = {"upid": GC_UPID, "disk-bytes": 5}
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/gc": ok(legacy)})
    )
    gc = out["datastores"][0]["gc"]
    assert (gc["last_run_starttime"], gc["last_run_state"], gc["schedule"]) == (
        11,
        None,
        None,
    )
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/gc": ok({})})
    )
    assert out["datastores"][0]["gc"]["last_run_starttime"] is None


def test_namespaces_endpoint_missing_means_root_only(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/namespace": fail(
                    404, "Path '/api2/json/admin/datastore/ds/namespace' not found."
                ),
            }
        ),
    )
    assert out["datastores"][0]["namespaces"] == [""]
    assert out["errors"] == [] and len(out["groups"]) == 1


def test_namespace_failures(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore/ds/namespace": fail(400, "unavailable")}
        ),
    )
    datastore = out["datastores"][0]
    assert (datastore["namespaces"], datastore["unread_namespaces"]) == (None, None)
    assert out["groups"] == [] and out["errors"][0]["scope"] == "namespaces"
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/namespace": ok({})})
    )
    assert out["errors"][0]["message"] == "unexpected response shape (not a list)"
    for junk in ({"ns": 3}, "junk"):
        out, _ = collect(
            monkeypatch,
            minimal_responses(
                **{"/admin/datastore/ds/namespace": ok([{"ns": ""}, junk])}
            ),
        )
        # One unparseable row makes the whole set unknown, never smaller.
        assert out["datastores"][0]["namespaces"] is None
        assert out["groups"] == []
        assert out["errors"][0] == {
            "scope": "namespaces",
            "store": "ds",
            "ns": None,
            "message": "unparseable namespace row",
        }


def test_a_capped_namespace_listing_leaves_the_set_unknown(monkeypatch):
    """Past the namespace cap the store's namespace SET is incomplete, so it
    ships as null (nothing may be pruned there); the namespaces kept -- sorted,
    so the cap trims deterministically -- still ship their groups."""
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 1)
    responses = minimal_responses(
        **{"/admin/datastore/ds/namespace": ok([{"ns": "b"}, {"ns": ""}])}
    )
    out, session = collect(monkeypatch, responses)
    datastore = out["datastores"][0]
    assert (datastore["namespaces"], datastore["unread_namespaces"]) == (None, None)
    assert [g["ns"] for g in out["groups"]] == [""]
    assert out["errors"] == [
        {
            "scope": "cap",
            "store": "ds",
            "ns": None,
            "message": "namespaces capped at 1: 1 dropped",
        }
    ]
    assert "/admin/datastore/ds/groups?ns=b" not in [route(u) for u in session.calls]


# --- groups and snapshots --------------------------------------------------


def test_a_failed_groups_read_marks_the_namespace_unread(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/datastore/ds/groups": fail(500, "boom")}),
    )
    assert out["groups"] == [] and out["datastores"][0]["unread_namespaces"] == [""]
    assert out["errors"][0] == {
        "scope": "groups",
        "store": "ds",
        "ns": "",
        "message": "HTTP 500: boom",
    }
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/groups": ok({})})
    )
    assert out["groups"] == [] and out["errors"][0]["scope"] == "groups"


def test_snapshots_failure_keeps_the_groups_with_null_details(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore/ds/snapshots": {"error": "timeout", "message": "t"}}
        ),
    )
    group = out["groups"][0]
    assert group["last_backup"] == 200 and group["count"] == 2
    assert all(
        group[k] is None
        for k in (
            "in_progress",
            "size",
            "crypt_mode",
            "protected",
            "verify_state",
            "verify_time",
            "last_verified_ok",
            "verify_failed_count",
        )
    )
    assert out["errors"][0]["scope"] == "snapshots"
    # PBS's scan never ended: a group it left out of /groups (its snapshot
    # directory unreadable) would not show, so the namespace is unread.
    assert out["datastores"][0]["unread_namespaces"] == [""]


def test_a_non_list_snapshot_listing_nulls_the_details(monkeypatch):
    out, session = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/snapshots": ok({})})
    )
    assert "/admin/datastore/ds/snapshots" in [route(u) for u in session.calls]
    group = out["groups"][0]
    assert group["size"] is None and group["in_progress"] is None
    assert out["errors"] == [
        {
            "scope": "snapshots",
            "store": "ds",
            "ns": "",
            "message": "unexpected response shape (not a list)",
        }
    ]
    # Only a list proves the scan ended: unread, like any other failure.
    assert out["datastores"][0]["unread_namespaces"] == [""]


def test_an_unparseable_group_row_marks_the_namespace_unread(monkeypatch):
    """The parseable rows still ship, but a group silently skipped would read
    as deleted, so the namespace is no longer authoritative."""
    rows = [
        "junk",
        {"backup-type": "vm"},
        {"backup-type": "vm", "backup-id": 5},
        {
            "backup-type": "vm",
            "backup-id": "100",
            "last-backup": 200,
            "backup-count": 2,
        },
    ]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/groups": ok(rows)})
    )
    assert [g["id"] for g in out["groups"]] == ["100"]
    assert out["datastores"][0]["unread_namespaces"] == [""]
    assert out["errors"] == [
        {
            "scope": "groups",
            "store": "ds",
            "ns": "",
            "message": "3 unparseable group row(s) skipped",
        }
    ]


# Value: protects=a snapshot list missing the last_backup manifest keeps its namespace read;
#   fails_when=a details-unknown row starts marking its namespace unread;
#   why_new=pins the contract's list-means-read rule for this case; seam=none
def test_a_last_backup_missing_from_the_listing_reads_unknown(monkeypatch):
    """/groups names a finished last backup that the snapshot listing does not
    show finished (an unreadable manifest, or a listing that raced a prune):
    every detail -- in_progress included -- is unknown, never 'never
    verified', and an error names the group."""
    unreadable = {
        "backup-type": "vm",
        "backup-id": "100",
        "backup-time": 200,
        "files": [{"filename": "index.json.blob"}],
    }
    for listing in ([], [unreadable]):
        out, _ = collect(
            monkeypatch,
            minimal_responses(**{"/admin/datastore/ds/snapshots": ok(listing)}),
        )
        group = out["groups"][0]
        assert group["last_backup"] == 200
        assert group["in_progress"] is None and group["verify_state"] is None
        assert out["errors"] == [
            {
                "scope": "snapshots",
                "store": "ds",
                "ns": "",
                "message": "vm/100: last backup 200 has no readable manifest in "
                "the snapshot listing",
            }
        ]
        # A list came back: PBS's scan ended, the namespace stays read.
        assert out["datastores"][0]["unread_namespaces"] == []


def test_the_group_cap_marks_every_truncated_namespace_unread(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_GROUPS", 1)
    groups = [
        {"backup-type": "vm", "backup-id": str(i), "last-backup": 1} for i in (1, 2)
    ]
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": "b"}]),
            "/admin/datastore/ds/groups": ok(groups),
            "/admin/datastore/ds/snapshots": ok([]),
        }
    )
    out, session = collect(monkeypatch, responses)
    assert len(out["groups"]) == 1
    assert out["datastores"][0]["unread_namespaces"] == ["", "b"]
    caps = [(e["ns"], e["message"]) for e in out["errors"] if e["scope"] == "cap"]
    assert caps == [
        ("", "groups capped at 1: 1 dropped"),
        (None, "groups capped at 1: 1 namespace(s) not read"),
    ]
    # Once the cap is full, no namespace is read only to be thrown away, and
    # the next build starts at the first one left out.
    assert "/admin/datastore/ds/groups?ns=b" not in [route(u) for u in session.calls]
    assert pbs._rotation == ("ds", "b")


def test_the_errors_cap_never_hides_an_unread_namespace(monkeypatch):
    """errors[] is capped, so what gates pruning cannot live there alone: every
    namespace whose groups are unknown is listed in unread_namespaces whatever
    happened to its error entry."""
    monkeypatch.setattr(pbs, "MAX_ERRORS", 3)
    names = ["", "a", "b", "c", "d"]
    responses = minimal_responses(
        **{"/admin/datastore/ds/namespace": ok([{"ns": n} for n in names])}
    )
    for ns in names:
        suffix = f"?ns={ns}" if ns else ""
        responses[f"/admin/datastore/ds/groups{suffix}"] = fail(500, "down")
    out, _ = collect(monkeypatch, responses)
    assert len(out["errors"]) == 3
    assert out["errors"][-1]["message"] == "errors capped at 3: 3 dropped"
    datastore = out["datastores"][0]
    assert datastore["namespaces"] == names
    assert datastore["unread_namespaces"] == names


def test_groups_are_sorted_whatever_the_read_order(monkeypatch):
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": "b"}, {"ns": ""}]),
            "/admin/datastore/ds/groups": ok(
                [
                    {"backup-type": "vm", "backup-id": "200", "last-backup": 1},
                    {"backup-type": "ct", "backup-id": "100", "last-backup": 1},
                ]
            ),
            "/admin/datastore/ds/snapshots": ok(
                [snapshot("vm", "200", 1), snapshot("ct", "100", 1)]
            ),
            "/admin/datastore/ds/groups?ns=b": ok(
                [{"backup-type": "vm", "backup-id": "1", "last-backup": 1}]
            ),
            "/admin/datastore/ds/snapshots?ns=b": ok([snapshot("vm", "1", 1)]),
        }
    )
    monkeypatch.setattr(pbs, "_rotation", ("ds", "b"))  # read "b" first
    out, _ = collect(monkeypatch, responses)
    keys = [(g["ns"], g["type"], g["id"]) for g in out["groups"]]
    assert keys == [("", "ct", "100"), ("", "vm", "200"), ("b", "vm", "1")]


def _slow_groups(monkeypatch, clock, seconds=100):
    """Make every namespace read eat `seconds` of this module's clock."""
    real = pbs._read_groups
    order = []

    def slow(session, target, errors, deadline, store, ns, room):
        order.append(ns)
        rows = real(session, target, errors, deadline, store, ns, room)
        clock.now += seconds
        return rows

    monkeypatch.setattr(pbs, "_read_groups", slow)
    return order


def test_the_budget_resumes_at_the_first_namespace_not_read(monkeypatch):
    """When the budget fits only part of the namespaces, the rest are marked
    unread (one error per datastore, not one per namespace) and the NEXT build
    starts at the first one skipped, so every namespace is read within a few
    builds instead of the same tail starving forever."""
    clock = use_clock(monkeypatch, Clock())
    order = _slow_groups(monkeypatch, clock)
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": "b"}, {"ns": "c"}]),
            "/admin/datastore/ds/groups?ns=b": ok([]),
            "/admin/datastore/ds/snapshots?ns=b": ok([]),
            "/admin/datastore/ds/groups?ns=c": ok([]),
            "/admin/datastore/ds/snapshots?ns=c": ok([]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert order == [""]
    assert out["datastores"][0]["unread_namespaces"] == ["b", "c"]
    assert out["errors"] == [
        {
            "scope": "groups",
            "store": "ds",
            "ns": None,
            "message": f"{pbs._DEADLINE_MESSAGE} (2 namespace(s) not read)",
        }
    ]
    assert pbs._rotation == ("ds", "b")
    collect(monkeypatch, responses)
    assert order == ["", "b"] and pbs._rotation == ("ds", "c")
    collect(monkeypatch, responses)
    assert order == ["", "b", "c"] and pbs._rotation == ("ds", "")


def test_a_full_read_keeps_the_rotation(monkeypatch):
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": "b"}]),
            "/admin/datastore/ds/groups?ns=b": ok([]),
            "/admin/datastore/ds/snapshots?ns=b": ok([]),
        }
    )
    monkeypatch.setattr(pbs, "_rotation", ("ds", "b"))
    collect(monkeypatch, responses)
    assert pbs._rotation == ("ds", "b")


def test_deadline_between_groups_and_snapshots(monkeypatch):
    real_deadline_hit = pbs._deadline_hit

    def deadline_hit(deadline, errors, scope, store=None, ns=None):
        spent = 0 if scope == "snapshots" else float("inf")
        return real_deadline_hit(spent, errors, scope, store=store, ns=ns)

    monkeypatch.setattr(pbs, "_deadline_hit", deadline_hit)
    out, _ = collect(monkeypatch, minimal_responses())
    group = out["groups"][0]
    assert group["last_backup"] == 200 and group["size"] is None
    assert group["in_progress"] is None
    assert out["errors"] == [
        {
            "scope": "snapshots",
            "store": "ds",
            "ns": "",
            "message": pbs._DEADLINE_MESSAGE,
        }
    ]


@pytest.mark.parametrize(
    "scope",
    [
        "usage",
        "gc",
        "namespaces",
        "snapshots",
        "sync_jobs",
        "verify_jobs",
        "prune_jobs",
    ],
)
def test_each_read_honours_the_deadline(scope, monkeypatch):
    real_deadline_hit = pbs._deadline_hit

    def deadline_hit(deadline, errors, s, store=None, ns=None):
        spent = 0 if s == scope else float("inf")
        return real_deadline_hit(spent, errors, s, store=store, ns=ns)

    monkeypatch.setattr(pbs, "_deadline_hit", deadline_hit)
    out, _ = collect(monkeypatch, minimal_responses())
    assert [e["scope"] for e in out["errors"]] == [scope]


def test_a_spent_budget_before_the_build_is_a_timeout(monkeypatch):
    """/version and the block share one budget: a build that starts with none
    left fails (and is not cached) instead of running past it."""
    clock = use_clock(monkeypatch, Clock())
    real_get = pbs._get

    def slow_version(session, target, path, *args, **kwargs):
        data = real_get(session, target, path, *args, **kwargs)
        if path == "/version":
            clock.now += 100
        return data

    monkeypatch.setattr(pbs, "_get", slow_version)
    out, session = collect(monkeypatch, minimal_responses())
    assert (out["error_type"], out["error_message"]) == (
        "timeout",
        pbs._DEADLINE_MESSAGE,
    )
    assert [route(u) for u in session.calls] == ["/version"]


# --- snapshot summary ------------------------------------------------------


def test_crypt_mode():
    manifest = {"filename": "index.json.blob", "crypt-mode": "sign-only"}
    assert (
        pbs._crypt_mode([{"filename": "a.didx", "crypt-mode": "encrypt"}, manifest])
        == "encrypt"
    )
    assert pbs._crypt_mode([{"filename": "a.didx", "crypt-mode": "none"}]) == "none"
    assert (
        pbs._crypt_mode(
            [
                {"filename": "a.didx", "crypt-mode": "encrypt"},
                {"filename": "b.fidx", "crypt-mode": "none"},
            ]
        )
        == "mixed"
    )
    assert (
        pbs._crypt_mode([manifest, "junk", {"filename": "a", "crypt-mode": None}])
        is None
    )
    assert pbs._crypt_mode(None) is None


def test_upid_starttime():
    assert (
        pbs._upid_starttime(
            "UPID:n:00000025:000023D8:00000009:6ABA2CB6:verify:store1:root@pam:"
        )
        == 0x6ABA2CB6
    )
    # PBS keeps it in an i64, like every integer it sends (_as_int64).
    assert pbs._upid_starttime("UPID:n:1:2:3:7" + "f" * 15 + ":v:s:u:") == 2**63 - 1
    assert pbs._upid_starttime("UPID:n:1:2:3:8" + "0" * 15 + ":v:s:u:") is None
    assert pbs._upid_starttime("UPID:n:1:2:3:" + "f" * 16 + ":v:s:u:") is None
    assert pbs._upid_starttime(None) is None
    assert pbs._upid_starttime("UPID:short") is None
    assert pbs._upid_starttime("TASK:n:1:2:3:6ABA2CB6:verify:s:u:") is None
    assert pbs._upid_starttime("UPID:n:1:2:3:nothex:verify:s:u:") is None
    # An unbounded hex field would make json.dumps of the WHOLE payload refuse
    # the int (the 4300-digit limit) and drop every collector's tick.
    assert pbs._upid_starttime("UPID:n:1:2:3:" + "f" * 4000 + ":v:s:u:") is None


def test_summary_tracks_unfinished_and_verification():
    snaps = [
        "junk",
        {"backup-type": "vm", "backup-id": 1, "backup-time": 5},
        {"backup-type": "vm", "backup-id": "1", "backup-time": "bad"},
        snapshot("vm", "1", 100, verification=verified("failed")),
        snapshot("vm", "1", 200, verification=verified("ok")),
        snapshot("vm", "1", 150, verification=verified("ok")),
        snapshot("vm", "1", 300, size=None, files=[]),
        snapshot("vm", "1", 250, size=None, files=[]),
        snapshot("vm", "1", 400, verification="junk"),
    ]
    summaries, unparseable = pbs._summarize_snapshots(snaps, "ds")
    assert unparseable == 3  # "junk", an int id, an unparseable time
    summary = summaries[("vm", "1")]
    assert sorted(summary["finished"]) == [100, 150, 200, 400]
    assert summary["newest_unfinished"] == 300
    assert summary["last_verified_ok"] == 200
    assert summary["verify_failed_count"] == 1


def test_verify_failed_count_counts_every_failed_snapshot():
    snaps = [
        snapshot("vm", "1", t, verification=verified("failed")) for t in (100, 200, 300)
    ]
    snaps.append(snapshot("vm", "1", 400))
    assert (
        pbs._summarize_snapshots(snaps, "ds")[0][("vm", "1")]["verify_failed_count"]
        == 3
    )


def test_group_row_edge_cases():
    group = {"backup-type": "vm", "backup-id": "1", "last-backup": 0, "backup-count": 0}
    row = pbs._group_row("ds", "", group, None)
    assert row["last_backup"] is None and row["count"] == 0
    assert row["in_progress"] is None

    finished = {
        100: snapshot(
            "vm", "1", 100, protected=1, verification={"state": "ok", "upid": "junk"}
        )
    }
    summary = {"finished": finished, "newest_unfinished": 50}
    row = pbs._group_row("ds", "", {"backup-type": "vm", "backup-id": "1"}, summary)
    # No last-backup from /groups: the newest finished snapshot stands in.
    assert row["last_backup"] == 100 and row["in_progress"] is False
    # A verification whose task id cannot be read is not provably this
    # datastore's (a synced copy carries its source's): not reported.
    assert row["protected"] is True and row["verify_state"] is None
    assert row["verify_time"] is None

    summary = {"finished": {}, "newest_unfinished": 50}
    row = pbs._group_row("ds", "", {"backup-type": "vm", "backup-id": "1"}, summary)
    # A first backup in flight: nothing finished, so nothing unknown either.
    assert row["last_backup"] is None and row["in_progress"] is True
    assert row["verify_failed_count"] == 0

    # /groups and /snapshots raced: the finished snapshot named by last-backup
    # is not in the listing, so every detail is unknown.
    summary = {"finished": {100: snapshot("vm", "1", 100)}, "newest_unfinished": None}
    row = pbs._group_row(
        "ds", "", {"backup-type": "vm", "backup-id": "1", "last-backup": 200}, summary
    )
    assert row["last_backup"] == 200 and row["size"] is None
    assert row["in_progress"] is None and row["verify_failed_count"] is None


# --- jobs ------------------------------------------------------------------


def test_job_shapes():
    sync = pbs._sync_job(
        {
            "id": "s",
            "store": "ds",
            "remote": "r",
            "remote-store": "rs",
            "sync-direction": "push",
            "max-depth": 2,
        }
    )
    assert sync["direction"] == "push" and sync["remote_ns"] == ""
    assert sync["max_depth"] == 2
    assert pbs._sync_job({"id": "local", "store": "ds"})["remote"] is None
    assert pbs._sync_job({"id": "old"})["direction"] == "pull"
    verify = pbs._verify_job(
        {"id": "v", "ns": "a", "outdated-after": 30, "ignore-verified": True}
    )
    assert (verify["ns"], verify["outdated_after"], verify["ignore_verified"]) == (
        "a",
        30,
        True,
    )
    assert pbs._prune_job({"id": "p", "disable": True})["disabled"] is True
    assert pbs._prune_job({"id": "p"})["disabled"] is False


def test_job_list_failures(monkeypatch):
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/verify": fail(500, "boom")})
    )
    assert out["verify_jobs"] is None and out["errors"][0]["scope"] == "verify_jobs"
    out, _ = collect(monkeypatch, minimal_responses(**{"/admin/prune": ok({})}))
    assert out["prune_jobs"] is None and out["errors"][0]["scope"] == "prune_jobs"
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/verify": ok(
                    ["junk", {"id": "b", "store": "z"}, {"id": "a", "store": "z"}]
                )
            }
        ),
    )
    assert [j["id"] for j in out["verify_jobs"]] == ["a", "b"]


def test_job_cap(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_JOBS", 1)
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/prune": ok([{"id": "a"}, {"id": "b"}])}),
    )
    assert [j["id"] for j in out["prune_jobs"]] == ["a"]
    # Flagged under the list's own scope, like any partial job list.
    assert out["errors"] == [
        {
            "scope": "prune_jobs",
            "store": None,
            "ns": None,
            "message": "partial: capped at 1: 1 dropped",
        }
    ]


def test_sync_jobs_need_remote_audit(monkeypatch):
    perms = {"/datastore": {"Datastore.Audit": True}}
    out, session = collect(
        monkeypatch, minimal_responses(**{"/access/permissions": ok(perms)})
    )
    assert out["sync_jobs"] is None
    assert out["errors"][0]["scope"] == "sync_jobs"
    assert not any("/admin/sync" in u for u in session.calls)


def test_sync_jobs_fall_back_on_a_pbs_without_push(monkeypatch):
    responses = minimal_responses(
        **{
            "/admin/sync?sync-direction=all": fail(400, _NO_SYNC_DIRECTION),
            "/admin/sync": ok([{"id": "pull1", "store": "ds", "remote": "r"}]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert [j["id"] for j in out["sync_jobs"]] == ["pull1"] and out["errors"] == []
    responses["/admin/sync"] = fail(500, "boom")
    out, _ = collect(monkeypatch, responses)
    assert out["sync_jobs"] is None and out["errors"][0]["scope"] == "sync_jobs"


def test_sync_fallback_with_a_malformed_listing_is_unknown(monkeypatch):
    """The pre-3.3 fallback listing gets the same shape check as the first
    read: a non-list is null plus a scoped error, never an empty job list."""
    responses = minimal_responses(
        **{
            "/admin/sync?sync-direction=all": fail(400, _NO_SYNC_DIRECTION),
            "/admin/sync": ok({"id": "pull1"}),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert out["sync_jobs"] is None
    assert out["errors"] == [
        {
            "scope": "sync_jobs",
            "store": None,
            "ns": None,
            "message": "unexpected response shape (not a list)",
        }
    ]


def test_a_malformed_sync_listing_is_unknown(monkeypatch):
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/sync?sync-direction=all": ok({})})
    )
    assert out["sync_jobs"] is None
    assert out["errors"][0]["message"] == "unexpected response shape (not a list)"


def test_sync_jobs_other_failures(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/sync?sync-direction=all": fail(500, "boom")}),
    )
    assert out["sync_jobs"] is None and out["errors"][0]["message"] == "HTTP 500: boom"


# --- wire hygiene ----------------------------------------------------------


def test_owner_and_notes_never_ship(monkeypatch):
    groups = [
        {
            "backup-type": "host",
            "backup-id": "web",
            "last-backup": 1,
            "owner": "secret-owner@pbs",
            "comment": "notes",
        }
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/groups": ok(groups),
                "/admin/datastore/ds/snapshots": ok([]),
            }
        ),
    )
    assert out["groups"][0]["id"] == "web"
    assert "secret-owner" not in json.dumps(out) and "notes" not in json.dumps(out)


@pytest.mark.parametrize(
    "btype, bid",
    [
        ("host", "web\x00"),
        ("host", "\U0001f600" * 10),
        ("host", "x" * 256),
        ("host", ".hidden"),
        ("host", ""),
        ("HOST", "web"),
        ("a" * 17, "web"),
        ("file", "web"),
        ("vmx", "web"),
        ("hostile", "web"),
        ("ct2", "web"),
        ("h\u00f4st", "web"),
    ],
)
def test_a_group_outside_the_pbs_schema_is_unparseable(btype, bid, monkeypatch):
    """A group is (type)/(safe id) in PBS's own schema. Anything else -- a NUL,
    astral-plane padding copied into every row and re-serialized every tick --
    is an unparseable row: the namespace is unread (unknown, never smaller)."""
    groups = [
        {"backup-type": "vm", "backup-id": "100", "last-backup": 1},
        {"backup-type": btype, "backup-id": bid, "last-backup": 1},
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/groups": ok(groups),
                "/admin/datastore/ds/snapshots": ok([]),
            }
        ),
    )
    assert [(g["type"], g["id"]) for g in out["groups"]] == [("vm", "100")]
    assert out["datastores"][0]["unread_namespaces"] == [""]
    assert [e["message"] for e in out["errors"] if e["scope"] == "groups"] == [
        "1 unparseable group row(s) skipped"
    ]


def test_the_longest_names_pbs_allows_are_read(monkeypatch):
    """The schema check refuses nothing a real PBS sends: a 255-character id,
    dots, dashes and underscores, and eight namespace levels."""
    bid = "a" + "._-Z9" * 50 + "b" * 4
    ns = "/".join(["n" + str(level) for level in range(8)])
    assert len(bid) == 255
    assert pbs._SAFE_ID_RE.fullmatch(bid) and pbs._is_name(ns, namespace=True)
    assert pbs._is_name("_s.t-1") and pbs._is_name("", namespace=True)
    assert not pbs._is_name("") and not pbs._is_name("a/b")
    assert not pbs._is_name("/".join(["n"] * 9), namespace=True)
    assert not pbs._is_name("a//b", namespace=True)
    assert not pbs._is_name(None, namespace=True)


def test_hostile_datastore_strings_are_scrubbed(monkeypatch):
    responses = minimal_responses(
        **{
            "/admin/datastore": ok(
                [{"store": "ds", "mount-status": "m\x00" + "z" * 1000}]
            ),
        }
    )
    out, _ = collect(monkeypatch, responses)
    value = out["datastores"][0]["mount_status"]
    assert "\x00" not in value and len(value) <= 500


@pytest.mark.parametrize("store", ["ds\x00", "\U0001f600" * 10, "d" * 256, "a/b"])
def test_a_datastore_name_outside_the_pbs_schema_fails_the_listing(store, monkeypatch):
    """A datastore silently dropped would read as removed: ONE name outside
    PBS's schema makes the whole listing untrustworthy."""
    responses = minimal_responses(
        **{"/admin/datastore": ok([{"store": "ds"}, {"store": store}])}
    )
    out, _ = collect(monkeypatch, responses)
    assert (out["error_type"], out["error_message"]) == (
        "http_error",
        "unexpected datastore listing shape",
    )


def test_error_messages_are_redacted(monkeypatch):
    body = "failed token=" + "A" * 40
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/gc": fail(500, body)})
    )
    assert "A" * 40 not in out["errors"][0]["message"]


_HOSTILE_BODY = "denied\nFAKE LOG LINE token=" + "A" * 40


@pytest.mark.parametrize(
    "override, where",
    [
        (
            {"/admin/datastore/ds/gc": fail(500, _HOSTILE_BODY)},
            "PBS gc read failed on ds:",
        ),
        (
            {"/admin/datastore/ds/namespace": fail(500, _HOSTILE_BODY)},
            "PBS namespaces read failed on ds:",
        ),
        (
            {"/admin/datastore/ds/groups": fail(500, _HOSTILE_BODY)},
            "PBS groups read failed on ds:",
        ),
        (
            {"/admin/sync?sync-direction=all": fail(500, _HOSTILE_BODY)},
            "PBS sync_jobs read failed:",
        ),
    ],
)
def test_sub_read_log_lines_name_the_read_and_are_log_safe(
    override, where, monkeypatch
):
    logged = capture_logs(monkeypatch)
    collect(monkeypatch, minimal_responses(**override))
    lines = [line for _, line in logged]
    assert any(line.startswith(where) for line in lines), lines
    assert all("\n" not in line and "A" * 40 not in line for line in lines)


def test_a_namespace_read_failure_names_the_namespace(monkeypatch):
    logged = capture_logs(monkeypatch)
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": "clusterA"}]),
            "/admin/datastore/ds/groups?ns=clusterA": fail(500, "boom"),
        }
    )
    collect(monkeypatch, responses)
    assert ("error", "PBS groups read failed on ds/clusterA: HTTP 500: boom") in logged


def test_pve_join_key_spells_the_fingerprint_like_the_pbs_collector():
    """The server joins a PVE 'pbs' storage row (proxmox._pbs_storage_ref) to
    data['pbs'] on the certificate fingerprint plus the datastore (the host only
    breaks a tie between cloned PBS; pve_join_contract). PVE's storage.cfg spelling
    (upper-case, colons), a pinned config value without colons, and the peer
    certificate the collector reads must all land on ONE string, or the join
    silently matches nothing."""
    from fivenines_agent.proxmox import _pbs_storage_ref

    der = b"certificate-bytes"
    digest = hashlib.sha256(der).digest()
    pve_spelling = _colon(digest).upper()
    ref = _pbs_storage_ref(
        {"server": "pbs.example", "datastore": "ds", "fingerprint": pve_spelling}
    )
    response = MagicMock()
    response.raw.connection.sock.getpeercert.return_value = der
    assert (
        ref["fingerprint"]
        == pbs._peer_fingerprint(response)
        == pbs._normalize_fingerprint(pve_spelling)
        == pbs._normalize_fingerprint(digest.hex().upper())
    )


def test_loopback_insecure_warning_is_filtered_only_for_loopback():
    import warnings

    from urllib3.exceptions import InsecureRequestWarning

    # pytest discards filters installed while collecting, so install it again
    # inside a scratch filter list, exactly as the import does.
    with warnings.catch_warnings():
        pbs._silence_loopback_insecure_warning()
        registered = [
            f
            for f in warnings.filters
            if f[0] == "ignore"
            and f[2] is InsecureRequestWarning
            and f[1] is not None
            and f[1].pattern == pbs._LOOPBACK_WARNING
        ]
    assert registered
    matcher = registered[0][1]
    for host in ("localhost", "127.0.0.1", "127.1.2.3", "::1"):
        assert matcher.match(
            f"Unverified HTTPS request is being made to host '{host}'. Adding"
        )
    for host in ("pbs.example", "10.0.0.1", "127.0.0.1.evil"):
        assert not matcher.match(
            f"Unverified HTTPS request is being made to host '{host}'. Adding"
        )


# --- edge cases: TLS names, log dedup, fallbacks, budget and rotation -------


@pytest.mark.parametrize(
    "host",
    ["localhost.attacker.example", "localhost-pbs", "mylocalhost", "127.0.0.1.nip.io"],
)
def test_only_an_exact_loopback_name_skips_tls_verification(host):
    assert pbs._url_host(host)[2] is False
    with pytest.raises(pbs._PbsError) as excinfo:
        _target(host=host)  # verify_ssl False, no fingerprint
    assert excinfo.value.error_type == "config_error"


def test_the_localhost_name_is_only_rewritten_when_unverified():
    # Unverified: the loopback literal, so no resolver can send the token away.
    assert _target(host="LOCALHOST").base == "https://127.0.0.1:8007/api2/json"
    # Verified or pinned: the name is kept (certificate names, SNI).
    pinned = _target(fingerprint=FINGERPRINT)
    assert pinned.base == "https://localhost:8007/api2/json"
    assert pinned.host == "localhost"
    verified = _target(verify_ssl=True)
    assert verified.base == "https://localhost:8007/api2/json"


def test_the_newest_finished_snapshot_stands_in_for_a_missing_last_backup():
    finished = {t: snapshot("vm", "1", t) for t in (300, 100, 200)}
    row = pbs._group_row(
        "ds",
        "",
        {"backup-type": "vm", "backup-id": "1"},
        {"finished": finished, "newest_unfinished": None},
    )
    assert row["last_backup"] == 300


def test_a_first_backup_still_uploading_is_never_the_last_backup():
    """Measured on PBS 4.2: a group whose ONLY snapshot is uploading reports
    that upload as last-backup, with no manifest among its files."""
    when = 1790594854
    group = {
        "backup-type": "host",
        "backup-id": "fresh01",
        "backup-count": 1,
        "last-backup": when,
        "files": [],
    }
    snaps = [
        {
            "backup-type": "host",
            "backup-id": "fresh01",
            "backup-time": when,
            "files": [],
        }
    ]
    summary = pbs._summarize_snapshots(snaps, "ds")[0][("host", "fresh01")]
    row = pbs._group_row("ds", "", group, summary)
    assert row["last_backup"] is None and row["in_progress"] is True
    assert row["verify_failed_count"] == 0
    # Without the snapshot listing: no last backup, details unknown.
    row = pbs._group_row("ds", "", group, None)
    assert row["last_backup"] is None and row["in_progress"] is None
    # A finished group lists its manifest: last-backup is trusted.
    finished = dict(group, files=["root.pxar.didx", "index.json.blob"])
    assert pbs._group_row("ds", "", finished, None)["last_backup"] == when


def test_a_changed_failure_logs_at_error_again(monkeypatch):
    logged = capture_logs(monkeypatch)
    collect(monkeypatch, {"/version": {"error": "timeout", "message": "slow"}})
    collect(monkeypatch, {"/version": {"error": "connection_refused", "message": "no"}})
    assert [level for level, _ in logged] == ["error", "error"]


def test_a_steady_connect_timeout_is_one_message(monkeypatch):
    """urllib3 embeds the connection object's address and the clamped timeout
    in its message, both new every tick: stripped, so the log dedup works and
    the wire message is stable."""
    logged = capture_logs(monkeypatch)
    for address, timeout in (("0x10b282290", "4.99"), ("0x10b294290", "3.2")):
        message = (
            "HTTPSConnectionPool(host='10.0.0.9', port=8007): Max retries exceeded "
            f"(Caused by ConnectTimeoutError(<HTTPSConnection(host='10.0.0.9', "
            f"port=8007) at {address}>, 'Connection to 10.0.0.9 timed out. "
            f"(connect timeout={timeout})'))"
        )
        out, _ = collect(
            monkeypatch, {"/version": {"error": "timeout", "message": message}}
        )
    assert [level for level, _ in logged] == ["error", "debug"]
    assert "0x" not in out["error_message"]
    assert "(connect timeout)" in out["error_message"]


@pytest.mark.parametrize(
    "status, body",
    [
        (401, "x"),
        (403, "x"),
        (404, "x"),
        # Every PBS handler error is a 400 too: only the parameter rejection
        # itself means "a PBS without push sync".
        (400, "unable to parse sync job config"),
    ],
)
def test_only_the_parameter_rejection_falls_back_to_the_pull_only_listing(
    status, body, monkeypatch
):
    # A pull-only list shipped as complete would drop the push jobs.
    responses = minimal_responses(
        **{
            "/admin/sync?sync-direction=all": fail(status, body),
            "/admin/sync": ok([{"id": "pull1"}]),
        }
    )
    out, session = collect(monkeypatch, responses)
    assert out["sync_jobs"] is None
    assert "/admin/sync" not in [route(u) for u in session.calls]


def _two_datastores(namespaces=("", "x"), **overrides):
    responses = minimal_responses(
        **{
            "/admin/datastore": ok([{"store": "a"}, {"store": "b"}]),
            "/status/datastore-usage": ok([]),
        }
    )
    for store in ("a", "b"):
        responses[f"/admin/datastore/{store}/gc"] = ok({})
        responses[f"/admin/datastore/{store}/namespace"] = ok(
            [{"ns": ns} for ns in namespaces]
        )
        for ns in namespaces:
            query = f"?ns={ns}" if ns else ""
            responses[f"/admin/datastore/{store}/groups{query}"] = ok([])
            responses[f"/admin/datastore/{store}/snapshots{query}"] = ok([])
    responses.update(overrides)
    return responses


def test_the_namespace_cap_is_shared_across_datastores(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 3)
    out, _ = collect(
        monkeypatch,
        _two_datastores(**{"/admin/datastore/b/groups": fail(500, "down")}),
    )
    a, b = out["datastores"]
    assert (a["namespaces"], a["unread_namespaces"]) == (["", "x"], [])
    # b's set is unknown; its kept-but-failed namespace does not resurrect an
    # unread list for it.
    assert (b["namespaces"], b["unread_namespaces"]) == (None, None)
    assert {
        "scope": "cap",
        "store": "b",
        "ns": None,
        "message": "namespaces capped at 3: 1 dropped",
    } in out["errors"]


def test_budget_skips_are_counted_per_datastore(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    _slow_groups(monkeypatch, clock)
    out, _ = collect(monkeypatch, _two_datastores())
    skipped = [e for e in out["errors"] if e["scope"] == "groups"]
    assert skipped == [
        {
            "scope": "groups",
            "store": "a",
            "ns": None,
            "message": f"{pbs._DEADLINE_MESSAGE} (1 namespace(s) not read)",
        },
        {
            "scope": "groups",
            "store": "b",
            "ns": None,
            "message": f"{pbs._DEADLINE_MESSAGE} (2 namespace(s) not read)",
        },
    ]
    a, b = out["datastores"]
    assert (a["unread_namespaces"], b["unread_namespaces"]) == (["x"], ["", "x"])


def test_a_unit_the_budget_ran_out_inside_is_read_first_next_time(monkeypatch):
    """The clamped timeouts make the budget run out INSIDE a read. That unit --
    even the last one -- is read first on the next build; if it outlasts the
    budget again as the first unit, the rotation moves past it."""
    clock = use_clock(monkeypatch, Clock())
    real_get = pbs._get

    sent_b = 0

    def get(session, target, path, *args, **kwargs):
        nonlocal sent_b
        if path.endswith("/snapshots") and (args and args[0] == {"ns": "b"}):
            sent_b += 1
            clock.now += 100  # the read that eats the rest of the budget
            raise pbs._PbsError(
                "timeout", "read timed out", reachable=False, pending=True
            )
        return real_get(session, target, path, *args, **kwargs)

    monkeypatch.setattr(pbs, "_get", get)
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": "b"}]),
            "/admin/datastore/ds/groups?ns=b": ok([]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert pbs._rotation == ("ds", "b")  # the last unit is read first next time
    # Its groups were read, but not its snapshot listing: unread.
    assert out["datastores"][0]["unread_namespaces"] == ["b"]
    # The next rebuild starts at b, but its /snapshots got a full read timeout
    # and timed out: PBS may still be running that scan, so it is held back
    # (the timeout backoff) and b reads unread meanwhile.
    clock.now += pbs.PBS_CACHE_TTL
    out, _ = collect(monkeypatch, responses)
    assert sent_b == 1
    assert out["datastores"][0]["unread_namespaces"] == ["b"]
    # Past its backoff it is sent again, first: cut again, move past it.
    clock.now += pbs.PBS_CACHE_TTL
    pbs._rotation = ("ds", "b")
    out, _ = collect(monkeypatch, responses)
    assert sent_b == 2
    assert pbs._rotation == ("ds", "")


def test_a_wedged_datastore_does_not_starve_the_others(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real_read_gc = pbs._read_gc
    seen = []

    def read_gc(session, target, errors, deadline, store):
        seen.append(store)
        if store == "a":
            clock.now += 100  # a hung mount eats the whole budget
            return None
        return real_read_gc(session, target, errors, deadline, store)

    monkeypatch.setattr(pbs, "_read_gc", read_gc)
    out, _ = collect(monkeypatch, _two_datastores())
    assert seen == ["a", "b"] and out["datastores"][1]["namespaces"] is None
    assert pbs._store_rotation == "b"
    out, _ = collect(monkeypatch, _two_datastores())
    assert seen[2:] == ["b", "a"]
    assert out["datastores"][1]["namespaces"] == ["", "x"]  # b read this time
    assert [d["store"] for d in out["datastores"]] == ["a", "b"]  # still sorted


def test_a_scoped_grant_counts_without_propagation():
    # It audits at least that datastore (or namespace) itself.
    assert pbs._check_privileges({"/datastore/ds": {"Datastore.Audit": False}})[:2] == (
        False,
        False,
    )


def test_the_block_says_whether_absence_means_gone(monkeypatch):
    out, _ = collect(monkeypatch, minimal_responses())
    assert out["scope"] == "full"
    perms = {"/datastore/ds": {"Datastore.Audit": True}}
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/access/permissions": ok(perms),
                "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
            }
        ),
    )
    assert out["scope"] == "partial"
    monkeypatch.setattr(pbs, "MAX_DATASTORES", 1)
    listing = [{"store": "ds"}, {"store": "zz"}]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore": ok(listing)})
    )
    assert out["scope"] == "partial"  # a datastore past the cap is not gone


def test_the_bare_handshake_is_only_made_on_a_tls_failure(monkeypatch):
    calls = []
    install(monkeypatch, {"/version": {"error": "timeout"}})
    monkeypatch.setattr(
        pbs, "_presented_fingerprint", lambda target, deadline: calls.append(target)
    )
    out = pbs.pbs_metrics(**LOOPBACK)
    assert out["error_type"] == "timeout" and "presented_fingerprint" not in out
    assert calls == []


def test_the_summary_is_order_independent():
    snaps = [
        snapshot("vm", "1", 250, size=None, files=[]),
        snapshot("vm", "1", 300, size=None, files=[]),
        snapshot("vm", "1", 150, verification=verified("ok")),
        snapshot("vm", "1", 200, verification=verified("ok")),
    ]
    for order in (snaps, snaps[::-1]):
        summary = pbs._summarize_snapshots(order, "ds")[0][("vm", "1")]
        assert (summary["newest_unfinished"], summary["last_verified_ok"]) == (300, 200)


def test_a_failed_rebuild_after_version_answered_is_not_unreachable(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore": {"error": "timeout", "message": "slow"}}
        ),
    )
    assert (out["error_type"], out["reachable"]) == ("timeout", True)

    def broken(session, target, deadline):
        raise RuntimeError("bug")

    monkeypatch.setattr(pbs, "_build_block", broken)
    out, _ = collect(monkeypatch, minimal_responses())
    assert (out["error_type"], out["reachable"]) == ("http_error", True)


def test_a_steady_sub_read_failure_logs_at_error_once_per_streak(monkeypatch):
    logged = capture_logs(monkeypatch)
    monkeypatch.setattr(pbs, "_read_failures", {"previous": set(), "current": set()})
    responses = minimal_responses(**{"/admin/datastore/ds/gc": fail(403, "denied")})
    for _ in range(3):
        collect(monkeypatch, responses)
    assert [level for level, _ in logged] == ["error", "debug", "debug"]
    collect(monkeypatch, minimal_responses())  # the failure stops
    collect(monkeypatch, responses)  # and starts again: a new streak
    assert logged[-1][0] == "error"


def test_a_failed_build_does_not_restart_a_sub_read_failure_streak(monkeypatch):
    """A build that raises (here on the token check) publishes nothing, so
    the steady gc failure is still a known one on the build after it."""
    logged = capture_logs(monkeypatch)
    good = minimal_responses(**{"/admin/datastore/ds/gc": fail(403, "denied")})
    bad = {**good, "/access/permissions": fail(500, "boom")}
    for responses in (good, good, bad, good):
        collect(monkeypatch, responses)
    levels = [lvl for lvl, m in logged if m.startswith("PBS gc read failed")]
    assert levels == ["error", "debug", "debug"]


def test_headers_arriving_past_the_budget_end_the_read(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    response = FakeResponse(200, json_body={"data": {}})

    def slow(url):
        clock.now += 10  # headers arrive after the budget
        return response

    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(FakeSession(slow), _target(), "/version", deadline=clock.now + 5)
    assert excinfo.value.message == pbs._DEADLINE_MESSAGE and response.closed


def test_the_error_body_read_is_clamped_to_the_budget(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    bodies = []
    real = pbs.read_capped_body

    def recording(response, max_bytes, timeout_s):
        bodies.append(timeout_s)
        return real(response, max_bytes, timeout_s)

    monkeypatch.setattr(pbs, "read_capped_body", recording)
    session = FakeSession(lambda url: FakeResponse(500, body="boom"))
    with pytest.raises(pbs._PbsError):
        pbs._get(session, _target(), "/version", deadline=clock.now + 1.5)
    assert bodies == [1.5]


# --- edge cases: snapshots, jobs, usage fallback, caps and rotation --------


def test_every_request_of_a_tick_is_clamped_to_the_budget_left(monkeypatch):
    """The tick's deadline must reach EVERY request, not only _get called
    directly: each connect/read timeout and body deadline is at most what is
    left of the budget when the request starts."""
    clock = use_clock(monkeypatch, Clock())
    deadline = clock.now + pbs.PBS_COLLECT_DEADLINE
    handler = responses_handler(minimal_responses())
    left, bodies = [], []

    def slow(url):
        left.append(deadline - clock.now)
        # /version eats a quarter of the budget: the later reads are clamped,
        # and the namespace walk still has its whole read timeout ahead.
        clock.now += 5 if route(url) == "/version" else 0.5
        return handler(url)

    real = pbs.read_capped_body

    def recording(response, max_bytes, timeout_s):
        bodies.append((timeout_s, deadline - clock.now))
        return real(response, max_bytes, timeout_s)

    session = FakeSession(slow)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    monkeypatch.setattr(pbs, "read_capped_body", recording)
    pbs.pbs_metrics(**LOOPBACK)
    routes = [route(u) for u in session.calls]
    assert "/admin/sync?sync-direction=all" in routes
    assert "/admin/datastore/ds/gc" in routes
    assert "/admin/datastore/ds/snapshots" in routes
    for (connect, read), remaining in zip(session.timeouts, left):
        # A held or backed-off read keeps _TIMEOUT_BACKOFF_MIN_WAIT (see _get);
        # here every walk has its whole read timeout left anyway.
        floor = pbs._TIMEOUT_BACKOFF_MIN_WAIT
        assert connect <= remaining and read <= max(remaining, floor)
    assert bodies and all(timeout <= remaining for timeout, remaining in bodies)


def test_a_backoff_is_scoped_to_its_pbs_even_with_the_same_secret(monkeypatch):
    use_clock(monkeypatch, Clock())
    collect(monkeypatch, {"/version": fail(401, "authentication failed")})
    out, session = collect(
        monkeypatch, minimal_responses(), token_id="fixed@pbs!monitoring"
    )
    assert "datastores" in out and session.calls


@pytest.mark.parametrize("status", [400, 403, 500])
def test_an_http_error_on_snapshots_marks_the_namespace_unread(status, monkeypatch):
    """PBS leaves out of /groups a group whose snapshots it failed to read and
    still answers 200; the failure shows only on /snapshots, as HTTP 400 (the
    status proxmox-rest-server gives every handler error), so any HTTP error
    there makes the namespace unread while its groups still ship."""
    message = "unable to list backup snapshots of vm/101 - EIO"
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/datastore/ds/snapshots": fail(status, message)}),
    )
    assert out["datastores"][0]["unread_namespaces"] == [""]
    assert out["groups"][0]["in_progress"] is None
    assert [e["scope"] for e in out["errors"]] == ["snapshots"]
    # So does a timeout: the scan may never have reached the dropped group.
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/datastore/ds/snapshots": {"error": "timeout"}}),
    )
    assert out["datastores"][0]["unread_namespaces"] == [""]


# Value: protects=a snapshot list with an unparseable row keeps its namespace read, since the scan ended;
#   fails_when=any snapshot error starts marking the namespace unread;
#   why_new=the contract now states it and no test pinned it; seam=none
def test_an_unparseable_snapshot_row_makes_the_details_unknown(monkeypatch):
    snaps = [snapshot("vm", "100", 200), {"backup-type": "vm", "backup-id": 7}]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/snapshots": ok(snaps)})
    )
    group = out["groups"][0]
    assert group["in_progress"] is None and group["size"] is None
    assert out["errors"] == [
        {
            "scope": "snapshots",
            "store": "ds",
            "ns": "",
            "message": "1 unparseable snapshot row(s): details unknown",
        }
    ]
    # A list came back: PBS's scan ended, the namespace stays read.
    assert out["datastores"][0]["unread_namespaces"] == []


def test_an_unparseable_job_row_flags_the_list_partial(monkeypatch):
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/verify": ok(["junk", {"id": "v"}])})
    )
    assert [j["id"] for j in out["verify_jobs"]] == ["v"]
    assert out["errors"] == [
        {
            "scope": "verify_jobs",
            "store": None,
            "ns": None,
            "message": "partial: 1 unparseable job row(s) skipped",
        }
    ]


def test_a_running_job_shows_its_start():
    # PBS reports a running job with its task id and no state or end time.
    running = pbs._sync_job(
        {"id": "s", "last-run-upid": "UPID:n:1:2:3:0000000C:syncjob:s:root@pam:"}
    )
    assert (running["last_run_starttime"], running["last_run_state"]) == (12, None)
    assert running["last_run_endtime"] is None
    assert pbs._verify_job({"id": "v"})["last_run_starttime"] is None


def test_in_progress_since_dates_the_upload():
    summary = {"finished": {100: snapshot("vm", "1", 100)}, "newest_unfinished": 150}
    group = {"backup-type": "vm", "backup-id": "1", "last-backup": 100}
    row = pbs._group_row("ds", "", group, summary)
    assert (row["in_progress"], row["in_progress_since"]) == (True, 150)
    summary["newest_unfinished"] = None
    row = pbs._group_row("ds", "", group, summary)
    assert (row["in_progress"], row["in_progress_since"]) == (False, None)


def test_an_old_orphan_upload_is_not_in_progress_since():
    """A crash-orphaned upload OLDER than the last finished backup (prune
    keeps it) is not in progress, so it must not date one either."""
    summary = {"finished": {200: snapshot("vm", "1", 200)}, "newest_unfinished": 150}
    group = {"backup-type": "vm", "backup-id": "1", "last-backup": 200}
    row = pbs._group_row("ds", "", group, summary)
    assert (row["in_progress"], row["in_progress_since"]) == (False, None)


def test_s3_usage_is_not_shipped_as_the_datastore_capacity(monkeypatch):
    listing = [{"store": "ds", "backend-type": "s3"}]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore": ok(listing)})
    )
    datastore = out["datastores"][0]
    assert datastore["backend_type"] == "s3"
    assert (datastore["total"], datastore["estimated_full_date"]) == (None, None)


def test_a_failed_aggregate_usage_falls_back_to_each_datastore(monkeypatch):
    """PBS fails /status/datastore-usage as a whole when ONE datastore's statfs
    errors; a full-scope token then reads each datastore's own status."""
    responses = minimal_responses(
        **{
            "/status/datastore-usage": fail(500, "EIO"),
            "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
        }
    )
    out, _ = collect(monkeypatch, responses)
    datastore = out["datastores"][0]
    assert (datastore["total"], datastore["used"], datastore["avail"]) == (9, 4, 5)
    assert datastore["estimated_full_date"] is None
    # A token scoped BELOW the datastore never reads it: PBS answers it a
    # false 0/0/0 (measurement 6).
    perms = {"/datastore/ds/a": {"Datastore.Audit": True}}
    responses["/access/permissions"] = ok(perms)
    out, session = collect(monkeypatch, responses)
    assert out["datastores"][0]["total"] is None
    assert "/admin/datastore/ds/status" not in [route(u) for u in session.calls]


def test_a_hung_datastore_leaves_the_other_ones_namespaces_their_half(monkeypatch):
    """Every read of datastore b (its own status, gc) hangs until the deadline
    it was given, and its namespace walk is then skipped (less than its whole
    read timeout left in the tick). Given the whole budget, b would leave the
    groups phase nothing and a's namespaces would go unread; given half, a's
    namespaces are still read."""
    clock = use_clock(monkeypatch, Clock())
    real_get = pbs._get

    def get(session, target, path, *args, deadline=None, **kwargs):
        if path.startswith("/admin/datastore/b/"):
            clock.now = max(clock.now, deadline)  # a hung mount
            raise pbs._PbsError("timeout", "read timed out", reachable=False)
        return real_get(session, target, path, *args, deadline=deadline, **kwargs)

    monkeypatch.setattr(pbs, "_get", get)
    responses = _two_datastores(**{"/status/datastore-usage": fail(500, "EIO")})
    responses["/admin/datastore/a/status"] = ok({"total": 1, "used": 1, "avail": 0})
    out, session = collect(monkeypatch, responses)
    a, b = out["datastores"]
    assert (a["namespaces"], a["unread_namespaces"]) == (["", "x"], [])
    assert b["namespaces"] is None
    assert "/admin/datastore/a/groups?ns=x" in [route(u) for u in session.calls]


def test_a_group_cap_trim_on_the_last_unit_rotates(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_GROUPS", 3)
    groups = [
        {"backup-type": "vm", "backup-id": str(i), "last-backup": 1} for i in (1, 2)
    ]
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": "b"}]),
            "/admin/datastore/ds/groups": ok(groups),
            "/admin/datastore/ds/snapshots": ok([]),
            "/admin/datastore/ds/groups?ns=b": ok(groups),
            "/admin/datastore/ds/snapshots?ns=b": ok([]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert out["datastores"][0]["unread_namespaces"] == ["b"]
    assert pbs._rotation == ("ds", "b")
    out, _ = collect(monkeypatch, responses)
    assert out["datastores"][0]["unread_namespaces"] == [""]
    assert pbs._rotation == ("ds", "")


def test_a_namespace_cap_trim_rotates_across_datastores(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 3)
    out, _ = collect(monkeypatch, _two_datastores())
    assert [d["namespaces"] for d in out["datastores"]] == [["", "x"], None]
    assert pbs._store_rotation == "b"
    out, _ = collect(monkeypatch, _two_datastores())
    assert [d["namespaces"] for d in out["datastores"]] == [None, ["", "x"]]
    assert pbs._store_rotation == "a"


def test_a_full_group_cap_skips_the_next_namespace_without_reading_it(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_GROUPS", 2)
    groups = [
        {"backup-type": "vm", "backup-id": str(i), "last-backup": 1} for i in (1, 2)
    ]
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": "b"}]),
            "/admin/datastore/ds/groups": ok(groups),
            "/admin/datastore/ds/snapshots": ok([]),
        }
    )
    out, session = collect(monkeypatch, responses)
    assert len(out["groups"]) == 2
    assert out["datastores"][0]["unread_namespaces"] == ["b"]
    assert {
        "scope": "cap",
        "store": "ds",
        "ns": None,
        "message": "groups capped at 2: 1 namespace(s) not read",
    } in out["errors"]
    assert "/admin/datastore/ds/groups?ns=b" not in [route(u) for u in session.calls]
    assert pbs._rotation == ("ds", "b")


# --- behaviours covered by mutation, not by line coverage alone ------------


def test_the_errors_cap_keeps_the_block_level_entries(monkeypatch):
    """errors_contract: the cap drops the TAIL. A job list's 'partial:' flag
    lives ONLY in errors[] and is appended before any per-namespace entry, so
    a flood of namespace failures must never push it out."""
    monkeypatch.setattr(pbs, "MAX_ERRORS", 4)
    perms = {
        "/datastore/ds": {"Datastore.Audit": True},
        "/remote": {"Remote.Audit": True},
    }
    names = ["", "a", "b", "c", "d"]
    responses = minimal_responses(
        **{
            "/access/permissions": ok(perms),
            "/admin/datastore/ds/namespace": ok([{"ns": n} for n in names]),
            "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
        }
    )
    for ns in names:
        suffix = f"?ns={ns}" if ns else ""
        responses[f"/admin/datastore/ds/groups{suffix}"] = fail(500, "down")
    out, _ = collect(monkeypatch, responses)
    assert [e["scope"] for e in out["errors"]] == [
        "sync_jobs",
        "verify_jobs",
        "prune_jobs",
        "cap",
    ]
    assert all(e["message"].startswith("partial:") for e in out["errors"][:3])
    assert out["errors"][-1]["message"] == "errors capped at 4: 5 dropped"
    assert out["datastores"][0]["unread_namespaces"] == names


_USAGE = (1000, 400, 600, 1900000000)


@pytest.mark.parametrize(
    "overrides, backend, usage_ships",
    [
        # PBS < 4.1.6 lists no backend-type: the config says, and no backend
        # property is a filesystem datastore (every one before S3, 4.0.4).
        ({"/config/datastore": ok([{"name": "ds", "path": "/p"}])}, "filesystem", True),
        # An S3 datastore of PBS 4.0.4-4.1.5: its usage is the CACHE disk.
        (
            {"/config/datastore": ok([{"name": "ds", "backend": "type=s3,bucket=b"}])},
            "s3",
            False,
        ),
        # The property's default-key spelling.
        (
            {"/config/datastore": ok([{"name": "ds", "backend": "s3,bucket=b"}])},
            "s3",
            False,
        ),
        # PBS 4.1.6 names it in the usage status: no config read needed.
        (
            {"/status/datastore-usage": ok([{"store": "ds", "backend-type": "s3"}])},
            "s3",
            False,
        ),
        # Unknown -- the store absent from the config (a token scoped below
        # it), or a backend that cannot be read: usage withheld too.
        ({"/config/datastore": ok([])}, None, False),
        ({"/config/datastore": ok([{"name": "ds", "backend": 5}])}, None, False),
        (
            {"/config/datastore": ok([{"name": "ds", "backend": "bucket=b"}])},
            None,
            False,
        ),
    ],
)
def test_the_backend_decides_whether_usage_is_the_datastores(
    overrides, backend, usage_ships, monkeypatch
):
    responses = minimal_responses(**{"/admin/datastore": ok([{"store": "ds"}])})
    responses.update(overrides)
    out, session = collect(monkeypatch, responses)
    datastore = out["datastores"][0]
    assert datastore["backend_type"] == backend
    usage = (
        datastore["total"],
        datastore["used"],
        datastore["avail"],
        datastore["estimated_full_date"],
    )
    if "backend-type" in str(overrides):
        # The usage row named the backend; it carries no numbers here.
        assert "/config/datastore" not in [route(u) for u in session.calls]
    else:
        assert usage == (_USAGE if usage_ships else (None,) * 4)


def test_an_unreadable_datastore_config_withholds_usage_with_an_error(monkeypatch):
    responses = minimal_responses(
        **{
            "/admin/datastore": ok([{"store": "ds"}]),
            "/config/datastore": fail(500, "boom"),
        }
    )
    out, _ = collect(monkeypatch, responses)
    datastore = out["datastores"][0]
    assert (datastore["backend_type"], datastore["total"]) == (None, None)
    assert out["errors"] == [
        {
            "scope": "datastore_config",
            "store": None,
            "ns": None,
            "message": "HTTP 500: boom",
        }
    ]


def test_a_listing_that_names_the_backend_never_reads_the_config(monkeypatch):
    out, session = collect(monkeypatch, minimal_responses())
    assert out["datastores"][0]["backend_type"] == "filesystem"
    assert "/config/datastore" not in [route(u) for u in session.calls]


def test_a_unit_finished_as_the_budget_ran_out_is_not_read_first_again(monkeypatch):
    """freshness: the next build starts at the first unit this one could NOT
    finish. A unit whose reads completed just as the budget ran out was
    finished; re-reading it first would spend the next budget on it again."""
    clock = use_clock(monkeypatch, Clock())
    order = _slow_groups(monkeypatch, clock, seconds=15)
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": "b"}, {"ns": "c"}]),
            "/admin/datastore/ds/groups?ns=b": ok([]),
            "/admin/datastore/ds/snapshots?ns=b": ok([]),
            "/admin/datastore/ds/groups?ns=c": ok([]),
            "/admin/datastore/ds/snapshots?ns=c": ok([]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert order == ["", "b"]  # "b" completed past the 20s budget
    assert out["datastores"][0]["unread_namespaces"] == ["c"]
    assert pbs._rotation == ("ds", "c")  # not "b"


def test_unread_namespaces_are_sorted_whatever_the_rotation(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    _slow_groups(monkeypatch, clock)
    monkeypatch.setattr(pbs, "_rotation", ("ds", "b"))  # reads b, c, then ""
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": "b"}, {"ns": "c"}]),
            "/admin/datastore/ds/groups?ns=b": ok([]),
            "/admin/datastore/ds/snapshots?ns=b": ok([]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert out["datastores"][0]["unread_namespaces"] == ["", "c"]


def test_the_datastore_rotation_resumes_at_the_first_one_the_budget_cut(monkeypatch):
    """A datastore whose read FAILED fast (a 403 on gc) was not cut by the
    budget and does not move the rotation; the first one the budget cut (a
    hung mount) is read first next time -- not the last one cut after it."""
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c", "d"]
    responses = minimal_responses(
        **{
            "/admin/datastore": ok([{"store": n} for n in names]),
            "/status/datastore-usage": ok([]),
        }
    )
    for store in names:
        responses[f"/admin/datastore/{store}/gc"] = ok({})
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": ""}])
        responses[f"/admin/datastore/{store}/groups"] = ok([])
        responses[f"/admin/datastore/{store}/snapshots"] = ok([])
    responses["/admin/datastore/b/gc"] = fail(403, "permission check failed")
    real_read_gc = pbs._read_gc

    def read_gc(session, target, errors, deadline, store):
        if store == "c":
            clock.now += 100  # a hung mount eats the whole budget
            return None
        return real_read_gc(session, target, errors, deadline, store)

    monkeypatch.setattr(pbs, "_read_gc", read_gc)
    out, _ = collect(monkeypatch, responses)
    a, b, c, d = out["datastores"]
    assert b["gc"] is None and b["namespaces"] == [""]  # failed fast, rest read
    assert c["namespaces"] is None and d["namespaces"] is None  # cut
    assert pbs._store_rotation == "c"


def test_a_datastore_finished_as_the_phase_ran_out_is_not_read_first_again(
    monkeypatch,
):
    """The datastore counterpart of the namespace rule: b completed its reads
    by the tick's deadline (its namespace walk is bounded by the tick, not the
    phase), so it was finished; the next build starts at c, the first
    datastore actually skipped."""
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c"]
    responses = minimal_responses(
        **{
            "/admin/datastore": ok([{"store": n} for n in names]),
            "/status/datastore-usage": ok([]),
        }
    )
    for store in names:
        responses[f"/admin/datastore/{store}/gc"] = ok({})
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": ""}])
        responses[f"/admin/datastore/{store}/groups"] = ok([])
        responses[f"/admin/datastore/{store}/snapshots"] = ok([])
    real = pbs._read_namespaces

    def slow(session, target, errors, deadline, store):
        rows = real(session, target, errors, deadline, store)
        if store == "b":
            clock.now = max(clock.now, deadline)  # done as the tick budget ends
        return rows

    monkeypatch.setattr(pbs, "_read_namespaces", slow)
    out, _ = collect(monkeypatch, responses)
    assert [d["namespaces"] for d in out["datastores"]] == [[""], [""], None]
    assert pbs._store_rotation == "c"  # not b


def test_a_tls_failure_whose_handshake_fails_ships_a_null_fingerprint(monkeypatch):
    """envelope_contract: a tls_error envelope always carries
    presented_fingerprint -- null when the bare handshake could not read one,
    never a missing key."""
    install(
        monkeypatch,
        {"/version": {"error": "tls_error", "message": "bad"}},
        presented=None,
    )
    out = pbs.pbs_metrics(host="pbs.example", fingerprint=FINGERPRINT, **TOKEN)
    assert out == {
        "reachable": False,
        "error_type": "tls_error",
        "error_message": "bad",
        "presented_fingerprint": None,
    }


def test_the_bare_handshake_waits_at_most_one_connect_timeout(monkeypatch):
    seen = []

    def fake(addr, timeout=None):
        seen.append(timeout)
        raise OSError("handshake failed")

    monkeypatch.setattr(pbs.ssl, "get_server_certificate", fake)
    clock = use_clock(monkeypatch, Clock())
    assert pbs._presented_fingerprint(_target(), clock.now + 100) is None
    assert seen == [5]  # a literal: the connect timeout, not the budget left


def test_an_http_error_past_the_budget_keeps_its_status(monkeypatch):
    """What an HTTP status decides (here: a /snapshots error marks the
    namespace unread) must not depend on when its headers arrived: an error
    answered past the budget keeps its status, and only its body is skipped."""
    clock = use_clock(monkeypatch, Clock())
    handler = responses_handler(
        minimal_responses(**{"/admin/datastore/ds/snapshots": fail(400, "EIO")})
    )
    late = []

    def slow(url):
        response = handler(url)
        if route(url) == "/admin/datastore/ds/snapshots":
            clock.now += 100  # headers arrive after the budget
            late.append(response)
        return response

    session = FakeSession(slow)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    out = pbs.pbs_metrics(**LOOPBACK)
    assert out["datastores"][0]["unread_namespaces"] == [""]
    snapshots_errors = [e for e in out["errors"] if e["scope"] == "snapshots"]
    assert [e["message"] for e in snapshots_errors] == ["HTTP 400: "]
    assert late[0].closed


def test_peer_fingerprint_is_read_before_the_body_releases_the_connection(
    monkeypatch,
):
    """The PVE join key is the peer certificate of the /version connection;
    reading the body returns that connection to the pool (urllib3's
    release_conn drops response.raw.connection), so it is read first."""
    der = b"certificate-bytes"

    class LiveResponse(FakeResponse):
        def __init__(self, status, raw):
            super().__init__(status)
            self._raw = raw
            sock = MagicMock()
            sock.getpeercert.return_value = der
            self.raw = MagicMock()
            self.raw.connection.sock = sock

        def close(self):
            super().close()
            self.raw.connection = None  # urllib3 release_conn

    handler = responses_handler(minimal_responses())

    def live(url):
        recorded = handler(url)
        return LiveResponse(recorded.status_code, recorded._raw)

    session = FakeSession(live)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    out = pbs.pbs_metrics(**LOOPBACK)
    assert out["fingerprint"] == hashlib.sha256(der).digest().hex(":")


def test_a_changed_sub_read_failure_logs_at_error_again(monkeypatch):
    """The streak key is the whole failure: the same read failing DIFFERENTLY
    (a 403 turning into an I/O error) is a new failure, logged at error."""
    logged = capture_logs(monkeypatch)
    for message in ("denied", "EIO"):
        collect(
            monkeypatch,
            minimal_responses(**{"/admin/datastore/ds/gc": fail(500, message)}),
        )
    levels = [lvl for lvl, m in logged if m.startswith("PBS gc read failed")]
    assert levels == ["error", "error"]


@pytest.mark.parametrize(
    "usage",
    [{"error": "timeout", "message": "t"}, {"status": 200, "body": "not json"}],
)
def test_any_failed_aggregate_usage_read_falls_back_to_each_datastore(
    usage, monkeypatch
):
    responses = minimal_responses(
        **{
            "/status/datastore-usage": usage,
            "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert out["datastores"][0]["total"] == 9


def test_expected_fallback_statuses_are_not_logged_as_failures(monkeypatch):
    """A 404 on /namespace (PBS < 2.2) and a 400 on sync-direction=all
    (PBS < 3.3) are version fallbacks, not failures: no error, no log line."""
    logged = capture_logs(monkeypatch)
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": fail(404, "not found"),
            "/admin/sync?sync-direction=all": fail(400, _NO_SYNC_DIRECTION),
            "/admin/sync": ok([]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert out["errors"] == []
    assert not [m for _, m in logged if "read failed" in m]


def test_errors_past_the_cap_are_counted_not_built(monkeypatch):
    """Building an entry means redacting its message: past MAX_ERRORS a
    hostile body of thousands of rows must cost a count, not a redaction."""
    monkeypatch.setattr(pbs, "MAX_ERRORS", 4)
    built = []
    real = pbs.scrub_message

    def counting(message):
        built.append(message)
        return real(message)

    monkeypatch.setattr(pbs, "scrub_message", counting)
    # One "no readable manifest" error per group: 50 groups, no snapshots.
    groups = [
        {"backup-type": "vm", "backup-id": str(i), "last-backup": 5} for i in range(50)
    ]
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/groups": ok(groups),
            "/admin/datastore/ds/snapshots": ok([]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert len(out["errors"]) == 4
    assert out["errors"][-1]["message"] == "errors capped at 4: 47 dropped"
    assert len(built) == 5  # the four kept, then the cap entry
    assert type(out["errors"]) is list


def test_usage_row_errors_are_recorded_only_for_listed_datastores(monkeypatch):
    """A usage row names its datastore; one this block does not list (past
    the datastore cap, or a flood from a broken PBS) must not crowd the job
    lists' 'partial:' flags out of the capped errors[]."""
    rows = [{"store": f"s{i}", "error": "unavailable"} for i in range(600)]
    rows.append({"store": "ds", "error": "offline maintenance mode"})
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/status/datastore-usage": ok(rows)})
    )
    assert out["errors"] == [
        {
            "scope": "usage",
            "store": "ds",
            "ns": None,
            "message": "offline maintenance mode",
        }
    ]


def test_a_body_deadline_failure_is_one_stable_message():
    """read_capped_body names its clamped (fractional) deadline, which changes
    every build: stripped, so a steady slow body is one failure streak."""
    target = _target()
    messages = {
        pbs._transport_message(
            target, BodyOverBudget(f"response body read exceeded {s}s deadline")
        )
        for s in ("7.25", "6.8342109", "1e-05")
    }
    assert messages == {"response body read exceeded its deadline"}


def _serve(monkeypatch, handler):
    """One tick against a custom handler (the recorded responses, altered)."""
    session = FakeSession(handler)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    return pbs.pbs_metrics(**LOOPBACK)


def test_a_steady_slow_body_is_one_redacted_message_through_get(monkeypatch):
    logged = capture_logs(monkeypatch)
    messages = []
    for seconds in ("7.25", "6.83"):

        def failing(response, max_bytes, timeout_s, seconds=seconds):
            response.close()
            raise BodyOverBudget(
                f"response body read exceeded {seconds}s deadline {SECRET}"
            )

        monkeypatch.setattr(pbs, "read_capped_body", failing)
        out, _ = collect(monkeypatch, minimal_responses())
        messages.append(out["error_message"])
    assert (
        messages
        == ["body read failed: response body read exceeded its deadline [REDACTED]"] * 2
    )
    assert [level for level, _ in logged] == ["error", "debug"]


@pytest.mark.parametrize("late", [5, 10])  # exactly at, and past, the deadline
def test_a_200_at_or_past_the_budget_is_a_timeout_with_its_body_unread(
    late, monkeypatch
):
    clock = use_clock(monkeypatch, Clock())
    touched = []

    class Watched(FakeResponse):
        def iter_content(self, chunk_size=65536):
            touched.append(True)
            return super().iter_content(chunk_size)

    response = Watched(200, json_body={"data": {}})

    def slow(url):
        clock.now += late
        return response

    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(FakeSession(slow), _target(), "/version", deadline=clock.now + 5)
    e = excinfo.value
    assert (e.error_type, e.message, e.reachable) == (
        "timeout",
        pbs._DEADLINE_MESSAGE,
        True,
    )
    assert touched == [] and response.closed


def test_an_error_body_past_the_budget_is_never_read(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    touched = []

    class Unreadable(FakeResponse):
        def iter_content(self, chunk_size=65536):
            touched.append(True)  # a blocking recv on a real socket
            return super().iter_content(chunk_size)

    response = Unreadable(400, body="EIO")

    def slow(url):
        clock.now += 10
        return response

    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(FakeSession(slow), _target(), "/x", deadline=clock.now + 5)
    assert (excinfo.value.status, excinfo.value.message) == (400, "HTTP 400: ")
    assert touched == [] and response.closed


def test_an_error_body_gets_its_own_bounds_not_the_body_budget(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    seen = []
    real = pbs.read_capped_body

    def recording(response, max_bytes, timeout_s):
        seen.append((max_bytes, timeout_s))
        return real(response, max_bytes, timeout_s)

    monkeypatch.setattr(pbs, "read_capped_body", recording)
    for deadline in (None, clock.now + 18):
        with pytest.raises(pbs._PbsError):
            pbs._get(
                FakeSession(lambda url: FakeResponse(500, body="boom")),
                _target(),
                "/x",
                deadline=deadline,
            )
    assert seen == [(4096, 2), (4096, 2)]


def _group_errors(n):
    """n "no readable manifest" errors: n groups, no snapshots."""
    groups = [
        {"backup-type": "vm", "backup-id": str(i), "last-backup": 5} for i in range(n)
    ]
    return minimal_responses(
        **{
            "/admin/datastore/ds/groups": ok(groups),
            "/admin/datastore/ds/snapshots": ok([]),
        }
    )


def test_exactly_max_errors_is_not_capped(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_ERRORS", 4)
    out, _ = collect(monkeypatch, _group_errors(4))
    assert [e["scope"] for e in out["errors"]] == ["snapshots"] * 4
    out, _ = collect(monkeypatch, _group_errors(5))
    assert len(out["errors"]) == 4
    assert out["errors"][-1]["message"] == "errors capped at 4: 2 dropped"


def test_usage_errors_of_a_capped_out_datastore_are_not_recorded(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_DATASTORES", 1)
    rows = [{"store": "ds", "total": 1}, {"store": "zz", "error": "offline"}]
    listing = [{"store": "zz"}, {"store": "ds"}]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore": ok(listing), "/status/datastore-usage": ok(rows)}
        ),
    )
    assert [e["scope"] for e in out["errors"]] == ["cap"]


def test_an_oversized_snapshot_listing_leaves_the_namespace_unread(monkeypatch):
    """Only a snapshot LIST proves PBS's scan ended: a body that fails after
    its 200 leaves the namespace unread too, its details unknown."""
    handler = responses_handler(minimal_responses())
    big = []

    def get(url):
        response = handler(url)
        if route(url) == "/admin/datastore/ds/snapshots":
            big.append(response)
        return response

    real = pbs.read_capped_body

    def capped(response, max_bytes, timeout_s):
        if response in big:
            response.close()
            raise BodyOverBudget(f"response body exceeded {max_bytes} bytes")
        return real(response, max_bytes, timeout_s)

    monkeypatch.setattr(pbs, "read_capped_body", capped)
    out = _serve(monkeypatch, get)
    assert out["datastores"][0]["unread_namespaces"] == [""]
    group = out["groups"][0]
    assert (group["last_backup"], group["in_progress"]) == (200, None)
    assert [e["message"] for e in out["errors"] if e["scope"] == "snapshots"] == [
        "body read failed: response body exceeded 16777216 bytes"
    ]


def test_a_steady_connection_refused_is_one_message(monkeypatch):
    """A DOWN PBS: urllib3's text names the connection object's address,
    which changes every tick; stripped, it is one failure streak."""
    logged = capture_logs(monkeypatch)
    for address in ("0x7f0a1c2b3d40", "0x7f0a1c2b9e10"):
        message = (
            "HTTPSConnectionPool(host='127.0.0.1', port=8007): Max retries "
            "exceeded with url: /api2/json/version (Caused by NewConnectionError("
            f"'<urllib3.connection.HTTPSConnection object at {address}>: Failed "
            "to establish a new connection: [Errno 111] Connection refused'))"
        )
        out, _ = collect(
            monkeypatch,
            {"/version": {"error": "connection_refused", "message": message}},
        )
    assert [level for level, _ in logged] == ["error", "debug"]
    assert "0x" not in out["error_message"]


def test_a_non_utf8_error_body_is_one_scoped_failure(monkeypatch):
    handler = responses_handler(minimal_responses())

    def latin1(url):
        if route(url) == "/admin/datastore/ds/gc":
            response = FakeResponse(502)
            response._raw = "Passerelle d\xe9faillante".encode("latin-1")
            return response
        return handler(url)

    out = _serve(monkeypatch, latin1)
    assert out["reachable"] is True and "datastores" in out
    assert out["errors"][0]["scope"] == "gc"
    assert out["errors"][0]["message"].startswith("HTTP 502: Passerelle d")


@pytest.mark.parametrize(
    "version",
    [{"status": 200, "body": "<html>proxy</html>"}, {"status": 200, "json": [1]}],
)
def test_an_answered_version_with_a_bad_body_is_reachable(version, monkeypatch):
    out, _ = collect(monkeypatch, {"/version": version})
    assert (out["reachable"], out["error_type"]) == (True, "http_error")


def test_an_answered_version_whose_body_read_fails_is_reachable(monkeypatch):
    monkeypatch.setattr(pbs, "_VERSION_MAX_BYTES", 8)
    out, _ = collect(monkeypatch, minimal_responses())
    assert (out["reachable"], out["error_type"]) == (True, "http_error")


@pytest.mark.parametrize("evil", ["n\x00", "\U0001f600" * 10, "a//b", "/a"])
def test_a_namespace_outside_the_pbs_schema_is_unparseable(evil, monkeypatch):
    """No namespace is read or shipped from a listing that holds one PBS's
    schema refuses: namespaces is null (unknown), nothing hostile ships."""
    out, session = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": evil}])}
        ),
    )
    datastore = out["datastores"][0]
    assert datastore["namespaces"] is None and out["groups"] == []
    assert not [u for u in session.calls if route(u) == "/admin/datastore/ds/groups"]
    assert [e["message"] for e in out["errors"] if e["scope"] == "namespaces"] == [
        "unparseable namespace row"
    ]
    assert evil not in json.dumps(out)


_SPLIT_SECRETS = [
    # Split by NUL, which the wire scrub deletes after redaction.
    fail(500, SECRET[:4] + "\x00" + SECRET[4:]),
    # Split around a pattern the message normalization deletes.
    {"error": "connection_refused", "message": SECRET[:4] + " at 0x0" + SECRET[4:]},
]


@pytest.mark.parametrize("path", ["/version", "/admin/datastore/ds/gc"])
@pytest.mark.parametrize("answer", _SPLIT_SECRETS)
def test_a_secret_split_by_a_deleted_character_is_still_redacted(
    path, answer, monkeypatch
):
    """Both the envelope (/version) and a scoped sub-read (gc), whose message
    is logged with no later redaction (errors[] is redacted again by _Errors,
    so the log line is what pins _get's own redaction)."""
    logged = capture_logs(monkeypatch)
    responses = minimal_responses(**{path: answer})
    out, _ = collect(monkeypatch, responses)
    shipped = [out.get("error_message", "")]
    shipped += [e["message"] for e in out.get("errors", [])]
    assert shipped != [""] and not [m for m in shipped if SECRET in m]
    assert not [m for _, m in logged if SECRET in m.replace("\x00", "")]


def test_privilege_names_are_redacted_in_the_envelope(monkeypatch):
    """over_privileged names what PBS listed; a PBS holding the token could
    list it, so the envelope message is redacted like any other."""
    perms = {"/": {"Datastore.Audit": True, SECRET: True}}
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/access/permissions": ok(perms)})
    )
    assert out["error_type"] == "over_privileged"
    assert SECRET not in out["error_message"]


def test_a_transport_message_is_bounded():
    """urllib3 quotes whole status lines and headers (64 KB each), and a
    message is kept in the log-dedup set until the next build."""
    message = pbs._transport_message(_target(), Exception("x" * 100000))
    assert len(message) == pbs.ERROR_PRE_REDACT_MAX_LEN


def test_a_usage_read_answered_past_the_budget_is_a_skip_not_a_failure(
    monkeypatch,
):
    """Headers arriving past the budget are a skip: no per-datastore usage
    fallback (every one of its reads would only record another skip)."""
    clock = use_clock(monkeypatch, Clock())
    handler = responses_handler(minimal_responses())

    def slow(url):
        if route(url) == "/status/datastore-usage":
            clock.now += 100
        return handler(url)

    out = _serve(monkeypatch, slow)
    assert [e for e in out["errors"] if e["scope"] == "usage"] == [
        {"scope": "usage", "store": None, "ns": None, "message": pbs._DEADLINE_MESSAGE}
    ]


def test_gc_counters_are_null_without_a_successful_gc(monkeypatch):
    """Until a GC succeeds PBS answers its status defaults (every counter 0,
    captured on store2 of the healthy scenario): never measured, so null --
    'all null = no successful GC known', and no 0/0 dedup factor."""
    never = {"store": "ds", "index-file-count": 0, "disk-bytes": 0, "still-bad": 0}
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/gc": ok(never)})
    )
    gc = out["datastores"][0]["gc"]
    assert gc["last_run_starttime"] is None
    assert {gc[key] for _, key in pbs._GC_COUNTERS} == {None}
    out, _ = collect(monkeypatch, minimal_responses())  # a successful GC
    assert out["datastores"][0]["gc"]["disk_bytes"] == 10


# --- ship audit: behaviours line coverage did not pin ----------------------


def test_a_verified_session_ignores_the_environment_ca_bundle_and_proxies(
    monkeypatch,
):
    """verify_ssl on a remote host is the setting that keeps the token off a
    man in the middle: the session must verify against requests' bundled CA
    set, and neither a CA bundle nor a proxy from the environment may replace
    it (trust_env = False), so the effective per-request settings are checked,
    not only the attributes."""
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/nonexistent/attacker-ca.pem")
    monkeypatch.setenv("CURL_CA_BUNDLE", "/nonexistent/attacker-ca.pem")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    target = _target(host="pbs.example", verify_ssl=True)
    session = pbs._new_session(target)
    try:
        assert session.verify is True
        settings = session.merge_environment_settings(
            target.base + "/version", {}, None, None, None
        )
        assert settings["verify"] is True
        assert not settings["proxies"]
    finally:
        session.close()


@pytest.mark.parametrize(
    "exc",
    [
        # What a PBS behind a firewall that DROPS the SYN raises: requests
        # makes it both a ConnectionError and a Timeout.
        requests.exceptions.ConnectTimeout("connect timed out"),
        requests.exceptions.ReadTimeout("read timed out"),
    ],
)
def test_a_firewalled_pbs_reads_timeout_not_connection_refused(exc):
    def handler(url):
        raise exc

    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(FakeSession(handler), _target(), "/version")
    assert (excinfo.value.error_type, excinfo.value.reachable) == ("timeout", False)


def test_non_finite_or_mistyped_numbers_never_reach_the_wire(monkeypatch):
    """PBS JSON is parsed with json.loads, which accepts NaN and Infinity. The
    synchronizer serializes with the default allow_nan=True, so one of them
    shipped would be a non-RFC-8259 token that a strict backend parser
    rejects, losing the WHOLE tick for every collector. Every number is
    therefore coerced to an int or null field by field."""
    nan, inf = float("nan"), float("inf")
    usage = {
        "store": "ds",
        "total": nan,
        "used": inf,
        "avail": "600",
        "estimated-full-date": -inf,
    }
    gc = {
        "store": "ds",
        "upid": GC_UPID,
        "last-run-state": "OK",
        "next-run": nan,
        "last-run-endtime": inf,
        "duration": "7",
        "disk-bytes": nan,
        "index-data-bytes": "10",
        "still-bad": True,
    }
    group = {
        "backup-type": "vm",
        "backup-id": "100",
        "backup-count": nan,
        "last-backup": 200,
    }
    job = {
        "id": "v",
        "store": "ds",
        "next-run": nan,
        "max-depth": inf,
        "outdated-after": nan,
        "last-run-endtime": nan,
    }
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/status/datastore-usage": ok([usage]),
                "/admin/datastore/ds/gc": ok(gc),
                "/admin/datastore/ds/groups": ok([group]),
                "/admin/datastore/ds/snapshots": ok(
                    [snapshot("vm", "100", 200, size="100")]
                ),
                "/admin/verify": ok([job]),
            }
        ),
    )
    json.dumps(out, allow_nan=False)  # raises on any NaN/Infinity
    datastore = out["datastores"][0]
    assert (
        datastore["total"],
        datastore["used"],
        datastore["avail"],
        datastore["estimated_full_date"],
    ) == (None, None, 600, None)
    shipped_gc = datastore["gc"]
    assert (shipped_gc["next_run"], shipped_gc["last_run_endtime"]) == (None, None)
    assert (shipped_gc["duration"], shipped_gc["index_data_bytes"]) == (7, 10)
    assert (shipped_gc["disk_bytes"], shipped_gc["still_bad"]) == (None, None)
    row = out["groups"][0]
    assert (row["count"], row["last_backup"], row["size"]) == (None, 200, 100)
    verify = out["verify_jobs"][0]
    assert (
        verify["next_run"],
        verify["max_depth"],
        verify["outdated_after"],
        verify["last_run_endtime"],
    ) == (None, None, None, None)


def test_exactly_at_every_cap_is_not_capped(monkeypatch):
    """A cap trims only PAST its limit: a PBS with exactly the maximum number
    of datastores, namespaces, groups or jobs ships a complete, full-scope
    block with no 'cap' or 'partial:' entry, since either one tells the server
    that something may be missing."""
    for name in ("MAX_DATASTORES", "MAX_NAMESPACES", "MAX_GROUPS", "MAX_JOBS"):
        monkeypatch.setattr(pbs, name, 1)
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/verify": ok([{"id": "v"}])})
    )
    assert out["errors"] == [] and out["scope"] == "full"
    datastore = out["datastores"][0]
    assert (datastore["namespaces"], datastore["unread_namespaces"]) == ([""], [])
    assert len(out["groups"]) == 1 and len(out["verify_jobs"]) == 1


def test_an_unread_long_namespace_is_spelled_as_in_namespaces(monkeypatch):
    """unread_namespaces gates pruning and is matched against namespaces:
    both carry the SAME spelling. A namespace is at most the wire cap long,
    so it ships whole -- a longer one could ship as the same prefix as
    another, and is unparseable instead (PBS caps them well below it)."""
    long_ns = "n" * 255 + "/" + "m" * 244
    assert len(long_ns) == 500
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/namespace": ok([{"ns": long_ns}]),
                "/admin/datastore/ds/groups?ns=" + long_ns: fail(500, "boom"),
            }
        ),
    )
    datastore = out["datastores"][0]
    assert datastore["unread_namespaces"] == datastore["namespaces"] == [long_ns]
    too_long = [{"ns": long_ns + "x"}, {"ns": long_ns + "y"}]
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/datastore/ds/namespace": ok(too_long)}),
    )
    assert out["datastores"][0]["namespaces"] is None


def test_a_changed_tls_policy_rebuilds_the_block(monkeypatch):
    """The same PBS reached under another trust policy (verification turned
    on) must not re-emit the block built under the old one."""
    collect(monkeypatch, minimal_responses(), host="127.0.0.1")
    _, session = collect(
        monkeypatch,
        minimal_responses(),
        keep_cache=True,
        host="127.0.0.1",
        verify_ssl=True,
    )
    assert "/access/permissions" in [route(u) for u in session.calls]


def test_a_body_is_decoded_exactly_as_json_loads_would():
    """_get decodes the bytes itself (so they can be freed before parsing):
    that must not turn a body json.loads accepts into a failed read."""
    raw = b'{"data": "\xed\xa0\x80"}'
    response = FakeResponse(200)
    response._raw = raw
    data = pbs._get(FakeSession(lambda url: response), _target(), "/version")
    assert data == json.loads(raw)["data"]


def test_port_bounds_are_inclusive():
    assert pbs._valid_port(1) == 1
    assert pbs._valid_port(65535) == 65535
    assert pbs._valid_port("65535") == 65535


def test_a_datastore_whose_gc_is_unknown_as_the_phase_ran_out_is_read_first(
    monkeypatch,
):
    """The counterpart of the 'finished as the phase ran out' rule: b's gc
    read failed and its namespace read ended at the tick's deadline, so b
    could NOT be finished; the next build starts at b, not at c."""
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c"]
    responses = minimal_responses(
        **{
            "/admin/datastore": ok([{"store": n} for n in names]),
            "/status/datastore-usage": ok([]),
        }
    )
    for store in names:
        responses[f"/admin/datastore/{store}/gc"] = ok({})
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": ""}])
        responses[f"/admin/datastore/{store}/groups"] = ok([])
        responses[f"/admin/datastore/{store}/snapshots"] = ok([])
    responses["/admin/datastore/b/gc"] = fail(500, "EIO")
    real = pbs._read_namespaces

    def slow(session, target, errors, deadline, store):
        rows = real(session, target, errors, deadline, store)
        if store == "b":
            clock.now = max(clock.now, deadline)  # done as the tick budget ends
        return rows

    monkeypatch.setattr(pbs, "_read_namespaces", slow)
    out, _ = collect(monkeypatch, responses)
    a, b, c = out["datastores"]
    assert b["gc"] is None and b["namespaces"] == [""]
    assert c["namespaces"] is None
    assert pbs._store_rotation == "b"  # not c


# A real TLS listener: what the FakeSession tests cannot see -- urllib3's own
# response object (the peer certificate read), the pinned adapter refusing a
# certificate BEFORE the token is sent, and urllib3's real warning text.


class _PbsHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, like the PBS proxy

    def do_GET(self):
        self.server.seen.append(self.headers.get("Authorization"))
        desc = self.server.responses.get(
            unquote(self.path.removeprefix("/api2/json")), fail(404, "no route")
        )
        if "json" in desc:
            body = json.dumps(desc["json"]).encode("utf-8")
        else:
            body = desc.get("body", "").encode("utf-8")
        self.send_response(desc["status"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _self_signed_certificate(directory):
    """A throwaway certificate from the openssl CLI; skipped without one (a
    private key is never committed to this public repository)."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("no openssl CLI to make a test certificate")
    cert, key = directory / "cert.pem", directory / "key.pem"
    result = subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=pbs.test",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.skip("openssl could not make a test certificate")
    return cert, key


@contextlib.contextmanager
def _tls_pbs(cert, key, responses):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PbsHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.responses, server.seen = responses, []
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def test_tls_against_a_live_listener(tmp_path):
    import warnings

    from urllib3.exceptions import InsecureRequestWarning

    cert, key = _self_signed_certificate(tmp_path)
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    real = hashlib.sha256(der).digest().hex(":")
    wrong = ("11" if real[:2] != "11" else "22") + real[2:]
    with _tls_pbs(cert, key, minimal_responses()) as server, warnings.catch_warnings(
        record=True
    ) as caught:
        warnings.simplefilter("always")
        pbs._silence_loopback_insecure_warning()
        config = {"host": "127.0.0.1", "port": server.server_address[1], **TOKEN}

        # Loopback, unverified: the payload's fingerprint (the PVE join key)
        # is the certificate read off urllib3's live connection, and the
        # token went out in the header only.
        out = pbs.pbs_metrics(verify_ssl=False, **config)
        assert out["fingerprint"] == real and out["errors"] == []
        assert server.seen and set(server.seen) == {
            f"PBSAPIToken={TOKEN['token_id']}:{SECRET}"
        }

        # A wrong pin is refused after the handshake and BEFORE any request:
        # the token never reaches the listener. The envelope names the
        # certificate that was presented...
        server.seen.clear()
        out = pbs.pbs_metrics(fingerprint=wrong, **config)
        assert out["error_type"] == "tls_error" and out["reachable"] is False
        assert out["presented_fingerprint"] == real
        assert server.seen == []

        # ...which, pasted back as the pin, is accepted.
        out = pbs.pbs_metrics(fingerprint=out["presented_fingerprint"], **config)
        assert "datastores" in out and out["fingerprint"] == real

        # verify_ssl checks the bundled CA set: a self-signed certificate is
        # refused, again before any request.
        server.seen.clear()
        out = pbs.pbs_metrics(verify_ssl=True, **config)
        assert out["error_type"] == "tls_error" and server.seen == []

    # Every unverified request went to a loopback address: urllib3's real
    # warning text matched the loopback filter each time.
    assert not [w for w in caught if issubclass(w.category, InsecureRequestWarning)]


def test_a_name_that_cannot_go_back_in_a_url_is_an_unparseable_row(monkeypatch):
    """A JSON "\\udcXX" escape decodes to a lone surrogate that requests cannot
    encode into the next URL: an unparseable namespace nulls only its
    datastore's set; an unparseable datastore name fails the listing (as any
    malformed /admin/datastore row does), never an unexpected exception."""
    bad = json.loads('"x\\udc80"')
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/datastore/ds/namespace": ok([{"ns": bad}])}),
    )
    assert "datastores" in out and out["datastores"][0]["namespaces"] is None
    assert out["errors"][0]["message"] == "unparseable namespace row"
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore": ok([{"store": bad}])})
    )
    assert out["error_message"] == "unexpected datastore listing shape"


def test_the_cap_never_leaves_a_prefix_of_the_secret(monkeypatch):
    """The secret is removed BEFORE the message is cut: a cut first would
    leave a prefix of it at the end, past what the redaction can match."""
    secret = "c9b7e5b5-3e4f-4d3e-9d2a-1f2e3d4c5b6a"
    n = pbs.ERROR_PRE_REDACT_MAX_LEN
    target = _target(token_secret=secret)
    assert pbs._transport_message(target, Exception("x" * (n - 9) + secret)) == (
        "x" * (n - 9) + "[REDACTED]"[:9]
    )
    blob = "A" * (n - 10) + " "  # a run the generic redact() collapses
    logged = capture_logs(monkeypatch)
    out, _ = collect(
        monkeypatch,
        {"/version": {"error": "connection_refused", "message": blob + secret}},
        token_secret=secret,
    )
    assert secret[:8] not in out["error_message"]
    assert not [m for _, m in logged if secret[:8] in m]


_URLLIB3_REFUSED = (
    "HTTPSConnectionPool(host='127.0.0.1', port=8007): Max retries exceeded "
    "with url: /api2/json/admin/sync?sync-direction=all (Caused by "
    "NewConnectionError('...: [Errno 111] Connection refused'))"
)


@pytest.mark.parametrize(
    "answer",
    [
        # A transport error NAMES the parameter: the request URL is quoted.
        {"error": "connection_refused", "message": _URLLIB3_REFUSED},
        fail(502, "bad gateway: GET /api2/json/admin/sync?sync-direction=all"),
    ],
)
def test_a_non_400_naming_the_parameter_never_falls_back(answer, monkeypatch):
    responses = minimal_responses(
        **{
            "/admin/sync?sync-direction=all": answer,
            "/admin/sync": ok([{"id": "pull1", "store": "ds"}]),
        }
    )
    out, session = collect(monkeypatch, responses)
    assert out["sync_jobs"] is None
    assert "/admin/sync" not in [route(u) for u in session.calls]


def test_a_datastore_whose_namespaces_are_cut_by_the_phase_is_read_first(
    monkeypatch,
):
    """b's gc was read but its namespace read hung until the tick's deadline
    (a walk is bounded by the tick, not the phase): b was not finished, so the
    next build starts at b, not at c (as the last datastore, c would otherwise
    never be cut, and b would starve)."""
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c"]
    responses = minimal_responses(
        **{
            "/admin/datastore": ok([{"store": n} for n in names]),
            "/status/datastore-usage": ok([]),
        }
    )
    for store in names:
        responses[f"/admin/datastore/{store}/gc"] = ok({})
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": ""}])
        responses[f"/admin/datastore/{store}/groups"] = ok([])
        responses[f"/admin/datastore/{store}/snapshots"] = ok([])
    real_get = pbs._get

    def get(session, target, path, *args, deadline=None, **kwargs):
        if path == "/admin/datastore/b/namespace":
            clock.now = max(clock.now, deadline)  # hangs until the tick budget ends
            raise pbs._PbsError("timeout", "read timed out", reachable=False)
        return real_get(session, target, path, *args, deadline=deadline, **kwargs)

    monkeypatch.setattr(pbs, "_get", get)
    out, _ = collect(monkeypatch, responses)
    a, b, c = out["datastores"]
    assert b["gc"] is not None and b["namespaces"] is None
    assert pbs._store_rotation == "b"  # not c


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def test_every_shipped_string_is_scrubbed_and_join_keys_match(monkeypatch):
    """Every string PBS returns is scrubbed and capped before it ships (a NUL
    is refused by Postgres, the whole tick with it), and the groups' (store,
    ns) are spelled exactly as datastores[].store and namespaces[]: they are
    the join keys."""

    def evil(tag):
        return tag + "\x00" + "x" * 1000

    # Identifiers follow PBS's schema (anything else is unparseable, see
    # test_a_group_outside_the_pbs_schema_is_unparseable) and fit the wire
    # cap, at its longest: a 255-character store, a 500-character namespace.
    store, ns = "d" * 255, "n" * 255 + "/" + "m" * 244
    base = "/admin/datastore/" + store
    job = {
        "id": evil("id"),
        "store": evil("st"),
        "ns": evil("ns"),
        "schedule": evil("sc"),
        "last-run-state": evil("lr"),
    }
    sync = dict(
        job,
        **{
            "remote": evil("r"),
            "remote-store": evil("rs"),
            "remote-ns": evil("rn"),
            "sync-direction": evil("d"),
        },
    )
    snap = snapshot("host", "i" * 255, 200, verification=verified(evil("v"), store))
    for item in snap["files"]:
        item["crypt-mode"] = evil("c")
    responses = minimal_responses(
        **{
            "/version": ok({"version": evil("4"), "release": evil("0")}),
            "/admin/datastore": ok(
                [
                    {
                        "store": store,
                        "backend-type": evil("b"),
                        "mount-status": evil("m"),
                        "maintenance": evil("mm") + ",message=hi",
                    }
                ]
            ),
            "/status/datastore-usage": ok([]),
            "/admin/sync?sync-direction=all": ok([sync]),
            "/admin/verify": ok([job]),
            "/admin/prune": ok([job]),
            base
            + "/gc": ok(
                {"schedule": evil("s"), "last-run-state": evil("l"), "upid": GC_UPID}
            ),
            base + "/namespace": ok([{"ns": ns}]),
            base
            + "/groups?ns="
            + ns: ok(
                [
                    {
                        "backup-type": "host",
                        "backup-id": "i" * 255,
                        "last-backup": 200,
                        "files": ["index.json.blob"],
                    }
                ]
            ),
            base + "/snapshots?ns=" + ns: ok([snap]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert out["groups"] and out["sync_jobs"] and out["verify_jobs"]
    assert all("\x00" not in s and len(s) <= 500 for s in _strings(out))
    datastore, group = out["datastores"][0], out["groups"][0]
    assert (group["store"], group["ns"]) == (
        datastore["store"],
        datastore["namespaces"][0],
    )


def test_the_same_failure_on_another_datastore_logs_at_error(monkeypatch):
    logged = capture_logs(monkeypatch)
    for failing in ("a", "b"):
        collect(
            monkeypatch,
            _two_datastores(**{f"/admin/datastore/{failing}/gc": fail(500, "EIO")}),
        )
    levels = [lvl for lvl, m in logged if m.startswith("PBS gc read failed")]
    assert levels == ["error", "error"]


def test_the_same_failure_on_another_namespace_logs_at_error(monkeypatch):
    logged = capture_logs(monkeypatch)
    for failing in ("x", "y"):
        responses = minimal_responses(
            **{
                "/admin/datastore/ds/namespace": ok(
                    [{"ns": ""}, {"ns": "x"}, {"ns": "y"}]
                )
            }
        )
        for ns in ("x", "y"):
            responses[f"/admin/datastore/ds/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/ds/snapshots?ns={ns}"] = ok([])
        responses[f"/admin/datastore/ds/groups?ns={failing}"] = fail(500, "EIO")
        collect(monkeypatch, responses)
    levels = [lvl for lvl, m in logged if m.startswith("PBS groups read failed")]
    assert levels == ["error", "error"]


@pytest.mark.parametrize("flag", [1, "true", "false", [True]])
def test_only_a_json_true_propagate_flag_counts_as_propagated(flag):
    """A non-bool flag is unparseable, and an unparseable value makes a scope
    unknown, never larger: 'false' must not read as a propagated grant."""
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._check_privileges({"/datastore": {"Datastore.Audit": flag}})
    assert excinfo.value.error_type == "no_datastore_access"
    assert pbs._check_privileges(
        {"/datastore": {"Datastore.Audit": True}, "/remote": {"Remote.Audit": flag}}
    )[:2] == (False, True)


def test_repeated_usage_rows_are_one_error_per_datastore(monkeypatch):
    """A usage row per datastore is at most MAX_DATASTORES errors only if a
    datastore named by many rows is counted once."""
    rows = [{"store": "ds", "error": "offline"}] * 600
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/status/datastore-usage": ok(rows)})
    )
    assert out["errors"] == [
        {"scope": "usage", "store": "ds", "ns": None, "message": "offline"}
    ]


def test_messages_quoting_pbs_data_are_redacted_too(monkeypatch):
    """A PBS holding the token could echo it in data an error message quotes
    (a usage row's error, a group id): every errors[] message is redacted."""
    groups = [{"backup-type": "vm", "backup-id": SECRET, "last-backup": 5}]
    responses = minimal_responses(
        **{
            "/status/datastore-usage": ok([{"store": "ds", "error": "x " + SECRET}]),
            "/admin/datastore/ds/groups": ok(groups),
            "/admin/datastore/ds/snapshots": ok([]),
        }
    )
    out, _ = collect(monkeypatch, responses)
    messages = [e["message"] for e in out["errors"]]
    assert len(messages) == 2 and not [m for m in messages if SECRET in m]


@pytest.mark.parametrize(
    "late, scope",
    [
        ("/status/datastore-usage", "usage"),  # through _sub_read
        ("/admin/sync?sync-direction=all", "sync_jobs"),  # its own read
    ],
)
def test_a_read_skipped_past_the_budget_is_not_logged_as_a_failure(
    late, scope, monkeypatch
):
    """Headers arriving past the budget are a skip, recorded like any skip
    (an errors[] entry) but not logged as a failed read."""
    clock = use_clock(monkeypatch, Clock())
    logged = capture_logs(monkeypatch)
    handler = responses_handler(minimal_responses())

    def slow(url):
        if route(url) == late:
            clock.now += 100
        return handler(url)

    out = _serve(monkeypatch, slow)
    assert {"scope": scope, "store": None, "ns": None} | {
        "message": pbs._DEADLINE_MESSAGE
    } in out["errors"]
    assert not [m for _, m in logged if "read failed" in m]


def test_a_newer_finished_snapshot_than_groups_last_backup_wins(monkeypatch):
    """PBS < 4.0.17 folds last-backup over an UNSORTED directory listing: with
    an upload in progress read in between, it names an OLDER finished backup
    (here 200 while 300 finished). The listing's newest finished one wins, so
    the details are the real latest backup's, not an older one's."""
    group = {
        "backup-type": "vm",
        "backup-id": "100",
        "backup-count": 4,
        "last-backup": 200,
        "files": ["index.json.blob"],
    }
    snapshots = [
        snapshot("vm", "100", 300, verification=verified("failed")),
        snapshot("vm", "100", 400, size=None, files=[]),  # uploading
        snapshot("vm", "100", 100, verification=VERIFY_OK),
        snapshot("vm", "100", 200, verification=VERIFY_OK),
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/groups": ok([group]),
                "/admin/datastore/ds/snapshots": ok(snapshots),
            }
        ),
    )
    row = out["groups"][0]
    assert (row["last_backup"], row["verify_state"], row["in_progress"]) == (
        300,
        "failed",
        True,
    )


def test_an_absent_ignore_verified_ships_the_pbs_default_true():
    """PBS's schema defaults ignore-verified to true and its verify job reads
    `ignore_verified.unwrap_or(true)`; a job created without the flag has no
    key at all in /admin/verify."""
    assert pbs._verify_job({"id": "v", "store": "ds"})["ignore_verified"] is True
    assert (
        pbs._verify_job({"id": "v", "ignore-verified": False})["ignore_verified"]
        is False
    )


@pytest.mark.parametrize(
    "files",
    [[], ["qemu-server.conf.blob"], ["qemu-server.conf.blob", "drive-scsi0.img.fidx"]],
)
def test_a_lone_upload_with_some_archives_is_never_the_last_backup(files, monkeypatch):
    """A first VM backup still uploading lists its config blob at once: its
    files are NOT empty, but carry no manifest -- still not a finished backup."""
    group = {
        "backup-type": "vm",
        "backup-id": "100",
        "backup-count": 1,
        "last-backup": 500,
        "files": files,
    }
    snaps = [
        snapshot("vm", "100", 500, size=None, files=[{"filename": f} for f in files])
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/groups": ok([group]),
                "/admin/datastore/ds/snapshots": ok(snaps),
            }
        ),
    )
    row = out["groups"][0]
    assert (row["last_backup"], row["in_progress"], row["in_progress_since"]) == (
        None,
        True,
        500,
    )
    assert pbs._group_row("ds", "", group, None)["last_backup"] is None


def test_a_redirect_is_an_http_error_with_its_status(monkeypatch):
    """Redirects are refused, not followed: a 3xx (a reverse proxy or SSO
    login page) is an HTTP error with its status, everywhere."""
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/version": fail(302, "<html>login</html>")})
    )
    assert out["error_type"] == "http_error"
    assert out["error_message"].startswith("HTTP 302")
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/datastore/ds/snapshots": fail(302, "<html>")}),
    )
    assert out["datastores"][0]["unread_namespaces"] == [""]


def test_a_datastore_path_without_datastore_audit_is_no_access():
    """The documented intersection mistake: the token got DatastoreAudit on
    /datastore/ds, its user did not, so only an inherited Remote.Audit survives
    there -- no datastore is auditable, and the message says what to grant."""
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._check_privileges(
            {"/datastore/ds": {"Remote.Audit": True}, "/remote": {"Remote.Audit": True}}
        )
    assert excinfo.value.error_type == "no_datastore_access"
    assert "grant DatastoreAudit" in excinfo.value.message


def test_a_repeated_group_is_an_unparseable_row(monkeypatch):
    """PBS lists a group once. A repeat marks the namespace unread (a group
    row PBS may have mangled), ships the group once, and never re-scans the
    snapshot summary: thousands of repeats would cost minutes of CPU."""
    group = {"backup-type": "vm", "backup-id": "100", "last-backup": 200}
    scans = []
    real = pbs._group_row

    def counting(*args):
        scans.append(args)
        return real(*args)

    monkeypatch.setattr(pbs, "_group_row", counting)
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/admin/datastore/ds/groups": ok([group] * 1000)}),
    )
    assert [g["id"] for g in out["groups"]] == ["100"] and len(scans) == 1
    assert out["datastores"][0]["unread_namespaces"] == [""]
    assert "999 unparseable group row(s) skipped" in [
        e["message"] for e in out["errors"]
    ]


def test_the_401_backoff_is_armed_before_anything_is_logged(monkeypatch):
    """A log line that fails (print() on a stdout that cannot encode it) must
    not change what the collector does: the backoff is already armed."""
    seen = []

    def log_failure(error_type, message):
        seen.append((error_type, pbs._auth_backoff is not None))

    monkeypatch.setattr(pbs, "_log_failure", log_failure)
    collect(monkeypatch, {"/version": fail(401, "authentication failed")})
    assert seen == [("auth_failed", True)]


def test_a_repeated_namespace_or_datastore_row_is_unparseable(monkeypatch):
    """PBS lists a namespace, and a datastore, once: a repeat would ship its
    groups twice, breaking "one row per group" for the server's upsert."""
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": ""}])}
        ),
    )
    assert out["datastores"][0]["namespaces"] is None and out["groups"] == []
    assert out["errors"][0]["message"] == "repeated namespace row"
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore": ok([{"store": "ds"}, {"store": "ds"}])}
        ),
    )
    assert out["error_message"] == "unexpected datastore listing shape"


def _one_verified_group(upid, gc=None):
    """A tick whose one group's last backup carries a verification by `upid`."""
    snaps = [snapshot("vm", "100", 200, verification={"state": "ok", "upid": upid})]
    return minimal_responses(
        **{
            "/admin/datastore/ds/gc": ok(gc if gc is not None else {"upid": GC_UPID}),
            "/admin/datastore/ds/snapshots": ok(snaps),
        }
    )


@pytest.mark.parametrize(
    "upid, local",
    [
        # This datastore, this node (GC_UPID's).
        ("UPID:n:1:2:3:0000000A:verify:ds:root@pam:", True),
        # A verify job: the worker id is 'store:jobid', escaped.
        ("UPID:n:1:2:3:0000000A:verificationjob:ds\\x3av\\x2d1:root@pam:", True),
        # Copied by a sync from another datastore of this PBS...
        ("UPID:n:1:2:3:0000000A:verify:other:root@pam:", False),
        # ...or from a same-named datastore of another PBS.
        ("UPID:elsewhere:1:2:3:0000000A:verify:ds:root@pam:", False),
        ("junk", False),
    ],
)
def test_only_a_verification_run_here_counts(upid, local, monkeypatch):
    """A pull sync copies the source's verification into the copy's manifest:
    it is shipped only when its task ran on this datastore of this PBS."""
    out, _ = collect(monkeypatch, _one_verified_group(upid))
    row = out["groups"][0]
    expected = ("ok", 10, 200) if local else (None, None, None)
    assert (
        row["verify_state"],
        row["verify_time"],
        row["last_verified_ok"],
    ) == expected


def test_without_a_local_task_only_the_datastore_is_checked(monkeypatch):
    """No GC has succeeded and no job has run, so this PBS's node is unknown:
    the datastore is still checked, the node cannot be."""
    no_jobs = {"/admin/sync?sync-direction=all": ok([]), "/admin/verify": ok([])}
    for upid, state in (
        ("UPID:elsewhere:1:2:3:0000000A:verify:ds:root@pam:", "ok"),
        ("UPID:elsewhere:1:2:3:0000000A:verify:other:root@pam:", None),
    ):
        responses = _one_verified_group(upid, gc={})
        responses.update(no_jobs)
        out, _ = collect(monkeypatch, responses)
        assert out["groups"][0]["verify_state"] == state
    # A job's task id is enough to learn the node.
    responses = _one_verified_group(
        "UPID:elsewhere:1:2:3:0000000A:verify:ds:root@pam:", gc={}
    )
    responses.update(no_jobs)
    responses["/admin/verify"] = ok(
        [{"id": "v", "store": "ds", "last-run-upid": GC_UPID}]
    )
    out, _ = collect(monkeypatch, responses)
    assert out["groups"][0]["verify_state"] is None
    # What a build learned does not outlive it.
    responses = _one_verified_group(
        "UPID:elsewhere:1:2:3:0000000A:verify:ds:root@pam:", gc={}
    )
    responses.update(no_jobs)
    out, _ = collect(monkeypatch, responses)
    assert out["groups"][0]["verify_state"] == "ok"


def _budget_runs_out_on(monkeypatch, path, names=("", "b", "c")):
    """A tick whose budget runs out INSIDE the read of `path`."""
    clock = use_clock(monkeypatch, Clock())
    responses = minimal_responses(
        **{"/admin/datastore/ds/namespace": ok([{"ns": n} for n in names])}
    )
    for ns in names[1:]:
        responses[f"/admin/datastore/ds/groups?ns={ns}"] = ok([])
        responses[f"/admin/datastore/ds/snapshots?ns={ns}"] = ok([])
    session = install(monkeypatch, responses)
    real = session._handler

    def handler(url):
        if route(url) == path:
            clock.now += 100
        return real(url)

    session._handler = handler
    return pbs.pbs_metrics(**LOOPBACK)


def test_budget_out_inside_a_namespace_marks_every_later_one_unread(monkeypatch):
    """Every namespace after the one the budget ran out inside is unread: one
    silently skipped would read as 'read, no groups' and be pruned."""
    out = _budget_runs_out_on(monkeypatch, "/admin/datastore/ds/snapshots")
    assert out["datastores"][0]["namespaces"] == ["", "b", "c"]
    # The root too: its snapshot listing never came back.
    assert out["datastores"][0]["unread_namespaces"] == ["", "b", "c"]
    assert [g["ns"] for g in out["groups"]] == [""]


def test_budget_out_inside_a_groups_read_resumes_there(monkeypatch):
    out = _budget_runs_out_on(monkeypatch, "/admin/datastore/ds/groups?ns=b")
    assert out["datastores"][0]["unread_namespaces"] == ["b", "c"]
    assert pbs._rotation == ("ds", "b")  # where the budget ran out -- not "c"


# Value: protects=a unit whose groups were read but whose snapshot details
#   were not (an unparseable row) as the budget ran out is read first next
#   time; fails_when=the rotation counts it finished on its groups alone
#   (finished = complete); why_new=every other budget test cuts a unit whose
#   groups are unread too; seam=none
# Value: protects=the same for a unit whose GROUP listing had an unparseable
#   row (complete is False, its details are not); fails_when=the rotation
#   counts it finished on its snapshot details alone (finished = detailed);
#   why_new=the first row only pins the detailed half of the rule; seam=none
@pytest.mark.parametrize(
    "override, unread",
    [
        # b's snapshot listing has an unparseable row: its details are unknown,
        # but the listing came back, so b stays read.
        ({"/admin/datastore/ds/snapshots?ns=b": ok([{"backup-type": "vm"}])}, ["c"]),
        # b's group listing has an unparseable row: b is unread.
        ({"/admin/datastore/ds/groups?ns=b": ok([{"backup-type": "vm"}])}, ["b", "c"]),
    ],
    ids=["unparseable_snapshot_row", "unparseable_group_row"],
)
def test_a_unit_left_incomplete_as_the_budget_ran_out_is_read_first_next_time(
    monkeypatch, override, unread
):
    # test_a_unit_finished_as_the_budget_ran_out_is_not_read_first_again, but
    # one of b's listings has an unparseable row.
    clock = use_clock(monkeypatch, Clock())
    order = _slow_groups(monkeypatch, clock, seconds=15)
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": "b"}, {"ns": "c"}]),
            "/admin/datastore/ds/groups?ns=b": ok([]),
            "/admin/datastore/ds/snapshots?ns=b": ok([]),
            **override,
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert order == ["", "b"]
    # c never started.
    assert out["datastores"][0]["unread_namespaces"] == unread
    assert pbs._rotation == ("ds", "b")  # again, still incomplete


def test_a_hyphenated_datastore_matches_its_escaped_worker_id():
    """PBS escapes '-' in a worker id as \\x2d (the fixture's 'sjob\\x2ddead')."""
    upid = "UPID:n:1:2:3:0000000A:verify:pbs\\x2dlocal:root@pam:"
    verification = {"state": "ok", "upid": upid}
    assert pbs._local_verification(verification, "pbs-local") == verification
    snaps = [snapshot("vm", "1", 100, verification={"state": "failed", "upid": upid})]
    summary = pbs._summarize_snapshots(snaps, "pbs-local")[0][("vm", "1")]
    assert summary["verify_failed_count"] == 1


@pytest.mark.parametrize(
    "upid",
    [
        "UPID:n",
        "UPID:n:1:2:3:0000000A:verify:ds",
        "XPID:n:1:2:3:0000000A:verify:ds:root@pam:",
    ],
)
def test_a_malformed_task_id_is_not_a_local_verification(upid, monkeypatch):
    out, _ = collect(monkeypatch, _one_verified_group(upid))
    row = out["groups"][0]
    assert (row["verify_state"], row["verify_time"], row["last_verified_ok"]) == (
        None,
        None,
        None,
    )


def test_a_malformed_gc_or_job_task_id_does_not_sink_the_block(monkeypatch):
    responses = _one_verified_group(
        "UPID:n:1:2:3:0000000A:verify:ds:root@pam:", gc={"upid": "UPID:short"}
    )
    responses["/admin/verify"] = ok(
        [{"id": "v", "store": "ds", "last-run-upid": "UPID:x"}]
    )
    out, _ = collect(monkeypatch, responses)
    assert out["reachable"] is True and "error_type" not in out
    assert out["groups"][0]["verify_state"] == "ok"


def test_a_missing_verify_ssl_key_keeps_verification_on(monkeypatch):
    targets = []
    session = FakeSession(responses_handler(minimal_responses()))

    def new_session(target):
        targets.append(target)
        return session

    monkeypatch.setattr(pbs, "_new_session", new_session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    out = pbs.pbs_metrics(host="localhost", **TOKEN)  # no verify_ssl key
    assert out["reachable"] is True and targets[-1].verify is True
    assert session.calls[0].startswith("https://localhost:8007/")
    out = pbs.pbs_metrics(host="pbs.example", **TOKEN)
    assert "error_type" not in out and targets[-1].verify is True


def test_a_failed_namespace_listing_does_not_move_the_store_rotation(monkeypatch):
    """A read that merely FAILED is not a cut."""
    out, _ = collect(
        monkeypatch,
        _two_datastores(**{"/admin/datastore/a/namespace": fail(500, "boom")}),
    )
    assert out["datastores"][0]["namespaces"] is None
    assert pbs._store_rotation == "a"


def test_a_snapshot_listed_without_a_protected_key_is_not_protected():
    snap = snapshot("vm", "1", 100)
    del snap["protected"]
    summary = {"finished": {100: snap}, "newest_unfinished": None}
    group = {"backup-type": "vm", "backup-id": "1", "last-backup": 100}
    assert pbs._group_row("ds", "", group, summary)["protected"] is False


def test_a_backup_time_past_any_real_epoch_is_unparseable():
    """Past 2**61 - 1 an int's hash is no longer itself: a hostile PBS could
    send colliding times and make the summary quadratic. No real time is
    near, so such a row is unparseable (details unknown), like a negative."""
    for when in (2**61 - 1, -1):
        snaps = [snapshot("vm", "1", 100), snapshot("vm", "1", when)]
        summaries, unparseable = pbs._summarize_snapshots(snaps, "ds")
        assert unparseable == 1 and list(summaries[("vm", "1")]["finished"]) == [100]


def test_the_local_node_set_is_bounded(monkeypatch):
    """A PBS has one node name: a listing of thousands of job rows, each with
    a different task node, must not grow the set without bound."""
    for i in range(100):
        pbs._note_local_task(f"UPID:node{i}:1:2:3:0000000A:verify:ds:root@pam:")
    assert len(pbs._local_nodes) == pbs._MAX_LOCAL_NODES


def test_a_vm_and_a_container_sharing_an_id_are_two_groups(monkeypatch):
    """A group is (type, id): two clusters backing up into one namespace can
    each have a guest 100, one a VM and one a container. Neither is a repeat
    of the other (which would mark the namespace unread), and each keeps its
    own snapshot details."""
    groups = [
        {"backup-type": "vm", "backup-id": "100", "last-backup": 200},
        {"backup-type": "ct", "backup-id": "100", "last-backup": 300},
    ]
    snaps = [
        snapshot("vm", "100", 200, size=10),
        snapshot("ct", "100", 300, size=20, verification=verified("failed")),
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/groups": ok(groups),
                "/admin/datastore/ds/snapshots": ok(snaps),
            }
        ),
    )
    assert [
        (g["type"], g["id"], g["last_backup"], g["size"], g["verify_state"])
        for g in out["groups"]
    ] == [("ct", "100", 300, 20, "failed"), ("vm", "100", 200, 10, None)]
    assert out["datastores"][0]["unread_namespaces"] == [] and out["errors"] == []


def test_usage_errors_are_in_datastore_order_whatever_the_hash_seed(monkeypatch):
    """The usage-error pass walks a set of names: it is sorted, so errors[]
    (and which entries its cap keeps) does not change from one agent start
    to the next with the string hash seed."""
    names = ["f", "b", "d", "a", "e", "c"]
    responses = minimal_responses(
        **{
            "/admin/datastore": ok([{"store": n} for n in names]),
            "/status/datastore-usage": ok(
                [{"store": n, "error": f"{n} offline"} for n in names]
            ),
        }
    )
    for n in names:
        responses[f"/admin/datastore/{n}/gc"] = ok({})
        responses[f"/admin/datastore/{n}/namespace"] = ok([])
    out, _ = collect(monkeypatch, responses)
    assert [(e["scope"], e["store"]) for e in out["errors"]] == [
        ("usage", n) for n in sorted(names)
    ]


def test_a_usage_row_whose_store_is_not_a_string_is_skipped(monkeypatch):
    """A usage row's store becomes a dict key: an unhashable one (a list, an
    object) is an unparseable row, skipped like "junk" -- never an exception
    that turns the whole block into an error envelope."""
    rows = [
        {"store": ["ds"], "total": 1},
        {"store": {"ds": 1}, "total": 2},
        {"store": "ds", "total": 1000, "used": 400, "avail": 600},
    ]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/status/datastore-usage": ok(rows)})
    )
    assert out["datastores"][0]["total"] == 1000 and out["errors"] == []


def test_job_flags_ship_as_booleans_whatever_pbs_spells_them(monkeypatch):
    """ignore_verified and disabled are booleans on the wire: a 0/1 or a
    string is coerced (as_bool, the Proxmox spellings), never passed through
    -- a raw string would also skip the scrub every shipped string gets."""
    hostile = "\x00" + "x" * 1000
    responses = minimal_responses(
        **{
            "/admin/verify": ok(
                [
                    {"id": "v1", "store": "ds", "ignore-verified": 0},
                    {"id": "v2", "store": "ds", "ignore-verified": "1"},
                    {"id": "v3", "store": "ds", "ignore-verified": hostile},
                ]
            ),
            "/admin/prune": ok(
                [
                    {"id": "p1", "store": "ds", "disable": 1},
                    {"id": "p2", "store": "ds", "disable": "0"},
                ]
            ),
        }
    )
    out, _ = collect(monkeypatch, responses)
    verify = [(j["id"], j["ignore_verified"]) for j in out["verify_jobs"]]
    prune = [(j["id"], j["disabled"]) for j in out["prune_jobs"]]
    assert verify == [("v1", False), ("v2", True), ("v3", True)]
    assert prune == [("p1", True), ("p2", False)]
    assert all(type(flag) is bool for _, flag in verify + prune)


def _peak_bytes(fn, *args):
    """Peak Python allocation of fn(*args), whoever else is tracing."""
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        base, _ = tracemalloc.get_traced_memory()
        fn(*args)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        if not was_tracing:
            tracemalloc.stop()
    return peak - base


def test_a_hostile_task_id_costs_its_size_not_its_fields_or_escapes():
    """A task id is parsed per verification, from a body of up to 16 MB: it
    is split into at most ten fields, and only _WORKER_ID_SCAN characters of
    its worker id are decoded. Unbounded, a million fields cost ~20x the id's
    size in strings, and a million escapes a callback each plus a list of
    their results, on the watchdog-bounded loop. Bounded, the one copy is the
    field split off."""
    many_fields = "UPID:n:1:2:3:0000000A:verify:ds:root@pam:" + "ab:" * 1_000_000
    many_escapes = "UPID:n:1:2:3:0000000A:verify:" + "\\x41" * 1_000_000 + ":u:"
    for upid in (many_fields, many_escapes):
        for parse in (pbs._upid_origin, pbs._upid_starttime):
            assert _peak_bytes(parse, upid) < 2 * len(upid)
    assert pbs._upid_origin(many_fields) == ("n", "ds")
    assert pbs._upid_starttime(many_fields) == 10
    assert pbs._upid_origin(many_escapes) == ("n", "A" * (pbs._WORKER_ID_SCAN // 4))


def test_an_unparseable_sync_job_row_flags_the_sync_list_partial(monkeypatch):
    """The sync list's OWN 'partial:' flag (the one pruning signal inside
    errors[]) carries the sync_jobs scope."""
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/sync?sync-direction=all": ok(
                    ["junk", {"id": "s", "store": "ds"}]
                )
            }
        ),
    )
    assert [j["id"] for j in out["sync_jobs"]] == ["s"]
    assert out["errors"] == [
        {
            "scope": "sync_jobs",
            "store": None,
            "ns": None,
            "message": "partial: 1 unparseable job row(s) skipped",
        }
    ]


def test_import_installs_the_loopback_filter_and_initial_state():
    """What the module does at import time: the tests reset warnings and every
    mutable global, so only a fresh import can see it."""
    spec = importlib.util.spec_from_file_location("pbs_fresh", pbs.__file__)
    fresh = importlib.util.module_from_spec(spec)
    with warnings.catch_warnings():
        warnings.resetwarnings()
        spec.loader.exec_module(fresh)
        assert [
            f
            for f in warnings.filters
            if f[0] == "ignore"
            and f[2] is fresh.InsecureRequestWarning
            and f[1].pattern == fresh._LOOPBACK_WARNING
        ]
    assert fresh._read_failures == {"previous": set(), "current": set()}
    assert (
        fresh._rotation,
        fresh._store_rotation,
        fresh._auth_backoff,
        fresh._last_logged_failure,
        fresh._local_nodes,
        fresh._stalled_worker,
        fresh._stalled_progress,
        fresh._read_failure_lines,
        fresh._timeout_backoff,
    ) == (None, None, None, None, set(), None, {}, {"error": 0, "quieted": 0}, {})


def test_sync_job_ships_its_remote_namespace():
    job = {"id": "s", "store": "ds", "remote": "r", "remote-store": "rs"}
    assert pbs._sync_job(dict(job, **{"remote-ns": "clusterA"}))["remote_ns"] == (
        "clusterA"
    )


@pytest.mark.parametrize("value", [float("inf"), "200", 200.5, True])
def test_a_mistyped_last_backup_never_reaches_the_wire(value, monkeypatch):
    group = {"backup-type": "vm", "backup-id": "100", "last-backup": value}
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/groups": ok([group])})
    )
    json.dumps(out, allow_nan=False)
    assert out["groups"][0]["last_backup"] == 200  # the newest finished stands in


def test_a_non_string_backup_type_is_an_unparseable_row(monkeypatch):
    groups = [{"backup-type": None, "backup-id": "100", "last-backup": 200}]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/groups": ok(groups)})
    )
    assert out["groups"] == [] and out["datastores"][0]["unread_namespaces"] == [""]
    row = {"backup-type": 5, "backup-id": "1", "backup-time": 5}
    assert pbs._summarize_snapshots([row], "ds")[1] == 1


def test_a_nul_split_secret_is_redacted_exactly(monkeypatch):
    """Deleted, not substituted: a NUL turned into another character would
    ship the secret with one character inserted."""
    logged = capture_logs(monkeypatch)
    out, _ = collect(
        monkeypatch, {"/version": fail(500, SECRET[:4] + "\x00" + SECRET[4:])}
    )
    assert out["error_message"] == "HTTP 500: [REDACTED]"
    assert logged == [
        ("error", "PBS collection failed (http_error): HTTP 500: [REDACTED]")
    ]


def test_scoped_shape_errors_name_their_datastore_and_namespace(monkeypatch):
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/gc": ok([])})
    )
    assert out["errors"] == [
        {
            "scope": "gc",
            "store": "ds",
            "ns": None,
            "message": "unexpected response shape (not an object)",
        }
    ]
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/groups": ok({})})
    )
    assert out["errors"] == [
        {
            "scope": "groups",
            "store": "ds",
            "ns": "",
            "message": "unexpected response shape (not a list)",
        }
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore/ds/namespace": ok([{"ns": ""}, {"ns": ""}])}
        ),
    )
    assert out["errors"] == [
        {
            "scope": "namespaces",
            "store": "ds",
            "ns": None,
            "message": "repeated namespace row",
        }
    ]


def test_a_group_cap_entry_names_its_datastore_and_namespace(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_GROUPS", 1)
    groups = [
        {"backup-type": "vm", "backup-id": str(i), "last-backup": 1} for i in (1, 2)
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/groups": ok(groups),
                "/admin/datastore/ds/snapshots": ok([]),
            }
        ),
    )
    assert {
        "scope": "cap",
        "store": "ds",
        "ns": "",
        "message": "groups capped at 1: 1 dropped",
    } in out["errors"]


def test_a_list_envelope_naming_data_is_refused():
    with pytest.raises(pbs._PbsError) as excinfo:
        pbs._get(
            FakeSession(lambda url: FakeResponse(200, json_body=["data"])),
            _target(),
            "/version",
        )
    assert excinfo.value.message == "unexpected response envelope"


def test_an_over_privileged_message_names_a_bounded_number(monkeypatch):
    """A hostile map of a million 'privileges' must not be sorted, joined and
    kept for log dedup on every tick."""
    perms = {"/datastore": {f"P{i:07d}": True for i in range(1000)}}
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/access/permissions": ok(perms)})
    )
    assert out["error_type"] == "over_privileged"
    assert "P0000000, " in out["error_message"]
    assert f"and {1000 - pbs._MAX_PRIVILEGES_NAMED} more" in out["error_message"]
    assert "P0000999" not in out["error_message"]


def test_a_privilege_name_cut_never_leaves_a_prefix_of_the_secret(monkeypatch):
    """Each name is redacted BEFORE it is cut to 64 characters."""
    secret = "c9b7e5b5-3e4f-4d3e-9d2a-1f2e3d4c5b6a"
    name = ("Sys.Modify." * 4)[:40] + secret  # straddles the 64-char cut
    logged = capture_logs(monkeypatch)
    perms = {"/datastore": {"Datastore.Audit": True, name: True}}
    out, _ = collect(
        monkeypatch,
        minimal_responses(**{"/access/permissions": ok(perms)}),
        token_secret=secret,
    )
    assert out["error_type"] == "over_privileged"
    assert secret[:8] not in out["error_message"]
    assert not [m for _, m in logged if secret[:8] in m]
    long = "Z." * 500
    perms = {"/datastore": {"Datastore.Audit": True, long: True}}
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/access/permissions": ok(perms)})
    )
    assert long[:64] in out["error_message"] and long[:65] not in out["error_message"]
    assert out["error_message"].startswith(
        "the API token holds privileges beyond Datastore.Audit and Remote.Audit: "
        "grant it the DatastoreAudit and RemoteAudit roles only"
    )


def _two_backend_datastores(**overrides):
    responses = minimal_responses(
        **{"/admin/datastore": ok([{"store": "a"}, {"store": "b"}])}
    )
    for store in ("a", "b"):
        responses[f"/admin/datastore/{store}/gc"] = ok({"store": store})
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": ""}])
        responses[f"/admin/datastore/{store}/groups"] = ok([])
        responses[f"/admin/datastore/{store}/snapshots"] = ok([])
    responses.update(overrides)
    return responses


def test_one_known_backend_does_not_skip_the_config_for_the_others(monkeypatch):
    """PBS 4.1.6 names the backend in the usage status -- but not for a
    datastore whose usage row is missing: the config still answers for it."""
    responses = _two_backend_datastores(
        **{
            "/status/datastore-usage": ok(
                [
                    {"store": "a", "backend-type": "s3", "total": 1},
                    {"store": "b", "total": 1000, "used": 400, "avail": 600},
                ]
            ),
            "/config/datastore": ok(
                [{"name": "a", "backend": "type=s3"}, {"name": "b"}]
            ),
        }
    )
    out, _ = collect(monkeypatch, responses)
    a, b = out["datastores"]
    assert (a["backend_type"], a["total"]) == ("s3", None)
    assert (b["backend_type"], b["total"], b["used"], b["avail"]) == (
        "filesystem",
        1000,
        400,
        600,
    )


def test_junk_datastore_config_rows_never_fail_the_block(monkeypatch):
    responses = minimal_responses(
        **{
            "/admin/datastore": ok([{"store": "ds"}]),
            "/config/datastore": ok(
                ["junk", None, {"name": ["x"]}, {"name": {"k": 1}}, {"name": "ds"}]
            ),
        }
    )
    out, _ = collect(monkeypatch, responses)
    assert (out["datastores"][0]["backend_type"], out["datastores"][0]["total"]) == (
        "filesystem",
        1000,
    )
    responses["/config/datastore"] = ok({"ds": {}})
    out, _ = collect(monkeypatch, responses)
    assert out["datastores"][0]["total"] is None
    assert [e["scope"] for e in out["errors"]] == ["datastore_config"]
    # A listing backend-type that is not a string falls back to the config.
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{"/admin/datastore": ok([{"store": "ds", "backend-type": 5}])}
        ),
    )
    assert out["datastores"][0]["backend_type"] == "filesystem"


def test_the_per_store_usage_fallback_is_read_only_where_it_can_ship(monkeypatch):
    """With the aggregate usage failed, an S3 (or unknown) datastore's own
    status is not read: its usage would be withheld anyway."""
    responses = _two_backend_datastores(
        **{
            "/status/datastore-usage": fail(500, "EIO"),
            "/config/datastore": ok(
                [{"name": "a", "backend": "type=s3"}, {"name": "b"}]
            ),
            "/admin/datastore/b/status": ok({"total": 9, "used": 4, "avail": 5}),
        }
    )
    out, session = collect(monkeypatch, responses)
    requested = [route(u) for u in session.calls]
    assert "/admin/datastore/a/status" not in requested
    assert out["datastores"][1]["total"] == 9


def test_the_older_pbs_scenario_really_reads_the_datastore_config(monkeypatch):
    """The SYNTHETIC older_pbs scenario covers the /config/datastore path its
    description claims (a listing and a usage status that name no backend)."""
    fixture = _load_fixture()
    scenario = fixture["scenarios"]["older_pbs"]
    session = install(monkeypatch, scenario_responses(fixture, scenario))
    pbs.pbs_metrics(**scenario["config"]["pbs"])
    assert "/config/datastore" in [route(u) for u in session.calls]


def test_a_failed_verification_survives_a_node_rename(monkeypatch):
    """A PBS renamed or reinstalled keeps its past verifications under the old
    node name (GC status and manifests live in the datastore). A FAILED one
    still counts -- hiding it is missed corruption -- while an OK one needs a
    local node, since a copied 'intact' is what the node check guards."""
    new_gc = (
        "UPID:pbs-new:00000025:000023D8:0000000A:0000000B:"
        "garbage_collection:ds:root@pam:"
    )
    old = "UPID:pbs-old:1:2:3:0000000A:verify:ds:root@pam:"
    snaps = [
        snapshot("vm", "100", 100, verification={"state": "ok", "upid": old}),
        snapshot("vm", "100", 200, verification={"state": "failed", "upid": old}),
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/gc": ok({"store": "ds", "upid": new_gc}),
                "/admin/datastore/ds/snapshots": ok(snaps),
            }
        ),
    )
    row = out["groups"][0]
    assert (row["verify_state"], row["verify_failed_count"]) == ("failed", 1)
    assert row["last_verified_ok"] is None  # the old node's OK is not counted


def test_a_file_outside_the_manifest_keeps_the_crypt_mode(monkeypatch):
    """PBS lists a file that is not in the manifest -- the client.log.blob PVE
    uploads after every backup -- with no crypt-mode and no size: it must not
    turn every PVE backup 'mixed'."""
    for mode in ("encrypt", "none"):
        files = [
            {"filename": "drive-scsi0.img.fidx", "crypt-mode": mode, "size": 100},
            {"filename": "index.json.blob", "crypt-mode": "sign-only", "size": 300},
            {"filename": "client.log.blob"},
        ]
        snaps = [snapshot("vm", "100", 200, files=files)]
        out, _ = collect(
            monkeypatch,
            minimal_responses(**{"/admin/datastore/ds/snapshots": ok(snaps)}),
        )
        assert out["groups"][0]["crypt_mode"] == mode


@pytest.mark.parametrize(
    "token_id, token_secret", [(None, None), ("", ""), ("a@pbs!t", None)]
)
def test_a_missing_token_says_so(token_id, token_secret, monkeypatch):
    out, _ = collect(monkeypatch, {}, token_id=token_id, token_secret=token_secret)
    assert (out["error_type"], out["error_message"]) == (
        "config_error",
        "no API token configured",
    )


def test_integers_past_an_i64_are_unknown(monkeypatch):
    """A 4300-digit integer would be re-serialized and gzipped on every tick
    while the block is cached; PBS's own integers fit an i64."""
    huge = 10**30
    group = {"backup-type": "vm", "backup-id": "100", "backup-count": huge}
    usage = [{"store": "ds", "total": huge, "used": 2**63 - 1, "avail": -(2**63)}]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/groups": ok([group]),
                "/status/datastore-usage": ok(usage),
            }
        ),
    )
    datastore = out["datastores"][0]
    assert (datastore["total"], datastore["used"], datastore["avail"]) == (
        None,
        2**63 - 1,
        -(2**63),
    )
    assert out["groups"][0]["count"] is None


def test_a_repeated_config_row_is_parsed_once(monkeypatch):
    """Each pending datastore is parsed once, whatever it parses to."""
    parsed = []
    real = pbs._backend_type

    def counting(value):
        parsed.append(value)
        return real(value)

    monkeypatch.setattr(pbs, "_backend_type", counting)
    rows = [{"name": "ds", "backend": "bucket=b"}] * 50
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore": ok([{"store": "ds"}]),
                "/config/datastore": ok(rows),
            }
        ),
    )
    assert len(parsed) == 1 and out["datastores"][0]["backend_type"] is None


def test_a_collection_that_outlives_the_hard_bound_is_abandoned(monkeypatch):
    """What no request timeout covers -- resolving a host name, connecting to
    every address it resolves to -- is bounded as a whole: the collection is
    abandoned at PBS_HARD_DEADLINE, and until it returns no other starts (one
    leaked thread, not one per tick)."""
    release = threading.Event()
    started = []

    def stuck(*args):
        started.append(args)
        release.wait(5)
        return {"reachable": True}

    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 0.05)
    monkeypatch.setattr(pbs, "_collect", stuck)
    logged = capture_logs(monkeypatch)
    out = pbs.pbs_metrics(**LOOPBACK)
    assert (out["reachable"], out["error_type"]) == (False, "timeout")
    assert "did not finish within 0.05s" in out["error_message"]
    assert logged[0][0] == "error"
    again = pbs.pbs_metrics(**LOOPBACK)  # still stuck: not a second worker
    assert again["error_type"] == "timeout" and len(started) == 1
    release.set()
    pbs._stalled_worker.join(5)
    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 5)  # no slow runner trips it
    assert pbs.pbs_metrics(**LOOPBACK) == {"reachable": True} and len(started) == 2
    assert pbs._stalled_worker is None


def test_the_collection_runs_on_a_worker_named_pbs_with_the_config_in_order(
    monkeypatch,
):
    calls = []

    def collect(*args):
        calls.append((threading.current_thread().name, args))
        return {"reachable": True}

    monkeypatch.setattr(pbs, "_collect", collect)
    assert pbs.pbs_metrics(**LOOPBACK) == {"reachable": True}
    config = ("localhost", 8007, TOKEN["token_id"], SECRET, False, None, {})
    assert calls == [("pbs", config)]


def test_a_collection_that_cannot_run_is_still_an_envelope(monkeypatch):
    """data["pbs"] is never null: a worker that cannot start (out of threads
    under a pids limit) is an http_error envelope, logged once, then debug --
    and not a stall, so the next tick tries again."""

    def no_thread(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", no_thread)
    logged = capture_logs(monkeypatch)
    message = "the collection could not run: can't start new thread"
    for _ in range(2):
        assert pbs.pbs_metrics(**LOOPBACK) == {
            "reachable": False,
            "error_type": "http_error",
            "error_message": message,
        }
        assert pbs._stalled_worker is None
    line = f"PBS collection failed (http_error): {message}"
    assert logged == [("error", line), ("debug", line)]


def test_a_config_changed_during_a_stall_waits_for_it(monkeypatch):
    """Single-flight whatever the config says: a corrected host does not start
    a second collection beside the stalled one (the io_topology posture: one
    leaked thread at most); it runs on the first tick after that returns."""
    release = threading.Event()
    started = []

    def collect(host, *args):
        started.append(host)
        if host == "pbs.invalid":
            release.wait(5)
        return {"reachable": True, "host": host}

    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 0.05)
    monkeypatch.setattr(pbs, "_collect", collect)
    stalled = pbs.pbs_metrics(**dict(LOOPBACK, host="pbs.invalid"))
    assert stalled["error_type"] == "timeout"
    assert pbs.pbs_metrics(**LOOPBACK) == stalled
    assert started == ["pbs.invalid"]
    release.set()
    pbs._stalled_worker.join(5)
    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 5)
    assert pbs.pbs_metrics(**LOOPBACK) == {"reachable": True, "host": "localhost"}


def test_a_steady_stall_logs_once_then_debug(monkeypatch):
    """A PBS that stalls on every tick: the stall line and the abandoned
    worker's own late failure each log at error ONCE, then at debug. (They used
    to share one latch and alternate: two error lines per cycle, forever.) A
    collection that finishes in time ends the streak."""
    gate = {}

    def stalls(*args):
        mine = gate["now"]
        mine.wait(5)
        pbs._log_failure("timeout", "slow")
        return pbs._failure("timeout", "slow", reachable=False)

    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 0.05)
    monkeypatch.setattr(pbs, "_collect", stalls)
    logged = capture_logs(monkeypatch)

    def one_stall():
        gate["now"] = threading.Event()
        assert pbs.pbs_metrics(**LOOPBACK)["error_type"] == "timeout"
        gate["now"].set()
        pbs._stalled_worker.join(5)
        assert not pbs._stalled_worker.is_alive()

    for _ in range(3):
        one_stall()
    stall = f"PBS collection failed (timeout): {pbs._STALLED_MESSAGE.format(0.05)}"
    late = "PBS collection failed (timeout): slow"
    assert logged == [("error", stall), ("error", late)] + 2 * [
        ("debug", stall),
        ("debug", late),
    ]
    monkeypatch.setattr(pbs, "_collect", lambda *args: {"reachable": True})
    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 5)
    assert pbs.pbs_metrics(**LOOPBACK) == {"reachable": True}
    monkeypatch.setattr(pbs, "_collect", stalls)
    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 0.05)
    del logged[:]
    one_stall()
    assert logged[0] == ("error", stall)


def test_a_stall_after_version_answered_is_reachable(monkeypatch):
    """Once /version answered, a later failure in the tick is a slow PBS, not
    an unreachable one -- a stall included, although the answer came on the
    worker the tick abandoned."""
    release, entered = threading.Event(), threading.Event()
    answer = responses_handler(minimal_responses())

    def handler(url):
        if route(url) == "/access/permissions" and not entered.is_set():
            entered.set()
            release.wait(5)
        return answer(url)

    session = FakeSession(handler)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    # Long enough for /version on a slow runner; the held read outlives it.
    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 1)
    out = pbs.pbs_metrics(**LOOPBACK)
    assert entered.is_set()
    assert (out["reachable"], out["error_type"]) == (True, "timeout")
    release.set()
    pbs._stalled_worker.join(5)
    assert not pbs._stalled_worker.is_alive()


def _stall_first_version(monkeypatch, then):
    """A PBS whose FIRST /version is held until the returned `release` event
    is set (a resolver or a connect that outlives the hard bound), then
    answered from `then`; every later request is answered from `then` at
    once. `entered` is set once the held request has arrived."""
    release, entered = threading.Event(), threading.Event()
    answer = responses_handler(then)

    def handler(url):
        if not entered.is_set() and route(url) == "/version":
            entered.set()
            release.wait(5)
        return answer(url)

    session = FakeSession(handler)
    session.entered = entered
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 0.05)
    return release, session


def _finish_stalled(monkeypatch, release):
    """Let the abandoned worker return, and give the next tick's collection a
    bound no slow CI runner can trip."""
    release.set()
    pbs._stalled_worker.join(5)
    assert not pbs._stalled_worker.is_alive()
    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 5)


def test_a_tick_while_the_abandoned_collection_runs_sends_nothing(monkeypatch):
    """Single-flight: while the abandoned worker still runs, a tick reports
    the same timeout WITHOUT a request of its own and logs it at debug (the
    error line was the first tick's)."""
    release, session = _stall_first_version(monkeypatch, minimal_responses())
    logged = capture_logs(monkeypatch)
    message = pbs._STALLED_MESSAGE.format(0.05)
    envelope = {"reachable": False, "error_type": "timeout", "error_message": message}
    assert pbs.pbs_metrics(**LOOPBACK) == envelope
    assert session.entered.wait(5)  # a slow runner: the worker is at /version
    assert pbs.pbs_metrics(**LOOPBACK) == envelope
    assert [route(u) for u in session.calls] == ["/version"]
    assert logged == [
        ("error", f"PBS collection failed (timeout): {message}"),
        ("debug", f"PBS collection skipped: {message}"),
    ]
    _finish_stalled(monkeypatch, release)


def test_a_block_the_abandoned_collection_finishes_serves_the_next_tick(
    monkeypatch,
):
    """The abandoned worker's return value is dropped, not its work: a build
    it finishes late is cached under its target, so the next tick re-emits it
    after one /version read instead of rebuilding it."""
    release, session = _stall_first_version(monkeypatch, minimal_responses())
    assert pbs.pbs_metrics(**LOOPBACK)["error_type"] == "timeout"
    _finish_stalled(monkeypatch, release)
    built = len(session.calls)
    assert "/access/permissions" in [route(u) for u in session.calls]
    out = pbs.pbs_metrics(**LOOPBACK)
    assert [route(u) for u in session.calls[built:]] == ["/version"]
    assert out["reachable"] is True and out["datastores"][0]["store"] == "ds"
    assert pbs._stalled_worker is None


def test_a_401_the_abandoned_collection_got_holds_the_next_tick_back(monkeypatch):
    """A 401 answered to the abandoned worker was still an authentication
    failure in the PBS auth log: it arms the backoff, so the next tick sends
    nothing and reports auth_failed, not the stall."""
    release, session = _stall_first_version(
        monkeypatch, {"/version": fail(401, "authentication failed")}
    )
    assert pbs.pbs_metrics(**LOOPBACK)["error_type"] == "timeout"
    _finish_stalled(monkeypatch, release)
    assert pbs.pbs_metrics(**LOOPBACK) == {
        "reachable": True,
        "error_type": "auth_failed",
        "error_message": "HTTP 401: authentication failed",
    }
    assert [route(u) for u in session.calls] == ["/version"]


@pytest.mark.parametrize(
    "when, parseable", [(0, True), (2**53 - 1, True), (2**53, False)]
)
def test_the_backup_time_bound_is_exact(when, parseable):
    """The epoch itself and everything below _MAX_BACKUP_TIME are real
    backup times; the bound itself is not (a `<=` slip would admit it)."""
    summaries, unparseable = pbs._summarize_snapshots([snapshot("vm", "1", when)], "ds")
    assert unparseable == (0 if parseable else 1)
    assert (("vm", "1") in summaries) is parseable


def test_a_tick_skipped_behind_a_stall_that_got_version_stays_reachable(
    monkeypatch,
):
    """A tick skipped behind the abandoned worker reports the reachability of
    the tick that abandoned it: a PBS that answered /version, then stalled,
    reads reachable on every such tick, not true then false."""
    release = threading.Event()

    def collect(*args):
        args[-1]["answered"] = True  # /version answered, then the build stalls
        release.wait(5)
        return {"reachable": True}

    # Long enough for the worker to record /version on a slow runner.
    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 1)
    monkeypatch.setattr(pbs, "_collect", collect)
    first = pbs.pbs_metrics(**LOOPBACK)
    second = pbs.pbs_metrics(**LOOPBACK)  # skipped: the worker still runs
    assert (first["error_type"], first["reachable"]) == ("timeout", True)
    assert second == first
    release.set()
    pbs._stalled_worker.join(5)
    monkeypatch.setattr(pbs, "PBS_HARD_DEADLINE", 5)
    assert pbs.pbs_metrics(**LOOPBACK) == {"reachable": True}
    assert pbs._stalled_progress == {}


def test_version_is_read_under_its_own_small_cap(monkeypatch):
    """/version is read every tick, cached path included: its body gets a
    64 KB cap, not the 16 MB one the listings need."""
    caps = []
    real = pbs.read_capped_body

    def spy(response, max_bytes, timeout_s):
        caps.append(max_bytes)
        return real(response, max_bytes, timeout_s)

    monkeypatch.setattr(pbs, "read_capped_body", spy)
    out, _ = collect(monkeypatch, minimal_responses())
    assert out["reachable"] is True
    assert caps[0] == pbs._VERSION_MAX_BYTES == 64 * 1024
    # Every other endpoint's cap is its _body_cap: only the group and
    # snapshot listings get the 16 MB one.
    assert sorted(set(caps[1:])) == [pbs._SMALL_MAX_BYTES, pbs._MAX_RESPONSE_BYTES]
    assert pbs._body_cap("/admin/datastore/ds/groups") == pbs._MAX_RESPONSE_BYTES
    assert pbs._body_cap("/admin/datastore/ds/snapshots") == pbs._MAX_RESPONSE_BYTES
    for path in ("/access/permissions", "/admin/datastore", "/admin/sync"):
        assert pbs._body_cap(path) == pbs._SMALL_MAX_BYTES
    big = minimal_responses(**{"/version": ok({"version": "x" * (64 * 1024)})})
    out, _ = collect(monkeypatch, big)
    assert (out["reachable"], out["error_type"]) == (True, "http_error")
    assert out["error_message"].startswith("body read failed")


def test_job_rows_shape_only_the_rows_the_cap_keeps(monkeypatch):
    """A hostile listing of many tiny rows costs a sort key each, not a
    shaped row; the kept rows are exactly sorted(...)[:MAX_JOBS], ties in
    listing order."""
    monkeypatch.setattr(pbs, "MAX_JOBS", 3)
    shaped = []

    def shape(job):
        shaped.append(job)
        return pbs._verify_job(job)

    listing = [
        {"store": "b", "id": "1", "n": 0},
        {"store": "a", "id": "2", "n": 1},
        "junk",
        {"store": "a", "id": "2", "n": 2},
        {"id": "9", "n": 3},
        {"store": "c", "id": "0", "n": 4},
    ]
    errors = pbs._Errors(str)
    rows = pbs._job_rows(listing, errors, "verify_jobs", shape)
    assert [(r["store"], r["id"]) for r in rows] == [
        (None, "9"),
        ("a", "2"),
        ("a", "2"),
    ]
    assert [job["n"] for job in shaped] == [3, 1, 2]
    assert [e["message"] for e in errors] == [
        "partial: 1 unparseable job row(s) skipped",
        "partial: capped at 3: 2 dropped",
    ]


def test_read_failures_past_the_line_cap_log_at_debug(monkeypatch):
    """At most _MAX_READ_FAILURE_LINES distinct sub-read failures log at error
    per build, then debug, then one count at the end of the build."""
    monkeypatch.setattr(pbs, "_MAX_READ_FAILURE_LINES", 2)
    logged = capture_logs(monkeypatch)
    names = ["a", "b", "c", "d"]
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/namespace": ok(
                [{"ns": ""}] + [{"ns": n} for n in names]
            )
        },
        # A distinct body each, so the error-once dedup never engages.
        **{
            f"/admin/datastore/ds/groups?ns={n}": fail(400, f"broken {n}")
            for n in names
        },
    )
    out, _ = collect(monkeypatch, responses)
    assert out["reachable"] is True
    levels = [lvl for lvl, m in logged if "groups read failed" in m]
    assert levels == ["error", "error", "debug", "debug"]
    assert logged[-1] == (
        "error",
        "PBS: 2 more read failure(s) this build, logged at debug",
    )


_NS_PATH = "/admin/datastore/ds/namespace"


def _ns_calls(session):
    return [u for u in session.calls if route(u) == _NS_PATH]


# Value (held builds, ship audit): protects=every build while the walk hold
#   stands reads walks_held true, not only the build that armed it;
#   fails_when=walks_held tracks a hold armed THIS build, so later held builds
#   read false while no walk is sent; why_new=the held builds below never read
#   it and the namespace_walk_held fixture is the arming build only; seam=none
def test_a_timed_out_namespace_listing_is_held_until_a_reload(monkeypatch):
    """Every re-send of a namespace walk PBS may still be running pins one
    more proxy thread for good (two kill a 2-vCPU PBS): after a read timeout
    it is HELD -- never sent again, its scope unknown -- until the operator
    reloads the agent (reset_timeout_holds, on SIGHUP). So is every other
    walk: the usage status too, a full-scope token then reading each
    datastore's own status."""
    clock = use_clock(monkeypatch, Clock())
    logged = capture_logs(monkeypatch)
    stuck = minimal_responses(
        **{
            _NS_PATH: {"error": "timeout", "message": "t"},
            "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
        }
    )
    out, session = collect(monkeypatch, stuck)
    assert len(_ns_calls(session)) == 1
    assert out["datastores"][0]["namespaces"] is None
    [key] = pbs._timeout_backoff
    assert key == pbs._WALK_HOLD
    assert out["walks_held"] is True
    failure = ("namespaces", "ds", None, "t")
    assert pbs._timeout_backoff[key] == (math.inf, 1, failure)
    assert (
        "error",
        f"PBS namespaces read on ds held: {pbs._TIMEOUT_HOLD_MESSAGE}",
    ) in logged
    for later in (pbs.PBS_CACHE_TTL, pbs._TIMEOUT_BACKOFF_MAX, 30 * 86400):
        clock.now = 1000.0 + later
        out, session = collect(monkeypatch, stuck)
        assert _ns_calls(session) == []
        assert out["datastores"][0]["namespaces"] is None
        assert out["walks_held"] is True  # every held build, not just the first
        held = [e["message"] for e in out["errors"] if e["scope"] == "namespaces"]
        assert held == [pbs._TIMEOUT_HOLD_MESSAGE]
        usage = [e["message"] for e in out["errors"] if e["scope"] == "usage"]
        assert usage == [pbs._TIMEOUT_HOLD_MESSAGE]
        assert "/status/datastore-usage" not in [route(u) for u in session.calls]
        assert out["datastores"][0]["total"] == 9  # from its own status
    pbs.reset_timeout_holds()  # SIGHUP: the datastore is repaired
    out, session = collect(monkeypatch, minimal_responses())
    assert len(_ns_calls(session)) == 1
    assert out["datastores"][0]["namespaces"] == [""]
    assert pbs._timeout_backoff == {}
    assert out["walks_held"] is False


# Value: protects=a hold surviving any configuration change -- a pasted
#   fingerprint, the same PBS spelled 127.0.0.2 or ::1, a rotated token --
#   through whole builds; fails_when=the key or the stale-entry cleanup
#   depends on the host, the URL or the token again; why_new=the key test
#   never runs a build; seam=none
@pytest.mark.parametrize(
    "change, url",
    [
        ({"fingerprint": FINGERPRINT}, "https://localhost:8007/"),
        ({"host": "127.0.0.2"}, "https://127.0.0.2:8007/"),
        ({"host": "::1"}, "https://[::1]:8007/"),
        ({"token_id": "other@pbs!t"}, "https://127.0.0.1:8007/"),
    ],
    ids=["pasted_pin", "loopback_alias", "ipv6_loopback", "rotated_token"],
)
def test_a_hold_survives_any_configuration_change(monkeypatch, change, url):
    clock = use_clock(monkeypatch, Clock())
    stuck = minimal_responses(
        **{
            _NS_PATH: {"error": "timeout", "message": "t"},
            "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
        }
    )
    collect(monkeypatch, stuck)  # unverified localhost: https://127.0.0.1
    clock.now += pbs.PBS_CACHE_TTL + 5
    out, session = collect(monkeypatch, stuck, **change)
    assert session.calls[0].startswith(url)
    assert _ns_calls(session) == []
    assert out["datastores"][0]["namespaces"] is None


# Value: protects=the one deeper ACL entry the permissions map DOES show (a
#   path present under an absent ancestor); fails_when=the parent/datastore
#   check is dropped, or a namespace-level gap is read as a datastore one;
#   why_new=nothing read the map's shape below /datastore before; seam=none
# Value (row): protects=a gap two namespace levels deep, below an audited
#   namespace, still reads hidden now that each path checks only its parent;
#   fails_when=the parent check is narrowed to one fixed namespace depth;
#   why_new=every hidden case sat at the first namespace level; seam=none
# Value (rows, ship 8): protects=a deeper entry whose role LACKS the audited
#   privilege (a RemoteAudit on /datastore/<s>: PBS 4.2 then reports that path
#   as Remote.Audit and no longer lists <s>) reads hidden, and so does a
#   remote; fails_when=the check goes back to path presence alone, so the
#   block claims scope full and the server prunes a datastore that still
#   exists (QA capture 005); why_new=every row hid a path by its ABSENCE;
#   seam=none
def test_a_path_below_an_absent_one_names_a_hidden_datastore_or_namespace():
    audit = {"Datastore.Audit": True}
    remote = {"Remote.Audit": True}
    assert pbs._hidden_below(PERMS_FULL) == (False, set(), False)
    visible = {**PERMS_FULL, "/datastore/s1": audit, "/datastore/s1/a": audit}
    assert pbs._hidden_below(visible) == (False, set(), False)
    # A token scoped at the datastore level holds nothing on /datastore.
    assert pbs._hidden_below({"/datastore/s1": audit}) == (False, set(), False)
    # NoAccess on /datastore/s2 (absent) and an audit grant on a namespace.
    assert pbs._hidden_below({**PERMS_FULL, "/datastore/s2/a": audit}) == (
        True,
        {"s2"},
        False,
    )
    # A namespace hidden inside an audited datastore: not the datastore.
    deep = {**PERMS_FULL, "/datastore/s1": audit, "/datastore/s1/a/b": audit}
    assert pbs._hidden_below(deep) == (True, set(), False)
    # NoAccess on s1/a/b below an audited s1/a, an audit grant deeper still.
    deeper = {**visible, "/datastore/s1/a/b/c": audit}
    assert pbs._hidden_below(deeper) == (True, set(), False)
    # RemoteAudit on /datastore/s1 (measured): s1 and its namespaces inherit
    # Remote.Audit alone, and PBS no longer lists s1.
    replaced = {**PERMS_FULL, "/datastore/s1": remote, "/datastore/s1/a": remote}
    assert pbs._hidden_below(replaced) == (True, {"s1"}, False)
    # The same entry on a namespace of an audited datastore.
    on_ns = {**PERMS_FULL, "/datastore/s1": audit, "/datastore/s1/a": remote}
    assert pbs._hidden_below(on_ns) == (True, set(), False)
    # A remote: audited, without Remote.Audit, or under an absent remote.
    assert pbs._hidden_below({**PERMS_FULL, "/remote/r": remote}) == (
        False,
        set(),
        False,
    )
    for gap in ({"/remote/r": audit}, {"/remote/r/s": remote}):
        assert pbs._hidden_below({**PERMS_FULL, **gap}) == (False, set(), True)
    # Paths outside both trees, or not absolute, say nothing.
    odd = {**PERMS_FULL, "/system/x": audit, "/access/y": {}, "datastore/s3": {}}
    assert pbs._hidden_below(odd) == (False, set(), False)


_AUDIT = {"Datastore.Audit": True}


# Value: protects=a datastore a deeper ACL entry hides at its own level ships
#   as partial scope with usage unknown, never PBS's 0/0/0; fails_when=the
#   fallback reads its /status (a false "0 bytes free") or scope stays full
#   (its root groups would be pruned); why_new=reproduced on PBS 4.2 by the
#   pass-3 red team; seam=none
# Value (rows): protects=a namespace hidden inside an audited datastore reads
#   partial too, and only a datastore hidden at its own level loses its
#   /status fallback -- an audited one beside it keeps its usage;
#   fails_when=scope is derived from the datastore-level gaps alone, or the
#   fallback guard is widened to every datastore once anything is hidden;
#   why_new=the test had one datastore hidden whole, and the _hidden_below
#   unit test never reaches _build_block; seam=none
@pytest.mark.parametrize(
    "hidden, a_status, read, a_usage",
    [
        # NoAccess on /datastore/a (absent), an audit grant on a namespace:
        # PBS lists a only for a token with an ACL entry of its own below it
        # (else a is simply absent); its own status answers 0/0/0 and is
        # never read.
        (
            {"/datastore/a/x": _AUDIT},
            {"total": 0, "used": 0, "avail": 0},
            ["b"],
            (None, None, None),
        ),
        # NoAccess on namespace a/x (absent) below an audited a: a is still
        # audited, so its own status is real and read.
        (
            {"/datastore/a": _AUDIT, "/datastore/a/x/y": _AUDIT},
            {"total": 7, "used": 2, "avail": 5},
            ["a", "b"],
            (7, 2, 5),
        ),
    ],
    ids=["datastore_hidden", "namespace_hidden"],
)
def test_a_datastore_audited_only_below_is_partial_and_never_zero(
    monkeypatch, hidden, a_status, read, a_usage
):
    responses = _two_backend_datastores(
        **{
            "/access/permissions": ok({**PERMS_FULL, **hidden}),
            "/status/datastore-usage": fail(500, "EIO"),
            "/admin/datastore/a/status": ok(a_status),
            "/admin/datastore/b/status": ok({"total": 9, "used": 4, "avail": 5}),
        }
    )
    out, session = collect(monkeypatch, responses)
    assert out["scope"] == "partial"
    sent = [route(u) for u in session.calls]
    assert [s for s in "ab" if f"/admin/datastore/{s}/status" in sent] == read
    a, b = out["datastores"]
    assert (a["total"], a["used"], a["avail"]) == a_usage
    assert (b["total"], b["used"], b["avail"]) == (9, 4, 5)


# Value: protects=a TLS handshake that stalled (urllib3 calls it a read
#   timeout) never arms a hold for a request PBS never received;
#   fails_when=every ReadTimeout counts as pending again; why_new=the fake
#   transport could not tell the two apart before; seam=none
def test_a_stalled_tls_handshake_holds_nothing(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    stalled = minimal_responses(
        **{_NS_PATH: {"error": "handshake_timeout", "message": "t"}}
    )
    out, _ = collect(monkeypatch, stalled)
    assert out["datastores"][0]["namespaces"] is None
    assert pbs._timeout_backoff == {}
    clock.now += pbs.PBS_CACHE_TTL + 5
    out, session = collect(monkeypatch, minimal_responses())
    assert len(_ns_calls(session)) == 1  # sent again: nothing held
    assert out["datastores"][0]["namespaces"] == [""]


# Value: protects=one broken storage pins ONE proxy thread: the first walk
#   that times out holds every other walk, the other datastores' namespace
#   listings in the same build and the usage status after it; fails_when=the
#   walks are held per request again (N datastores, N threads); why_new=the
#   red team reproduced two and three pinned threads live; seam=none
# Value (ship 8): protects=the second walk of the arming build reads held,
#   not merely late; fails_when=the hold is keyed per request (b is then a
#   budget skip, and the next build re-sends it); why_new=within one build
#   "not sent" cannot tell the two apart; seam=none
def test_one_timed_out_walk_holds_every_walk(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    responses = _two_backend_datastores(
        **{
            "/admin/datastore/a/namespace": {"error": "timeout", "message": "t"},
            "/admin/datastore/a/status": ok({"total": 9, "used": 4, "avail": 5}),
            "/admin/datastore/b/status": ok({"total": 7, "used": 2, "avail": 5}),
        }
    )
    out, session = collect(monkeypatch, responses)
    sent = [route(u) for u in session.calls]
    assert "/admin/datastore/a/namespace" in sent
    assert "/admin/datastore/b/namespace" not in sent  # held with a's
    # Held, not merely late: a's pending timeout leaves under a whole read
    # timeout in the tick, so b would not be sent either way -- only its
    # message tells the two apart.
    walks = [
        (e["store"], e["message"]) for e in out["errors"] if e["scope"] == "namespaces"
    ]
    assert walks == [("a", "t"), ("b", pbs._TIMEOUT_HOLD_MESSAGE)]
    assert [d["namespaces"] for d in out["datastores"]] == [None, None]
    assert list(pbs._timeout_backoff) == [pbs._WALK_HOLD]
    clock.now += pbs.PBS_CACHE_TTL + 5
    out, session = collect(monkeypatch, responses)
    sent = [route(u) for u in session.calls]
    walks = [p for p in sent if p.endswith("/namespace") or "usage" in p]
    assert walks == []  # nothing that walks namespaces is sent
    assert [d["total"] for d in out["datastores"]] == [9, 7]  # own status


# Value: protects=the collection loop against a hostile permissions map (one
#   deep chain with every ancestor present, 4 MB): the hidden-path check is
#   linear; fails_when=it rebuilds every ancestor of every path again (37s of
#   CPU measured); why_new=nothing bounded its cost; seam=none
def test_a_deep_permissions_chain_is_checked_in_linear_time():
    chain = {"/datastore": {"Datastore.Audit": True}}
    path = "/datastore/s"
    for _ in range(3000):
        chain[path] = {"Datastore.Audit": True}
        path += "/x"
    started = time.perf_counter()
    assert pbs._hidden_below(chain) == (False, set(), False)
    assert time.perf_counter() - started < 2  # ~10 ms linear, ~40 s cubic


# Value: protects=a hidden path flags every job list 'partial:' (PBS drops
#   the jobs of what it hides); fails_when=only a scoped token flags them, so
#   the server prunes jobs that still exist; why_new=reproduced live by the
#   red team (vjob1/pjob1 gone, no flag); seam=none
# Value (row): protects=a namespace hidden inside an audited datastore flags
#   the job lists too (PBS filters jobs by their namespace); fails_when=the
#   flag keys on the datastore-level gaps alone; why_new=the first row hid a
#   datastore, where both signals are set; seam=none
@pytest.mark.parametrize(
    "hidden",
    [
        {"/datastore/ds/a/b": {"Datastore.Audit": True}},
        {
            "/datastore/ds": {"Datastore.Audit": True},
            "/datastore/ds/a/b": {"Datastore.Audit": True},
        },
    ],
    ids=["datastore_hidden", "namespace_hidden"],
)
def test_a_hidden_path_flags_the_job_lists_partial(monkeypatch, hidden):
    responses = minimal_responses(
        **{"/access/permissions": ok({**PERMS_FULL, **hidden})}
    )
    out, _ = collect(monkeypatch, responses)
    assert out["scope"] == "partial"
    partial = {e["scope"] for e in out["errors"] if e["message"].startswith("partial:")}
    assert partial == {"sync_jobs", "verify_jobs", "prune_jobs"}
    assert all(
        "deeper ACL entry" in e["message"]
        for e in out["errors"]
        if e["message"].startswith("partial:")
    )


# Value: protects=a walk that could not wait its whole read timeout is never
#   sent (so neither a stalled TLS handshake nor a PBS merely slow late in the
#   tick can arm the hold), and one that is sent gets its whole read timeout;
#   fails_when=a walk is sent with a clamped read; why_new=QA 003 reproduced a
#   hold at a 5s budget; seam=none
def test_a_stalled_tls_handshake_late_in_the_budget_holds_nothing(monkeypatch):
    clock = use_clock(monkeypatch, Clock())

    def stall(url):
        raise HandshakeStall("t")

    session = FakeSession(stall)
    target = _target()
    for left in (9.9, 5.0, 1.0):  # QA 003: (5, 5) held before the fix
        errors = pbs._Errors(target.redact)
        read = pbs._sub_read(
            session,
            target,
            errors,
            clock.now + left,
            "namespaces",
            _NS_PATH,
            store="ds",
            backoff="hold",
        )
        assert read is None
        assert session.calls == []  # not sent: its read would be cut short
        assert [e["message"] for e in errors] == [pbs._DEADLINE_MESSAGE]
    errors = pbs._Errors(target.redact)
    pbs._sub_read(
        session,
        target,
        errors,
        clock.now + pbs.PBS_COLLECT_DEADLINE,
        "namespaces",
        _NS_PATH,
        store="ds",
        backoff="hold",
    )
    assert session.timeouts == [(pbs._CONNECT_TIMEOUT, pbs._READ_TIMEOUT)]


# Value: protects=a held or backed-off read late in the tick keeps its TCP
#   connect plus a stalled TLS handshake under its read timeout, so neither
#   can count as pending; fails_when=the connect clamp to read/2 is dropped
#   (the read is cut to 8s, the connect stays 5s); why_new=a walk always has
#   its whole 10s since the fit rule, so only a retry read reaches the clamp
#   and nothing pinned it there (review run 8: the mutant survived);
#   seam=none
def test_a_backed_off_read_late_in_the_budget_keeps_its_connect_under_half_its_read(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    session = FakeSession(responses_handler(minimal_responses()))
    pbs._get(
        session,
        _target(),
        "/admin/datastore/ds/snapshots",
        deadline=clock.now + 8,
        min_wait=pbs._TIMEOUT_BACKOFF_MIN_WAIT,
    )
    assert session.timeouts == [(4, 8)]
    assert pbs._timeout_backoff == {}


def test_a_timeout_backoff_is_capped_and_per_request(monkeypatch):
    """A retried read's delay stops doubling at _TIMEOUT_BACKOFF_MAX; the
    walk hold never expires. A retry's key is the exact request, and nothing
    else."""
    use_clock(monkeypatch, Clock())
    key = pbs._timeout_backoff_key("/p", {"ns": "a"})
    assert key == ("/p", (("ns", "a"),))
    assert pbs._timeout_backoff_key("/p", None) != key
    failure = ("snapshots", "ds", "a", "t")
    for _ in range(12):
        pbs._arm_timeout_backoff(key, failure, hold=False)
    assert pbs._timeout_backoff[key] == (
        1000.0 + pbs._TIMEOUT_BACKOFF_MAX,
        12,
        failure,
    )
    held = ("namespaces", "ds", None, "t")
    pbs._arm_timeout_backoff(pbs._WALK_HOLD, held, hold=True)
    assert pbs._timeout_backoff[pbs._WALK_HOLD] == (math.inf, 1, held)


# Value: protects=the backoff dict's bound; fails_when=the cap check is
#   dropped or evicts the newest entry; why_new=no other test arms past the
#   cap; seam=none
def test_the_timeout_backoff_drops_its_oldest_entry_at_the_cap(monkeypatch):
    use_clock(monkeypatch, Clock())
    monkeypatch.setattr(pbs, "_TIMEOUT_BACKOFF_ENTRIES", 3)
    failure = ("groups", "ds", "a", "t")
    keys = [(f"/p{i}", ()) for i in range(4)]
    for key in keys[:3]:
        pbs._arm_timeout_backoff(key, failure, hold=False)
    pbs._arm_timeout_backoff(keys[1], failure, hold=False)  # re-armed: no drop
    assert list(pbs._timeout_backoff) == keys[:3]
    pbs._arm_timeout_backoff(keys[3], failure, hold=False)
    assert list(pbs._timeout_backoff) == keys[1:]
    assert pbs._timeout_backoff[keys[1]][1] == 2


# Value: protects=a hold (a walk that never ends) outliving newer retries at
#   the cap; fails_when=the cap drops the oldest entry whatever it is;
#   why_new=the test above holds only; seam=none
def test_the_timeout_backoff_cap_drops_a_retry_before_a_hold(monkeypatch):
    use_clock(monkeypatch, Clock())
    monkeypatch.setattr(pbs, "_TIMEOUT_BACKOFF_ENTRIES", 3)
    held, retried = ("namespaces", "ds", None, "t"), ("groups", "ds", "a", "t")
    keys = [pbs._WALK_HOLD] + [(f"/p{i}", ()) for i in range(1, 4)]
    pbs._arm_timeout_backoff(keys[0], held, hold=True)
    pbs._arm_timeout_backoff(keys[1], retried, hold=False)
    pbs._arm_timeout_backoff(keys[2], retried, hold=False)
    pbs._arm_timeout_backoff(keys[3], retried, hold=False)
    assert list(pbs._timeout_backoff) == [keys[0], keys[2], keys[3]]
    assert pbs._timeout_backoff[keys[0]][0] == math.inf


def test_a_snapshots_timeout_holds_back_only_that_namespace(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = [{"ns": ""}, {"ns": "a"}]
    responses = minimal_responses(
        **{
            _NS_PATH: ok(names),
            "/admin/datastore/ds/groups?ns=a": ok([]),
            "/admin/datastore/ds/snapshots?ns=a": {"error": "timeout", "message": "t"},
        }
    )
    collect(monkeypatch, responses)
    clock.now += pbs.PBS_CACHE_TTL + 5
    out, session = collect(monkeypatch, responses)
    sent = [route(u) for u in session.calls]
    assert "/admin/datastore/ds/snapshots" in sent  # the root's, still read
    assert "/admin/datastore/ds/snapshots?ns=a" not in sent
    skipped = [e for e in out["errors"] if e["message"] == pbs._TIMEOUT_BACKOFF_MESSAGE]
    assert [(e["scope"], e["ns"]) for e in skipped] == [("snapshots", "a")]
    # Held back, it never looked for the 400 that would reveal a group PBS
    # left out of /groups: the namespace is unread, as after the timeout.
    assert out["datastores"][0]["unread_namespaces"] == ["a"]


def test_an_answer_past_the_budget_arms_no_backoff(monkeypatch):
    """A 200 that arrived past the budget was answered: PBS is done with it,
    so it is simply read again next build."""
    use_clock(monkeypatch, Clock())
    real = pbs._get

    def late(session, target, path, *args, **kwargs):
        if path == _NS_PATH:
            raise pbs._PbsError(
                "timeout", pbs._DEADLINE_MESSAGE, True, skipped="deadline"
            )
        return real(session, target, path, *args, **kwargs)

    monkeypatch.setattr(pbs, "_get", late)
    collect(monkeypatch, minimal_responses())
    assert pbs._timeout_backoff == {}


def test_stale_backoffs_are_forgotten_at_the_next_build(monkeypatch):
    """A retry expired long ago and never sent again (its namespace or
    datastore is gone) is dropped. A hold stays."""
    clock = use_clock(monkeypatch, Clock(now=100_000.0))
    gone, recent, held = ("/gone", ()), ("/recent", ()), ("/held", ())
    pbs._timeout_backoff[gone] = (clock.now - pbs._TIMEOUT_BACKOFF_MAX - 1, 3, None)
    pbs._timeout_backoff[recent] = (clock.now - 60, 1, None)
    pbs._timeout_backoff[held] = (math.inf, 1, None)
    collect(monkeypatch, minimal_responses())
    assert sorted(pbs._timeout_backoff) == sorted([recent, held])


# Value: protects=a slow /groups is retried, never blinded until a reload;
#   fails_when=/groups is held like the namespace walk again;
#   why_new=PBS's /groups reads one level and ends, so a hold only blinds a
#   slow PBS (the red team's upstream reading); seam=none
def test_a_groups_timeout_backs_off_that_namespace_and_leaves_it_unread(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    responses = minimal_responses(
        **{
            _NS_PATH: ok([{"ns": ""}, {"ns": "a"}]),
            "/admin/datastore/ds/groups?ns=a": {"error": "timeout", "message": "t"},
        }
    )
    collect(monkeypatch, responses)
    clock.now += pbs.PBS_CACHE_TTL + 5
    out, session = collect(monkeypatch, responses)
    sent = [route(u) for u in session.calls]
    assert "/admin/datastore/ds/groups" in sent  # the root's, still read
    assert "/admin/datastore/ds/groups?ns=a" not in sent
    assert out["datastores"][0]["unread_namespaces"] == ["a"]
    skipped = [e for e in out["errors"] if e["message"] == pbs._TIMEOUT_BACKOFF_MESSAGE]
    assert [(e["scope"], e["ns"]) for e in skipped] == [("groups", "a")]
    # Past its backoff (two rebuilds after one timeout) it is sent again.
    clock.now += pbs.PBS_CACHE_TTL
    _, session = collect(monkeypatch, responses)
    assert "/admin/datastore/ds/groups?ns=a" in [route(u) for u in session.calls]


def test_groups_past_the_cap_are_counted_not_built(monkeypatch):
    """A /groups listing longer than what the group cap has left builds only
    the rows it keeps (a hostile listing would otherwise cost a row each);
    the rest are counted for the cap error and the namespace is unread."""
    monkeypatch.setattr(pbs, "MAX_GROUPS", 2)
    built = []
    real = pbs._group_row

    def group_row(store, ns, group, summary):
        built.append(group["backup-id"])
        return real(store, ns, group, summary)

    monkeypatch.setattr(pbs, "_group_row", group_row)
    listing = [
        {"backup-type": "vm", "backup-id": str(n), "last-backup": 1} for n in range(5)
    ]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/groups": ok(listing),
                "/admin/datastore/ds/snapshots": ok([]),
            }
        ),
    )
    assert built == ["0", "1"]
    assert [g["id"] for g in out["groups"]] == ["0", "1"]
    assert out["datastores"][0]["unread_namespaces"] == [""]
    assert [e["message"] for e in out["errors"] if e["scope"] == "cap"] == [
        "groups capped at 2: 3 dropped"
    ]


def test_a_walk_read_always_gets_a_real_wait(monkeypatch):
    """Near the end of the budget a read is clamped to what is left -- except
    a held or backed-off one, which keeps _TIMEOUT_BACKOFF_MIN_WAIT: its
    timing out must mean PBS did not answer, not that the budget ran out."""
    clock = use_clock(monkeypatch, Clock())
    session = FakeSession(responses_handler(minimal_responses()))
    deadline = clock.now + 1
    pbs._get(session, _target(), "/access/permissions", deadline=deadline)
    pbs._get(session, _target(), _NS_PATH, deadline=deadline, min_wait=5)
    assert session.timeouts == [(1, 1), (1, 5)]


def test_only_a_read_timeout_arms_the_hold(monkeypatch):
    """A connect timeout never reached PBS: nothing to wait for, the read is
    sent again next build. A read timeout that waited its whole read timeout
    was sent and may still be running (a stalled handshake was not: see
    test_a_stalled_tls_handshake_holds_nothing)."""
    clock = use_clock(monkeypatch, Clock())
    responses = minimal_responses(
        **{_NS_PATH: {"error": "connect_timeout", "message": "t"}}
    )
    out, _ = collect(monkeypatch, responses)
    assert out["datastores"][0]["namespaces"] is None
    assert pbs._timeout_backoff == {}
    clock.now += pbs.PBS_CACHE_TTL + 5
    _, session = collect(monkeypatch, responses)
    assert len(_ns_calls(session)) == 1


def test_a_read_held_back_by_its_backoff_stays_quiet_on_retry(monkeypatch):
    """A snapshot listing that keeps timing out logs at error once: the retry
    after its backoff logs the same failure at debug, like any steady one."""
    clock = use_clock(monkeypatch, Clock())
    logged = capture_logs(monkeypatch)
    stuck = minimal_responses(
        **{"/admin/datastore/ds/snapshots": {"error": "timeout", "message": "t"}}
    )
    collect(monkeypatch, stuck)
    clock.now += pbs.PBS_CACHE_TTL + 5
    collect(monkeypatch, stuck)  # held back
    clock.now += pbs.PBS_CACHE_TTL  # two rebuilds after the timeout
    collect(monkeypatch, stuck)  # retried, times out again
    levels = [lvl for lvl, m in logged if "snapshots read failed" in m]
    assert levels == ["error", "debug"]


def test_steady_repeats_do_not_use_up_the_error_line_cap(monkeypatch):
    """The cap counts lines actually logged at error: a NEW failure among
    steady ones (already at debug) still logs at error."""
    monkeypatch.setattr(pbs, "_MAX_READ_FAILURE_LINES", 2)
    logged = capture_logs(monkeypatch)
    names = ["a", "b", "c"]
    base = {
        _NS_PATH: ok([{"ns": ""}] + [{"ns": n} for n in names]),
        "/admin/datastore/ds/groups?ns=a": fail(400, "broken a"),
        "/admin/datastore/ds/groups?ns=b": fail(400, "broken b"),
        "/admin/datastore/ds/groups?ns=c": ok([]),
        "/admin/datastore/ds/snapshots?ns=c": ok([]),
    }
    collect(monkeypatch, minimal_responses(**base))
    del logged[:]
    base["/admin/datastore/ds/groups?ns=c"] = fail(400, "broken c")
    collect(monkeypatch, minimal_responses(**base))
    lines = [(lvl, m) for lvl, m in logged if "groups read failed" in m]
    assert lines == [
        ("debug", "PBS groups read failed on ds/a: HTTP 400: broken a"),
        ("debug", "PBS groups read failed on ds/b: HTTP 400: broken b"),
        ("error", "PBS groups read failed on ds/c: HTTP 400: broken c"),
    ]


# Value: protects=a scoped token never reads the aggregate usage status (PBS
#   walks every datastore it cannot audit, visible or not, so another tenant's
#   broken datastore would hold this one's walks); a datastore it audits at
#   the datastore level reports its usage from its own status;
#   fails_when=a scoped token reads the aggregate again, or its datastore-level
#   stores lose their usage; why_new=the red team traced the out-of-scope walk
#   in PBS's datastore_status; seam=none
@pytest.mark.parametrize(
    "grant, own_status",
    [("/datastore/ds", True), ("/datastore/ds/a", False)],
    ids=["datastore_level", "namespace_level"],
)
def test_a_scoped_token_never_reads_the_aggregate_usage(monkeypatch, grant, own_status):
    responses = minimal_responses(
        **{
            "/access/permissions": ok({grant: {"Datastore.Audit": True}}),
            "/status/datastore-usage": {"error": "timeout", "message": "t"},
            "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
        }
    )
    out, session = collect(monkeypatch, responses)
    sent = [route(u) for u in session.calls]
    assert "/status/datastore-usage" not in sent
    assert ("/admin/datastore/ds/status" in sent) is own_status
    assert out["datastores"][0]["total"] == (9 if own_status else None)
    assert out["datastores"][0]["estimated_full_date"] is None
    assert pbs._timeout_backoff == {}


def test_a_held_back_usage_status_still_falls_back_per_datastore(monkeypatch):
    """For a full-scope token an aggregate held back by its backoff reads as
    failed, so each filesystem datastore's own status is read instead. It is
    HELD for that token too: PBS walks any datastore a deeper ACL entry hides
    from it, which the agent cannot always see (reproduced on PBS 4.2)."""
    clock = use_clock(monkeypatch, Clock())
    responses = minimal_responses(
        **{
            "/status/datastore-usage": {"error": "timeout", "message": "t"},
            "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
        }
    )
    collect(monkeypatch, responses)
    clock.now += pbs.PBS_CACHE_TTL + 5
    out, session = collect(monkeypatch, responses)
    sent = [route(u) for u in session.calls]
    assert "/status/datastore-usage" not in sent
    assert "/admin/datastore/ds/status" in sent
    assert out["datastores"][0]["total"] == 9
    # Value: protects=a full-scope usage status held after a timeout, the
    #   hidden-datastore walk; fails_when=it is retried for a full-scope token
    #   (each re-send pins one more PBS proxy thread); why_new=the held-usage
    #   test above uses a scoped token; seam=none
    skipped = [e["message"] for e in out["errors"] if e["scope"] == "usage"]
    assert skipped == [pbs._TIMEOUT_HOLD_MESSAGE]
    clock.now += pbs._TIMEOUT_BACKOFF_MAX + pbs.PBS_CACHE_TTL
    _, session = collect(monkeypatch, responses)
    assert "/status/datastore-usage" not in [route(u) for u in session.calls]


# Value: protects=a datastore's own status is retried after a timeout;
#   fails_when=it is held until a reload again;
#   why_new=it is one statfs that ends, so a hold only blinds; seam=none
def test_a_timed_out_per_datastore_status_backs_off(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    responses = minimal_responses(
        **{
            "/status/datastore-usage": fail(500, "EIO"),
            "/admin/datastore/ds/status": {"error": "timeout", "message": "t"},
        }
    )
    collect(monkeypatch, responses)
    clock.now += pbs.PBS_CACHE_TTL + 5
    out, session = collect(monkeypatch, responses)
    assert "/admin/datastore/ds/status" not in [route(u) for u in session.calls]
    assert out["datastores"][0]["total"] is None
    skipped = [e for e in out["errors"] if e["message"] == pbs._TIMEOUT_BACKOFF_MESSAGE]
    assert [(e["scope"], e["store"]) for e in skipped] == [("usage", "ds")]
    clock.now += pbs.PBS_CACHE_TTL
    _, session = collect(monkeypatch, responses)
    assert "/admin/datastore/ds/status" in [route(u) for u in session.calls]


def test_a_block_too_large_to_ship_fails_the_build(monkeypatch):
    """The block is re-serialized every tick for a TTL: one over
    _MAX_BLOCK_JSON_BYTES (a broken PBS's free text) or, gzipped, over
    _MAX_BLOCK_GZIP_BYTES (random identifiers barely compress) is an error
    envelope instead -- cached like a block, so it costs one build per TTL."""
    clock = use_clock(monkeypatch, Clock(), cache_too=True)
    out, _ = collect(monkeypatch, minimal_responses())
    keys = (
        "scope",
        "datastores",
        "groups",
        "sync_jobs",
        "verify_jobs",
        "prune_jobs",
        "errors",
        "built_at",
        "walks_held",
    )
    raw = json.dumps({key: out[key] for key in keys}).encode()
    size, packed = len(raw), len(gzip.compress(raw, 1))
    monkeypatch.setattr(pbs, "_MAX_BLOCK_JSON_BYTES", size)
    monkeypatch.setattr(pbs, "_MAX_BLOCK_GZIP_BYTES", packed)
    assert "datastores" in collect(monkeypatch, minimal_responses())[0]  # ships
    monkeypatch.setattr(pbs, "_MAX_BLOCK_JSON_BYTES", size - 1)
    out, _ = collect(monkeypatch, minimal_responses())
    assert out == {
        "reachable": True,
        "error_type": "http_error",
        "error_message": f"block too large to ship: over {size - 1} bytes of "
        "JSON (a working PBS keeps its fields short)",
    }
    monkeypatch.setattr(pbs, "_MAX_BLOCK_JSON_BYTES", size)
    monkeypatch.setattr(pbs, "_MAX_BLOCK_GZIP_BYTES", packed - 1)
    out, _ = collect(monkeypatch, minimal_responses())
    assert out["error_message"] == (
        f"block too large to ship: over {packed - 1} bytes gzipped (a working "
        "PBS keeps its fields short)"
    )
    # Cached for the TTL: the next tick reads /version only, same envelope.
    clock.now += 60
    again, session = collect(monkeypatch, minimal_responses(), keep_cache=True)
    assert again == out
    assert [route(u) for u in session.calls] == ["/version"]


# Value: protects=the build's memory against a broken PBS's ~90 MB block;
# fails_when=the whole block is encoded (json.dumps) before either limit is
# checked; why_new=the too-large test above only proves the verdict, not that
# the encoding stops; seam=none
@pytest.mark.parametrize("limit", ["_MAX_BLOCK_JSON_BYTES", "_MAX_BLOCK_GZIP_BYTES"])
def test_an_oversized_block_stops_encoding_at_the_first_limit(monkeypatch, limit):
    rng = random.Random(7)
    block = {
        "ids": ["".join(rng.choices("0123456789abcdef", k=64)) for _ in range(8000)]
    }
    raw = json.dumps(block)
    monkeypatch.setattr(pbs, "_ENCODE_BATCH_CHARS", 1024)
    monkeypatch.setattr(pbs, limit, 4096)
    drawn = []
    real = pbs._encoded

    def spy(value):
        for text in real(value):
            drawn.append(text)
            yield text

    monkeypatch.setattr(pbs, "_encoded", spy)
    assert pbs._oversize(block) is not None
    # It streamed, and stopped AT the limit (4096), not before it: json.dumps
    # of the whole block would draw no piece at all.
    assert len(drawn) > 1 and len("".join(drawn)) > 4096
    # Every piece but the last one drawn was under the limit: it stopped
    # there (zlib holds ~48 KB before it emits), a fraction of ~540 KB.
    assert "".join(drawn) == raw[: len("".join(drawn))]
    assert len("".join(drawn)) < len(raw) // 4
    monkeypatch.setattr(pbs, limit, 10 * len(raw))
    assert pbs._oversize(block) is None


# Value: protects=each limit is checked against the block as the payload
#   ships it (json.dumps, non-ASCII escaped; the gzipped size of every piece
#   summed); fails_when=the JSON count uses ensure_ascii=False, or the gzipped
#   size is one piece's output, not the running total; why_new=the other size
#   tests use ASCII blocks, or a limit one zlib emission crosses; seam=none
def test_the_block_limits_count_the_block_as_the_payload_ships_it(monkeypatch):
    """The synchronizer json.dumps the payload (an astral character is 12
    escaped bytes on the wire, not 1) and gzips it whole: the verdict counts
    exactly that JSON, and the gzipped bytes of EVERY piece -- zlib emits in
    chunks far below the gzip limit, so counting one piece never trips it."""
    rng = random.Random(7)
    block = {
        "ids": ["".join(rng.choices("0123456789abcdef", k=64)) for _ in range(8000)],
        # A maintenance message or a PBS error body: scrubbed, not ASCII-only.
        "notes": [
            "".join(rng.choices(["a", "b", chr(0xE9), chr(0x1F600)], k=64))
            for _ in range(500)
        ],
    }
    raw = json.dumps(block)
    gzipped = len(gzip.compress(raw.encode(), 1))
    monkeypatch.setattr(pbs, "_ENCODE_BATCH_CHARS", 1024)  # many pieces
    for json_limit, gzip_limit, verdict in (
        (len(raw), 2 * gzipped, None),
        (len(raw) - 1, 2 * gzipped, f"over {len(raw) - 1} bytes of JSON"),
        (len(raw), gzipped // 2, f"over {gzipped // 2} bytes gzipped"),
    ):
        monkeypatch.setattr(pbs, "_MAX_BLOCK_JSON_BYTES", json_limit)
        monkeypatch.setattr(pbs, "_MAX_BLOCK_GZIP_BYTES", gzip_limit)
        assert pbs._oversize(block) == verdict


def test_only_the_kept_groups_are_summarized():
    """Summaries are built for the groups the group cap kept, not for every
    group a hostile snapshot listing names."""
    snaps = [snapshot("vm", "1", 100), snapshot("vm", "2", 100)]
    summaries, unparseable = pbs._summarize_snapshots(snaps, "ds", {("vm", "1")})
    assert list(summaries) == [("vm", "1")] and unparseable == 0
    assert set(pbs._summarize_snapshots(snaps, "ds")[0]) == {("vm", "1"), ("vm", "2")}


# Value: protects=a backed-off read keeps a 5s read timeout near the end of the budget, and a walk is not sent then, so a late answer never holds or backs off a healthy PBS;
#   fails_when=min_wait is not passed to backed-off reads, the max() floor in _get is dropped, or a walk is sent late;
#   why_new=the only test that walk and snapshot reads get min_wait while other
#   reads stay clamped; seam=none
def test_a_walk_sent_as_the_budget_runs_out_is_late_never_held(monkeypatch):
    """A backed-off read (a snapshot listing) waits _TIMEOUT_BACKOFF_MIN_WAIT
    whatever budget is left: sent with 1s left and answered 2s later it is
    merely late (a skip, sent again next build) -- clamped to that 1s it would
    read as a READ TIMEOUT and back off. A walk is not even sent with less
    than its whole read timeout left. Every other read stays clamped to the
    budget left."""
    clock = use_clock(monkeypatch, Clock())
    handler = responses_handler(minimal_responses())

    def answers_in_two_seconds(url):
        if session.timeouts[-1][1] < 2:  # what a socket read timeout does
            raise requests.exceptions.ReadTimeout("Read timed out.")
        clock.now += 2
        return handler(url)

    session = FakeSession(answers_in_two_seconds)
    target = _target()
    errors = pbs._Errors(target.redact)
    held = pbs._sub_read(
        session, target, errors, clock.now + 1, "namespaces", _NS_PATH, backoff="hold"
    )
    assert held is None and session.calls == []  # a walk: not sent at all
    assert [e["message"] for e in errors] == [pbs._DEADLINE_MESSAGE]
    errors = pbs._Errors(target.redact)
    read = pbs._sub_read(
        session,
        target,
        errors,
        clock.now + 1,
        "snapshots",
        "/admin/datastore/ds/snapshots",
        backoff="retry",
    )
    assert read is None
    assert session.timeouts[-1] == (1, pbs._TIMEOUT_BACKOFF_MIN_WAIT)
    assert [e["message"] for e in errors] == [pbs._DEADLINE_MESSAGE]
    assert pbs._timeout_backoff == {}
    errors = pbs._Errors(target.redact)
    gc = pbs._sub_read(
        session, target, errors, clock.now + 1, "gc", "/admin/datastore/ds/gc"
    )
    assert gc is None and session.timeouts[-1] == (1, 1)
    assert [e["message"] for e in errors] == ["Read timed out."]
    assert pbs._timeout_backoff == {}


# Value: protects=a successful /snapshots read clears its retry backoff, so a later timeout restarts at one skipped rebuild;
#   fails_when=the success path stops popping the backoff entry;
#   why_new=no test followed a success with a new timeout; seam=none
def test_a_snapshot_listing_that_answers_again_restarts_its_backoff(monkeypatch):
    """A success clears a retried read's backoff: the next timeout starts the
    ladder over (one skipped rebuild), not where the old streak left off."""
    clock = use_clock(monkeypatch, Clock())
    path = "/admin/datastore/ds/snapshots"
    stuck = minimal_responses(**{path: {"error": "timeout", "message": "t"}})
    collect(monkeypatch, stuck)  # the timeout takes its whole read timeout
    [key] = pbs._timeout_backoff
    timed_out = 1000.0 + pbs._READ_TIMEOUT
    assert pbs._timeout_backoff[key][:2] == (timed_out + 2 * pbs.PBS_CACHE_TTL, 1)
    clock.now = timed_out + 2 * pbs.PBS_CACHE_TTL  # the retry, answered this time
    out, _ = collect(monkeypatch, minimal_responses())
    assert out["groups"][0]["in_progress"] is False
    assert out["datastores"][0]["unread_namespaces"] == []
    assert pbs._timeout_backoff == {}
    collect(monkeypatch, stuck)  # and times out again later
    assert pbs._timeout_backoff[key][:2] == (clock.now + 2 * pbs.PBS_CACHE_TTL, 1)


# Value: protects=SIGHUP releases a /snapshots retry backoff, not only the held walks;
#   fails_when=reset_timeout_holds clears only the hold entries;
#   why_new=the hold tests covered the walks only; seam=none
def test_a_reload_also_releases_a_snapshot_listing_backing_off(monkeypatch):
    """SIGHUP sends again every read waiting on a timeout -- a retried
    snapshot listing too, not only the held walks: the operator just repaired
    the datastore, and the namespace must not stay unread for hours."""
    clock = use_clock(monkeypatch, Clock())
    path = "/admin/datastore/ds/snapshots"
    collect(
        monkeypatch, minimal_responses(**{path: {"error": "timeout", "message": "t"}})
    )
    [(retry_at, _, _)] = pbs._timeout_backoff.values()
    assert retry_at != math.inf  # backing off, not held
    pbs.reset_timeout_holds()
    clock.now += pbs.PBS_CACHE_TTL + 5  # the next rebuild, inside the backoff
    out, session = collect(monkeypatch, minimal_responses())
    assert path in [route(u) for u in session.calls]
    assert out["datastores"][0]["unread_namespaces"] == []
    assert out["errors"] == []


# Value: protects=GC and job-list reads that time out are never backed off or held;
#   fails_when=a backoff= argument is added to the gc or job-list reads;
#   why_new=the backoff tests covered walk and snapshot reads only; seam=none
@pytest.mark.parametrize(
    "path",
    [
        "/admin/datastore/ds/gc",
        "/admin/verify",
        "/admin/prune",
        "/admin/sync?sync-direction=all",
    ],
)
def test_a_timed_out_read_that_is_not_a_walk_is_sent_again_next_build(
    path, monkeypatch
):
    """Only the namespace walks are held and only the reads that can take
    long back off: a GC status or a job list that timed out is simply read
    again at the next build."""
    clock = use_clock(monkeypatch, Clock())
    out, _ = collect(
        monkeypatch, minimal_responses(**{path: {"error": "timeout", "message": "t"}})
    )
    assert "datastores" in out  # a scoped failure, not the envelope
    # (A GC read that times out also spends the per-datastore half of the
    # budget, so the namespace listing after it may be skipped.)
    assert [e["message"] for e in out["errors"]][:1] == ["t"]
    assert pbs._timeout_backoff == {}
    clock.now += pbs.PBS_CACHE_TTL + 5
    out, session = collect(monkeypatch, minimal_responses())
    assert path in [route(u) for u in session.calls]
    assert out["errors"] == []


# Value: protects=only the first walk that timed out is logged as held, with
#   no datastore for the usage status (the listing's 'on ds' line is pinned by
#   test_a_timed_out_namespace_listing_is_held_until_a_reload);
#   fails_when=every held walk logs its own line, or the usage line names a
#   datastore; why_new=no test read the text of the hold log line; seam=none
def test_a_hold_names_the_read_it_holds_in_the_log(monkeypatch):
    """The held line is the operator's pointer to WHAT to repair: logged once,
    for the walk that timed out -- here the aggregate usage status, which
    names no datastore."""
    use_clock(monkeypatch, Clock())
    logged = capture_logs(monkeypatch)
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                _NS_PATH: {"error": "timeout", "message": "t"},
                "/status/datastore-usage": {"error": "timeout", "message": "t"},
                "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
            }
        ),
    )
    held = [(lvl, m) for lvl, m in logged if " held: " in m]
    # The usage status timed out first: every walk is held from then on, so
    # the namespace listing is never sent -- one pinned proxy thread, not two.
    assert held == [("error", f"PBS usage read held: {pbs._TIMEOUT_HOLD_MESSAGE}")]
    # ...and it reads held, not merely late (both leave it unsent here).
    namespaces = [e["message"] for e in out["errors"] if e["scope"] == "namespaces"]
    assert namespaces == [pbs._TIMEOUT_HOLD_MESSAGE]


# Value: protects=_read_groups passes only the groups the cap kept to the snapshot summary;
#   fails_when=the wanted set is no longer passed to _summarize_snapshots;
#   why_new=the summary filter was tested alone, not its wiring; seam=none
def test_a_namespace_summarizes_only_the_groups_the_cap_kept(monkeypatch):
    """_read_groups hands the snapshot summary the groups the cap KEPT: a
    hostile listing naming thousands of other groups (or groups /groups never
    listed) costs no summary each."""
    monkeypatch.setattr(pbs, "MAX_GROUPS", 1)
    wanted = []
    real = pbs._summarize_snapshots

    def spy(snapshots, store, keys=None):
        wanted.append(keys)
        return real(snapshots, store, keys)

    monkeypatch.setattr(pbs, "_summarize_snapshots", spy)
    listing = [
        {"backup-type": "vm", "backup-id": str(n), "last-backup": 100} for n in range(3)
    ]
    snaps = [snapshot("vm", str(n), 100) for n in range(3)] + [snapshot("ct", "9", 100)]
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/admin/datastore/ds/groups": ok(listing),
                "/admin/datastore/ds/snapshots": ok(snaps),
            }
        ),
    )
    assert wanted == [{("vm", "0")}]
    assert [(g["id"], g["size"]) for g in out["groups"]] == [("0", 100)]


# Value: protects=SIGHUP drops the cached PBS block so the next tick rebuilds it;
#   fails_when=reset_timeout_holds stops replacing the block cache;
#   why_new=the hold tests reset the cache themselves through collect(); seam=none
def test_a_reload_drops_the_cached_block_that_reports_the_hold(monkeypatch):
    """After SIGHUP the next tick rebuilds: the cached block still says the
    read is held, which would otherwise ship for up to PBS_CACHE_TTL after
    the operator reloaded the agent."""
    use_clock(monkeypatch, Clock(), cache_too=True)
    stuck = minimal_responses(**{_NS_PATH: {"error": "timeout", "message": "t"}})
    collect(monkeypatch, stuck)
    _, session = collect(monkeypatch, minimal_responses(), keep_cache=True)
    assert [route(u) for u in session.calls] == ["/version"]  # cached
    pbs.reset_timeout_holds()
    out, session = collect(monkeypatch, minimal_responses(), keep_cache=True)
    assert len(_ns_calls(session)) == 1
    assert out["datastores"][0]["namespaces"] == [""]


def _datastores_with(names, **overrides):
    """A full-scope PBS with these filesystem datastores, each holding the
    root namespace only."""
    responses = minimal_responses(
        **{
            "/admin/datastore": ok(
                [{"store": n, "backend-type": "filesystem"} for n in names]
            ),
            "/status/datastore-usage": ok([]),
        }
    )
    for store in names:
        responses[f"/admin/datastore/{store}/gc"] = ok({})
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": ""}])
        responses[f"/admin/datastore/{store}/groups"] = ok([])
        responses[f"/admin/datastore/{store}/snapshots"] = ok([])
    responses.update(overrides)
    return responses


# Value: protects=a datastore whose namespace walk the budget skipped (less
#   than a whole read timeout left in the tick) is where the next build
#   resumes; fails_when=the cut is taken at the per-datastore half only, which
#   comes AFTER the walk cutoff, so one slow but answering walk starves every
#   datastore after it on every build; why_new=found by two review
#   specialists (run 8), no test had a walk skipped before the half ended;
#   seam=none
def test_a_walk_skipped_for_budget_is_where_the_next_build_resumes(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c", "d"]
    handler = responses_handler(_datastores_with(names))

    def timed(url):
        key = route(url)
        if key == "/admin/datastore/a/namespace":
            clock.now += 8  # slow, but answered inside its read timeout
        elif not key.startswith("/admin/datastore/"):
            clock.now += 0.3  # the head reads
        return handler(url)

    session = FakeSession(timed)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    read = []
    for _ in range(3):
        monkeypatch.setattr(pbs, "_cache", TTLCache())
        clock.now += 1000
        out = pbs.pbs_metrics(**LOOPBACK)
        read.append(
            [d["store"] for d in out["datastores"] if d["namespaces"] is not None]
        )
    # b, c and d were skipped while the per-datastore half still ran.
    assert read[0] == ["a"]
    assert set().union(*read) == set(names)  # nobody starves


# Value: protects=once the namespace cap is full, no further namespace walk
#   is sent (its answer would be dropped whole, and a walk may never end on
#   the PBS); fails_when=the walk is sent and thrown away; why_new=the red
#   team (run 8) saw b and c walked for nothing; seam=none
def test_no_namespace_walk_is_sent_once_the_namespace_cap_is_full(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 1)
    out, session = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    sent = [route(u) for u in session.calls]
    assert [p for p in sent if p.endswith("/namespace")] == [
        "/admin/datastore/a/namespace"
    ]
    assert [d["namespaces"] for d in out["datastores"]] == [[""], None, None]
    caps = [(e["store"], e["message"]) for e in out["errors"] if e["scope"] == "cap"]
    assert caps == [
        ("b", "namespaces capped at 1: not read"),
        ("c", "namespaces capped at 1: not read"),
    ]
    assert pbs._store_rotation == "b"  # the first one the cap left out


# Value: protects=a datastore a deeper ACL entry hides by REPLACING the
#   token's role with one lacking Datastore.Audit (PBS then no longer lists
#   it) makes the block partial with every job list flagged; fails_when=the
#   hidden check reads path presence alone (scope full: the server prunes a
#   datastore that still exists); why_new=QA capture 005, reproduced live on
#   PBS 4.2; seam=none
def test_a_datastore_whose_role_lost_datastore_audit_reads_partial(monkeypatch):
    perms = {**PERMS_FULL, "/datastore/gone": {"Remote.Audit": True}}
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/access/permissions": ok(perms)})
    )
    assert out["scope"] == "partial"
    partial = {
        e["scope"]: e["message"]
        for e in out["errors"]
        if e["message"].startswith("partial:")
    }
    assert set(partial) == {"sync_jobs", "verify_jobs", "prune_jobs"}
    assert all("hides part of /datastore" in m for m in partial.values())


# Value: protects=a remote a deeper ACL entry hides flags the sync job list
#   alone (PBS lists a sync job only to a token that audits its remote) and
#   leaves the scope full; fails_when=the remote tree is ignored (the server
#   prunes sync jobs that still exist) or read as a hidden datastore (every
#   list flagged, scope partial); why_new=nothing read paths below /remote;
#   seam=none
def test_a_hidden_remote_flags_only_the_sync_jobs(monkeypatch):
    perms = {**PERMS_FULL, "/remote/offsite": {"Datastore.Audit": True}}
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/access/permissions": ok(perms)})
    )
    assert out["scope"] == "full"
    partial = [
        (e["scope"], e["message"])
        for e in out["errors"]
        if e["message"].startswith("partial:")
    ]
    assert partial == [
        (
            "sync_jobs",
            "partial: a deeper ACL entry hides part of /remote from the API "
            "token, so sync jobs using it are not listed",
        )
    ]


# Value: protects=the rotation resumes at the unit it NAMED wherever that now
#   sits (a unit added before it; the unit gone: the next one in sort order,
#   wrapping), for namespaces and datastores alike; fails_when=it resumes by
#   position again (each build of a PBS too big for the budget walks a
#   different set, so a position points at an arbitrary unit); why_new=every
#   rotation test kept the lists unchanged between builds; seam=none
def test_the_rotation_resumes_by_name_when_the_lists_change(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    order = _slow_groups(monkeypatch, clock)  # one namespace per build
    for names, first in (
        (["", "b", "bb", "c"], "c"),  # "bb" added before c
        (["", "b", "d"], "d"),  # c gone: the next one
        (["", "b"], ""),  # c gone and nothing after it: wrap
    ):
        responses = minimal_responses(
            **{"/admin/datastore/ds/namespace": ok([{"ns": n} for n in names])}
        )
        for ns in names[1:]:
            responses[f"/admin/datastore/ds/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/ds/snapshots?ns={ns}"] = ok([])
        monkeypatch.setattr(pbs, "_rotation", ("ds", "c"))
        del order[:]
        collect(monkeypatch, responses)
        assert order[0] == first
    gc_order = []
    real = pbs._read_gc

    def read_gc(session, target, errors, deadline, store):
        gc_order.append(store)
        return real(session, target, errors, deadline, store)

    monkeypatch.setattr(pbs, "_read_gc", read_gc)
    monkeypatch.setattr(pbs, "_store_rotation", "b")
    collect(monkeypatch, _datastores_with(["a", "aa", "b"]))  # "aa" added
    assert gc_order == ["b", "a", "aa"]
