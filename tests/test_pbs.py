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


def _reset_state(monkeypatch):
    """Every piece of the module's state, fresh (the containers mutated in
    place too: a test ending with a deferred walk would defer it in the
    next one)."""
    for name, value in (
        ("_cache", TTLCache()),
        ("_rotation", None),
        ("_local_nodes", set()),
        ("_stalled_worker", None),
        ("_stalled_progress", {}),
        ("_timeout_backoff", {}),
        ("_auth_backoff", None),
        ("_last_logged_failure", None),
        ("_store_rotation", None),
        ("_listings", {}),
        ("_listings_key", None),
        ("_deferred_walks", set()),
        ("_walked_since_reload", set()),
        ("_reloads", 0),
        ("_known_nodes", (None, frozenset())),
        ("_read_failures", {"previous": set(), "current": set()}),
        ("_read_failure_lines", {"error": 0, "quieted": 0}),
    ):
        monkeypatch.setattr(pbs, name, value)


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    _reset_state(monkeypatch)


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
    # The body deadline pbs hands read_capped_body is on this clock too.
    monkeypatch.setattr("fivenines_agent.http_body.time", clock)
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
    state = scenario.get("agent_state", {})
    # A state this harness cannot set fails here.
    assert set(state) <= {"walks_held", "listings"}, state
    if state.get("walks_held"):
        # An earlier build of this agent armed the walk hold.
        failure = ("namespaces", "store1", None, "armed by an earlier build")
        pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    if state.get("listings"):
        # The namespace listings an earlier build of this agent remembers.
        target = pbs._Target(**scenario["config"]["pbs"])
        monkeypatch.setattr(pbs, "_listings", dict(state["listings"]))
        monkeypatch.setattr(pbs, "_listings_key", target.cache_key)
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
        # Its own status: the usage fallback after a reload.
        "/admin/datastore/ds/status": ok({"total": 1000, "used": 400, "avail": 600}),
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
    "namespace_walk_held_remembered",
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
    fixture = _load_fixture()
    texts = list(fixture["errors_contract"].values())
    texts += list(fixture["field_contract"].values())
    quoted = [q for text in texts for q in re.findall(r"'(skipped:[^']*)'", text)]
    shipped = {
        pbs._DEADLINE_MESSAGE,
        pbs._TIMEOUT_BACKOFF_MESSAGE,
        pbs._TIMEOUT_HOLD_MESSAGE,
        pbs._ROTATION_MESSAGE,
        pbs._RELOAD_DEFER_MESSAGE,
        pbs._TIMED_OUT_MESSAGE,
        pbs._GROUPS_HOLD_MESSAGE,
        pbs._USAGE_DEFERRED_MESSAGE,
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


# Value: protects=the array caps the shared contract quotes to the server
#   (errors_contract.cap) match the agent's; fails_when=a cap changes on one
#   side only (the server's copy of the contract then promises a bound the
#   agent does not keep); why_new=pre-landing review (testing): no test
#   pinned them; seam=none
def test_the_caps_match_the_contract():
    assert (pbs.MAX_DATASTORES, pbs.MAX_NAMESPACES, pbs.MAX_GROUPS) == (100, 1000, 5000)
    assert (pbs.MAX_JOBS, pbs.MAX_ERRORS) == (200, 500)
    cap = _load_fixture()["errors_contract"]["cap"]
    for text in (
        "datastores (100;",
        "namespaces (1000,",
        "block-wide 5000",
        "errors (500)",
    ):
        assert text in cap, text


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
    # Every read one build can back off -- a status and a gc per datastore, a
    # /groups and a /snapshots per namespace and the note of that /snapshots
    # sent past the budget (_grace_key), the usage status -- plus the two
    # holds.
    assert pbs._TIMEOUT_BACKOFF_ENTRIES == 2 * 100 + 3 * 1000 + 3


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


# Value (extension): protects=an empty listing stays a trusted, error-free
#   block after earlier builds left their resume points on a datastore since
#   removed (its last one); fails_when=a resume point is looked up in the
#   empty datastore list (modulo by zero: every tick fails until a restart);
#   why_new=the row ran with no resume point set; seam=none
def test_a_full_scope_token_trusts_an_empty_pbs(monkeypatch):
    empty = minimal_responses(
        **{"/admin/datastore": ok([]), "/status/datastore-usage": ok([])}
    )
    out, _ = collect(monkeypatch, empty)
    assert out["datastores"] == [] and out["groups"] == [] and out["errors"] == []
    collect(monkeypatch, minimal_responses())  # ds, then removed from PBS
    out, _ = collect(monkeypatch, empty)
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
    # Value (row): protects=a build whose namespace listing was not read flags
    #   every job list it read (a namespace hidden there would hide its jobs);
    #   fails_when=the job lists ship as complete; why_new=found in QA on PBS
    #   4.2; seam=none
    assert out["errors"][:3] == _unlisted_flags()
    assert out["groups"] == [] and out["errors"][3]["scope"] == "namespaces"
    out, _ = collect(
        monkeypatch, minimal_responses(**{"/admin/datastore/ds/namespace": ok({})})
    )
    assert out["errors"][3]["message"] == "unexpected response shape (not a list)"
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
        assert out["errors"][3] == {
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
    flags = ["sync_jobs", "verify_jobs", "prune_jobs"] if scope == "namespaces" else []
    assert [e["scope"] for e in out["errors"]] == flags + [scope]


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


# Value (extension): protects=a task id cut short after its start time (fewer
#   than the nine fields a PBS task id has) reads unknown, like every other
#   unparseable field; fails_when=the length check is narrowed to the field
#   it reads (six): the truncated id ships a start time, and a gc status
#   carrying one reads PBS's never-measured default counters as measured;
#   why_new=the only short row had two fields, so only removing the check
#   failed; seam=none
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
    # Extension: eight fields, the start time among them: still not a task id.
    assert pbs._upid_starttime("UPID:n:1:2:3:6ABA2CB6:verify:s") is None
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


# Value (rows): protects=a listing the namespace cap drops whole was still
#   read and scanned: a parentless namespace in it makes the block partial,
#   a clean one flags no job list; fails_when=it is scanned only
#   when kept (scope full, jobs pruned) or counted as unread; why_new=both
#   mutants survived, the cap rows asserted no flag; seam=none
@pytest.mark.parametrize(
    "b_listing, scope, flag",
    [
        (["", "x"], "full", None),
        (["", "x/y"], "partial", pbs._HIDDEN_NAMESPACE_REASON),
    ],
    ids=["clean", "hides_a_namespace"],
)
def test_the_namespace_cap_is_shared_across_datastores(
    monkeypatch, b_listing, scope, flag
):
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 3)
    listing = ok([{"ns": ns} for ns in b_listing])
    out, _ = collect(
        monkeypatch, _two_datastores(**{"/admin/datastore/b/namespace": listing})
    )
    assert out["scope"] == scope
    flags = [e["message"] for e in out["errors"] if e["message"].startswith("partial")]
    assert flags == ([] if flag is None else ["partial: " + flag] * 3)
    a, b = out["datastores"]
    assert (a["namespaces"], a["unread_namespaces"]) == (["", "x"], [])
    # b's listing does not fit what a left: none of it is kept (its set is
    # unknown, nothing of it read), and it is listed first next build.
    assert (b["namespaces"], b["unread_namespaces"]) == (None, None)
    assert {
        "scope": "cap",
        "store": "b",
        "ns": None,
        "message": "namespaces capped at 3: not read",
    } in out["errors"]
    assert pbs._rotation == ("b", "")


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


# Value: protects=a datastore whose gc never answers (a hung mount) takes at
#   most the gc share: the other datastores' namespaces are still read in
#   that build, and the next build starts its gc reads past it; fails_when=
#   the hung read is not bounded by the share, or the gc cursor stays on it;
#   seam=none
def test_a_wedged_datastore_does_not_starve_the_others(monkeypatch):
    clock = use_clock(monkeypatch, Clock())

    def latency(path):
        return math.inf if path == "/admin/datastore/a/gc" else 0.1

    responses = _datastores_with(["a", "b"])
    for store in ("a", "b"):
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": ""}, {"ns": "x"}])
        responses[f"/admin/datastore/{store}/groups?ns=x"] = ok([])
        responses[f"/admin/datastore/{store}/snapshots?ns=x"] = ok([])
    session = _install_timed(monkeypatch, responses, clock, latency)
    out, sent = _timed_build(monkeypatch, clock, session)
    a, b = out["datastores"]
    assert a["gc"] is None and b["gc"] is None  # b's gc past the share
    assert (b["namespaces"], b["unread_namespaces"]) == (["", "x"], [])
    assert pbs._store_rotation == "b"
    out, sent = _timed_build(monkeypatch, clock, session)
    assert out["datastores"][1]["gc"] is not None  # read first this time
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
    """Every read of datastore b hangs: its namespace walk until its read
    timeout, its own status and gc until the per-datastore half. Given the
    whole budget, b would leave the groups phase nothing and a's namespaces
    would go unread; given half, a's namespaces are still read."""
    clock = use_clock(monkeypatch, Clock())
    real_get = pbs._get

    def get(session, target, path, *args, deadline=None, **kwargs):
        if path.startswith("/admin/datastore/b/"):
            # A hung mount: no request waits past its own read timeout.
            clock.now = max(clock.now, min(deadline, clock.now + pbs._READ_TIMEOUT))
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
    # Every unit walked was read: the next walks start at b, the one trimmed.
    assert pbs._rotation == ("b", "")
    out, _ = collect(monkeypatch, _two_datastores())
    assert [d["namespaces"] for d in out["datastores"]] == [None, ["", "x"]]
    assert pbs._rotation == ("a", "")


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
    """A datastore whose gc read FAILED fast (a 403) was not cut by the
    budget and does not move the gc rotation; the first one the budget cut
    (a hung mount) is read first next time -- not the last one cut after it,
    nor b again."""
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c", "d"]
    responses = _datastores_with(
        names, **{"/admin/datastore/b/gc": fail(403, "permission check failed")}
    )
    real_read_gc = pbs._read_gc

    def read_gc(session, target, errors, deadline, store, **kwargs):
        if store == "c":
            clock.now += 100  # a hung mount eats the whole budget
            return None
        return real_read_gc(session, target, errors, deadline, store, **kwargs)

    monkeypatch.setattr(pbs, "_read_gc", read_gc)
    out, _ = collect(monkeypatch, responses)
    assert [d["gc"] is None for d in out["datastores"]] == [False, True, True, True]
    assert pbs._store_rotation == "c"


def test_a_datastore_finished_as_the_phase_ran_out_is_not_read_first_again(
    monkeypatch,
):
    """The gc counterpart of the namespace rule: b's gc answered as the
    share ran out, so b was finished; the next build starts at c, the first
    datastore actually skipped."""
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_gc

    def slow(session, target, errors, deadline, store, **kwargs):
        gc = real(session, target, errors, deadline, store, **kwargs)
        if store == "b":
            clock.now = max(clock.now, deadline)  # done as the share ends
        return gc

    monkeypatch.setattr(pbs, "_read_gc", slow)
    out, _ = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    assert [d["gc"] is not None for d in out["datastores"]] == [True, True, False]
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
    # Value (row): protects=a datastore past the cap, never walked, leaves
    #   every job list read 'partial:' (a namespace hidden there would hide its
    #   jobs); fails_when=the cap is left out of the unread-listing rule;
    #   why_new=security and maintainability review; seam=none
    assert out["errors"] == [out["errors"][0]] + _unlisted_flags()
    assert out["errors"][0]["scope"] == "cap"


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


# --- behaviours line coverage did not pin ----------------------------------


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
    assert out["errors"][3]["message"] == "unparseable namespace row"
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
    assert out["errors"][3]["message"] == "repeated namespace row"
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
    # Value (row): protects=a build that learns no node (every gc backed off,
    #   no job with a task id) keeps the nodes the last build learned from the
    #   same PBS, never another PBS's; fails_when=the nodes are relearned from
    #   each build alone (a copied verification reads 'ok' for the whole gc
    #   backoff) or carried across PBSes; why_new=red-team review, reproduced
    #   in-process; seam=none
    responses = _one_verified_group(
        "UPID:elsewhere:1:2:3:0000000A:verify:ds:root@pam:", gc={}
    )
    responses.update(no_jobs)
    out, _ = collect(monkeypatch, responses)
    assert out["groups"][0]["verify_state"] is None
    out, _ = collect(monkeypatch, responses, port=8008)  # another PBS
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


def test_a_failed_namespace_listing_is_no_cut(monkeypatch):
    """A walk that merely FAILED is not a cut: the walks still go round
    every datastore, and a is walked again on the next build."""
    out, _ = collect(
        monkeypatch,
        _two_datastores(**{"/admin/datastore/a/namespace": fail(500, "boom")}),
    )
    assert [d["namespaces"] for d in out["datastores"]] == [None, ["", "x"]]
    out, session = collect(monkeypatch, _two_datastores())
    assert _walked([route(u) for u in session.calls]) == ["b", "a"]
    assert [d["namespaces"] for d in out["datastores"]] == [["", "x"]] * 2


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
    # Value (row): protects=a node name longer than a host name is no node: the
    #   set outlives the build (_known_nodes); fails_when=a hostile task id
    #   keeps megabytes of node name in the agent's memory for good;
    #   why_new=security review; seam=none
    pbs._local_nodes.clear()
    pbs._note_local_task("UPID:" + "n" * 256 + ":1:2:3:0000000A:verify:ds:root@pam:")
    pbs._note_local_task("UPID:" + "n" * 255 + ":1:2:3:0000000A:verify:ds:root@pam:")
    assert pbs._local_nodes == {"n" * 255}
    # Value (row): protects=the cap holds across builds too: a build that
    #   learns nodes replaces the ones carried from the last build of the same
    #   PBS, never adds to them; fails_when=the carried nodes are merged into
    #   every build (16 more per build from a PBS whose task ids name new
    #   nodes, and a node learned once counts as local for the life of the
    #   agent); why_new=coverage audit: only a build that learns no node was
    #   tested; seam=none
    for build in range(2):
        nodes = {f"b{build}n{i}" for i in range(pbs._MAX_LOCAL_NODES)}
        jobs = [
            {
                "id": node,
                "store": "ds",
                "last-run-upid": f"UPID:{node}:1:2:3:0000000A:verify:ds:root@pam:",
            }
            for node in sorted(nodes)
        ]
        collect(monkeypatch, minimal_responses(**{"/admin/verify": ok(jobs)}))
        assert pbs._local_nodes == nodes


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
    assert (fresh._listings, fresh._listings_key, fresh._deferred_walks) == (
        {},
        None,
        set(),
    )
    assert fresh._reloads == 0
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
    assert out["errors"] == _unlisted_flags() + [
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


def _unlisted_flags():
    """The job-list flags of a build where a datastore's namespaces were not
    read (unknown, so the jobs of a namespace hidden there are not
    taken for deleted)."""
    message = "partial: " + pbs._UNLISTED_REASON
    return [
        {"scope": scope, "store": None, "ns": None, "message": message}
        for scope in ("sync_jobs", "verify_jobs", "prune_jobs")
    ]


def _ns_calls(session):
    return [u for u in session.calls if route(u) == _NS_PATH]


# Value (held builds): protects=every build while the walk hold
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
    # Only the usage status stays backed off, for the build the reload
    # triggers: each datastore's own status read instead.
    assert set(pbs._timeout_backoff) == {pbs._USAGE_BACKOFF}
    assert "/status/datastore-usage" not in [route(u) for u in session.calls]
    assert out["datastores"][0]["total"] == 1000
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


# Value: protects=the deeper ACL entries the permissions map DOES show (a
#   path present under an absent ancestor, or present without the audited
#   privilege, below /datastore or /remote); fails_when=the parent/datastore
#   check is dropped, or a namespace-level gap is read as a datastore one;
#   why_new=nothing read the map's shape below /datastore before; seam=none
# Value (row): protects=a gap two namespace levels deep, below an audited
#   namespace, still reads hidden now that each path checks only its parent;
#   fails_when=the parent check is narrowed to one fixed namespace depth;
#   why_new=every hidden case sat at the first namespace level; seam=none
# Value (rows): protects=a deeper entry whose role LACKS the audited
#   privilege (a RemoteAudit on /datastore/<s>: PBS 4.2 then reports that path
#   as Remote.Audit and no longer lists <s>) reads hidden, and so does a
#   remote; fails_when=the check goes back to path presence alone, so the
#   block claims scope full and the server prunes a datastore that still
#   exists (reproduced live); why_new=every row hid a path by its ABSENCE;
#   seam=none
# Value (rows): protects=an audited privilege held but NOT
#   propagated reads its subtree hidden (measured: the user's non-propagated
#   DatastoreAudit beside a propagated DatastoreBackup hides every namespace
#   of the datastore, measured live) while the datastore itself stays
#   audited; fails_when=the check reads the privilege's presence only (scope
#   full: the server prunes namespaces that still exist); why_new=every row
#   had a propagated privilege or none; seam=none
def test_hidden_below_reads_the_deeper_acl_entries_the_map_shows():
    audit = {"Datastore.Audit": True}
    remote = {"Remote.Audit": True}
    assert pbs._hidden_below(PERMS_FULL) == (False, {}, False)
    visible = {**PERMS_FULL, "/datastore/s1": audit, "/datastore/s1/a": audit}
    assert pbs._hidden_below(visible) == (False, {"s1": True}, False)
    # A token scoped at the datastore level holds nothing on /datastore.
    assert pbs._hidden_below({"/datastore/s1": audit}) == (False, {"s1": True}, False)
    # NoAccess on /datastore/s2 (absent) and an audit grant on a namespace.
    assert pbs._hidden_below({**PERMS_FULL, "/datastore/s2/a": audit}) == (
        True,
        {"s2": False},
        False,
    )
    # A namespace hidden inside an audited datastore: not the datastore.
    deep = {**PERMS_FULL, "/datastore/s1": audit, "/datastore/s1/a/b": audit}
    assert pbs._hidden_below(deep) == (True, {"s1": True}, False)
    # NoAccess on s1/a/b below an audited s1/a, an audit grant deeper still.
    deeper = {**visible, "/datastore/s1/a/b/c": audit}
    assert pbs._hidden_below(deeper) == (True, {"s1": True}, False)
    # RemoteAudit on /datastore/s1 (measured): s1 and its namespaces inherit
    # Remote.Audit alone, and PBS no longer lists s1.
    replaced = {**PERMS_FULL, "/datastore/s1": remote, "/datastore/s1/a": remote}
    assert pbs._hidden_below(replaced) == (True, {"s1": False}, False)
    # The same entry on a namespace of an audited datastore.
    on_ns = {**PERMS_FULL, "/datastore/s1": audit, "/datastore/s1/a": remote}
    assert pbs._hidden_below(on_ns) == (True, {"s1": True}, False)
    # Audited but not propagated (measured at the datastore level): the
    # subtree is hidden, the datastore itself still audited.
    unpropagated = {"Datastore.Audit": False}
    for held in (
        {"/datastore/s1": unpropagated},
        {"/datastore/s1": audit, "/datastore/s1/a": unpropagated},
    ):
        assert pbs._hidden_below({**PERMS_FULL, **held}) == (True, {"s1": True}, False)
    # Value (rows): protects=a hidden path reads hidden
    #   wherever it sits in the map (arbitrary order), and a propagate flag
    #   that is not JSON true reads not propagated; fails_when=the verdict
    #   keeps the LAST path's, or the flag is read by truthiness (a 1 reads
    #   propagated: scope full over hidden namespaces); why_new=every
    #   hidden row listed its hidden path last, with boolean flags;
    #   seam=none
    first = {"/datastore/s1/a/b": audit, **PERMS_FULL, "/datastore/s1": audit}
    assert pbs._hidden_below(first) == (True, {"s1": True}, False)
    for flag in (1, "true", None):
        held = {**PERMS_FULL, "/datastore/s1": {"Datastore.Audit": flag}}
        assert pbs._hidden_below(held) == (True, {"s1": True}, False)
        gap = {**PERMS_FULL, "/remote/r": {"Remote.Audit": flag}}
        assert pbs._hidden_below(gap) == (False, {}, True)
    # A remote: audited, without Remote.Audit, or under an absent remote.
    assert pbs._hidden_below({**PERMS_FULL, "/remote/r": remote}) == (
        False,
        {},
        False,
    )
    # Value (row): protects=a hidden remote reads hidden wherever
    #   it sits in the map (PBS serializes a hash map: path order is arbitrary);
    #   fails_when=the remote verdict keeps only the LAST remote path's, so a
    #   visible remote listed after it ships the sync list as complete;
    #   why_new=every row put the hidden remote last; seam=none
    for gap in (
        {"/remote/r": audit},
        {"/remote/r/s": remote},
        {"/remote/r": audit, "/remote/v": remote},
        {"/remote/r": {"Remote.Audit": False}},  # not propagated
    ):
        assert pbs._hidden_below({**PERMS_FULL, **gap}) == (False, {}, True)
    # Paths outside both trees, or not absolute, say nothing.
    odd = {**PERMS_FULL, "/system/x": audit, "/access/y": {}, "datastore/s3": {}}
    assert pbs._hidden_below(odd) == (False, {}, False)


_AUDIT = {"Datastore.Audit": True}


# Value: protects=a datastore a deeper ACL entry hides at its own level ships
#   as partial scope with usage unknown, never PBS's 0/0/0; fails_when=the
#   fallback reads its /status (a false "0 bytes free") or scope stays full
#   (its root groups would be pruned); why_new=reproduced on PBS 4.2 by a
#   red-team review; seam=none
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
# Value: protects=the second walk of the arming build reads held,
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
    assert pbs._hidden_below(chain) == (False, {"s": True}, False)
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
        # Audited but not propagated (measured live): its namespaces hidden.
        {"/datastore/ds": {"Datastore.Audit": False}},
    ],
    ids=["datastore_hidden", "namespace_hidden", "not_propagated"],
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
#   fails_when=a walk is sent with a clamped read; why_new=a hold armed at a
#   5s budget was reproduced; seam=none
def test_a_stalled_tls_handshake_late_in_the_budget_holds_nothing(monkeypatch):
    clock = use_clock(monkeypatch, Clock())

    def stall(url):
        raise HandshakeStall("t")

    session = FakeSession(stall)
    target = _target()
    for left in (9.9, 5.0, 1.0):  # 5.0: was sent clamped (5, 5) and held
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
    assert pbs._timeout_backoff == {}  # the stalled handshake held nothing


# Value: protects=a held or backed-off read late in the tick keeps its TCP
#   connect plus a stalled TLS handshake under its read timeout, so neither
#   can count as pending; fails_when=the connect clamp to read/2 is dropped
#   (the read is cut to 8s, the connect stays 5s); why_new=a walk always has
#   its whole 10s since the fit rule, so only a retry read reaches the clamp
#   and nothing pinned it there (a review: the mutant survived);
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
    held, retried = ("namespaces", "ds", None, "t"), ("gc", "ds", None, "t")
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
# Value (row): protects=a namespace-scoped token whose
#   RemoteAudit sits on / (/datastore and /datastore/<s> then read Remote.Audit
#   alone) still collects and never reads the 0/0/0 own status;
#   fails_when=_hidden_below drops its depth guard (IndexError on /datastore:
#   every build an http_error) or the at_store map skips its privilege check;
#   why_new=no scoped map had /datastore present; seam=none
@pytest.mark.parametrize(
    "perms, own_status",
    [
        ({"/datastore/ds": {"Datastore.Audit": True}}, True),
        ({"/datastore/ds/a": {"Datastore.Audit": True}}, False),
        (
            {
                "/datastore": {"Remote.Audit": True},
                "/datastore/ds": {"Remote.Audit": True},
                "/datastore/ds/a": {"Datastore.Audit": True},
                "/remote": {"Remote.Audit": True},
            },
            False,
        ),
    ],
    ids=["datastore_level", "namespace_level", "namespace_level_remote_audit_on_root"],
)
def test_a_scoped_token_never_reads_the_aggregate_usage(monkeypatch, perms, own_status):
    responses = minimal_responses(
        **{
            "/access/permissions": ok(perms),
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
# Value (row): protects=a datastore's gc status that timed out is retried on
#   the same backoff, not re-sent on every build; fails_when=the gc read has
#   no backoff: one stuck gc takes the per-datastore half of every build, and
#   on a PBS where no walk fits the cursor stays on it, so no other gc is
#   ever read (reproduced live on PBS 4.2); why_new=red-team review;
#   seam=none
@pytest.mark.parametrize(
    "leaf, scope, field", [("status", "usage", "total"), ("gc", "gc", "gc")]
)
def test_a_timed_out_per_datastore_read_backs_off(monkeypatch, leaf, scope, field):
    clock = use_clock(monkeypatch, Clock())
    path = f"/admin/datastore/ds/{leaf}"
    responses = minimal_responses(
        **{
            "/status/datastore-usage": fail(500, "EIO"),
            "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
            path: {"error": "timeout", "message": "t"},
        }
    )
    collect(monkeypatch, responses)
    clock.now += pbs.PBS_CACHE_TTL + 5
    out, session = collect(monkeypatch, responses)
    assert path not in [route(u) for u in session.calls]
    assert out["datastores"][0][field] is None
    skipped = [e for e in out["errors"] if e["message"] == pbs._TIMEOUT_BACKOFF_MESSAGE]
    assert [(e["scope"], e["store"]) for e in skipped] == [(scope, "ds")]
    clock.now += pbs.PBS_CACHE_TTL
    _, session = collect(monkeypatch, responses)
    assert path in [route(u) for u in session.calls]


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
    read, its answer being what that wait was for -- clamped to that 1s it
    would read as a READ TIMEOUT and back off. A walk is not even sent with
    less than its whole read timeout left. Every other read (here a job list)
    stays clamped to the budget left."""
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
    assert [row["backup-time"] for row in read] == [100, 200]
    assert session.timeouts[-1] == (1, pbs._TIMEOUT_BACKOFF_MIN_WAIT)
    assert list(errors) == []
    assert pbs._timeout_backoff == {}
    errors = pbs._Errors(target.redact)
    jobs = pbs._sub_read(
        session, target, errors, clock.now + 1, "verify_jobs", "/admin/verify"
    )
    assert jobs is None and session.timeouts[-1] == (1, 1)
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


# Value: protects=job-list reads that time out are never backed off or held;
#   fails_when=a backoff= argument is added to the job-list reads;
#   why_new=the backoff tests covered walk and snapshot reads only; seam=none
@pytest.mark.parametrize(
    "path",
    [
        "/admin/verify",
        "/admin/prune",
        "/admin/sync?sync-direction=all",
    ],
)
def test_a_timed_out_read_that_is_not_a_walk_is_sent_again_next_build(
    path, monkeypatch
):
    """Only the namespace walks are held and only the reads that can take
    long back off: a job list that timed out is simply read again at the
    next build."""
    clock = use_clock(monkeypatch, Clock())
    out, _ = collect(
        monkeypatch, minimal_responses(**{path: {"error": "timeout", "message": "t"}})
    )
    assert "datastores" in out  # a scoped failure, not the envelope
    reads = [e["message"] for e in out["errors"]]
    assert [m for m in reads if not m.startswith("partial: ")][:1] == ["t"]
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
    root namespace only (and answering its own status: the usage fallback
    after a reload)."""
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
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 1, "avail": 8}
        )
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
#   specialists, no test had a walk skipped before the half ended;
#   seam=none
# Value (row): protects=the walk cut is taken at the walk
#   cutoff, not at the per-datastore half, also when time was spent before
#   the datastore reads (the two then differ); fails_when=the cut compares
#   against the half: a's slow walk ends before it, b, c and d are not cut,
#   and only a is ever walked; why_new=with no time spent first the cutoff
#   and the half coincide, so the mutant survived every test; seam=none
@pytest.mark.parametrize("preamble", [0, 4], ids=["none_before", "time_before"])
def test_a_walk_skipped_for_budget_is_where_the_next_build_resumes(
    monkeypatch, preamble
):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c", "d"]
    real_backends = pbs._read_backends

    def slow_preamble(*args):
        clock.now += preamble
        return real_backends(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    real = pbs._read_namespaces

    def slow(session, target, errors, deadline, store):
        rows = real(session, target, errors, deadline, store)
        if store == "a":
            # Slow, but answered: no walk fits after it.
            clock.now = max(clock.now, pbs._walk_deadline(deadline) + 0.5)
        return rows

    monkeypatch.setattr(pbs, "_read_namespaces", slow)
    read = []
    for _ in range(3):
        clock.now += 1000
        out, _ = collect(monkeypatch, _datastores_with(names))
        read.append(
            [d["store"] for d in out["datastores"] if d["namespaces"] is not None]
        )
        if len(read) == 1:
            # b, c and d were skipped while the per-datastore half still ran:
            # the next walks start at b.
            assert pbs._rotation == ("b", "")
    assert read[0] == ["a"]
    assert set().union(*read) == set(names)  # nobody starves


# Value: protects=once the namespace cap is full, no further namespace walk
#   is sent (its answer would be dropped whole, and a walk may never end on
#   the PBS); fails_when=the walk is sent and thrown away; why_new=the red
#   team saw b and c walked for nothing; seam=none
def test_no_namespace_walk_is_sent_once_the_namespace_cap_is_full(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 1)
    out, session = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    sent = [route(u) for u in session.calls]
    assert [p for p in sent if p.endswith("/namespace")] == [
        "/admin/datastore/a/namespace"
    ]
    assert [d["namespaces"] for d in out["datastores"]] == [[""], None, None]
    # Value (row): protects=the cap stops only the walk: a
    #   datastore past it still reports its GC status; fails_when=the cap check
    #   is hoisted above the per-datastore reads (gc null past the cap);
    #   why_new=the test pinned the walks and the cut, not the gc; seam=none
    assert [d["gc"] is not None for d in out["datastores"]] == [True] * 3
    caps = [(e["store"], e["message"]) for e in out["errors"] if e["scope"] == "cap"]
    assert caps == [
        ("b", "namespaces capped at 1: not read"),
        ("c", "namespaces capped at 1: not read"),
    ]
    assert pbs._rotation == ("b", "")  # walked first next: the cap left it out
    # Value (row): protects=a datastore the namespace cap
    #   kept from being walked counts as unread, so every job list read is
    #   flagged 'partial:' (a namespace hidden there would hide its jobs);
    #   fails_when=only a failed or held listing counts and the cap's skip is
    #   taken for read (the server prunes jobs that still exist); why_new=
    #   mutant survived all 514 tests: no build cut by the namespace cap had
    #   its job-list flags checked; seam=none
    assert out["errors"][:3] == _unlisted_flags()


# Value: protects=a datastore a deeper ACL entry hides by REPLACING the
#   token's role with one lacking Datastore.Audit (PBS then no longer lists
#   it) makes the block partial with every job list flagged; fails_when=the
#   hidden check reads path presence alone (scope full: the server prunes a
#   datastore that still exists); why_new=reproduced live on PBS 4.2;
#   seam=none
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
    real_groups = pbs._read_groups
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

    def read_gc(session, target, errors, deadline, store, **kwargs):
        gc_order.append(store)
        return real(session, target, errors, deadline, store, **kwargs)

    monkeypatch.setattr(pbs, "_read_gc", read_gc)
    # The gc reads keep their own cursor.
    monkeypatch.setattr(pbs, "_read_groups", real_groups)
    monkeypatch.setattr(pbs, "_store_rotation", "b")
    collect(monkeypatch, _datastores_with(["a", "aa", "b"]))  # "aa" added
    assert gc_order == ["b", "a", "aa"]
    # Value (row): protects=a resume name gone and LAST in sort
    #   order wraps to the first on a build that reads everything (no cut);
    #   fails_when=_start_index drops its modulo (names[len]: IndexError, every
    #   build an http_error, the stale name never replaced); why_new=each wrap
    #   above had a cut, which never indexes past the end; seam=none
    del gc_order[:]
    monkeypatch.setattr(pbs, "_store_rotation", "zz")  # removed, sorted last
    out, _ = collect(monkeypatch, _datastores_with(["a", "aa", "b"]))
    assert gc_order == ["a", "aa", "b"]
    assert [d["store"] for d in out["datastores"]] == ["a", "aa", "b"]
    assert pbs._store_rotation == "a"


# Value: protects=a datastore audited at its own level WITHOUT propagation
#   keeps its own status as usage when the aggregate failed (the datastore
#   itself is audited) while the block reads partial; fails_when=the
#   non-propagated privilege is read as not audited (real usage dropped) or
#   as fully audited (scope full: its hidden namespaces pruned);
#   why_new=found live on PBS 4.2; seam=none
def test_a_non_propagated_datastore_audit_keeps_its_own_status(monkeypatch):
    perms = {**PERMS_FULL, "/datastore/ds": {"Datastore.Audit": False}}
    out, session = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/access/permissions": ok(perms),
                "/status/datastore-usage": fail(400, "unable to get fs info: EIO"),
                "/admin/datastore/ds/status": ok({"total": 9, "used": 4, "avail": 5}),
            }
        ),
    )
    assert out["scope"] == "partial"
    assert (out["datastores"][0]["total"], out["datastores"][0]["used"]) == (9, 4)
    assert "/admin/datastore/ds/status" in [route(u) for u in session.calls]


# Value: protects=the namespace cursor resumes by (store, ns) ACROSS
#   datastores, in the sorted unit list, with the walks starting at its
#   datastore; fails_when=the units are kept in walk order (the bisect then
#   lands on the wrong unit) or the walks start elsewhere; why_new=every
#   keyed rotation test used one datastore; seam=none
def test_the_namespace_rotation_resumes_by_name_across_datastores(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_groups
    read = []

    def slow(session, target, errors, deadline, store, ns, room):
        read.append((store, ns))
        rows = real(session, target, errors, deadline, store, ns, room)
        clock.now += 100  # one namespace per build
        return rows

    monkeypatch.setattr(pbs, "_read_groups", slow)
    monkeypatch.setattr(pbs, "_rotation", ("b", "x"))
    out, session = collect(monkeypatch, _two_datastores())
    walks = [route(u) for u in session.calls if route(u).endswith("/namespace")]
    assert walks == ["/admin/datastore/b/namespace", "/admin/datastore/a/namespace"]
    assert read == [("b", "x")]
    assert pbs._rotation == ("a", "")


# Value: protects=on a PBS too big for one build, every namespace's groups
#   are read within a few builds, the namespace walks starting where the
#   group reads stopped; fails_when=the walks start anywhere else: they
#   outpace the group reads, and the namespaces between the two are never
#   read (~15% at the caps, measured in review); why_new=no test ran a PBS
#   whose walks and group reads both need several builds; seam=none
# Value: protects=the rotation wastes no
#   build: 220 namespaces at ~17 group reads a build (the walks and the gc
#   reads take the rest) are all read in 13 builds, scope full, with no error
#   but the budget's and the no-wrap rule's skips and the unread-listing job
#   flags; fails_when=a build re-reads namespaces already read in this round
#   -- the no-wrap rule is pinned by
#   test_group_reads_never_wrap_into_the_datastore_they_resumed_in;
#   why_new=the 24-build bound let a rotation that re-reads namespaces
#   pass; seam=none
def test_every_namespace_is_read_when_walks_outpace_group_reads(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    # ~23 walks a build but ~17 namespaces of group reads.
    names = [f"s{i:02d}" for i in range(44)]
    spaces = ["", "n1", "n2", "n3", "n4"]
    responses = _datastores_with(names)
    for store in names:
        responses[f"/admin/datastore/{store}/namespace"] = ok(
            [{"ns": ns} for ns in spaces]
        )
        for ns in spaces[1:]:
            responses[f"/admin/datastore/{store}/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/{store}/snapshots?ns={ns}"] = ok([])
    handler = responses_handler(responses)

    def timed(url):
        clock.now += 0.2  # a busy PBS
        return handler(url)

    session = FakeSession(timed)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    read, messages = set(), set()
    for _ in range(13):  # 220 / ~17
        monkeypatch.setattr(pbs, "_cache", TTLCache())
        clock.now += pbs.PBS_CACHE_TTL
        out = pbs.pbs_metrics(**LOOPBACK)
        assert out["scope"] == "full"
        messages |= {e["message"] for e in out["errors"]}
        for d in out["datastores"]:
            if d["namespaces"] is not None:
                listed = {(d["store"], ns) for ns in d["namespaces"]}
                read |= listed - {(d["store"], ns) for ns in d["unread_namespaces"]}
    assert len(read) == len(names) * len(spaces)
    skips = (
        pbs._DEADLINE_MESSAGE,
        pbs._ROTATION_MESSAGE,
        "partial: " + pbs._UNLISTED_REASON,  # walks short of a full round
    )
    assert all(m.startswith(skips) for m in messages)


# Value: protects=when no namespace of a build could be walked and read (the
#   first walk failed slowly, the others did not fit), the next build walks
#   from the first one that did not fit; fails_when=a build with nothing to
#   read keeps the old position: the slow failing datastore is walked first
#   on every build, and the others never; seam=none
def test_a_build_with_no_namespace_read_still_moves_the_walks_on(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_namespaces

    def slow_failure(session, target, errors, deadline, store):
        if store == "a":
            clock.now = max(clock.now, pbs._walk_deadline(deadline) + 0.5)
            return None  # the listing failed, slowly
        return real(session, target, errors, deadline, store)

    monkeypatch.setattr(pbs, "_read_namespaces", slow_failure)
    out, _ = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    assert [d["namespaces"] for d in out["datastores"]] == [None, None, None]
    assert pbs._rotation == ("b", "")
    clock.now += 1000
    out, _ = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    assert [d["namespaces"] for d in out["datastores"]] == [None, [""], [""]]


def _spy_groups(monkeypatch):
    real = pbs._read_groups
    read = []

    def spy(session, target, errors, deadline, store, ns, room):
        read.append((store, ns))
        return real(session, target, errors, deadline, store, ns, room)

    monkeypatch.setattr(pbs, "_read_groups", spy)
    return read


# Value: protects=when the walks did not go round every datastore, the group
#   reads never wrap back into the earlier namespaces of the datastore they
#   resumed in (read the build before: listed unread now, with their cause)
#   and the next build starts where the walks stopped; fails_when=they wrap
#   -- a cut there brings the reads back to that datastore, and the ones
#   past the walks starve; why_new=the single cursor couples
#   the walks to the group cut; seam=none
def test_group_reads_never_wrap_into_the_datastore_they_resumed_in(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 2)  # b is not walked
    read = _spy_groups(monkeypatch)
    monkeypatch.setattr(pbs, "_rotation", ("a", "x"))
    out, _ = collect(monkeypatch, _two_datastores())
    assert read == [("a", "x")]
    a, b = out["datastores"]
    assert (a["namespaces"], a["unread_namespaces"]) == (["", "x"], [""])
    assert b["namespaces"] is None
    assert pbs._rotation == ("b", "")
    # Value (row): protects=the namespace listed unread for
    #   this rule names its cause in errors[], like every other skipped read;
    #   fails_when=it is listed unread silently; why_new=a review
    #   (maintainability); seam=none
    assert {
        "scope": "groups",
        "store": "a",
        "ns": None,
        "message": f"{pbs._ROTATION_MESSAGE} (1 namespace(s) not read)",
    } in out["errors"]
    # Value (row): protects=the group reads still go into the
    #   OTHER datastores walked after the store order wrapped (read now, not
    #   listed unread); fails_when=the no-wrap rule drops every unit before
    #   the cursor: a walked datastore ships unread with budget left;
    #   why_new=mutant survived: the row above walks one datastore; seam=none
    monkeypatch.setattr(pbs, "_rotation", ("c", ""))  # walks c, a; b not walked
    read.clear()
    out, _ = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    assert read == [("c", ""), ("a", "")]
    a, b, c = out["datastores"]
    assert (a["namespaces"], a["unread_namespaces"]) == ([""], [])
    assert b["namespaces"] is None
    assert pbs._rotation == ("b", "")


# Value: protects=a build whose budget ran out before any group read started
#   keeps the group cursor on the unit it was going to read first;
#   fails_when=the cursor moves past it (that unit then waits a whole
#   rotation, never read); why_new=_resume_index skipped a first item it
#   never started; seam=none
def test_a_group_read_never_started_keeps_the_cursor(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_namespaces

    def last_walk_spends_the_budget(session, target, errors, deadline, store):
        rows = real(session, target, errors, deadline, store)
        if store == "b":
            clock.now = max(clock.now, deadline)
        return rows

    monkeypatch.setattr(pbs, "_read_namespaces", last_walk_spends_the_budget)
    read = _spy_groups(monkeypatch)
    monkeypatch.setattr(pbs, "_rotation", ("a", "x"))
    out, _ = collect(monkeypatch, _two_datastores())
    assert read == []
    assert [d["namespaces"] for d in out["datastores"]] == [["", "x"], ["", "x"]]
    assert pbs._rotation == ("a", "x")


# Value: protects=when the FIRST group read of a build is cut inside it (here
#   the group cap trims it), the reads -- and the walks, which start where
#   they stand -- move past it; fails_when=a first cut keeps the cursor on it
#   (that namespace takes the whole group share on every build); why_new=
#   mutant survived all 506 tests: every cut test cut at an index past 0 or
#   used one datastore; seam=none
def test_a_first_group_read_cut_moves_the_reads_past_it(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_GROUPS", 1)
    groups = [
        {"backup-type": "vm", "backup-id": str(i), "last-backup": 1} for i in (1, 2)
    ]
    responses = _datastores_with(
        ["a", "b"], **{"/admin/datastore/a/groups": ok(groups)}
    )
    out, _ = collect(monkeypatch, responses)
    assert [d["unread_namespaces"] for d in out["datastores"]] == [[""], [""]]
    assert pbs._rotation == ("b", "")
    _, session = collect(monkeypatch, responses)
    walks = [route(u) for u in session.calls if route(u).endswith("/namespace")]
    assert walks == ["/admin/datastore/b/namespace", "/admin/datastore/a/namespace"]
    # Value (row): protects=a first unit cut inside with
    #   more units left among the datastores walked moves the cursor to the
    #   NEXT unit of theirs, read on the next build, even while a datastore
    #   past the walks waits; fails_when=past a first cut is always where the
    #   walks stopped: the rest of this datastore waits a whole round unread;
    #   why_new=mutant survived all 514 tests: the lone-unit test is the only
    #   first-unit cut with a datastore left unwalked; seam=none
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 2)  # a fills the cap: b waits
    monkeypatch.setattr(pbs, "_rotation", None)
    responses = _two_datastores(**{"/admin/datastore/a/groups": ok(groups)})
    collect(monkeypatch, responses)
    assert pbs._rotation == ("a", "x")
    read = _spy_groups(monkeypatch)
    collect(monkeypatch, responses)
    assert read == [("a", "x")]


# Value: protects=a namespace listed without its parent (a deeper ACL entry
#   hid the parent, which the permission map does not show: measured on PBS
#   4.2)
#   makes the block partial, and every job list not flagged yet gets its
#   'partial:' flag in the slot reserved ahead of the per-datastore errors,
#   so the error cap trims those instead; fails_when=the listing's gaps are
#   ignored (scope full: the server prunes the hidden namespace's groups and
#   the jobs defined there) or the flags are appended after the per-datastore
#   errors (the cap drops them); why_new=found by a red-team review and
#   reproduced live on PBS 4.2; seam=none
def test_a_namespace_listed_without_its_parent_reads_partial(monkeypatch):
    # Room for the three flags and the cap's own entry: the two gc failures
    # read before the flags are inserted are what the cap drops.
    monkeypatch.setattr(pbs, "MAX_ERRORS", 4)
    # A hidden remote flags the sync list on its own; the namespace flags
    # the two others.
    perms = {**PERMS_FULL, "/remote/offsite": {"Datastore.Audit": True}}
    out, _ = collect(
        monkeypatch,
        _two_datastores(
            ("", "a/b"),
            **{
                "/access/permissions": ok(perms),
                "/admin/datastore/a/gc": fail(500, "down"),
                "/admin/datastore/b/gc": fail(500, "down"),
            },
        ),
    )
    assert out["scope"] == "partial"
    assert [d["namespaces"] for d in out["datastores"]] == [["", "a/b"]] * 2
    flags = [(e["scope"], e["message"]) for e in out["errors"]]
    namespace = (
        "partial: a deeper ACL entry hides a namespace from the API token, so "
        "jobs defined there are not listed"
    )
    assert flags == [
        (
            "sync_jobs",
            "partial: a deeper ACL entry hides part of /remote from the API "
            "token, so sync jobs using it are not listed",
        ),
        ("verify_jobs", namespace),
        ("prune_jobs", namespace),
        ("cap", "errors capped at 4: 2 dropped"),
    ]
    # Value (row): protects=a late flag has the errors[] shape
    #   of every other entry; fails_when=its store or ns key is dropped;
    #   why_new=only (scope, message) was compared; seam=none
    assert [set(e) for e in out["errors"]] == [{"scope", "store", "ns", "message"}] * 4
    assert [(e["store"], e["ns"]) for e in out["errors"][1:3]] == [(None, None)] * 2
    # Value (row): protects=a listing whose every namespace has its parent
    #   leaves the scope full; fails_when=the parent is taken from the
    #   FIRST level (a/b/c's parent read as a); why_new=the row above has
    #   one level; seam=none
    for listed, scope in ((("a", "a/b", "a/b/c"), "full"), (("a", "a/b/c"), "partial")):
        responses = minimal_responses(
            **{_NS_PATH: ok([{"ns": ns} for ns in ("",) + listed])}
        )
        for ns in listed:
            responses[f"/admin/datastore/ds/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/ds/snapshots?ns={ns}"] = ok([])
        out, _ = collect(monkeypatch, responses)
        assert out["scope"] == scope
    # Value (row): protects=a namespace hidden in the FIRST
    #   datastore walked still reads partial, and the late flags go to every
    #   READ job list, sync included, never to a null one; fails_when=the flag
    #   is overwritten per datastore (last wins: scope full), sync is left out
    #   of the late flags, or a null list gets one; why_new=three mutants
    #   survived: both datastores hid the same namespace, sync was flagged
    #   early, no list was null; seam=none
    monkeypatch.setattr(pbs, "_rotation", ("a", ""))  # a, the hiding one, first
    out, _ = collect(
        monkeypatch,
        _two_datastores(
            ("", "a/b"),
            **{
                "/admin/datastore/b/namespace": ok([{"ns": ""}]),
                "/admin/verify": fail(500, "down"),
            },
        ),
    )
    assert out["scope"] == "partial"
    assert out["verify_jobs"] is None
    flags = [(e["scope"], e["message"]) for e in out["errors"]]
    assert flags == [
        ("verify_jobs", "HTTP 500: down"),
        ("sync_jobs", namespace),
        ("prune_jobs", namespace),
    ]
    # Value (row): protects=the parent check reads the WHOLE
    #   listing, also past the namespace cap (that datastore's set is then
    #   null, but the hidden namespace's jobs are not); fails_when=only the
    #   kept prefix is checked: scope full, no flags; why_new=mutant survived
    #   (testing review); seam=none
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 2)
    responses = minimal_responses(
        **{_NS_PATH: ok([{"ns": ns} for ns in ("", "a", "b/c")])}
    )
    responses["/admin/datastore/ds/groups?ns=a"] = ok([])
    responses["/admin/datastore/ds/snapshots?ns=a"] = ok([])
    out, _ = collect(monkeypatch, responses)
    assert out["datastores"][0]["namespaces"] is None
    assert out["scope"] == "partial"
    assert sorted(
        e["scope"] for e in out["errors"] if e["message"].startswith("partial:")
    ) == ["prune_jobs", "sync_jobs", "verify_jobs"]


# Value: protects=a build with no whole read timeout left for a walk sends
#   none, reads no group -- not even through the remembered listings, which
#   serve only while the walks are held -- and keeps the reads where they
#   stand (its gc reads go round as usual); fails_when=a walk not sent
#   counts as a cut (the reads crawl one datastore a build with nothing
#   read), or the remembered listings are read whenever no walk fits (their
#   namespaces then pass unread for authority: never listed and read in one
#   build); why_new=no walk-cut test had a build where no walk fitted at all;
#   seam=none
def test_a_build_with_no_room_for_any_walk_keeps_the_cursor(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    collect(monkeypatch, _datastores_with(["a", "b", "c"]))  # remembered
    real = pbs._read_backends

    def slow_preamble(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - pbs._READ_TIMEOUT + 1
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    monkeypatch.setattr(pbs, "_rotation", ("b", ""))
    read = _spy_groups(monkeypatch)
    out, session = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    assert not [u for u in session.calls if route(u).endswith("/namespace")]
    assert read == [] and out["groups"] == []
    assert [d["gc"] is not None for d in out["datastores"]] == [True] * 3
    assert pbs._rotation == ("b", "")


# Value: protects=when the walks stop before going round every datastore, a
#   resume datastore's last namespace that is cut inside on every build never
#   pins the reads: past it is where the walks stopped; fails_when=moving
#   past the only namespace of a build wraps back to it (the reads stay there
#   and every other datastore stays unknown for good: reproduced live);
#   why_new=every started-first-item test had more than one unit in its order
#   (red-team review); seam=none
def test_a_lone_unit_cut_inside_moves_on_to_where_the_walks_stopped(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 2)  # a fills the cap: b waits
    handler = responses_handler(_two_datastores())

    def timed(url):
        reply = handler(url)
        if route(url) == "/admin/datastore/a/groups?ns=x":
            clock.now += pbs.PBS_COLLECT_DEADLINE  # x's snapshots miss the budget
        return reply

    session = FakeSession(timed)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    monkeypatch.setattr(pbs, "_rotation", ("a", "x"))
    walked = []
    for _ in range(2):
        monkeypatch.setattr(pbs, "_cache", TTLCache())
        clock.now += pbs.PBS_CACHE_TTL
        sent = len(session.calls)
        pbs.pbs_metrics(**LOOPBACK)
        walked.append(_walked([route(u) for u in session.calls[sent:]]))
    assert walked == [["a"], ["b"]]


# Value: protects=a datastore's own status answering 0/0/0 (what PBS answers a
#   token without the privilege at the datastore level) ships its usage as
#   null, never 0, with a usage error naming it; fails_when=the fallback
#   trusts that shape (a false "0 bytes free"); why_new=a review
#   (security: a hidden level the permission map does not show); seam=none
def test_an_own_status_of_zeros_reads_unknown(monkeypatch):
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/status/datastore-usage": fail(500, "EIO"),
                "/admin/datastore/ds/status": ok({"total": 0, "used": 0, "avail": 0}),
            }
        ),
    )
    ds = out["datastores"][0]
    assert (ds["total"], ds["used"], ds["avail"]) == (None, None, None)
    zeros = [e for e in out["errors"] if e["scope"] == "usage" and e["store"] == "ds"]
    assert [e["message"][:20] for e in zeros] == ["PBS answered 0/0/0, "]
    # Value (row): protects=only all three at 0 is the
    #   no-privilege shape: a FULL datastore (avail 0) ships its numbers, with
    #   no usage error; fails_when=any single 0 reads unknown (the fallback
    #   hides exactly the datastore the operator most needs to see);
    #   why_new=mutant (all -> any) survived all 514 tests: the row above is
    #   all zeros; seam=none
    out, _ = collect(
        monkeypatch,
        minimal_responses(
            **{
                "/status/datastore-usage": fail(500, "EIO"),
                "/admin/datastore/ds/status": ok({"total": 9, "used": 9, "avail": 0}),
            }
        ),
    )
    ds = out["datastores"][0]
    assert (ds["total"], ds["used"], ds["avail"]) == (9, 9, 0)
    assert not [e for e in out["errors"] if e["scope"] == "usage" and e["store"]]


# Value: protects=a build that reads no namespace listing (here the walk hold
#   keeps them all back) flags every job list it read, so a namespace a deeper
#   ACL entry hides -- which only a listing shows -- never lets the server
#   prune its jobs; fails_when=the hidden-namespace verdict counts only the
#   listings read this build (reproduced live: scope full, no flag, while
#   the namespace was still hidden); why_new=found in QA on PBS 4.2;
#   seam=none
def test_a_build_that_reads_no_listing_keeps_the_job_lists_partial(monkeypatch):
    hidden = _two_datastores(
        ("", "x"),
        **{
            "/admin/datastore/a/namespace": ok([{"ns": ""}, {"ns": "x/sub"}]),
            "/admin/datastore/a/groups?ns=x/sub": ok([]),
            "/admin/datastore/a/snapshots?ns=x/sub": ok([]),
            "/admin/datastore/a/status": ok({"total": 9, "used": 4, "avail": 5}),
            "/admin/datastore/b/status": ok({"total": 9, "used": 4, "avail": 5}),
        },
    )
    out, _ = collect(monkeypatch, hidden)
    flags = [e for e in out["errors"] if e["message"].startswith("partial:")]
    assert out["scope"] == "partial" and len(flags) == 3
    failure = ("namespaces", "a", None, "armed by an earlier build")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    out, _ = collect(monkeypatch, hidden)
    assert out["walks_held"] is True
    assert out["errors"][1:4] == _unlisted_flags()  # after the held usage


# Value: protects=a datastore whose gc read is slow still has its namespaces
#   walked on every build -- the walks come before the gc reads -- and its
#   slow gc is still read on every build; fails_when=the gc reads come first
#   and use up the walk's time (that datastore never walked again: 0 of 96
#   builds measured before the walk-first rule); why_new=performance
#   review and red team; seam=none
# Value (row): protects=the same for a slow OWN STATUS (a
#   scoped token's usage, or the fallback when the aggregate failed);
#   fails_when=only the gc is kept after the walks; why_new=testing
#   specialist; seam=none
@pytest.mark.parametrize("slow", ["_read_gc", "_read_store_status"])
def test_a_slow_gc_never_takes_its_own_datastores_walk(monkeypatch, slow):
    clock = use_clock(monkeypatch, Clock())
    real = getattr(pbs, slow)

    def slow_read(session, target, errors, deadline, store, **kwargs):
        answer = real(session, target, errors, deadline, store, **kwargs)
        if store == "a":
            clock.now += pbs._READ_TIMEOUT + 0.5  # answered, past the cutoff
        return answer

    monkeypatch.setattr(pbs, slow, slow_read)
    names = ["a", "b", "c"]
    responses = _datastores_with(names, **{"/status/datastore-usage": fail(500, "EIO")})
    for store in names:
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
    walked, gc_read = [], []
    for _ in range(6):
        clock.now += pbs.PBS_CACHE_TTL
        out, _ = collect(monkeypatch, responses)
        walked.append("a" in [d["store"] for d in out["datastores"] if d["namespaces"]])
        a = out["datastores"][0]
        gc_read.append((a["gc"] if slow == "_read_gc" else a["total"]) is not None)
    assert all(walked)
    assert all(gc_read)  # the slow read itself is still read on every build


# Value: protects=a build with no budget left for a walk sends none and
#   leaves the reads where they stand; its gc cursor is kept when nothing
#   could be sent at the head, and moved past b once b's gc went out (it
#   had what was left: its timeout says nothing about the rest); fails_when=
#   a gc never sent moves the cursor (b skipped for a round), or one that
#   went out and timed out keeps it (the others' gcs wait behind it);
#   why_new=no build ran with less than a walk's time left; seam=none
@pytest.mark.parametrize(
    "left, gc_cursor", [(-1, "b"), (2, "c")], ids=["nothing_left", "a_sliver_left"]
)
def test_a_build_with_no_budget_left_keeps_the_cursors(monkeypatch, left, gc_cursor):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_backends

    def spent(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - left  # (almost) nothing left
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", spent)
    monkeypatch.setattr(pbs, "_store_rotation", "b")
    monkeypatch.setattr(pbs, "_rotation", ("b", ""))
    timeout = {"error": "timeout", "message": "t"}
    responses = _datastores_with(["a", "b", "c"], **{"/admin/datastore/b/gc": timeout})
    out, _ = collect(monkeypatch, responses)
    assert [d["namespaces"] for d in out["datastores"]] == [None] * 3
    assert (pbs._store_rotation, pbs._rotation) == (gc_cursor, ("b", ""))
    monkeypatch.setattr(pbs, "_read_backends", real)
    clock.now += pbs.PBS_CACHE_TTL
    _, session = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    walks = [route(u) for u in session.calls if route(u).endswith("/namespace")]
    assert walks == [f"/admin/datastore/{s}/namespace" for s in ("b", "c", "a")]


# Value: protects=on a PBS where no walk fits, a gc that never answers at the
#   head of the order does not keep every other datastore's gc unread: it is
#   backed off, and the builds in between read the others; fails_when=the gc read
#   has no backoff (it takes the per-datastore half again on every build and,
#   cut first with no room for a walk, keeps the cursor: no other gc is ever
#   read, reproduced live on PBS 4.2); why_new=coverage audit:
#   no test ran consecutive builds with no room for a walk; seam=none
def test_a_wedged_head_gc_on_a_slow_pbs_never_starves_the_other_gcs(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_backends

    def slow_preamble(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - pbs._READ_TIMEOUT + 1  # no walk fits
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    responses = _datastores_with(
        ["a", "b", "c"],
        **{"/admin/datastore/a/gc": {"error": "timeout", "message": "t"}},
    )
    pattern = ""
    for _ in range(8):
        clock.now += pbs.PBS_CACHE_TTL
        out, session = collect(monkeypatch, responses)
        tried = "/admin/datastore/a/gc" in [route(u) for u in session.calls]
        read = {d["store"] for d in out["datastores"] if d["gc"] is not None}
        pattern += "a" if tried else ("+" if read == {"b", "c"} else "-")
    # a: a's gc tried (and timed out again: b and c skipped that build);
    # +: b and c read. Retried two builds later, then four (the backoff
    # doubles): every other build reads the rest.
    assert pattern == "a+a+++a+"


# Value: protects=a build where one datastore's listing names a namespace
#   without its parent (a deeper ACL entry hides it) while another datastore's
#   listing was not read stays partial, and its job lists carry the hidden
#   reason; fails_when=the unread-listing verdict is checked first or replaces
#   the hidden one: scope full, and the server prunes the hidden namespace's
#   groups; why_new=mutant (unlisted checked before ns_hidden) survived all
#   514 tests: no build had both a hidden namespace and an unread listing;
#   seam=none
def test_a_hidden_namespace_outranks_an_unread_listing_in_one_build(monkeypatch):
    out, _ = collect(
        monkeypatch,
        _two_datastores(
            ("", "x"),
            **{
                "/admin/datastore/a/namespace": ok([{"ns": ""}, {"ns": "x/sub"}]),
                "/admin/datastore/a/groups?ns=x/sub": ok([]),
                "/admin/datastore/a/snapshots?ns=x/sub": ok([]),
                "/admin/datastore/b/namespace": fail(400, "offline"),
            },
        ),
    )
    assert out["datastores"][1]["namespaces"] is None  # b's listing: unread
    assert out["scope"] == "partial"
    message = "partial: " + pbs._HIDDEN_NAMESPACE_REASON
    assert out["errors"][:3] == [
        {"scope": scope, "store": None, "ns": None, "message": message}
        for scope in ("sync_jobs", "verify_jobs", "prune_jobs")
    ]


# Value: protects=a PBS with one datastore and only the root namespace, whose
#   group read outlasts the budget on every build, keeps collecting with the
#   reads on that one namespace; fails_when=past the only namespace of a build
#   that walked every datastore names a resume point that does not exist (a
#   TypeError in the resume bisect: every later build an http_error
#   envelope); why_new=mutant survived all 514 tests: every lone-unit test had
#   a datastore past the walks; seam=none
def test_a_lone_namespace_cut_on_every_build_keeps_the_pbs_collected(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    handler = responses_handler(minimal_responses())

    def timed(url):
        reply = handler(url)
        if route(url) == "/admin/datastore/ds/groups":
            clock.now += pbs.PBS_COLLECT_DEADLINE  # its snapshots miss the budget
        return reply

    session = FakeSession(timed)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    for _ in range(2):
        monkeypatch.setattr(pbs, "_cache", TTLCache())
        clock.now += pbs.PBS_CACHE_TTL
        out = pbs.pbs_metrics(**LOOPBACK)
        assert out["datastores"][0]["unread_namespaces"] == [""]
        assert pbs._rotation == ("ds", "")


# Value: protects=a datastore whose namespace walk is slow (answered just under
#   the hold) still has its gc read on every build: its own status and gc come
#   before its walk; fails_when=the walk is read first and pushes the gc past
#   the per-datastore half on every build (reproduced live: never read on a
#   remote PBS); why_new=performance review, reproduced on PBS 4.2;
#   seam=none
def test_a_slow_walk_never_takes_its_own_datastores_gc(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real_backends, real_walk = pbs._read_backends, pbs._read_namespaces

    def remote(*args):
        clock.now += 2  # a remote PBS: the reads before the datastores take time
        return real_backends(*args)

    def slow_walk(session, target, errors, deadline, store):
        rows = real_walk(session, target, errors, deadline, store)
        if store == "a":
            clock.now += 9.3  # answered, under the hold threshold
        return rows

    monkeypatch.setattr(pbs, "_read_backends", remote)
    monkeypatch.setattr(pbs, "_read_namespaces", slow_walk)
    gc_read = []
    for _ in range(4):
        clock.now += pbs.PBS_CACHE_TTL
        out, _ = collect(monkeypatch, _datastores_with(["a", "b"]))
        gc_read.append([d["gc"] is not None for d in out["datastores"]][0])
    assert gc_read == [True] * 4


# Value: protects=a reload never fails, and defers no walk and keeps the
#   reads where they stand when the hold names no datastore (armed by the
#   usage status) or nothing is held; one naming a datastore since removed
#   defers nothing that is listed; fails_when=reset_timeout_holds raises on
#   the agent's main loop (the agent restarts), or a gone name stays
#   deferred; why_new=red-team review; seam=none
def test_a_reload_keeps_the_cursor_when_the_hold_names_no_listed_datastore(
    monkeypatch,
):
    monkeypatch.setattr(pbs, "_rotation", ("b", ""))
    failure = ("usage", None, None, "armed by the usage status")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    pbs.reset_timeout_holds()  # nothing held: nothing to remember
    assert (pbs._deferred_walks, pbs._rotation) == (set(), ("b", ""))
    _, session = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    walks = [route(u) for u in session.calls if route(u).endswith("/namespace")]
    assert walks == [f"/admin/datastore/{s}/namespace" for s in ("b", "c", "a")]
    gone = ("namespaces", "zz", None, "armed by a datastore since removed")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, gone)
    pbs.reset_timeout_holds()
    _, session = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    walks = [route(u) for u in session.calls if route(u).endswith("/namespace")]
    assert walks == [f"/admin/datastore/{s}/namespace" for s in ("a", "b", "c")]
    assert pbs._deferred_walks == set()


# Value: protects=a second reload before the next build keeps the walk the
#   first one deferred, and where it put the reads; fails_when=a reload with
#   nothing held forgets the datastore the first one remembered, so it is
#   walked first and re-arms the hold before any other walk; why_new=coverage
#   audit: every reload test sent one SIGHUP (two land on two ticks when
#   proxmox-backup-proxy is still restarting in between, so the first tick's
#   build never reaches the datastores); seam=none
def test_a_second_reload_before_the_next_build_keeps_the_deferred_walk(monkeypatch):
    failure = ("namespaces", "b", None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    pbs.reset_timeout_holds()  # a second SIGHUP before the next build
    _, session = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    walks = [route(u) for u in session.calls if route(u).endswith("/namespace")]
    # b's walk deferred: the first reload's deferral survived the second.
    assert walks == [f"/admin/datastore/{s}/namespace" for s in ("c", "a")]


class _TimedSession:
    """A session whose requests take `latency(path)` seconds on the test clock;
    one slower than its read timeout (math.inf: never answers) waits that whole
    timeout and raises a read timeout, as on the wire."""

    def __init__(self, responses, clock, latency):
        self.handler = responses_handler(responses)
        self.clock = clock
        self.latency = latency
        self.calls = []
        self.timeouts = []

    def get(self, url, params=None, timeout=None, stream=None, allow_redirects=None):
        if params:
            url += "?" + urlencode(params)
        self.calls.append(url)
        self.timeouts.append(timeout)
        wait = self.latency(route(url))
        if wait > timeout[1]:
            self.clock.now += timeout[1]
            raise requests.exceptions.ReadTimeout("t")
        self.clock.now += wait
        return self.handler(url)

    def close(self):
        pass


def _install_timed(monkeypatch, responses, clock, latency):
    session = _TimedSession(responses, clock, latency)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    return session


def _timed_build(monkeypatch, clock, session, gap=None):
    """One rebuild, a TTL and a bit after the last -- or `gap` seconds after
    it (the build a reload triggers, on the next tick): (block, paths it
    sent). `session.started` is when the build began."""
    monkeypatch.setattr(pbs, "_cache", TTLCache())
    clock.now += pbs.PBS_CACHE_TTL + 20 if gap is None else gap
    session.started = clock.now
    sent = len(session.calls)
    out = pbs.pbs_metrics(**LOOPBACK)
    return out, [route(u) for u in session.calls[sent:]]


def _walked(paths):
    return [p.split("/")[3] for p in paths if p.endswith("/namespace")]


# Value: protects=a stuck gc that seldom heads the gc reads is backed off
#   after its first late timeout instead of being sent on every build;
#   fails_when=a timeout without its minimum wait leaves no trace (sent every
#   build: 12 sends in 60 builds instead of 6, each a PBS proxy thread it may
#   pin on a dead mount); why_new=security, performance and red-team review;
#   seam=none
def test_a_wedged_gc_kept_off_the_head_backs_off(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i:02d}" for i in range(40)]

    def latency(path):
        if path == "/admin/datastore/s36/gc":
            return math.inf
        if path.endswith("/groups"):
            return 4.0  # ~2 namespaces a build
        return 0.2

    session = _install_timed(monkeypatch, _datastores_with(names), clock, latency)
    sends = 0
    for _ in range(60):
        _, sent = _timed_build(monkeypatch, clock, session)
        sends += sent.count("/admin/datastore/s36/gc")
    assert sends <= 7, sends


# Value: protects=a deferred datastore since removed from PBS is dropped, and
#   a broken one still listed stays deferred; fails_when=the deferred set
#   keeps names PBS no longer lists (memory), or dropping them drops the
#   others; why_new=coverage audit: dropping the intersection with
#   the listing survived (a gone name was only ever alone); seam=none
def test_a_removed_datastore_never_releases_the_other_deferred_walk(monkeypatch):
    use_clock(monkeypatch, Clock())
    # Two reloads deferred b and zz; zz has since been removed from PBS.
    monkeypatch.setattr(pbs, "_deferred_walks", {"b", "zz"})
    timeout = {"error": "timeout", "message": "t"}
    responses = _datastores_with(
        ["a", "b"], **{"/admin/datastore/b/namespace": timeout}
    )
    out, session = collect(monkeypatch, responses)
    assert _walked([route(u) for u in session.calls]) == ["a"]
    assert out["walks_held"] is False and pbs._deferred_walks == {"b"}


# Value: protects=a head read that was sent and failed (an HTTP error, no
#   backoff) still counts as started, so the gc cursor moves past it;
#   fails_when=only a read that answered counts (a head status failing slowly
#   pins the gc cursor on it: the other datastores' gc never read on a slow
#   PBS); why_new=testing review; seam=none
def test_a_slow_failed_head_read_never_pins_the_gc_reads(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real_backends, real_status = pbs._read_backends, pbs._read_store_status

    def slow_preamble(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - pbs._READ_TIMEOUT + 1  # no walk fits
        return real_backends(*args)

    def slow_status(session, target, errors, deadline, store, **kwargs):
        row = real_status(session, target, errors, deadline, store, **kwargs)
        if store == "a":
            clock.now = max(clock.now, deadline + 0.1)  # failed just past the half
        return row

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    monkeypatch.setattr(pbs, "_read_store_status", slow_status)
    responses = _datastores_with(["a", "b", "c"])
    responses["/status/datastore-usage"] = fail(500, "EIO")
    responses["/admin/datastore/a/status"] = fail(500, "EIO")  # not pending
    for store in ("b", "c"):
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
    read = set()
    for _ in range(3):
        clock.now += pbs.PBS_CACHE_TTL
        out, _ = collect(monkeypatch, responses)
        read |= {d["store"] for d in out["datastores"] if d["gc"] is not None}
    assert read >= {"b", "c"}, read


# Value: protects=a deferred walk kept through a build whose usage status
#   timed out (the hold re-armed under 'usage', no walk sent) survives a
#   second reload; fails_when=reset_timeout_holds resets the deferral from
#   any hold (the usage hold names no datastore), or a held build drops it:
#   the broken one is walked first again; why_new=testing review; seam=none
# (Here the build each reload triggers walks every datastore not deferred, c
# and a, so it releases the usage status, which times out on the build after
# it.)
def test_a_usage_armed_hold_keeps_the_deferred_walk(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    timeout = {"error": "timeout", "message": "t"}
    responses = _datastores_with(
        ["a", "b", "c"], **{"/admin/datastore/b/namespace": timeout}
    )
    for store in ("a", "b", "c"):
        responses[f"/admin/datastore/{store}/status"] = ok({"total": 9})
    failure = ("namespaces", "b", None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    stuck_usage = {**responses, "/status/datastore-usage": timeout}
    clock.now += pbs.PBS_CACHE_TTL
    _, session = collect(monkeypatch, stuck_usage)  # usage kept back
    assert _walked([route(u) for u in session.calls]) == ["c", "a"]
    clock.now += pbs.PBS_CACHE_TTL
    out, session = collect(monkeypatch, stuck_usage)
    assert not _walked([route(u) for u in session.calls])
    assert out["walks_held"] is True and pbs._deferred_walks == {"b"}
    pbs.reset_timeout_holds()  # the hold now names the usage status
    clock.now += pbs.PBS_CACHE_TTL
    _, session = collect(monkeypatch, responses)
    assert _walked([route(u) for u in session.calls]) == ["c", "a"]


def _slow_deferred_pbs(monkeypatch, names, overrides=()):
    """A scoped token over `names` whose datastore a's walk hangs until
    repaired, and whose own status and gc are slow but answer (4s each); a
    slow preamble (2s). Builds until a's walk arms the hold: (clock, session,
    the repair switch)."""
    clock = use_clock(monkeypatch, Clock())
    responses = _datastores_with(names, **dict(overrides))
    responses["/access/permissions"] = ok(
        {f"/datastore/{n}": {"Datastore.Audit": True} for n in names}
    )
    for store in names:
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
    real_backends = pbs._read_backends

    def slow_preamble(*args):
        clock.now += 2.0
        return real_backends(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    broken = {"on": True}

    def latency(path):
        if path == "/admin/datastore/a/namespace":
            return math.inf if broken["on"] else 1.0
        if path in ("/admin/datastore/a/status", "/admin/datastore/a/gc"):
            return 4.0  # slow storage: answers, never times out
        return 1.0 if path.endswith("/namespace") else 0.1

    session = _install_timed(monkeypatch, responses, clock, latency)
    for _ in range(10):
        _timed_build(monkeypatch, clock, session)
        if pbs._WALK_HOLD in pbs._timeout_backoff:
            break
    assert pbs._timeout_backoff[pbs._WALK_HOLD][2][1] == "a"
    return clock, session, broken


# Value: protects=a datastore whose walk armed the hold, repaired and
#   reloaded after held builds, with slow own reads, never pins the builds:
#   walks go out again and it is walked again, the others too; fails_when=a
#   build that starts at a deferred datastore sends no walk and reads
#   nothing, and the next one starts there again (every namespace null until
#   a restart, further reloads included: performance review,
#   88/294 sweep runs); seam=none
def test_a_slow_deferred_datastore_never_pins_the_builds(monkeypatch):
    clock, session, broken = _slow_deferred_pbs(monkeypatch, ["a", "b"])
    _timed_build(monkeypatch, clock, session)  # held
    broken["on"] = False
    pbs.reset_timeout_holds()
    walked = []
    for _ in range(20):
        _, sent = _timed_build(monkeypatch, clock, session)
        walked += _walked(sent)
    assert "b" in walked and "a" in walked, walked


# Value: protects=a repaired deferred datastore with slow own reads is
#   walked again once the group reads reach it, with or without a datastore
#   whose listing PBS refuses; fails_when=a refused listing, or the walks
#   stopping at the deferred datastore on every build, keeps it deferred
#   (never walked again until a restart: performance review,
#   85/294 sweep runs); seam=none
@pytest.mark.parametrize("offline", [False, True], ids=["two", "third_offline"])
def test_a_slow_deferred_datastore_is_walked_again_after_a_round(monkeypatch, offline):
    names, overrides = ["a", "b"], {}
    if offline:
        names = ["a", "b", "c"]
        overrides = {"/admin/datastore/c/namespace": fail(400, "offline")}
    clock, session, broken = _slow_deferred_pbs(monkeypatch, names, overrides)
    broken["on"] = False
    pbs.reset_timeout_holds()  # right after the build that armed the hold
    walked = []
    for _ in range(20):
        _, sent = _timed_build(monkeypatch, clock, session)
        walked += _walked(sent)
    assert "a" in walked, walked


# Value: protects=after a reload, the deferred walk goes out again only once
#   every other namespace was read, also when another datastore's own status
#   hangs (each build then reads little); fails_when=the deferred datastore
#   is walked before the group reads reach it (b's walk re-arms the hold with
#   a's and c's namespaces unread since the reload); why_new=red team; seam=none
def test_a_hanging_own_status_never_lets_the_deferred_walk_out_early(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names, nss = ["a", "b", "c"], ["", "n0", "n1", "n2"]
    responses = _datastores_with(names)
    responses["/access/permissions"] = ok(
        {f"/datastore/{n}": {"Datastore.Audit": True} for n in names}
    )
    for store in names:
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": n} for n in nss])
        for ns in nss[1:]:
            responses[f"/admin/datastore/{store}/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/{store}/snapshots?ns={ns}"] = ok([])
    real_backends = pbs._read_backends

    def slow_preamble(*args):
        clock.now += 3.0
        return real_backends(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)

    def latency(path):
        if path in ("/admin/datastore/b/namespace", "/admin/datastore/c/status"):
            return math.inf  # b's storage is dead; c's own status hangs
        if path.endswith("/namespace"):
            return 3.0
        return 0.5 if "/groups" in path or "/snapshots" in path else 0.1

    session = _install_timed(monkeypatch, responses, clock, latency)
    for _ in range(10):
        _timed_build(monkeypatch, clock, session)
        if pbs._WALK_HOLD in pbs._timeout_backoff:
            break
    assert pbs._timeout_backoff[pbs._WALK_HOLD][2][1] == "b"
    _timed_build(monkeypatch, clock, session)  # held
    pbs.reset_timeout_holds()
    others = {(s, n) for s in ("a", "c") for n in nss}
    read = set()
    for _ in range(12):
        out, sent = _timed_build(monkeypatch, clock, session)
        if "/admin/datastore/b/namespace" in sent:
            break
        for datastore in out["datastores"]:
            unread = set(datastore["unread_namespaces"] or [])
            read |= {
                (datastore["store"], n)
                for n in datastore["namespaces"] or []
                if n not in unread
            }
    else:
        raise AssertionError("b never walked again")
    assert read >= others, sorted(others - read)


# Value: protects=a datastore at the group cursor whose walk fails slowly
#   (an HTTP error under the read timeout, so no hold) still has its gc read
#   on every build: the own status and gc reads come after the walks and
#   keep half of what they leave; fails_when=the walk's time is taken from
#   the gc share (the earlier walk-first state starved it for
#   good); seam=none
def test_a_walk_failing_slowly_at_the_group_cursor_never_starves_its_gc(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    monkeypatch.setattr(pbs, "_rotation", ("a", "x"))  # cut inside a before
    responses = _datastores_with(
        ["a"], **{"/admin/datastore/a/namespace": fail(500, "EIO")}
    )

    def latency(path):
        return 9.9 if path == "/admin/datastore/a/namespace" else 0.1

    session = _install_timed(monkeypatch, responses, clock, latency)
    gcs = []
    for _ in range(4):
        out, sent = _timed_build(monkeypatch, clock, session)
        gcs.append(out["datastores"][0]["gc"] is not None)
    assert gcs == [True] * 4


# Value: protects=on a PBS whose datastores hold the root namespace only,
#   whose walks take most of their read timeout and whose lone namespace's
#   group read never ends in time, every gc is still read; fails_when=the gc
#   reads lose their share to the walks or to a namespace cut on every build
#   (the earlier walk-first state skipped every gc, for every datastore);
#   why_new=red team; seam=none
@pytest.mark.parametrize("names", [["a"], ["a", "b", "c"]], ids=["one", "three"])
def test_a_lone_unit_cut_on_every_build_never_starves_the_gcs(monkeypatch, names):
    clock = use_clock(monkeypatch, Clock())

    def latency(path):
        if path.endswith("/namespace"):
            return 9.9
        if "/groups" in path or "/snapshots" in path:
            return 5.0  # the lone unit never ends in time
        return 0.1

    session = _install_timed(monkeypatch, _datastores_with(names), clock, latency)
    gcs = dict.fromkeys(names, 0)
    for _ in range(3 * len(names) + 3):
        out, _ = _timed_build(monkeypatch, clock, session)
        for datastore in out["datastores"]:
            gcs[datastore["store"]] += datastore["gc"] is not None
    assert min(gcs.values()) >= 2, gcs


# Value: protects=on a PBS whose datastores all have slow walks, every
#   datastore's gc is still read; fails_when=the walks take the gc share (no
#   gc read at all, reproduced live with two datastores); why_new=performance review; seam=none
def test_slow_walks_on_every_datastore_never_starve_the_gc(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_backends

    def slow_preamble(*args):
        clock.now += 4.0
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    names = ["a", "b", "c"]

    def latency(path):
        return 8.5 if path.endswith("/namespace") else 0.1

    session = _install_timed(monkeypatch, _datastores_with(names), clock, latency)
    for _ in range(3):
        _timed_build(monkeypatch, clock, session)
    read = set()
    for _ in range(6):
        out, _ = _timed_build(monkeypatch, clock, session)
        read |= {d["store"] for d in out["datastores"] if d["gc"] is not None}
    assert read == set(names), read


# Value: protects=a datastore whose own status hangs (a dead mount, scoped
#   token) never keeps the other datastore's namespaces unread for long: they
#   are listed and read in the same build at least every 12 builds;
#   fails_when=the hanging status pins the reads on its datastore (until the
#   status backoff expires: up to 6h, re-armed each time); why_new=red team; seam=none
def test_a_held_head_status_never_pins_the_reads(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b"]
    responses = _datastores_with(names)
    responses["/access/permissions"] = ok(
        {f"/datastore/{n}": {"Datastore.Audit": True} for n in names}
    )
    nss = [""] + [f"n{i}" for i in range(5)]
    for store in names:
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": n} for n in nss])
        for ns in nss[1:]:
            responses[f"/admin/datastore/{store}/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/{store}/snapshots?ns={ns}"] = ok([])
    real_backends = pbs._read_backends

    def slow_preamble(*args):
        clock.now += 6.0
        return real_backends(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)

    def latency(path):
        if path == "/admin/datastore/a/status":
            return math.inf  # a dead mount: never answers
        if path.endswith("/namespace"):
            return 8.0
        if "/groups" in path or "/snapshots" in path:
            return 1.0
        return 0.1

    session = _install_timed(monkeypatch, responses, clock, latency)
    last_b, worst = {}, 0
    for build in range(60):
        out, _ = _timed_build(monkeypatch, clock, session)
        for d in out["datastores"]:
            if d["store"] == "b" and d["namespaces"] is not None:
                for ns in d["namespaces"]:
                    if ns not in (d["unread_namespaces"] or []):
                        last_b[ns] = build
        if build >= 20:
            worst = max(worst, max(build - last_b.get(ns, -1) for ns in nss))
    assert worst <= 12, worst


# Value: protects=a datastore whose listing comes back empty (a
#   namespace-scoped token whose namespace was deleted) after a build that
#   cut its group reads still has its gc read; fails_when=a build with
#   nothing to read keeps the reads on that datastore and its slow empty
#   listing takes the gc share (0 gc reads in 6 builds, maintainability review); seam=none
def test_an_empty_listing_cut_by_its_gc_does_not_starve_the_gc(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    state = {"phase": 1}
    responses = _datastores_with(["ds"])
    responses["/admin/datastore/ds/namespace"] = ok([{"ns": "x"}, {"ns": "y"}])
    for ns in ("x", "y"):
        responses[f"/admin/datastore/ds/groups?ns={ns}"] = ok([])
        responses[f"/admin/datastore/ds/snapshots?ns={ns}"] = ok([])

    def latency(path):
        if path == "/admin/datastore/ds/namespace":
            return 9.9 if state["phase"] == 2 else 0.1
        if "/groups" in path or "/snapshots" in path:
            return 9.0 if state["phase"] == 1 else 0.05
        return 0.1

    session = _install_timed(monkeypatch, responses, clock, latency)
    _timed_build(monkeypatch, clock, session)  # group reads cut inside ds
    state["phase"] = 2
    responses["/admin/datastore/ds/namespace"] = ok([])  # the namespace deleted
    gcs = []
    for _ in range(6):
        out, _ = _timed_build(monkeypatch, clock, session)
        gcs.append(out["datastores"][0]["gc"] is not None)
    assert any(gcs), gcs


# Value: protects=on a PBS with one datastore whose walk takes most of its
#   read timeout, a gc that answers within half of what the walk leaves is
#   read on every build; one that takes longer is the documented limit (it
#   times out, and its backoff keeps it unread for a while); fails_when=the
#   walk's time comes out of the gc share; why_new=red team
#   (the walk-first state starved it); seam=none
@pytest.mark.parametrize("gc_seconds, read", [(4.5, True), (5.5, False)])
def test_a_lone_datastore_with_a_slow_walk_reads_a_gc_within_its_share(
    monkeypatch, gc_seconds, read
):
    clock = use_clock(monkeypatch, Clock())

    def latency(path):
        if path == "/admin/datastore/ds/namespace":
            return 9.9
        return gc_seconds if path == "/admin/datastore/ds/gc" else 0.1

    responses = _datastores_with(["ds"])
    session = _install_timed(monkeypatch, responses, clock, latency)
    out, sent = _timed_build(monkeypatch, clock, session)
    assert _walked(sent) == ["ds"]
    assert (out["datastores"][0]["gc"] is not None) is read
    assert out["datastores"][0]["unread_namespaces"] == []


# Value: protects=a read noted after a late timeout gets its 5s minimum wait
#   next time, and an answer that comes within that wait -- past the
#   per-datastore half -- is read and clears the note; fails_when=the answer
#   is dropped as past the budget (the wait was for nothing: a gc that always
#   answers in 4.9s with 4s of the half left is never read, and its note never
#   cleared); why_new=red team; seam=none
def test_an_answer_within_the_granted_wait_is_read(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_backends

    def slow_preamble(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - 9  # 4.5s of the half left
        return real(*args)

    def latency(path):
        return 4.9 if path == "/admin/datastore/b/gc" else 0.1

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    session = _install_timed(monkeypatch, _datastores_with(["a", "b"]), clock, latency)
    key = pbs._timeout_backoff_key("/admin/datastore/b/gc", None)
    out, _ = _timed_build(monkeypatch, clock, session)
    assert out["datastores"][1]["gc"] is None
    assert pbs._timeout_backoff[key][1] == 0  # noted, not backed off
    monkeypatch.setattr(pbs, "_store_rotation", None)  # b past the head again
    out, sent = _timed_build(monkeypatch, clock, session)
    assert "/admin/datastore/b/gc" in sent
    assert out["datastores"][1]["gc"] is not None
    assert key not in pbs._timeout_backoff


# Value: protects=an HTTP error answered past the budget but within the
#   minimum wait the read was granted keeps its body in the errors[] message;
#   fails_when=the error body is still clamped to the budget (the detail is
#   dropped: 'HTTP 500: ' instead of 'HTTP 500: EIO'); why_new=testing review,
#   that mutant survived every test; seam=none
def test_an_error_answered_within_the_granted_wait_keeps_its_detail(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    path = "/admin/datastore/ds/snapshots"
    handler = responses_handler(minimal_responses(**{path: fail(500, "EIO")}))

    def answers_in_two_seconds(url):
        clock.now += 2  # past the 1s budget, inside the 5s wait it was granted
        return handler(url)

    session = FakeSession(answers_in_two_seconds)
    target = _target()
    errors = pbs._Errors(target.redact)
    read = pbs._sub_read(
        session, target, errors, clock.now + 1, "snapshots", path, backoff="retry"
    )
    assert read is None
    assert [e["message"] for e in errors] == ["HTTP 500: EIO"]


# Value: protects=one build whose group reads are cut never keeps a lone
#   datastore whose walk takes most of its read timeout from having its gc
#   read again; fails_when=the cut makes the next walks take the gc share (0
#   gc reads in 10 builds, reproduced live);
#   why_new=red team; seam=none
def test_one_cut_group_read_does_not_starve_a_lone_datastores_gc(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    slow = {"on": False}

    def latency(path):
        if path == "/admin/datastore/ds/namespace":
            return 9.9
        if "/groups" in path or "/snapshots" in path:
            return 9.0 if slow["on"] else 0.05
        return 0.1

    session = _install_timed(monkeypatch, _datastores_with(["ds"]), clock, latency)
    out, _ = _timed_build(monkeypatch, clock, session)
    assert out["datastores"][0]["gc"] is not None
    slow["on"] = True
    _timed_build(monkeypatch, clock, session)  # the group reads are cut once
    slow["on"] = False
    gcs = []
    for _ in range(10):
        out, _ = _timed_build(monkeypatch, clock, session)
        gcs.append(out["datastores"][0]["gc"] is not None)
    assert any(gcs), gcs


# Value: protects=a datastore repaired before the reload is walked again when
#   the walks of the builds after the reload stop short of going round every
#   datastore; fails_when=only a build whose group reads pass its datastore
#   releases it (it has no namespace to read, so the reads never pass it:
#   never walked again until a restart, reproduced live on PBS 4.2); why_new=performance review; seam=none
def test_a_repaired_deferred_datastore_is_walked_again_on_a_slow_pbs(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i:02d}" for i in range(7)]
    broken = {"s01"}

    def latency(path):
        if path == "/admin/datastore/s01/namespace" and broken:
            return math.inf
        if path.endswith("/namespace"):
            return 1.5
        if path.endswith(("/groups", "/snapshots")):
            return 0.05
        return 0.6

    session = _install_timed(monkeypatch, _datastores_with(names), clock, latency)
    for _ in range(50):
        _timed_build(monkeypatch, clock, session)
        if pbs._WALK_HOLD in pbs._timeout_backoff:
            break
    assert pbs._timeout_backoff[pbs._WALK_HOLD][2][1] == "s01"
    broken.clear()  # repaired, proxy restarted
    pbs.reset_timeout_holds()  # SIGHUP
    walked = []
    for _ in range(20):  # a healthy round takes 2 builds here
        _, sent = _timed_build(monkeypatch, clock, session)
        walked += _walked(sent)
    assert "s01" in walked


# Value: protects=reloads that defer nothing new (SIGHUP is the agent's
#   general capability refresh, sent by tooling) never keep a repaired
#   datastore deferred; fails_when=every reload puts the reads back past it
#   (with a SIGHUP every 3 builds the repaired datastore stays deferred for
#   good: 258 of 360 red-team runs); why_new=red team; seam=none
@pytest.mark.parametrize("every", [3, 1000])
def test_unrelated_reloads_do_not_keep_a_repaired_walk_deferred(monkeypatch, every):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i:02d}" for i in range(31)]
    broken = {"on": True}

    def latency(path):
        if path == "/admin/datastore/s15/namespace" and broken["on"]:
            return math.inf
        return 1.5 if path.endswith("/namespace") else 0.3

    session = _install_timed(monkeypatch, _datastores_with(names), clock, latency)
    for _ in range(100):
        _timed_build(monkeypatch, clock, session)
        if pbs._WALK_HOLD in pbs._timeout_backoff:
            break
    assert pbs._timeout_backoff[pbs._WALK_HOLD][2][1] == "s15"
    broken["on"] = False
    walked = []
    for i in range(60):
        if i % every == 0:
            pbs.reset_timeout_holds()
        _, sent = _timed_build(monkeypatch, clock, session)
        walked += _walked(sent)
        if "s15" in walked:
            break
    assert "s15" in walked


# Value: protects=a clamped own status or gc read past the head that timed out
#   is re-sent on the next build WITH the 5s minimum wait (so a stuck one arms
#   its backoff); fails_when=the note is skipped for one of the two reads, or
#   backs the read off (a stuck status kept off the head is re-sent clamped on
#   every build; a slow-but-alive one is blinded); why_new=only the gc variant
#   was pinned, and only by a send count; seam=none
@pytest.mark.parametrize("leaf", ["status", "gc"])
def test_a_late_clamped_timeout_gets_the_wait_next_time(monkeypatch, leaf):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_backends

    def slow_preamble(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - 9  # 4.5s of the half left
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    path = f"/admin/datastore/b/{leaf}"
    responses = _datastores_with(["a", "b"])
    responses["/status/datastore-usage"] = fail(500, "EIO")  # own status read
    for store in ("a", "b"):
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
    responses[path] = {"error": "timeout", "message": "t"}
    _, session = collect(monkeypatch, responses)
    first = dict(zip((route(u) for u in session.calls), session.timeouts))
    assert first[path][1] < pbs._TIMEOUT_BACKOFF_MIN_WAIT  # clamped, late
    monkeypatch.setattr(pbs, "_store_rotation", None)
    clock.now += pbs.PBS_CACHE_TTL
    _, session = collect(monkeypatch, responses)
    second = dict(zip((route(u) for u in session.calls), session.timeouts))
    assert second[path][1] == pbs._TIMEOUT_BACKOFF_MIN_WAIT  # due, with the wait


# Value: protects=a head whose own status backoff has EXPIRED (sent again this
#   build) and now fails slowly still counts as started, so the gc cursor
#   moves past it; fails_when=any backoff entry present counts as held (the gc
#   cursor pins on the head for good, the other datastores' gc never read);
#   why_new=the slow-failed-head test had no prior entry; seam=none
def test_an_expired_head_status_backoff_never_pins_the_gc_reads(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real_backends, real_status = pbs._read_backends, pbs._read_store_status

    def slow_preamble(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - pbs._READ_TIMEOUT + 1  # no walk fits
        return real_backends(*args)

    def slow_status(session, target, errors, deadline, store, **kwargs):
        row = real_status(session, target, errors, deadline, store, **kwargs)
        if store == "a":
            clock.now = max(clock.now, deadline + 0.1)  # failed just past the half
        return row

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    monkeypatch.setattr(pbs, "_read_store_status", slow_status)
    responses = _datastores_with(["a", "b", "c"])
    responses["/status/datastore-usage"] = fail(500, "EIO")
    responses["/admin/datastore/a/status"] = fail(500, "EIO")
    for store in ("b", "c"):
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
    key = pbs._timeout_backoff_key("/admin/datastore/a/status", None)
    # An earlier timeout's backoff, expired: due again.
    pbs._timeout_backoff[key] = (clock.now - 1, 1, ("usage", "a", None, "t"))
    read = set()
    for _ in range(3):
        clock.now += pbs.PBS_CACHE_TTL
        out, _ = collect(monkeypatch, responses)
        read |= {d["store"] for d in out["datastores"] if d["gc"] is not None}
    assert read >= {"b", "c"}, read


# Value: protects=the local nodes a build carries are the LAST learning
#   build's only; fails_when=the carried set accumulates every node ever
#   learned from this PBS (a node seen once counts as local for the life of
#   the agent, and the carried set outgrows _MAX_LOCAL_NODES); why_new=the
#   bound test's value card claims this but checks only learning builds;
#   seam=none
def test_the_carried_local_nodes_are_the_last_learned_only(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    copied = {"state": "ok", "upid": "UPID:src:1:2:3:0000000A:verify:ds:root@pam:"}
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/snapshots": ok(
                [snapshot("vm", "100", 200, verification=copied)]
            )
        }
    )
    seen = []
    for gc in (
        ok({"upid": GC_UPID.replace("UPID:n:", "UPID:src:")}),
        ok({"upid": GC_UPID}),
        fail(500, "EIO"),  # learns no node: the last build's stand
    ):
        responses["/admin/datastore/ds/gc"] = gc
        clock.now += pbs.PBS_CACHE_TTL
        out, _ = collect(monkeypatch, responses)
        seen += [g["verify_state"] for g in out["groups"]]
    assert seen == ["ok", None, None], seen
    assert pbs._local_nodes == {"n"}


# Value: protects=a suspect note is due at once with zero timeouts (its first
#   real timeout backs off one rebuild, as the contract says) and stays inside
#   the table cap; fails_when=the note counts as a timeout (first backoff
#   1200s), backs the read off, or grows the table past
#   _TIMEOUT_BACKOFF_ENTRIES; why_new=only _arm_timeout_backoff's cap and
#   ladder were pinned; seam=none
def test_a_suspect_note_is_due_at_once_uncounted_and_capped(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    key, late = ("/admin/datastore/b/gc", ()), ("gc", "b", None, "t")
    pbs._suspect_timeout(key, late)
    assert pbs._timeout_backoff[key] == (clock.now, 0, late)
    pbs._arm_timeout_backoff(key, late, hold=False)
    assert pbs._timeout_backoff[key][:2] == (clock.now + 2 * pbs.PBS_CACHE_TTL, 1)
    pbs._timeout_backoff.clear()
    monkeypatch.setattr(pbs, "_TIMEOUT_BACKOFF_ENTRIES", 3)
    held = ("namespaces", "ds", None, "t")
    keys = [pbs._WALK_HOLD] + [(f"/p{i}", ()) for i in range(1, 4)]
    pbs._arm_timeout_backoff(keys[0], held, hold=True)
    pbs._arm_timeout_backoff(keys[1], late, hold=False)
    pbs._arm_timeout_backoff(keys[2], late, hold=False)
    pbs._suspect_timeout(keys[3], late)
    assert list(pbs._timeout_backoff) == [keys[0], keys[2], keys[3]]
    # The hold alone at the cap (the table cleared by a SIGHUP meanwhile, or
    # a cap of one) is never the entry dropped.
    pbs._timeout_backoff.clear()
    monkeypatch.setattr(pbs, "_TIMEOUT_BACKOFF_ENTRIES", 1)
    pbs._arm_timeout_backoff(keys[0], held, hold=True)
    pbs._suspect_timeout(keys[1], late)
    assert list(pbs._timeout_backoff) == [keys[0], keys[1]]


# Value: protects=on a PBS where no walk fits, a head datastore whose own
#   status answers just past the per-datastore half never pins the gc reads
#   to it; fails_when=a head cut with no room counts as never started (the
#   cursor stays: every later build reads that head only, the others' usage
#   and gc null for good); why_new=maintainability review; seam=none
def test_a_slow_head_own_status_on_a_slow_pbs_never_pins_the_reads(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real_backends, real_status = pbs._read_backends, pbs._read_store_status

    def slow_preamble(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - pbs._READ_TIMEOUT + 1  # no walk fits
        return real_backends(*args)

    def slow_status(session, target, errors, deadline, store, **kwargs):
        row = real_status(session, target, errors, deadline, store, **kwargs)
        clock.now = max(clock.now, deadline + 0.1)  # answered just past the half
        return row

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    monkeypatch.setattr(pbs, "_read_store_status", slow_status)
    responses = _datastores_with(["a", "b", "c"])
    responses["/status/datastore-usage"] = fail(500, "EIO")  # own-status fallback
    for store in ("a", "b", "c"):
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
    read = set()
    for _ in range(4):
        clock.now += pbs.PBS_CACHE_TTL
        out, _ = collect(monkeypatch, responses)
        read |= {d["store"] for d in out["datastores"] if d["total"] is not None}
    assert read == {"a", "b", "c"}


# Value: protects=a datastore whose gc answers just past the walk cutoff,
#   on a PBS that has room for a walk only one build in three, never keeps
#   every namespace unlisted; fails_when=the gc reads take the time the
#   walks need (no namespace listed in 12 builds, measured by the red team);
#   why_new=red-team review; seam=none
def test_a_slow_gc_at_the_head_never_takes_every_walk(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    build = [0]

    def latency(path):
        if path == "/admin/verify" and build[0] % 3 != 2:
            return 9.5  # no room for a walk 2 builds in 3
        if path == "/admin/datastore/b/gc":
            return 9.0  # past the walk cutoff, inside a room build's half
        return 0.2

    session = _install_timed(
        monkeypatch, _datastores_with(["a", "b", "c"]), clock, latency
    )
    listed = 0
    for build[0] in range(12):
        out, _ = _timed_build(monkeypatch, clock, session)
        listed += sum(1 for d in out["datastores"] if d["namespaces"])
    assert listed > 0


# Value: protects=after a reload with the broken datastore still broken,
#   the other datastores' groups are read before its walk can time out
#   again; fails_when=its walk is sent in the reload build (last of the
#   datastore reads, still ahead of every group read: 1 of 19 datastores
#   read, measured by the red team); why_new=red-team review; seam=none
def test_the_reload_build_reads_the_others_before_the_broken_walk(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i:02d}" for i in range(20)]
    responses = _datastores_with(names)
    group = {"backup-type": "vm", "backup-id": "1", "backup-count": 1}
    for name in names:
        responses[f"/admin/datastore/{name}/groups"] = ok(
            [dict(group, **{"last-backup": 5})]
        )
    session = _install_timed(
        monkeypatch,
        responses,
        clock,
        lambda path: math.inf if path == "/admin/datastore/s10/namespace" else 0.2,
    )
    failure = ("namespaces", "s10", None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()  # s10 still broken
    out, sent = _timed_build(monkeypatch, clock, session)
    assert "/admin/datastore/s10/namespace" not in sent
    read = [
        d["store"]
        for d in out["datastores"]
        if d["namespaces"] and not d["unread_namespaces"]
    ]
    assert len(read) >= 10, read


# Value: protects=a gc that never answers (a dead mount: each send may pin a
#   PBS proxy thread) stays on its doubling backoff even when reached late in
#   the per-datastore half; fails_when=a late RETRY is clamped AND left
#   unarmed (10 sends in 60 builds instead of 7, red team); why_new=red-team
#   review of the clamp fix; seam=none
def test_a_wedged_gc_read_late_in_the_half_stays_backed_off(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i:02d}" for i in range(20)]
    session = _install_timed(
        monkeypatch,
        _datastores_with(names),
        clock,
        lambda path: math.inf if path == "/admin/datastore/s15/gc" else 0.2,
    )
    sends = 0
    for _ in range(60):
        _, sent = _timed_build(monkeypatch, clock, session)
        sends += sent.count("/admin/datastore/s15/gc")
    assert sends <= 8, sends


# Value: protects=a gc read sent late in the per-datastore half is clamped to
#   what is left of it, not given the 5s minimum wait; fails_when=every gc
#   read gets the minimum wait (the last one overruns the half by up to 5s,
#   taken from the group reads, and a slow but answering gc arms a backoff:
#   gc gaps up to 269 builds, measured); why_new=performance review; seam=none
def test_a_gc_read_late_in_the_phase_does_not_overrun_it(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_gc

    def slow_gc(session, target, errors, deadline, store, **kwargs):
        gc = real(session, target, errors, deadline, store, **kwargs)
        if store == "a":
            clock.now = deadline - 1  # a's gc answered with 1s of the half left
        return gc

    monkeypatch.setattr(pbs, "_read_gc", slow_gc)
    _, session = collect(monkeypatch, _datastores_with(["a", "b"]))
    timeouts = dict(zip((route(u) for u in session.calls), session.timeouts))
    assert timeouts["/admin/datastore/b/gc"][1] <= 1


# Value: protects=a datastore's own status read gets the 5s minimum wait as
#   the build's head read only: past the head, one sent with less than 5s of
#   the per-datastore half left is clamped to the half, like the gc read;
#   fails_when=own status reads get the minimum wait wherever they stand (each
#   one late in the half overruns it by up to 5s, taken from the group reads)
#   or the head's does not (on a PBS with no room for a walk, a timed-out
#   head status arms no backoff and is sent again); why_new=coverage audit:
#   only the gc read's wait was tested; seam=none
def test_an_own_status_read_waits_past_the_half_only_at_the_head(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_backends

    def slow_preamble(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - 9  # 4.5s of the half left
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    responses = _datastores_with(["a", "b"])
    responses["/status/datastore-usage"] = fail(500, "EIO")  # own status read
    for store in ("a", "b"):
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
    _, session = collect(monkeypatch, responses)
    timeouts = dict(zip((route(u) for u in session.calls), session.timeouts))
    assert timeouts["/admin/datastore/a/status"] == (2.5, 5)  # the head: 5s
    assert timeouts["/admin/datastore/b/status"] == (4.5, 4.5)
    assert timeouts["/admin/datastore/b/gc"] == (4.5, 4.5)


# Value: protects=an own status or gc read past the head that times out with
#   5s or more of its half left arms its backoff at once; fails_when=only the
#   head's read or a retried one arms (a wedged read past the head is sent
#   again by the very next build -- each send on a dead mount may pin one
#   more PBS proxy thread); why_new=coverage audit: every backoff test timed
#   out the head's read; seam=none
@pytest.mark.parametrize("leaf, scope", [("status", "usage"), ("gc", "gc")])
def test_a_read_past_the_head_timing_out_early_in_the_half_backs_off(
    monkeypatch, leaf, scope
):
    clock = use_clock(monkeypatch, Clock())
    path = f"/admin/datastore/b/{leaf}"
    responses = _datastores_with(
        ["a", "b"], **{path: {"error": "timeout", "message": "t"}}
    )
    responses["/status/datastore-usage"] = fail(500, "EIO")  # own status read
    for store in ("a", "b"):
        responses.setdefault(
            f"/admin/datastore/{store}/status", ok({"total": 9, "used": 4, "avail": 5})
        )
    _, session = collect(monkeypatch, responses)
    assert path in [route(u) for u in session.calls]  # sent past the head
    clock.now += pbs.PBS_CACHE_TTL
    out, session = collect(monkeypatch, responses)
    assert path not in [route(u) for u in session.calls]
    skipped = [e for e in out["errors"] if e["message"] == pbs._TIMEOUT_BACKOFF_MESSAGE]
    assert [(e["scope"], e["store"]) for e in skipped] == [(scope, "b")]


# Value: protects=a build that fails before its datastore reads keeps the
#   nodes the last build learned; fails_when=the carried nodes are cleared at
#   the start of every build (a transient 503 on /access/permissions makes a
#   copied verification read 'ok' for the rest of the gc backoff, up to 6h);
#   why_new=coverage audit, red before the fix; seam=none
def test_a_failed_build_keeps_the_local_nodes_it_was_carrying(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    copied = {"state": "ok", "upid": "UPID:src:1:2:3:0000000A:verify:ds:root@pam:"}
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/snapshots": ok(
                [snapshot("vm", "100", 200, verification=copied)]
            )
        }
    )
    seen = []
    for gc, permissions in (
        (ok({"upid": GC_UPID}), ok(PERMS_FULL)),
        ({"error": "timeout", "message": "t"}, ok(PERMS_FULL)),
        (None, fail(503, "proxy restarting")),
        (None, ok(PERMS_FULL)),
    ):
        if gc is not None:
            responses["/admin/datastore/ds/gc"] = gc
        responses["/access/permissions"] = permissions
        clock.now += 60
        out, _ = collect(monkeypatch, responses)
        seen.append(out.get("error_type") or [g["verify_state"] for g in out["groups"]])
    # Build 2 only arms the gc backoff (whether its walk fits sits on a tie).
    assert (seen[0], seen[2], seen[3]) == ([None], "http_error", [None]), seen


# Value: protects=a copied (synced) verification never counts as local in a
#   build whose only gc is backed off; fails_when=_local_nodes is relearned
#   from each build alone (the copy reads verify_state 'ok' for the whole gc
#   backoff, up to 6h); why_new=red-team review (a regression of the gc
#   backoff), reproduced in-process; seam=none
def test_a_backed_off_gc_never_makes_a_copied_verification_local(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    copied = {"state": "ok", "upid": "UPID:src:1:2:3:0000000A:verify:ds:root@pam:"}
    responses = minimal_responses(
        **{
            "/admin/datastore/ds/snapshots": ok(
                [snapshot("vm", "100", 200, verification=copied)]
            )
        }
    )
    seen = []
    for gc in (
        ok({"upid": GC_UPID}),
        {"error": "timeout", "message": "t"},
        ok({"upid": GC_UPID}),
    ):
        responses["/admin/datastore/ds/gc"] = gc
        clock.now += pbs.PBS_CACHE_TTL
        out, _ = collect(monkeypatch, responses)
        seen.append([g["verify_state"] for g in out["groups"]])
    # build 2: the gc timed out, build 3: it is backed off -- no node is
    # learned either time, and the last ones stand: the copy never counts.
    assert seen == [[None], [None], [None]], seen


# Value: protects=when the only namespace a build could read is cut inside
#   on every build, the reads move on to where the walks stopped: the next
#   build reads that datastore's namespaces first; fails_when=the reads stay
#   on the lone namespace (or lose their place), so it is read first again
#   and the next datastore ships unread; why_new=testing specialist; seam=none
def test_a_lone_unit_hands_the_group_reads_to_where_the_walks_stopped(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_namespaces

    def slow_walk(session, target, errors, deadline, store):
        rows = real(session, target, errors, deadline, store)
        if store == "a":  # answered, but no walk fits after it
            clock.now = max(clock.now, pbs._walk_deadline(deadline) + 0.5)
        return rows

    monkeypatch.setattr(pbs, "_read_namespaces", slow_walk)
    handler = responses_handler(
        _two_datastores(**{"/admin/datastore/b/namespace": ok([{"ns": ""}])})
    )

    def timed(url):
        reply = handler(url)
        if route(url) == "/admin/datastore/a/groups?ns=x":
            clock.now += pbs.PBS_COLLECT_DEADLINE  # a/x outlasts every budget
        return reply

    session = FakeSession(timed)
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    monkeypatch.setattr(pbs, "_rotation", ("a", "x"))
    outs = []
    for _ in range(2):
        monkeypatch.setattr(pbs, "_cache", TTLCache())
        clock.now += pbs.PBS_CACHE_TTL
        outs.append(pbs.pbs_metrics(**LOOPBACK))
    a, b = outs[1]["datastores"]
    assert b["unread_namespaces"] == []  # b is read first


# --- read order: walks, gc and own status, group reads ---


# Value: protects=past the first namespace walk of a build, a walk goes out
#   only with its read timeout AND _AFTER_WALKS left, so slow walks never
#   leave the gc and group reads with nothing -- while the first walk still
#   goes out with just its read timeout left (a build whose earlier reads
#   took long still walks one datastore); the datastores past the stop carry
#   the budget skip and the next build starts there; fails_when=every walk
#   needs the reserve (a slow preamble then walks nothing, ever: the
#   redesign's simulation read nothing in 60 builds) or none does (slow walks
#   take the whole tick); why_new=read-order redesign; seam=none
@pytest.mark.parametrize(
    "left, walked",
    [(11, ["a"]), (pbs._READ_TIMEOUT + pbs._AFTER_WALKS + 0.5, ["a", "b", "c"])],
    ids=["first_only", "all"],
)
def test_only_the_first_walk_of_a_build_may_use_the_reserve(monkeypatch, left, walked):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_backends

    def slow_preamble(*args):
        clock.now += pbs.PBS_COLLECT_DEADLINE - left
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    out, session = collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    assert _walked([route(u) for u in session.calls]) == walked
    skipped = [
        e["store"]
        for e in out["errors"]
        if (e["scope"], e["message"]) == ("namespaces", pbs._DEADLINE_MESSAGE)
    ]
    assert skipped == [s for s in ("a", "b", "c") if s not in walked]
    assert pbs._rotation == (("b", "") if walked == ["a"] else ("a", ""))


# Value: protects=a namespace walk that is sent and fails skips its datastore
#   without stopping the walks, and forgets the listing the agent remembered
#   for it, while one held back by the hold forgets nothing; fails_when=a
#   failed walk stops the round (one offline datastore blocks every one past
#   it) or its old listing is read while the walks are held;
#   why_new=read-order redesign; seam=none
def test_a_failed_walk_forgets_its_listing_and_a_held_one_does_not(monkeypatch):
    collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    assert set(pbs._listings) == {"a", "b", "c"}
    responses = _datastores_with(
        ["a", "b", "c"], **{"/admin/datastore/b/namespace": fail(400, "offline")}
    )
    for store in ("a", "b", "c"):  # read instead of the usage status, held
        responses[f"/admin/datastore/{store}/status"] = ok({"total": 9})
    out, _ = collect(monkeypatch, responses)
    assert [d["namespaces"] for d in out["datastores"]] == [[""], None, [""]]
    assert set(pbs._listings) == {"a", "c"}
    failure = ("namespaces", "c", None, "armed")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    collect(monkeypatch, responses)
    assert set(pbs._listings) == {"a", "c"}


# Value: protects=while every walk is held, the group reads go through the
#   listings remembered from earlier builds, from where they stand, and ship
#   those groups with every namespaces null (none authoritative); a
#   datastore forgotten since its last listing is left out; fails_when=a held
#   build reads no group (the dashboard goes stale for as long as the hold
#   lasts: days) or reads a datastore whose storage may be dead;
#   why_new=read-order redesign (a user decision); seam=none
def test_the_remembered_listings_are_read_while_the_walks_are_held(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    groups = [{"backup-type": "vm", "backup-id": "100", "last-backup": 5}]
    responses = _datastores_with(
        ["a", "b", "c"], **{"/admin/datastore/c/groups": ok(groups)}
    )
    for store in ("a", "b", "c"):  # read instead of the usage status, held
        responses[f"/admin/datastore/{store}/status"] = ok({"total": 9})
    collect(monkeypatch, responses)
    pbs._listings.pop("a")  # a read on it timed out since
    failure = ("namespaces", "a", None, "armed")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    monkeypatch.setattr(pbs, "_rotation", ("c", ""))
    read = _spy_groups(monkeypatch)
    clock.now += pbs.PBS_CACHE_TTL
    out, session = collect(monkeypatch, responses)
    assert not _walked([route(u) for u in session.calls])
    assert read == [("c", ""), ("b", "")]
    assert [d["namespaces"] for d in out["datastores"]] == [None] * 3
    assert [(g["store"], g["id"]) for g in out["groups"]] == [("c", "100")]
    assert out["walks_held"] is True


# Value: protects=a groups or snapshot listing that times out stops this
#   build's reads of the datastore's other namespaces (each could pin a PBS
#   proxy thread on a dead mount) and forgets its listing until a walk lists
#   it again -- every one of them then unread, with a 'groups' entry -- while
#   a gc that times out forgets nothing (a gc that merely answers slowly must
#   not cost its namespaces their turn: the redesign's fuzz found namespaces
#   never read when it did); fails_when=the timeout stops nothing, or a gc
#   timeout does; why_new=read-order redesign; seam=none
def test_a_timed_out_namespace_read_stops_its_datastore_a_gc_timeout_does_not(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    responses = _two_datastores(namespaces=("", "x", "y", "z"))
    session = _install_timed(
        monkeypatch,
        responses,
        clock,
        lambda path: math.inf if path == "/admin/datastore/a/groups?ns=x" else 0.1,
    )
    out, sent = _timed_build(monkeypatch, clock, session)
    a, b = out["datastores"]
    assert (a["unread_namespaces"], b["unread_namespaces"]) == (["x", "y", "z"], [])
    assert "/admin/datastore/a/groups?ns=y" not in sent
    # One entry counting the namespaces left, not one per namespace.
    assert [e for e in out["errors"] if e["ns"] is None and e["store"] == "a"] == [
        {
            "scope": "groups",
            "store": "a",
            "ns": None,
            "message": f"{pbs._TIMED_OUT_MESSAGE} (2 namespace(s) not read)",
        }
    ]
    assert "a" not in pbs._listings  # it waited its whole read timeout
    session.latency = lambda path: math.inf if path == "/admin/datastore/b/gc" else 0.1
    out, _ = _timed_build(monkeypatch, clock, session)
    a, b = out["datastores"]
    assert b["gc"] is None and b["unread_namespaces"] == []
    assert a["unread_namespaces"] == ["x"]  # backed off; walked again, y z read


# Value: protects=on a PBS with more namespaces than the cap, the listings go
#   round the datastores: one that does not fit what is left of the cap ends
#   the build's walks, none of it kept, and is listed first in a later build
#   -- every datastore listed whole and read in turn; fails_when=the cap
#   always keeps the same datastores (the others never read: a user decision:
#   a rotation under the cap) or keeps part of a listing it then reads as
#   whole; why_new=read-order redesign; seam=none
def test_the_namespace_cap_goes_round_the_datastores(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 3)
    names = ["a", "b", "c"]
    responses = _datastores_with(names)
    for store in names:
        responses[f"/admin/datastore/{store}/namespace"] = ok([{"ns": ""}, {"ns": "x"}])
        responses[f"/admin/datastore/{store}/groups?ns=x"] = ok([])
        responses[f"/admin/datastore/{store}/snapshots?ns=x"] = ok([])
    rounds = []
    for _ in range(3):
        out, _ = collect(monkeypatch, responses)
        rounds.append(
            [
                d["store"]
                for d in out["datastores"]
                if d["namespaces"] is not None and not d["unread_namespaces"]
            ]
        )
    assert rounds == [["a"], ["b"], ["c"]]
    capped = [(e["store"], e["message"]) for e in out["errors"] if e["scope"] == "cap"]
    assert capped == [("a", "namespaces capped at 3: not read")] + [
        ("b", "namespaces capped at 3: not read")
    ]


# Value: protects=after a reload, the reads resume just past the datastore
#   whose walk armed the hold, and that datastore is walked only once the
#   group reads reach it -- every other datastore listed and its namespaces
#   read first, over as many builds as that takes; fails_when=it is walked in
#   the reload's build (still broken, it re-arms the hold with the others
#   unread) or never again; why_new=read-order redesign (one rule for the earlier
#   per-round bookkeeping); seam=none
def test_the_walk_that_armed_the_hold_waits_for_the_group_reads(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_groups

    def one_per_build(session, target, errors, deadline, store, ns, room):
        rows = real(session, target, errors, deadline, store, ns, room)
        clock.now += 100  # the budget ends with each group read
        return rows

    monkeypatch.setattr(pbs, "_read_groups", one_per_build)
    failure = ("namespaces", "b", None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    walks, deferred = [], []
    for _ in range(4):
        clock.now += pbs.PBS_CACHE_TTL
        out, session = collect(monkeypatch, _datastores_with(["a", "b", "c", "d"]))
        walks.append(_walked([route(u) for u in session.calls]))
        deferred.append(
            [
                e["store"]
                for e in out["errors"]
                if e["message"] == pbs._RELOAD_DEFER_MESSAGE
            ]
        )
    assert walks == [["c", "d", "a"], ["d", "a"], ["a"], ["b", "c", "d", "a"]]
    assert deferred == [["b"], ["b", "c"], ["b", "c", "d"], []]
    assert pbs._deferred_walks == set()


# Value: protects=a reload starts the reads past the datastore its hold
#   names AND past every other deferred one, the walks stopping at the first
#   deferred datastore they reach -- whichever order the reloads came in;
#   fails_when=the reload's start lands on another deferred datastore (walked
#   at once: two broken datastores re-arm the hold on every reload with
#   nothing else read); why_new=read-order redesign; seam=none
@pytest.mark.parametrize("reloads", [("b", "c"), ("c", "b")])
def test_a_reload_starts_past_every_deferred_walk(monkeypatch, reloads):
    for name in reloads:
        failure = ("namespaces", name, None, "t")
        pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
        pbs.reset_timeout_holds()
    assert pbs._deferred_walks == {"b", "c"}
    _, session = collect(monkeypatch, _datastores_with(["a", "b", "c", "d"]))
    assert _walked([route(u) for u in session.calls]) == ["d", "a"]


# Value: protects=a PBS whose every datastore is deferred still walks: the
#   first datastore of the build is walked, deferred or not (a single
#   datastore after its own hold, included); fails_when=a deferred datastore
#   is never walked when nothing else can be (no namespace read again until
#   a restart); why_new=read-order redesign; seam=none
def test_a_pbs_whose_every_datastore_is_deferred_still_walks(monkeypatch):
    failure = ("namespaces", "ds", None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    out, session = collect(monkeypatch, minimal_responses())
    assert _walked([route(u) for u in session.calls]) == ["ds"]
    assert out["datastores"][0]["namespaces"] == [""]
    assert pbs._deferred_walks == set()


# Value: protects=a reload that lands while a build is still running (an
#   abandoned worker finishing late) keeps where it put the reads: that
#   build's end does not overwrite it; fails_when=the build writes its own
#   resume point over the reload's (the broken datastore is walked next and
#   re-arms the hold at once); why_new=read-order redesign (the `_reloads`
#   guard); seam=none
def test_a_reload_during_a_build_keeps_where_it_put_the_reads(monkeypatch):
    real = pbs._read_groups

    def reload_midway(*args):
        rows = real(*args)
        failure = ("namespaces", "a", None, "t")
        pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
        pbs.reset_timeout_holds()
        return rows

    monkeypatch.setattr(pbs, "_read_groups", reload_midway)
    collect(monkeypatch, _datastores_with(["a", "b", "c"]))
    assert pbs._rotation == ("a\x00", "")
    assert pbs._deferred_walks == {"a"}


# Value: protects=the listings the agent remembers hold at most
#   MAX_NAMESPACES namespaces in all, the oldest forgotten first (a listing
#   at the cap alone is kept), and another PBS or token starts afresh, as
#   does a datastore no longer listed; fails_when=they grow with every
#   datastore ever walked, or one PBS's listings are read on another;
#   why_new=read-order redesign; seam=none
# Value (extension): protects=a datastore listed again moves to newest, so the
#   bound holds; fails_when=it keeps its old slot (eviction stops at it: every
#   datastore's listing kept); why_new=no row re-remembered a store; seam=none
def test_the_remembered_listings_are_bounded_and_per_pbs(monkeypatch):
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 3)
    pbs._remember("a", ["", "x"])
    pbs._remember("b", ["", "x"])
    assert pbs._listings == {"b": ["", "x"]}
    pbs._remember("c", ["", "x", "y"])
    assert pbs._listings == {"c": ["", "x", "y"]}
    # Extension: a datastore listed again becomes the newest, so the ones
    # remembered since it was first listed are the oldest -- forgotten first.
    pbs._remember("a", [""])
    pbs._remember("b", [""])
    pbs._remember("a", ["", "x", "y"])  # walked again, grown
    assert pbs._listings == {"a": ["", "x", "y"]}
    monkeypatch.setattr(pbs, "MAX_NAMESPACES", 1000)
    collect(monkeypatch, _datastores_with(["a", "b"]))
    assert set(pbs._listings) == {"a", "b"}
    key = pbs._listings_key
    collect(monkeypatch, _datastores_with(["a"]))  # b removed from PBS
    assert set(pbs._listings) == {"a"} and pbs._listings_key == key
    collect(monkeypatch, _datastores_with(["b"]), token_id="other@pbs!t")
    assert set(pbs._listings) == {"b"} and pbs._listings_key != key


# Value: protects=when the datastore the reads stand in cannot be walked
#   (offline: PBS refuses its listing), the next one's namespaces are read in
#   that build; fails_when=the resume split applies to the first datastore
#   walked (all its namespaces skipped as 'before the resume point', a lap
#   late); why_new=mutant survived: the split tests walk the cursor's own
#   datastore; seam=none
def test_an_offline_datastore_at_the_cursor_never_skips_the_next_ones_groups(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    real_backends, real_walk = pbs._read_backends, pbs._read_namespaces

    def slow_preamble(*args):
        left = pbs._READ_TIMEOUT + pbs._AFTER_WALKS + 0.5
        clock.now += pbs.PBS_COLLECT_DEADLINE - left
        return real_backends(*args)

    def slow_a(session, target, errors, deadline, store):
        listing = real_walk(session, target, errors, deadline, store)
        if store == "a":
            clock.now += 1  # no further walk fits: the walks stop at b
        return listing

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    monkeypatch.setattr(pbs, "_read_namespaces", slow_a)
    offline = "datastore 'c' is unavailable: offline maintenance mode: disk swap"
    responses = _datastores_with(
        ["a", "b", "c"], **{"/admin/datastore/c/namespace": fail(400, offline)}
    )
    monkeypatch.setattr(pbs, "_rotation", ("c", ""))  # the reads stand in c
    read = _spy_groups(monkeypatch)
    out, session = collect(monkeypatch, responses)
    assert _walked([route(u) for u in session.calls]) == ["c", "a"]
    assert read == [("a", "")]
    a = out["datastores"][0]
    assert (a["namespaces"], a["unread_namespaces"]) == ([""], [])


# Value: protects=on random slow and broken PBSes, a namespace is never
#   shipped as read whole unless its /groups and /snapshots both answered in
#   that very build, after its datastore's listing answered in it too (the
#   server prunes on it); and every namespace of a datastore whose walk
#   works is read whole at least once; fails_when=a rule change lets a
#   remembered listing or a skipped read count as read (false prunes), or
#   starves a namespace; why_new=read-order redesign: the fuzz that validated it
#   (300 PBSes x 60 builds, 0 violations) kept as a small seeded test;
#   seam=none
def test_no_namespace_ships_as_read_without_both_reads_answering(monkeypatch):
    for seed in range(25):
        rnd = random.Random(seed)
        _reset_state(monkeypatch)
        clock = use_clock(monkeypatch, Clock())
        names = [f"s{i}" for i in range(rnd.randint(1, 4))]
        spaces = {s: [""] + [f"n{j}" for j in range(rnd.randint(0, 3))] for s in names}
        responses = _datastores_with(names)
        latency = {}
        for store in names:
            responses[f"/admin/datastore/{store}/status"] = ok({"total": 9})
            responses[f"/admin/datastore/{store}/namespace"] = ok(
                [{"ns": ns} for ns in spaces[store]]
            )
            for ns in spaces[store][1:]:
                responses[f"/admin/datastore/{store}/groups?ns={ns}"] = ok([])
                responses[f"/admin/datastore/{store}/snapshots?ns={ns}"] = ok([])
            latency[f"/admin/datastore/{store}/namespace"] = rnd.choice(
                [0.05, 0.05, 3, 9.5, math.inf]
            )
            latency[f"/admin/datastore/{store}/gc"] = rnd.choice([0.05, 4, math.inf])
            for ns in spaces[store]:
                query = f"?ns={ns}" if ns else ""
                for leaf in ("groups", "snapshots"):
                    latency[f"/admin/datastore/{store}/{leaf}{query}"] = rnd.choice(
                        [0.05, 1, 2, math.inf]
                    )
        session = _install_timed(
            monkeypatch, responses, clock, lambda path: latency.get(path, 0.05)
        )
        seen = set()
        for build in range(20):
            if rnd.random() < 0.1:
                pbs.reset_timeout_holds()
            out, sent = _timed_build(monkeypatch, clock, session)
            answered = {p for p in sent if latency.get(p, 0.05) != math.inf}
            for datastore in out["datastores"]:
                store = datastore["store"]
                if datastore["namespaces"] is None:
                    continue
                assert f"/admin/datastore/{store}/namespace" in answered, seed
                for ns in set(datastore["namespaces"]) - set(
                    datastore["unread_namespaces"]
                ):
                    query = f"?ns={ns}" if ns else ""
                    for leaf in ("groups", "snapshots"):
                        assert f"/admin/datastore/{store}/{leaf}{query}" in answered, (
                            seed,
                            build,
                            store,
                            ns,
                        )
                    seen.add((store, ns))
        readable = {
            (store, ns)
            for store in names
            if latency[f"/admin/datastore/{store}/namespace"] < 9
            for ns in spaces[store]
            if all(
                latency[f"/admin/datastore/{store}/{leaf}{'?ns=' + ns if ns else ''}"]
                < 2
                for leaf in ("groups", "snapshots")
            )
        }
        if all(latency[f"/admin/datastore/{s}/namespace"] < 9 for s in names):
            assert readable <= seen, (seed, sorted(readable - seen))


# Value: protects=a build with no time left for any walk leaves the group
#   reads where they stand, so builds alternating with such a build still
#   read every namespace; fails_when=the walks' stop at the datastore the
#   reads stand in is taken as the end of a round (the reads restart at its
#   root: 8 of 32 namespaces never read with a slow build every second one);
#   why_new=pre-landing review (testing + performance, CRITICAL); seam=none
def test_a_build_with_no_room_for_a_walk_keeps_the_group_reads_where_they_stand(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    spaces = [""] + [f"n{i:02d}" for i in range(30)]
    responses = _datastores_with(["x", "y"])
    responses["/admin/datastore/x/namespace"] = ok([{"ns": ns} for ns in spaces])
    for ns in spaces[1:]:
        responses[f"/admin/datastore/x/groups?ns={ns}"] = ok([])
        responses[f"/admin/datastore/x/snapshots?ns={ns}"] = ok([])
    slow = {"on": False}
    real = pbs._read_backends

    def maybe_slow(*args):
        if slow["on"]:  # less than a read timeout left: no walk is sent
            clock.now += pbs.PBS_COLLECT_DEADLINE - pbs._READ_TIMEOUT + 0.5
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", maybe_slow)
    session = _install_timed(
        monkeypatch,
        responses,
        clock,
        lambda path: 0.4 if "/groups" in path or "/snapshots" in path else 0.05,
    )
    slow["on"] = True
    monkeypatch.setattr(pbs, "_rotation", ("x", "n07"))
    _, sent = _timed_build(monkeypatch, clock, session)
    assert _walked(sent) == [] and pbs._rotation == ("x", "n07")
    read = set()
    for build in range(20):
        slow["on"] = build % 2 == 1
        out, _ = _timed_build(monkeypatch, clock, session)
        for d in out["datastores"]:
            if d["namespaces"] is not None:
                done = set(d["namespaces"]) - set(d["unread_namespaces"])
                read |= {(d["store"], ns) for ns in done}
    assert read == {("x", ns) for ns in spaces} | {("y", "")}


# Value: protects=slow walks that leave a slow head gc less than its 5s wait
#   plus the group reads' reserve never take the group reads' time: the gc
#   is clamped, so every build reads groups; fails_when=the wait is granted
#   whatever is left (the gc runs past the budget, no group read starts, the
#   next build is the same: no snapshot read in 8 builds); why_new=pre-landing
#   review (performance, CRITICAL); seam=none
# Value (extension): protects=a slow head OWN STATUS (usage aggregate
#   failed) is held to the same reserve as the gc; fails_when=the own status
#   read is sent without the reserve (its 5s wait runs past the budget, no
#   group read in 8 builds); why_new=that mutant survived: only the gc row
#   ran; seam=none
@pytest.mark.parametrize("slow", ["gc", "status"], ids=["gc", "own_status"])
def test_slow_walks_and_a_slow_head_gc_never_starve_the_group_reads(monkeypatch, slow):
    clock = use_clock(monkeypatch, Clock())
    walk = {"a": 0.1, "b": 5.4, "c": 9.9, "d": 0.1}
    responses = _datastores_with(list(walk))
    if slow == "status":  # each datastore's usage is read from its own status
        responses["/status/datastore-usage"] = fail(500, "EIO")
        for store in walk:
            responses[f"/admin/datastore/{store}/status"] = ok(
                {"total": 9, "used": 4, "avail": 5}
            )

    def latency(path):
        if path.endswith("/namespace"):
            return walk[path.split("/")[3]]
        hit = path.startswith("/admin/datastore/") and path.endswith("/" + slow)
        return 4.5 if hit else 0.05

    session = _install_timed(monkeypatch, responses, clock, latency)
    for _ in range(8):
        _, sent = _timed_build(monkeypatch, clock, session)
        assert any(p.split("?")[0].endswith("/snapshots") for p in sent)


# Value (rows): protects=an own status or gc read gets its 5s minimum wait
#   only with the group reads' reserve left after it -- else it is clamped:
#   a first timeout only notes it, one of a read noted before backs it off;
#   fails_when=the wait ignores the reserve (the group reads get nothing),
#   a noted read is re-sent clamped on every build (one proxy thread each
#   time on a dead mount), or is never sent again without that room (unread
#   for hours); why_new=pre-landing review (performance, red team); seam=none
@pytest.mark.parametrize(
    "left, noted, read_timeout, retry_later",
    [
        (8.0, False, 5, True),  # room: the wait, and a timeout arms the backoff
        (7.9, False, 3.9, False),  # no room: clamped to its half, only noted
        (8.0, True, 5, True),  # noted, room: sent with the wait, arms it
        (7.9, True, 3.9, True),  # noted, no room: clamped, and backed off
    ],
)
def test_a_gc_gets_its_minimum_wait_only_with_the_group_reads_reserve_left(
    monkeypatch, left, noted, read_timeout, retry_later
):
    clock = use_clock(monkeypatch, Clock())
    session = _install_timed(
        monkeypatch, _datastores_with(["a"]), clock, lambda path: math.inf
    )
    key = pbs._timeout_backoff_key("/admin/datastore/a/gc", None)
    if noted:
        pbs._timeout_backoff[key] = (clock.now, 0, ("gc", "a", None, "t"))
    errors = pbs._Errors(str)
    tick = clock.now + left
    gc = pbs._read_gc(
        session,
        _target(),
        errors,
        clock.now + 3.9,  # its half
        "a",
        first=True,
        wait_by=tick - pbs._GROUP_READS_RESERVE,
    )
    assert gc is None
    assert [t[1] for t in session.timeouts] == [pytest.approx(read_timeout)]
    # A backoff is its first finite rung (one rebuild), never a hold; a note
    # is due at once and uncounted.
    entry = (clock.now + 2 * pbs.PBS_CACHE_TTL, 1) if retry_later else (clock.now, 0)
    assert pbs._timeout_backoff[key][:2] == entry


# Value: protects=the gc is read before the own status, so a slow own status
#   (the usage aggregate failing) never takes the gc's time at the head;
#   fails_when=the own status goes first (it takes its 5s wait past the
#   half, the head gc is never sent and the head is moved past: no gc read
#   in 8 builds); why_new=pre-landing review (performance, CRITICAL); seam=none
def test_a_slow_own_status_never_starves_the_gc_reads(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    responses = _datastores_with(
        ["a", "b"], **{"/status/datastore-usage": fail(500, "EIO")}
    )
    for store in ("a", "b"):
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 4, "avail": 5}
        )
    walk = {"a": 5.4, "b": 9.9}

    def latency(path):
        if path.endswith("/namespace"):
            return walk[path.split("/")[3]]
        if path.startswith("/admin/datastore/") and path.endswith("/status"):
            return 2.5
        return 0.05

    session = _install_timed(monkeypatch, responses, clock, latency)
    for _ in range(8):
        out, sent = _timed_build(monkeypatch, clock, session)
        assert any(d["gc"] is not None for d in out["datastores"])
        for store in ("a", "b"):
            gc, status = (
                f"/admin/datastore/{store}/{leaf}" for leaf in ("gc", "status")
            )
            if status in sent:
                assert sent.index(gc) < sent.index(status)


def _held_two_datastores(namespaces=("", "x")):
    """_two_datastores, with the own status each datastore's usage is read
    from while the walk hold also holds the usage aggregate."""
    responses = _two_datastores(namespaces)
    for store in ("a", "b"):
        responses[f"/admin/datastore/{store}/status"] = ok(
            {"total": 9, "used": 1, "avail": 8}
        )
    return responses


# Value: protects=while every walk is held, a group read that times out
#   after its minimum wait stops every group read until the reload -- even
#   one the budget cut short -- and forgets its datastore's listing;
#   fails_when=only a read that waited its whole read timeout arms it (under
#   the hold the dead storage's own status reads eat the budget, every group
#   read is cut short, and a dead NAS gets one more pinned thread per
#   build); why_new=pre-landing review (security), reproduced; seam=none
def test_a_held_group_read_the_budget_cut_short_stops_the_group_reads(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    latency = {}
    session = _install_timed(
        monkeypatch, _held_two_datastores(), clock, lambda path: latency.get(path, 0.05)
    )
    _timed_build(monkeypatch, clock, session)  # both listings remembered
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, ("usage", None, None, "t"))
    latency["/admin/datastore/a/snapshots?ns=x"] = 6.0
    real = pbs._read_all_groups

    def late(session, target, errors, deadline, *args):
        clock.now = max(clock.now, deadline - 5.5)  # the read is clamped to 5.5s
        return real(session, target, errors, deadline, *args)

    monkeypatch.setattr(pbs, "_read_all_groups", late)
    out, sent = _timed_build(monkeypatch, clock, session)
    assert out["walks_held"] and "/admin/datastore/a/snapshots?ns=x" in sent
    assert pbs._GROUPS_HOLD in pbs._timeout_backoff and set(pbs._listings) == {"b"}
    monkeypatch.setattr(pbs, "_read_all_groups", real)
    _, sent = _timed_build(monkeypatch, clock, session)
    assert not [p for p in sent if p.split("?")[0].endswith(("/groups", "/snapshots"))]
    # Value (extension): protects=the datastore whose /snapshots read armed
    #   this hold is deferred by the reload, like one whose /groups read
    #   armed it: the next build walks and reads the other datastore only;
    #   fails_when=only a /groups-armed hold names a suspect (a is walked
    #   right after b and, its storage still dead, re-arms the walk hold);
    #   why_new=every reload test armed this hold with a /groups read;
    #   seam=none
    pbs.reset_timeout_holds()
    latency.clear()  # a answers again: it still waits for the reads to reach it
    _, sent = _timed_build(monkeypatch, clock, session)
    assert _walked(sent) == ["b"]
    reads = [p for p in sent if p.split("?")[0].endswith(("/groups", "/snapshots"))]
    assert reads and {p.split("/")[3] for p in reads} == {"b"}


# Value: protects=while every walk is held, a dead storage under several
#   datastores costs one group read for the whole hold: the first one that
#   times out stops every group read until the reload, a live datastore's
#   included; fails_when=the group reads go on through the other remembered
#   listings of the dead storage (one more pinned proxy thread per read) or
#   a reload leaves them stopped;
#   why_new=pre-landing review (security: PBS answers a gc from memory, so
#   no read proves a storage alive); seam=none
def test_a_dead_storage_costs_one_group_read_while_the_walks_are_held(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c", "d"]
    responses = _datastores_with(names)
    session = _install_timed(monkeypatch, responses, clock, lambda path: 0.1)
    _timed_build(monkeypatch, clock, session)  # every listing remembered
    dead = tuple(f"/admin/datastore/{store}/" for store in "abc")

    def latency(path):  # PBS answers the gc of a dead datastore from memory
        return math.inf if path.startswith(dead) and not path.endswith("/gc") else 0.1

    def group_reads(sent):
        return [p for p in sent if p.split("?")[0].endswith(("/groups", "/snapshots"))]

    session.latency = latency
    reads = []
    for _ in range(6):
        out, sent = _timed_build(monkeypatch, clock, session)
        assert out["walks_held"]
        reads += [p for p in group_reads(sent) if p.startswith(dead)]
    assert len(reads) == 1 and pbs._GROUPS_HOLD in pbs._timeout_backoff
    out, sent = _timed_build(monkeypatch, clock, session)
    assert group_reads(sent) == []  # the live d's too, until the reload
    assert any(pbs._GROUPS_HOLD_MESSAGE in e["message"] for e in out["errors"])
    pbs.reset_timeout_holds()
    assert pbs._GROUPS_HOLD not in pbs._timeout_backoff
    # Both suspects wait: the walk that armed the walk hold (a) and the group
    # read that armed the group-reads hold (b).
    assert pbs._deferred_walks == {"a", "b"}
    # Value (extension): protects=after the reload, with the storage repaired,
    #   the NEXT build walks again and sends group reads again, the live
    #   datastores' first; fails_when=the reload releases the group reads
    #   only a build or more later (each build is five minutes of stale
    #   backups after the operator's repair); why_new=the seeded fuzz test
    #   only checks that every namespace is read eventually; seam=none
    session.latency = lambda path: 0.1
    out, sent = _timed_build(monkeypatch, clock, session)
    assert out["walks_held"] is False and _walked(sent) == ["c", "d"]
    assert {p.split("/")[3] for p in group_reads(sent)} == {"c", "d"}


# Value: protects=while every walk is held, the group reads go through every
#   remembered listing whatever its gc answers (a 403, a hang): the gc says
#   nothing about the storage; fails_when=a gc gate comes back (a
#   namespace-scoped token, whose every gc is a 403, or a slow gc, would
#   starve the remembered listings, and a gc window out of step with the
#   group cursor left a third of them never read); why_new=pre-landing
#   review (security, red team, performance); seam=none
def test_held_group_reads_do_not_depend_on_the_gc(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    responses = _held_two_datastores()
    responses["/admin/datastore/a/gc"] = fail(403, "permission check failed")
    session = _install_timed(
        monkeypatch,
        responses,
        clock,
        lambda path: math.inf if path == "/admin/datastore/b/gc" else 0.05,
    )
    _timed_build(monkeypatch, clock, session)  # both listings remembered
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, ("usage", None, None, "t"))
    out, sent = _timed_build(monkeypatch, clock, session)
    assert out["walks_held"] and [d["gc"] for d in out["datastores"]] == [None, None]
    wanted = {"/admin/datastore/a/groups?ns=x", "/admin/datastore/b/groups?ns=x"}
    assert wanted <= set(sent)


# Value: protects=while every walk is held, every remembered namespace is
#   read within a bounded number of builds when the gc and group reads both
#   run out of time each build; fails_when=the group reads depend on a
#   window the gc reads move on their own (identical builds repeat and a
#   third of the namespaces are never read); why_new=pre-landing review
#   (performance); seam=none
def test_held_group_reads_reach_every_remembered_namespace(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i:02d}" for i in range(12)]
    spaces = [""] + [f"n{j}" for j in range(7)]
    responses = _datastores_with(names)
    for store in names:
        responses[f"/admin/datastore/{store}/namespace"] = ok(
            [{"ns": ns} for ns in spaces]
        )
        for ns in spaces[1:]:
            responses[f"/admin/datastore/{store}/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/{store}/snapshots?ns={ns}"] = ok([])
    session = _install_timed(monkeypatch, responses, clock, lambda path: 0.0)
    _timed_build(monkeypatch, clock, session)  # every listing remembered
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, ("usage", None, None, "t"))
    cost = {"gc": 0.6, "status": 0.6, "groups": 0.25, "snapshots": 0.25}
    session.latency = lambda path: cost.get(path.split("?")[0].rsplit("/", 1)[1], 0.01)
    read = set()
    for _ in range(30):
        _, sent = _timed_build(monkeypatch, clock, session)
        read |= {
            (p.split("/")[3], p.partition("ns=")[2])
            for p in sent
            if p.split("?")[0].endswith("/snapshots")
        }
    assert {(store, ns) for store in names for ns in spaces} <= read


# Value: protects=while every walk is held, a /groups read that waits its
#   whole read timeout stops every group read of the build -- its own
#   datastore's and every other's -- with one counted errors[] entry per
#   datastore; fails_when=the stop holds only for the datastore that timed
#   out (the rest of a dead storage sent, a proxy thread each), or writes
#   one entry per namespace; why_new=pre-landing review (security); seam=none
def test_under_the_hold_a_group_read_that_waited_its_whole_timeout_stops_them_all(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    latency = {}
    session = _install_timed(
        monkeypatch,
        _held_two_datastores(("", "x", "y")),
        clock,
        lambda path: latency.get(path, 0.05),
    )
    _timed_build(monkeypatch, clock, session)  # both listings remembered
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, ("usage", None, None, "t"))
    latency["/admin/datastore/a/groups?ns=x"] = math.inf
    out, sent = _timed_build(monkeypatch, clock, session)
    assert out["walks_held"]
    assert [p for p in sent if p.split("?")[0].endswith("/groups")] == [
        "/admin/datastore/a/groups",
        "/admin/datastore/a/groups?ns=x",
    ]
    skips = sorted(
        (e["store"], e["message"])
        for e in out["errors"]
        if e["scope"] == "groups" and e["ns"] is None
    )
    assert skips == [
        ("a", f"{pbs._GROUPS_HOLD_MESSAGE} (1 namespace(s) not read)"),
        ("b", f"{pbs._GROUPS_HOLD_MESSAGE} (3 namespace(s) not read)"),
    ]


# Value: protects=the build arming the walk hold still group-reads the
#   datastores it walked, whatever their gc answered: their listings came
#   back in that build, and their namespaces read whole there are the last
#   authoritative ones before a reload; fails_when=the arming build skips
#   them (their namespaces left unread); why_new=pre-landing coverage audit;
#   seam=none
def test_the_build_that_arms_the_hold_reads_the_datastores_it_walked(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    stuck = ("/admin/datastore/a/gc", "/admin/datastore/b/namespace")
    session = _install_timed(
        monkeypatch,
        _two_datastores(),
        clock,
        lambda path: math.inf if path in stuck else 0.05,
    )
    out, sent = _timed_build(monkeypatch, clock, session)
    a = out["datastores"][0]
    assert out["walks_held"] and a["gc"] is None
    assert "/admin/datastore/a/groups?ns=x" in sent
    assert (a["namespaces"], a["unread_namespaces"]) == (["", "x"], [])


# Value (rows): protects=a build whose walks stopped before every datastore
#   (the budget, or a walk deferred after a reload) flags every job list
#   'partial:' with the unlisted reason; fails_when=only a failed or trimmed
#   listing counts as not read (a namespace a deeper ACL entry hides in a
#   datastore not walked this build would hide its jobs from lists read as
#   complete); why_new=pre-landing review (testing); seam=none
@pytest.mark.parametrize("why", ["budget", "reload"])
def test_a_datastore_not_walked_flags_every_job_list(monkeypatch, why):
    clock = use_clock(monkeypatch, Clock())
    walk = 0.05
    if why == "budget":
        walk = 9.0  # the second walk would need 14s left
    else:
        monkeypatch.setattr(pbs, "_deferred_walks", {"b"})
    session = _install_timed(
        monkeypatch,
        _datastores_with(["a", "b"]),
        clock,
        lambda path: walk if path.endswith("/namespace") else 0.05,
    )
    out, sent = _timed_build(monkeypatch, clock, session)
    assert _walked(sent) == ["a"]
    flags = {
        e["scope"]: e["message"]
        for e in out["errors"]
        if e["message"].startswith("partial:")
    }
    assert flags == {
        scope: "partial: " + pbs._UNLISTED_REASON
        for scope in ("sync_jobs", "verify_jobs", "prune_jobs")
    }


# Value: protects=while every walk is held, group reads the budget cut inside
#   a namespace resume at that exact (store, ns) in the next build, through
#   the remembered listings; fails_when=the remembered reads restart at a
#   datastore's root or at the first listing (the namespaces past the cut
#   never read while the hold lasts); why_new=pre-landing review (testing);
#   seam=none
def test_the_group_reads_under_the_hold_resume_where_they_were_cut(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    session = _install_timed(
        monkeypatch, _held_two_datastores(("", "x", "y")), clock, lambda path: 0.05
    )
    _timed_build(monkeypatch, clock, session)  # both listings remembered
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, ("usage", None, None, "t"))
    real = pbs._read_groups
    read = []

    def spy(session, target, errors, deadline, store, ns, room):
        read.append((store, ns))
        if (store, ns) == ("b", "x") and len(read) < 10:
            clock.now = deadline  # the budget runs out inside it
        return real(session, target, errors, deadline, store, ns, room)

    monkeypatch.setattr(pbs, "_read_groups", spy)
    _timed_build(monkeypatch, clock, session)
    assert read[-1] == ("b", "x") and pbs._rotation == ("b", "x")
    del read[:]
    _timed_build(monkeypatch, clock, session)
    assert read[0] == ("b", "x")


# Value: protects=while every walk is held, the group reads resume at the
#   exact namespace they were cut in, whatever order the listings were
#   remembered in (walks start where the reads stand, so it is rarely
#   sorted); fails_when=the remembered units are not sorted before the
#   resume point is looked up (the namespaces past the cut go unread for
#   as long as the hold lasts); why_new=pre-landing review: dropping the
#   sort survived every test; seam=none
def test_held_reads_resume_at_the_cut_whatever_order_the_listings_were_remembered_in(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    names = ("a", "b", "c")
    responses = _datastores_with(list(names))
    for s in names:
        responses[f"/admin/datastore/{s}/status"] = ok(
            {"total": 9, "used": 1, "avail": 8}
        )
        responses[f"/admin/datastore/{s}/namespace"] = ok(
            [{"ns": ns} for ns in ("", "x", "y")]
        )
        for ns in ("x", "y"):
            responses[f"/admin/datastore/{s}/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/{s}/snapshots?ns={ns}"] = ok([])
    session = _install_timed(monkeypatch, responses, clock, lambda path: 0.05)
    monkeypatch.setattr(pbs, "_rotation", ("b", ""))  # walks go b, c, a
    _timed_build(monkeypatch, clock, session)
    assert list(pbs._listings) == ["b", "c", "a"]
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, ("usage", None, None, "t"))
    real, read = pbs._read_groups, []

    def spy(session, target, errors, deadline, store, ns, room):
        read.append((store, ns))
        if (store, ns) == ("a", "x") and len(read) < 20:
            clock.now = deadline  # the budget runs out inside it
        return real(session, target, errors, deadline, store, ns, room)

    monkeypatch.setattr(pbs, "_read_groups", spy)
    _timed_build(monkeypatch, clock, session)
    del read[:]
    _timed_build(monkeypatch, clock, session)
    assert read[0] == ("a", "x")


# Value: protects=the gc reads resume at the first datastore whose gc the
#   half cut, timed as its gc ENDS: a gc that failed fast is no cut, even
#   when the own status after it spends the half; fails_when=the cut is
#   taken after the own status (the next build re-reads the datastore whose
#   gc already answered instead of the one never read); why_new=pre-landing
#   review: that order survived every test; seam=none
def test_a_gc_that_failed_fast_is_no_cut_even_when_its_own_status_spends_the_half(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    responses = _datastores_with(
        ["a", "b", "c"],
        **{
            "/status/datastore-usage": fail(500, "EIO"),
            "/admin/datastore/b/gc": fail(403, "permission check failed"),
        },
    )
    for s in ("a", "b", "c"):
        responses[f"/admin/datastore/{s}/status"] = ok(
            {"total": 9, "used": 1, "avail": 8}
        )
    session = _install_timed(
        monkeypatch,
        responses,
        clock,
        lambda path: math.inf if path == "/admin/datastore/b/status" else 0.05,
    )
    _, sent = _timed_build(monkeypatch, clock, session)
    assert [p.split("/")[3] for p in sent if p.endswith("/gc")] == ["a", "b"]
    _, sent = _timed_build(monkeypatch, clock, session)
    assert [p.split("/")[3] for p in sent if p.endswith("/gc")][0] == "c"


# Value: protects=a walk that was sent and failed (an offline datastore's
#   400) still counts as the build's first walk, so the next one needs the
#   reserve too; fails_when=only a walk that returned a listing counts (a
#   second walk sent with just its read timeout left leaves the gc and
#   group reads nothing); why_new=pre-landing review: that change survived
#   every test; seam=none
def test_a_failed_walk_still_counts_as_the_builds_first_walk(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_backends

    def slow_preamble(*args):
        # A first walk fits, a second one (with the reserve) does not.
        clock.now += pbs.PBS_COLLECT_DEADLINE - 12 - 0.3
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    offline = "datastore 'a' is unavailable: offline maintenance mode"
    responses = _datastores_with(
        ["a", "b"], **{"/admin/datastore/a/namespace": fail(400, offline)}
    )
    session = _install_timed(monkeypatch, responses, clock, lambda path: 0.05)
    _, sent = _timed_build(monkeypatch, clock, session)
    assert _walked(sent) == ["a"]


# Value: protects=the head datastore's own status still gets its own wait
#   after a gc that took the half, within the group reads' reserve, so the
#   usage of a datastore whose status answers at once ships; fails_when=the
#   own status is held to the spent half (a lone datastore with a slow walk
#   and a 5s gc ships its usage null on every build); why_new=pre-landing
#   review (testing); seam=none
def test_a_slow_head_gc_inside_its_wait_never_starves_the_own_status(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    responses = _datastores_with(["a"], **{"/status/datastore-usage": fail(500, "EIO")})
    responses["/admin/datastore/a/status"] = ok({"total": 9, "used": 4, "avail": 5})

    def latency(path):
        if path.endswith("/namespace"):
            return 9.9
        if path == "/admin/datastore/a/gc":
            return 4.95  # past the half, inside its 5s wait
        return 0.05

    session = _install_timed(monkeypatch, responses, clock, latency)
    for _ in range(3):
        out, _ = _timed_build(monkeypatch, clock, session)
        a = out["datastores"][0]
        assert a["gc"] is not None and a["total"] == 9


# Value: protects=a gc that timed out once is read again within a few builds
#   on a PBS whose walks always leave less than its wait plus the reserve;
#   fails_when=a noted read is never sent without room for its wait (it
#   stays due, unread, until purged six hours later, while errors[] says
#   'retried later'); why_new=pre-landing review (red team); seam=none
def test_a_gc_slow_once_is_read_again_when_the_walks_leave_no_room(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    state = {"build": 0}

    def latency(path):
        if path.endswith("/namespace"):
            return 9.95
        if path.endswith("/gc"):
            return 4.0 if state["build"] == 0 else 0.1
        return 0.4

    session = _install_timed(monkeypatch, _datastores_with(["ds"]), clock, latency)
    read = []
    for build in range(6):
        state["build"] = build
        out, _ = _timed_build(monkeypatch, clock, session)
        read.append(out["datastores"][0]["gc"] is not None)
    assert read[0] is False and any(read[1:4])


# Value (rows): protects=the head datastore's own status keeps the whole
#   half when that is longer than its 5s wait, and is still sent, clamped,
#   when no wait fits; fails_when=its deadline is only the 5s wait (a head
#   status answering in 5-9s times out, is backed off and its usage ships
#   null) or it is skipped when the tick has under 8s left; why_new=coverage
#   audit: dropping the max() with the half survived every test; seam=none
@pytest.mark.parametrize(
    "preamble, status_latency",
    [(0.0, 6.5), (pbs.PBS_COLLECT_DEADLINE - 2.8, 0.05)],
    ids=["half_longer_than_the_wait", "no_room_for_the_wait"],
)
def test_the_head_own_status_keeps_the_whole_half_when_it_outlasts_its_wait(
    monkeypatch, preamble, status_latency
):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_backends

    def slow_preamble(*args):
        clock.now += preamble
        return real(*args)

    monkeypatch.setattr(pbs, "_read_backends", slow_preamble)
    responses = _datastores_with(["a"], **{"/status/datastore-usage": fail(500, "EIO")})
    responses["/admin/datastore/a/status"] = ok({"total": 9, "used": 4, "avail": 5})
    session = _install_timed(
        monkeypatch,
        responses,
        clock,
        lambda p: status_latency if p == "/admin/datastore/a/status" else 0.05,
    )
    out, sent = _timed_build(monkeypatch, clock, session)
    assert "/admin/datastore/a/status" in sent
    assert out["datastores"][0]["total"] == 9 and pbs._timeout_backoff == {}


# Value: protects=the group-reads hold lasts until the reload, like the walk
#   hold: never purged as stale, never dropped at the table cap, and it logs
#   one error line when it arms; fails_when=it is a finite entry (purged
#   after 6h: the group reads hit the dead NAS again with no signal), the
#   cap drops it, or nothing is logged when every group read stops;
#   why_new=coverage audit: those mutants survived every test; seam=none
def test_the_group_reads_hold_outlives_the_stale_purge_and_the_cap(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    logged = capture_logs(monkeypatch)
    latency = {}
    session = _install_timed(
        monkeypatch,
        _held_two_datastores(("", "x", "y")),
        clock,
        lambda path: latency.get(path, 0.05),
    )
    _timed_build(monkeypatch, clock, session)  # both listings remembered
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, ("usage", None, None, "t"))
    latency["/admin/datastore/a/groups?ns=x"] = math.inf
    _timed_build(monkeypatch, clock, session)
    assert pbs._GROUPS_HOLD in pbs._timeout_backoff
    del latency["/admin/datastore/a/groups?ns=x"]  # it would answer now
    for later in (pbs.PBS_CACHE_TTL, pbs._TIMEOUT_BACKOFF_MAX + 2 * pbs.PBS_CACHE_TTL):
        clock.now += later
        out, sent = _timed_build(monkeypatch, clock, session)
        assert out["walks_held"]
        assert not [
            p for p in sent if p.split("?")[0].endswith(("/groups", "/snapshots"))
        ]
    assert pbs._GROUPS_HOLD in pbs._timeout_backoff
    held = [(lvl, m) for lvl, m in logged if m.startswith("PBS group reads held")]
    assert held == [("error", f"PBS group reads held: {pbs._GROUPS_HOLD_MESSAGE}")]
    # At the cap, a retry goes -- never either hold.
    monkeypatch.setattr(pbs, "_TIMEOUT_BACKOFF_ENTRIES", len(pbs._timeout_backoff))
    for i in range(3):
        pbs._arm_timeout_backoff((f"/p{i}", ()), ("gc", "a", None, "t"), hold=False)
    assert {pbs._WALK_HOLD, pbs._GROUPS_HOLD} <= set(pbs._timeout_backoff)


# Value: protects=every datastore's own status (its usage) is read within a
#   round even when every gc fits the half and the last own status is cut
#   short; fails_when=only a gc defines the rotation's cut (the same
#   datastore stays last on every build and its usage is never read: a
#   filling datastore never alerts); why_new=pre-landing review
#   (performance); seam=none
def test_every_datastores_own_status_is_read_when_every_gc_fits(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i}" for i in range(12)]
    responses = _datastores_with(names, **{"/status/datastore-usage": fail(500, "x")})

    def latency(path):
        if path.startswith("/admin/datastore/") and path.endswith(
            ("/namespace", "/status")
        ):
            return 0.5
        return 0.1 if path.endswith("/gc") else 0.05

    session = _install_timed(monkeypatch, responses, clock, latency)
    read = set()
    for _ in range(24):
        out, _ = _timed_build(monkeypatch, clock, session)
        read |= {d["store"] for d in out["datastores"] if d["total"] is not None}
    assert read == set(names), sorted(set(names) - read)


# Value: protects=an own status that fails fast (or is skipped) under a note
#   an earlier build left is no cut: with every read fitting, the gc reads
#   stay where they start; fails_when=any timeouts-0 note counts as a cut
#   (the cursor ping-pongs to the failing datastore for up to 6h, the
#   datastores before it read half as often); why_new=pre-landing review
#   (maintainability, testing, performance); seam=none
@pytest.mark.parametrize("answer", [fail(500, "boom"), {"error": "connection_refused"}])
def test_an_old_status_note_under_a_fast_failure_is_no_cut(monkeypatch, answer):
    clock = use_clock(monkeypatch, Clock())
    names = ["s0", "s1", "s2", "s3"]
    responses = _datastores_with(names, **{"/status/datastore-usage": fail(500, "x")})
    session = _install_timed(monkeypatch, responses, clock, lambda p: 0.05)
    _timed_build(monkeypatch, clock, session)
    assert pbs._store_rotation == "s0"
    key = pbs._timeout_backoff_key(pbs._store_path("s2", "status"), None)
    pbs._timeout_backoff[key] = (clock.now, 0, ("usage", "s2", None, "t"))
    responses["/admin/datastore/s2/status"] = answer  # fails fast from now on
    for _ in range(4):
        out, _ = _timed_build(monkeypatch, clock, session)
        assert pbs._store_rotation == "s0"
    assert pbs._timeout_backoff[key][1] == 0  # the old note, untouched
    assert [d["total"] for d in out["datastores"]] == [9, 9, None, 9]


# Value: protects=after a /snapshots read times out, the rest of its
#   datastore's namespaces are read from the next build on (it resumes at
#   the first of them); fails_when=the skipped namespaces are passed over
#   for a round, meet the same slow read again on every round and are never
#   read; why_new=pre-landing review (red team); seam=none
def test_namespaces_after_a_timed_out_one_are_read_next(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    stores = [f"s{i:02d}" for i in range(12)]
    nss = [""] + [f"n{i:02d}" for i in range(1, 80)]
    responses = _datastores_with(stores)
    for s in stores:
        responses[f"/admin/datastore/{s}/namespace"] = ok([{"ns": n} for n in nss])
        for n in nss[1:]:
            responses[f"/admin/datastore/{s}/groups?ns={n}"] = ok([])
            responses[f"/admin/datastore/{s}/snapshots?ns={n}"] = ok([])
    slow = "/admin/datastore/s05/snapshots?ns=n22"

    def latency(path):
        if path == slow:
            return 12.0
        return 0.7 if path.split("?")[0].endswith(("/groups", "/snapshots")) else 0.02

    session = _install_timed(monkeypatch, responses, clock, latency)
    read = set()
    # Value (extension): protects=the build right after the slow read timed
    #   out reads the rest of s05, from the first namespace it skipped;
    #   fails_when=the next build resumes at the LAST namespace skipped (the
    #   ones in between wait a whole round, and meet the slow read again);
    #   why_new=the loop only checked each namespace is read within 300
    #   builds; seam=none
    timed_out, followed = False, 0
    for _ in range(300):
        out, sent = _timed_build(monkeypatch, clock, session)
        if timed_out:
            assert "/admin/datastore/s05/groups?ns=n23" in sent
            followed += 1
        timed_out = slow in sent
        for ds in out["datastores"]:
            for ns in ds["namespaces"] or []:
                if ns not in ds["unread_namespaces"]:
                    read.add((ds["store"], ns))
    assert {("s05", n) for n in nss if n != "n22"} <= read
    assert followed  # the slow read did time out, and a build followed it


# Value (rows): protects=a reload defers the datastore named by the
#   group-reads hold as well as the one named by the walk hold, the reads
#   placed past the latter; a usage-armed hold places them past the
#   group-reads hold's datastore and backs the usage status off;
#   fails_when=the group-reads hold's datastore, a known suspect, is walked
#   first after the reload and re-arms the hold before the others are read;
#   why_new=pre-landing review (maintainability, testing, performance);
#   seam=none
@pytest.mark.parametrize(
    "walk_failure, deferred, rotation, backed_off",
    [
        (
            ("namespaces", "a", None, "t"),
            {"a", "c"},
            ("a\x00", ""),
            {pbs._USAGE_BACKOFF},
        ),
        (("usage", None, None, "t"), {"c"}, ("c\x00", ""), {pbs._USAGE_BACKOFF}),
    ],
)
def test_a_reload_defers_both_holds_suspects(
    monkeypatch, walk_failure, deferred, rotation, backed_off
):
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, walk_failure)
    pbs._timeout_backoff[pbs._GROUPS_HOLD] = (math.inf, 1, ("groups", "c", "x", "t"))
    pbs.reset_timeout_holds()
    assert pbs._deferred_walks == deferred and pbs._rotation == rotation
    assert set(pbs._timeout_backoff) == backed_off


# Value: protects=after a reload of a hold the usage status armed, with the
#   group reads stopped on a dead datastore, the next build reads each
#   datastore's own status instead of the usage status and walks every other
#   datastore before the suspect; fails_when=the usage status is sent first
#   again (it re-arms the hold before any walk) or the suspect, where the
#   reads stood, is walked first (it re-arms the hold before the others);
#   why_new=pre-landing review (red team, maintainability, performance);
#   seam=none
def test_a_reload_after_a_usage_armed_hold_walks_the_others_first(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c", "d"]
    responses = _datastores_with(names)
    latency = {}
    session = _install_timed(
        monkeypatch, responses, clock, lambda p: latency.get(p, 0.05)
    )
    _timed_build(monkeypatch, clock, session)
    latency["/status/datastore-usage"] = math.inf
    for leaf in ("namespace", "groups", "snapshots"):
        latency[f"/admin/datastore/c/{leaf}"] = math.inf
    _timed_build(monkeypatch, clock, session)  # usage: walk hold; c: group hold
    assert pbs._timeout_backoff[pbs._WALK_HOLD][2][0] == "usage"
    assert pbs._timeout_backoff[pbs._GROUPS_HOLD][2][:2] == ("groups", "c")
    pbs.reset_timeout_holds()  # still dead
    out, sent = _timed_build(monkeypatch, clock, session, gap=30)  # next tick
    assert "/status/datastore-usage" not in sent
    assert _walked(sent) == ["d", "a", "b"] and not out["walks_held"]
    assert {"scope": "usage", "store": None, "ns": None} | {
        "message": pbs._USAGE_DEFERRED_MESSAGE
    } in out["errors"]
    assert {d["store"]: d["total"] for d in out["datastores"]} == dict.fromkeys(
        names, 9
    )


# Value: protects=a usage status that answers but leaves the walks no time
#   is backed off, doubling, so the builds in between walk every datastore
#   on each datastore's own status; one that is not the cause (a job list
#   took the time) is not; fails_when=it is sent first on every build (no
#   namespace is ever walked, nothing says why) or backed off for a job
#   list's slowness; why_new=pre-landing review (red team): a 9.9s usage
#   status starved every walk for good; seam=none
@pytest.mark.parametrize(
    "slow, walks",
    [
        ("/status/datastore-usage", [[], ["a", "b"], [], ["a", "b"], ["a", "b"]]),
        ("/admin/verify", [[], [], [], [], []]),
    ],
)
def test_a_usage_status_that_leaves_the_walks_no_time_is_backed_off(
    monkeypatch, slow, walks
):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b"]
    rows = [{"store": n, "total": 9, "used": 1, "avail": 8} for n in names]
    responses = _datastores_with(names, **{"/status/datastore-usage": ok(rows)})
    session = _install_timed(
        monkeypatch, responses, clock, lambda p: 9.9 if p == slow else 0.05
    )
    seen = []
    for _ in walks:
        out, sent = _timed_build(monkeypatch, clock, session)
        seen.append(_walked(sent))
        assert not out["walks_held"]
        assert [d["total"] for d in out["datastores"]] == [9, 9]
    assert seen == walks
    backed_off = pbs._timeout_backoff.get(pbs._USAGE_BACKOFF)
    assert (backed_off is not None) == (slow == "/status/datastore-usage")
    if backed_off is not None:
        assert backed_off[1] == 2  # sent twice, backed off twice (doubling)


# Value: protects=a usage status that leaves the walks time again ends its
#   backoff, so a later slow one starts again at the first rung; fails_when=
#   the entry is kept (each later slow spell waits twice as long as the last
#   one, up to 6h without estimated_full_date); why_new=the backoff test
#   only covers a usage status that stays slow; seam=none
def test_a_usage_status_that_leaves_the_walks_time_again_ends_its_backoff(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b"]
    rows = [{"store": n, "total": 9, "used": 1, "avail": 8} for n in names]
    responses = _datastores_with(names, **{"/status/datastore-usage": ok(rows)})
    slow = {"usage": 9.9}
    session = _install_timed(
        monkeypatch,
        responses,
        clock,
        lambda p: slow["usage"] if p == "/status/datastore-usage" else 0.05,
    )
    _timed_build(monkeypatch, clock, session)  # slow: backed off
    assert pbs._timeout_backoff[pbs._USAGE_BACKOFF][1] == 1
    slow["usage"] = 0.05
    retried = []
    for _ in range(3):  # skipped on the next build, retried on the one after
        _, sent = _timed_build(monkeypatch, clock, session)
        retried.append("/status/datastore-usage" in sent)
        if retried[-1]:
            break
    assert retried == [False, True]
    assert pbs._USAGE_BACKOFF not in pbs._timeout_backoff
    slow["usage"] = 9.9
    _timed_build(monkeypatch, clock, session)
    assert pbs._timeout_backoff[pbs._USAGE_BACKOFF][1] == 1  # the first rung


# Value: protects=a namespace whose /groups read answers late within its
#   granted wait is read whole when its /snapshots fits in what is left of
#   that wait, and the build never runs more than that wait past the budget
#   either way; fails_when=the /snapshots read is refused at its send past
#   the budget (the namespace is never read whole on such a PBS) or gets a
#   wait of its own (the build overruns by twice the wait); why_new=
#   pre-landing review (red team): 23 of 400 slow PBSes left namespaces
#   unread for good; seam=none
@pytest.mark.parametrize(
    "snapshots, whole", [(0.4, True), (1.0, False), (math.inf, False)]
)
def test_a_late_groups_read_shares_its_wait_with_the_snapshots_read(
    monkeypatch, snapshots, whole
):
    clock = use_clock(monkeypatch, Clock())
    names, nss = ["s0", "s1"], ["", "n0", "n1"]
    rows = [{"store": n, "total": 9, "used": 1, "avail": 8} for n in names]
    responses = _datastores_with(names, **{"/status/datastore-usage": ok(rows)})
    for store in names:
        responses[f"/admin/datastore/{store}/namespace"] = ok(
            [{"ns": ns} for ns in nss]
        )
        for ns in nss[1:]:
            responses[f"/admin/datastore/{store}/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/{store}/snapshots?ns={ns}"] = ok([])

    def latency(path):
        leaf = path.split("?")[0].rsplit("/", 1)[-1]
        return {
            "datastore-usage": 7.5,
            "namespace": 8,
            "groups": 4.5,
            "snapshots": snapshots,
        }.get(leaf, 0.05)

    session = _install_timed(monkeypatch, responses, clock, latency)
    read, longest = set(), 0.0
    for _ in range(12):
        out, _ = _timed_build(monkeypatch, clock, session)
        longest = max(longest, clock.now - session.started)
        for d in out["datastores"]:
            if d["namespaces"] is not None:  # listed whole this build
                unread = set(d["unread_namespaces"])
                read |= {(d["store"], ns) for ns in set(d["namespaces"]) - unread}
    assert (read == {(s, ns) for s in names for ns in nss}) is whole
    assert longest <= pbs.PBS_COLLECT_DEADLINE + pbs._TIMEOUT_BACKOFF_MIN_WAIT


# Value: protects=a first walk the budget skips at the very moment of
#   sending is handled like one the cutoff stopped: the reads stay where
#   they stand, the deferred walk stays deferred, its listing remembered;
#   fails_when=it counts as sent (the cursor moves past a datastore never
#   walked, its deferral is dropped, its listing forgotten); why_new=
#   pre-landing review (testing): two clock reads decided one send;
#   seam=none
def test_a_first_walk_skipped_at_its_send_keeps_the_cursor_and_the_deferral(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    real = pbs._read_namespaces

    def racing(session, target, errors, deadline, store):
        # Past the caller's cutoff check, before the send check.
        clock.now = max(clock.now, deadline - pbs._READ_TIMEOUT)
        return real(session, target, errors, deadline, store)

    session = _install_timed(
        monkeypatch, _datastores_with(["a", "b", "c"]), clock, lambda p: 0.05
    )
    _timed_build(monkeypatch, clock, session)  # every listing remembered
    monkeypatch.setattr(pbs, "_read_namespaces", racing)
    monkeypatch.setattr(pbs, "_rotation", ("b", ""))
    pbs._deferred_walks.add("b")
    _, sent = _timed_build(monkeypatch, clock, session)
    assert _walked(sent) == [] and pbs._rotation == ("b", "")
    assert "b" in pbs._deferred_walks and "b" in pbs._listings


# Value: protects=the first group read of a build that the budget skips at
#   the very moment of sending is not passed over: the next build starts at
#   it; fails_when=it counts as started (the next build moves past a
#   namespace never read, for a whole round); why_new=pre-landing review
#   (testing): two clock reads decided one send; seam=none
# Value (row): protects=the same when the budget runs out after _sub_read's
#   send check, at _get's own (a third clock read before the request goes
#   out); fails_when=that skip is not marked unsent; why_new=five review
#   specialists: the first row crossed the deadline only before _sub_read's
#   check; seam=none
@pytest.mark.parametrize("where", ["sub_read", "get"])
def test_a_first_group_read_skipped_at_its_send_is_read_first_next_time(
    monkeypatch, where
):
    clock = use_clock(monkeypatch, Clock())
    session = _install_timed(
        monkeypatch, _held_two_datastores(("", "x", "y")), clock, lambda p: 0.05
    )
    _timed_build(monkeypatch, clock, session)  # both listings remembered
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, ("usage", None, None, "t"))
    monkeypatch.setattr(pbs, "_rotation", ("a", "x"))
    if where == "sub_read":
        real = pbs._read_groups

        def racing(session, target, errors, deadline, store, ns, room):
            clock.now = max(clock.now, deadline)  # past the check, before the send
            return real(session, target, errors, deadline, store, ns, room)

        monkeypatch.setattr(pbs, "_read_groups", racing)
    else:
        real_hit = pbs._deadline_hit

        def racing_hit(deadline, errors, scope, store=None, ns=None):
            hit = real_hit(deadline, errors, scope, store=store, ns=ns)
            if scope == "groups" and not hit:
                clock.now = max(clock.now, deadline)  # before _get's own check
            return hit

        monkeypatch.setattr(pbs, "_deadline_hit", racing_hit)
    out, sent = _timed_build(monkeypatch, clock, session)
    assert not [p for p in sent if "/groups" in p]
    assert pbs._rotation == ("a", "x")
    # Value (extension): protects=every namespace that build did not read is
    #   named in errors[] with the budget as its cause (the walks are held:
    #   no namespaces list carries them); fails_when=only the unsent read is
    #   named and the five after it go unread silently; why_new=the test
    #   checked the cursor only; seam=none
    skipped = [
        (e["store"], e["ns"], e["message"])
        for e in out["errors"]
        if e["scope"] == "groups"
    ]
    assert skipped == [
        ("a", "x", pbs._DEADLINE_MESSAGE),
        ("a", None, f"{pbs._DEADLINE_MESSAGE} (2 namespace(s) not read)"),
        ("b", None, f"{pbs._DEADLINE_MESSAGE} (3 namespace(s) not read)"),
    ]


# Value: protects=a /snapshots read sent before the budget ran out keeps its
#   own minimum wait, even after a /groups read sent late that answered in
#   time, so a slow namespace is still read whole; fails_when=the /groups
#   read's wait caps it (the namespace times out on every build and is
#   never read whole); why_new=pre-landing review (performance): the shared
#   wait regressed this case; seam=none
def test_a_snapshots_read_sent_before_the_budget_keeps_its_own_wait(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    nss = ["", "n0", "n1", "n2"]
    rows = [{"store": "ds", "total": 9, "used": 1, "avail": 8}]
    responses = _datastores_with(["ds"], **{"/status/datastore-usage": ok(rows)})
    responses["/admin/datastore/ds/namespace"] = ok([{"ns": n} for n in nss])
    for ns in nss[1:]:
        responses[f"/admin/datastore/ds/groups?ns={ns}"] = ok([])
        responses[f"/admin/datastore/ds/snapshots?ns={ns}"] = ok([])

    def latency(path):
        leaf = path.split("?")[0].rsplit("/", 1)[-1]
        return {
            "datastore-usage": 6,
            "namespace": 9,
            "groups": 2,
            "snapshots": 3.5,
        }.get(leaf, 0.05)

    session = _install_timed(monkeypatch, responses, clock, latency)
    read = set()
    for _ in range(12):
        out, _ = _timed_build(monkeypatch, clock, session)
        d = out["datastores"][0]
        if d["namespaces"] is not None:
            read |= set(d["namespaces"]) - set(d["unread_namespaces"])
    assert read == set(nss)


# Value: protects=a live /snapshots read reached on what is left of its
#   /groups read's wait, past the budget, never arms the group-reads hold
#   under the walk hold, nor costs its datastore the listing remembered;
#   fails_when=its clamped timeout is taken for a stuck datastore (every
#   group read stops until a reload, or the datastore's groups stop
#   shipping); why_new=pre-landing review (red team); seam=none
@pytest.mark.parametrize("held", [True, False], ids=["walks_held", "not_held"])
def test_a_snapshots_read_on_its_groups_wait_never_holds_nor_forgets_the_listing(
    monkeypatch, held
):
    clock = use_clock(monkeypatch, Clock())
    latency = {}
    session = _install_timed(
        monkeypatch, _held_two_datastores(), clock, lambda p: latency.get(p, 0.05)
    )
    _timed_build(monkeypatch, clock, session)
    logged = []
    monkeypatch.setattr(
        pbs, "log", lambda message, level="info": logged.append((level, message))
    )
    if held:
        failure = ("usage", None, None, "t")
        pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    for store in ("a", "b"):
        for query in ("", "?ns=x"):
            latency[f"/admin/datastore/{store}/groups{query}"] = 3.5
            latency[f"/admin/datastore/{store}/snapshots{query}"] = 2.5
    real = pbs._read_all_groups

    def late(session, target, errors, deadline, *args):
        clock.now = max(clock.now, deadline - 3.0)
        return real(session, target, errors, deadline, *args)

    monkeypatch.setattr(pbs, "_read_all_groups", late)
    sent, cut = [], []
    for _ in range(8):
        out, paths = _timed_build(monkeypatch, clock, session)
        sent += [p for p in paths if p.split("?")[0].endswith("/snapshots")]
        cut += [e["message"] for e in out["errors"] if e["scope"] == "snapshots"]
    assert sent  # the /snapshots reads were sent on the /groups wait
    assert pbs._GROUPS_HOLD not in pbs._timeout_backoff
    assert set(pbs._listings) == {"a", "b"}
    # Value (extension): protects=such a cut reads like the same read refused
    #   at its send: errors[] names the budget (or, once noted twice, its
    #   backoff), and no error line is logged; fails_when=its raw timeout
    #   message ships and an error line is logged for each namespace (a busy
    #   tick reads as a failing PBS); why_new=pre-landing review (testing):
    #   only the hold and the listing were pinned; seam=none
    assert pbs._DEADLINE_MESSAGE in cut
    assert set(cut) <= {pbs._DEADLINE_MESSAGE, pbs._TIMEOUT_BACKOFF_MESSAGE}
    assert not [m for level, m in logged if level == "error" and "snapshots" in m]


# Value: protects=a /snapshots read on its /groups read's wait that never
#   answers is noted, then backed off like a late read, so it is not sent
#   again on every build, and its datastore keeps its listing and its group
#   reads; fails_when=a budget-cut timeout leaves no trace (a stuck
#   /snapshots reached only on that wait is sent on every build, 60 in 60,
#   each a PBS proxy thread it may pin) or takes the namespace side effects
#   of a stuck read; why_new=pre-landing review (performance), reproduced;
#   seam=none
def test_a_stuck_snapshots_read_on_the_groups_wait_backs_off(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    responses = _datastores_with(["s0"])
    responses["/admin/datastore/s0/namespace"] = ok([{"ns": ""}, {"ns": "n0"}])
    responses["/admin/datastore/s0/groups?ns=n0"] = ok([])
    responses["/admin/datastore/s0/snapshots?ns=n0"] = ok([])
    latency = {
        path: 1.5
        for path in (
            "/access/permissions",
            "/admin/datastore",
            "/status/datastore-usage",
            "/admin/sync?sync-direction=all",
            "/admin/verify",
            "/admin/prune",
        )
    }
    latency["/admin/datastore/s0/namespace"] = 9.5
    latency["/admin/datastore/s0/groups?ns=n0"] = 3  # answers past the budget
    latency["/admin/datastore/s0/snapshots?ns=n0"] = math.inf  # never answers
    session = _install_timed(
        monkeypatch, responses, clock, lambda p: latency.get(p, 0.05)
    )
    per_build = []
    for _ in range(60):
        _, sent = _timed_build(monkeypatch, clock, session)
        per_build.append(sent.count("/admin/datastore/s0/snapshots?ns=n0"))
    sends = sum(per_build)
    assert 2 <= sends <= 8, sends  # one rebuild, then twice as long each time
    # Value (extension): protects=the first such timeout is only noted, so the
    #   next build sends it again; fails_when=it arms the backoff at once (a
    #   live namespace slower than the grace waits a rebuild for nothing);
    #   why_new=pre-landing review (testing): the bound accepted both;
    #   seam=none
    assert per_build[:2] == [1, 1]
    assert pbs._GROUPS_HOLD not in pbs._timeout_backoff
    assert "s0" in pbs._listings


# Value: protects=a /snapshots timeout on its /groups read's wait never keeps
#   the next build's send of that read -- with its whole minimum wait --
#   from being sent, even after an earlier real timeout; fails_when=the
#   grace timeouts share the read's own backoff (a hopeless send on the grace
#   backs off the timely one, and a slow namespace is never read whole: 0
#   reads in 80 simulated builds instead of 7); why_new=pre-landing review
#   (performance), reproduced; seam=none
def test_a_grace_timeout_never_keeps_back_the_next_timely_send(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    session = _install_timed(
        monkeypatch,
        _datastores_with(["a"]),
        clock,
        lambda p: 4.5 if "snapshots" in p else 0.05,
    )
    path = "/admin/datastore/a/snapshots"
    key = pbs._timeout_backoff_key(path, None)
    pbs._timeout_backoff[key] = (clock.now - 1, 1, ("snapshots", "a", "", "t"))
    errors = pbs._Errors(str)
    pbs._sub_read(  # on the /groups read's wait, 2s left: times out
        session,
        _target(),
        errors,
        clock.now + 2,
        "snapshots",
        path,
        store="a",
        ns="",
        backoff="retry",
        budget_cut=True,
    )
    clock.now += pbs.PBS_CACHE_TTL + 20  # the next build, this namespace first
    sent = len(session.calls)
    out = pbs._sub_read(
        session,
        _target(),
        errors,
        clock.now + 15,
        "snapshots",
        path,
        store="a",
        ns="",
        backoff="retry",
    )
    assert len(session.calls) == sent + 1 and out == []
    assert not [k for k in pbs._timeout_backoff if k[0] == path]  # answered


# Value: protects=a /snapshots read on its /groups read's wait that answers
#   clears the read's own backoff too: it answers now; fails_when=an answer
#   on the grace leaves the read backed off (the next build's send with its
#   whole wait is skipped, the namespace unread for nothing); why_new=pre-
#   landing review (mutation testing); seam=none
def test_an_answer_on_the_grace_clears_the_reads_own_backoff(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    session = _install_timed(
        monkeypatch, _datastores_with(["a"]), clock, lambda p: 0.05
    )
    path = "/admin/datastore/a/snapshots"
    key = pbs._timeout_backoff_key(path, None)
    failure = ("snapshots", "a", "", "t")
    pbs._timeout_backoff[key] = (clock.now - 1, 2, failure)  # its retry due
    out = pbs._sub_read(
        session,
        _target(),
        pbs._Errors(str),
        clock.now + 2,
        "snapshots",
        path,
        store="a",
        ns="",
        backoff="retry",
        budget_cut=True,
    )
    assert out == [] and key not in pbs._timeout_backoff


# Value: protects=a /snapshots send on its /groups read's wait respects the
#   read's own backoff (armed by a timeout after its whole minimum wait),
#   while a note (count 0) never holds it back; fails_when=the grace path
#   checks only its own note (on a dead mount each backoff window of the
#   read gets two more hopeless sends: twice the proxy threads it may pin,
#   14 sends in 120 simulated builds instead of 7); why_new=scoped review of
#   the grace notes, reproduced; seam=none
@pytest.mark.parametrize("count, sent", [(1, False), (0, True)])
def test_a_grace_send_respects_the_reads_own_backoff(monkeypatch, count, sent):
    clock = use_clock(monkeypatch, Clock())
    session = _install_timed(
        monkeypatch, _datastores_with(["a"]), clock, lambda p: 0.05
    )
    path = "/admin/datastore/a/snapshots"
    key = pbs._timeout_backoff_key(path, None)
    retry_at = clock.now + 600 if count else clock.now
    pbs._timeout_backoff[key] = (retry_at, count, ("snapshots", "a", "", "t"))
    before = len(session.calls)
    pbs._sub_read(
        session,
        _target(),
        pbs._Errors(str),
        clock.now + 2,
        "snapshots",
        path,
        store="a",
        ns="",
        backoff="retry",
        budget_cut=True,
    )
    assert (len(session.calls) > before) is sent


class _StallingSession(_TimedSession):
    """A _TimedSession whose stalled TLS handshakes last their connect
    timeout, as on the wire."""

    def get(self, url, params=None, timeout=None, stream=None, allow_redirects=None):
        try:
            return super().get(url, params, timeout, stream, allow_redirects)
        except HandshakeStall:
            self.clock.now += timeout[0]
            raise


# Value: protects=a connect timeout or a stalled TLS handshake of a
#   /snapshots read on its /groups read's wait reads as the budget, like a
#   read timeout there; a connect timeout (never reached PBS) leaves no
#   backoff, while a handshake stalled for its whole connect timeout -- the
#   whole clamp, with no minimum wait -- is noted, the safe side for the
#   PBS; fails_when=only a read timeout that waited its whole clamp is taken
#   for the budget (the raw transport message ships and an error line is
#   logged for each namespace, every build), or a request that never
#   reached PBS is noted; why_new=pre-landing review (testing, coverage
#   audit): only a read timeout was pinned, and the stall lasted no time;
#   seam=none
@pytest.mark.parametrize(
    "error, noted", [("connect_timeout", False), ("handshake_timeout", True)]
)
def test_a_connect_timeout_on_the_groups_wait_is_a_budget_skip(
    monkeypatch, error, noted
):
    clock = use_clock(monkeypatch, Clock())
    responses = _held_two_datastores()
    latency = {}
    session = _StallingSession(responses, clock, lambda p: latency.get(p, 0.05))
    monkeypatch.setattr(pbs, "_new_session", lambda target: session)
    monkeypatch.setattr(pbs, "_peer_fingerprint", lambda response: None)
    _timed_build(monkeypatch, clock, session)
    logged = []
    monkeypatch.setattr(
        pbs, "log", lambda message, level="info": logged.append((level, message))
    )
    for store in ("a", "b"):
        for query in ("", "?ns=x"):
            latency[f"/admin/datastore/{store}/groups{query}"] = 3.5
            responses[f"/admin/datastore/{store}/snapshots{query}"] = {"error": error}
    real = pbs._read_all_groups

    def late(session, target, errors, deadline, *args):
        clock.now = max(clock.now, deadline - 3.0)
        return real(session, target, errors, deadline, *args)

    monkeypatch.setattr(pbs, "_read_all_groups", late)
    out, sent = _timed_build(monkeypatch, clock, session)
    assert [p for p in sent if p.split("?")[0].endswith("/snapshots")]
    cut = [e["message"] for e in out["errors"] if e["scope"] == "snapshots"]
    assert cut and set(cut) == {pbs._DEADLINE_MESSAGE}
    assert not [m for level, m in logged if level == "error" and "snapshots" in m]
    assert (
        bool([k for k in pbs._timeout_backoff if k[0].endswith("/snapshots")]) is noted
    )


# Value: protects=a stuck /snapshots first reached only on its /groups
#   read's wait (noted, backed off, never logged) still logs its first real
#   failure -- sent early, after its whole minimum wait -- at error;
#   fails_when=the note records the raw transport message (its backoff
#   skips mark that failure as already reported, so the operator never
#   sees an error line for a stuck datastore); why_new=pre-landing review
#   (coverage audit), reproduced; seam=none
def test_a_budget_cut_snapshots_history_does_not_silence_its_first_real_failure(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    responses = _datastores_with(["s0"])
    responses["/admin/datastore/s0/namespace"] = ok([{"ns": ""}, {"ns": "n0"}])
    responses["/admin/datastore/s0/snapshots"] = ok([])
    responses["/admin/datastore/s0/groups?ns=n0"] = ok([])
    responses["/admin/datastore/s0/snapshots?ns=n0"] = ok([])
    latency = {}
    session = _install_timed(
        monkeypatch, responses, clock, lambda p: latency.get(p, 0.05)
    )
    _timed_build(monkeypatch, clock, session)
    logged = []
    monkeypatch.setattr(
        pbs, "log", lambda message, level="info": logged.append((level, message))
    )
    latency["/admin/datastore/s0/snapshots?ns=n0"] = math.inf  # stuck from now on
    latency["/admin/datastore/s0/groups?ns=n0"] = 3.5
    real = pbs._read_all_groups

    def late(session, target, errors, deadline, *args):
        clock.now = max(clock.now, deadline - 3.0)
        return real(session, target, errors, deadline, *args)

    monkeypatch.setattr(pbs, "_read_all_groups", late)
    for _ in range(3):  # noted, backed off, skipped
        _timed_build(monkeypatch, clock, session)
    monkeypatch.setattr(pbs, "_read_all_groups", real)
    del latency["/admin/datastore/s0/groups?ns=n0"]
    early = 0
    for _ in range(6):
        _, sent = _timed_build(monkeypatch, clock, session)
        early += sent.count("/admin/datastore/s0/snapshots?ns=n0")
    assert early  # sent early, with its minimum wait
    assert [m for level, m in logged if level == "error" and "snapshots read" in m]


# Value: protects=on a healthy PBS whose gc reads do not all fit the
#   per-datastore half, the one its half cuts short ships as the budget skip
#   and logs no error line; fails_when=a read sent without its minimum wait,
#   clamped to a few ms, logs its timeout at error and ships it raw (one false
#   error a build, each naming another datastore, so it never quiets);
#   why_new=pre-landing review (red team), reproduced; seam=none
def test_a_gc_read_its_half_cuts_short_is_no_error_line(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i:02d}" for i in range(30)]
    session = _install_timed(
        monkeypatch,
        _datastores_with(names),
        clock,
        lambda p: 0.4 if p.endswith("/gc") else 0.05,
    )
    logged = []
    monkeypatch.setattr(
        pbs, "log", lambda message, level="info": logged.append((level, message))
    )
    shipped = []
    for _ in range(5):
        out, _ = _timed_build(monkeypatch, clock, session)
        shipped += [e["message"] for e in out["errors"] if e["scope"] == "gc"]
    assert not [m for level, m in logged if level == "error"]
    assert shipped and set(shipped) <= {
        pbs._DEADLINE_MESSAGE,
        pbs._TIMEOUT_BACKOFF_MESSAGE,
    }


# Value: protects=a gc that never answers -- its read or its connection
#   timing out -- on a PBS whose builds never leave room for its minimum
#   wait, still logs one error line: noted the first time, it is a failure
#   the next; fails_when=every timeout of a read sent without its wait ships
#   as the budget skip, or a connect timeout is never noted (the stuck gc,
#   or a proxy too busy to accept, is silent for good); why_new=scoped
#   review of the budget-cut rule (and the outside review's connect-timeout
#   case), reproduced; seam=none
@pytest.mark.parametrize("stuck", ["read", "connect"])
def test_a_stuck_gc_without_room_for_its_wait_is_still_logged(monkeypatch, stuck):
    clock = use_clock(monkeypatch, Clock())
    logged = []
    monkeypatch.setattr(
        pbs, "log", lambda message, level="info": logged.append((level, message))
    )
    latency = {
        path: 1.5
        for path in (
            "/access/permissions",
            "/admin/datastore",
            "/status/datastore-usage",
            "/admin/sync?sync-direction=all",
            "/admin/verify",
            "/admin/prune",
        )
    }
    latency["/admin/datastore/s0/namespace"] = 9.0
    latency["/admin/datastore/s1/namespace"] = 9.0
    responses = _datastores_with(["s0", "s1"])
    if stuck == "read":
        latency["/admin/datastore/s1/gc"] = math.inf  # never answers
    else:
        responses["/admin/datastore/s1/gc"] = {"error": "connect_timeout"}
    session = _install_timed(
        monkeypatch, responses, clock, lambda p: latency.get(p, 0.05)
    )
    for _ in range(40):
        _timed_build(monkeypatch, clock, session)
    errors = [m for level, m in logged if level == "error" and "gc" in m]
    assert len(errors) == 1, errors


# Value: protects=a /snapshots read on its /groups read's wait that PBS
#   answers with an HTTP error keeps that error: errors[] names it and it
#   is logged as a failure (an HTTP status is evidence, whatever the
#   timing); fails_when=
#   any failure of such a read reads as the budget (a datastore whose
#   snapshot listing fails is reported as merely busy); why_new=pre-landing
#   review (mutation testing): only a timeout there was pinned; seam=none
def test_an_http_error_on_the_groups_wait_is_no_budget_cut(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    responses = _held_two_datastores()
    latency = {}
    for store in ("a", "b"):
        for query in ("", "?ns=x"):
            responses[f"/admin/datastore/{store}/snapshots{query}"] = fail(400, "x")
    session = _install_timed(
        monkeypatch, responses, clock, lambda p: latency.get(p, 0.05)
    )
    _timed_build(monkeypatch, clock, session)
    logged = []
    monkeypatch.setattr(
        pbs, "log", lambda message, level="info": logged.append((level, message))
    )
    for store in ("a", "b"):
        for query in ("", "?ns=x"):
            latency[f"/admin/datastore/{store}/groups{query}"] = 3.5
    real = pbs._read_all_groups

    def late(session, target, errors, deadline, *args):
        clock.now = max(clock.now, deadline - 3.0)
        return real(session, target, errors, deadline, *args)

    monkeypatch.setattr(pbs, "_read_all_groups", late)
    out, sent = _timed_build(monkeypatch, clock, session)
    assert [p for p in sent if p.split("?")[0].endswith("/snapshots")]
    cut = [e["message"] for e in out["errors"] if e["scope"] == "snapshots"]
    assert cut and all(m.startswith("HTTP 400") for m in cut)
    # Logged (at debug: the same failure as the build before), as a failure.
    assert [m for _, m in logged if m.startswith("PBS snapshots read failed")]


# Value: protects=after any reload that lifts a hold, or while the usage
#   status is backed off, the builds until the walks went round read each
#   datastore's own status instead and the next one sends the usage status
#   again; fails_when=the reload clears the backoff (a usage status on a
#   storage still dead re-arms the hold before any walk) or keeps it past
#   the build whose walks went round; why_new=pre-landing review (security,
#   simplification, coverage audit): a second SIGHUP, or a walk-armed hold,
#   cleared it; seam=none
@pytest.mark.parametrize("gap", [30, pbs.PBS_CACHE_TTL + 20], ids=["tick", "late"])
@pytest.mark.parametrize(
    "before",
    ["usage_hold", "walk_hold", "group_hold", "backed_off", "double_reload"],
)
def test_a_reload_keeps_the_usage_status_backed_off_until_the_walks_went_round(
    monkeypatch, before, gap
):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b"]
    session = _install_timed(
        monkeypatch, _datastores_with(names), clock, lambda p: 0.05
    )
    _timed_build(monkeypatch, clock, session)
    failures = {
        "usage_hold": (pbs._WALK_HOLD, ("usage", None, None, "t")),
        "walk_hold": (pbs._WALK_HOLD, ("namespaces", "b", None, "t")),
        "group_hold": (pbs._GROUPS_HOLD, ("groups", "b", "", "t")),
    }
    if before in failures:
        key, failure = failures[before]
        pbs._timeout_backoff[key] = (math.inf, 1, failure)
    else:
        failure = ("usage", None, None, "t")
        retry_at = clock.now + 4 * pbs.PBS_CACHE_TTL
        pbs._timeout_backoff[pbs._USAGE_BACKOFF] = (retry_at, 2, failure)
    pbs.reset_timeout_holds()
    if before == "double_reload":
        pbs.reset_timeout_holds()
    # A usage status backed off before keeps its doubling count.
    count = 0 if before in failures else 2
    assert pbs._timeout_backoff[pbs._USAGE_BACKOFF][1] == count
    # The first build after the reload -- on the next tick, or later on an
    # agent whose interval is longer than the cache.
    out, sent = _timed_build(monkeypatch, clock, session, gap=gap)
    assert "/status/datastore-usage" not in sent
    assert {"scope": "usage", "store": None, "ns": None} | {
        "message": pbs._USAGE_DEFERRED_MESSAGE
    } in out["errors"]
    assert [d["total"] for d in out["datastores"]] == [9, 9]
    # Value: protects=the build that skips it keeps its doubling count, so a
    #   usage status that again leaves the walks no time backs off from where
    #   it was; fails_when=that build restarts the count (a slow usage status
    #   is re-sent several times as often after a reload); why_new=only the
    #   count right after the reload was checked; seam=none
    assert pbs._timeout_backoff[pbs._USAGE_BACKOFF][1] == count
    _, sent = _timed_build(monkeypatch, clock, session)  # the next one
    assert "/status/datastore-usage" in sent
    assert pbs._USAGE_BACKOFF not in pbs._timeout_backoff


# Value: protects=the reload's keep-back of the usage status is used up only
#   once the walks went round: after a build with no walk -- an abandoned
#   worker finishing past its deadline, or job lists that took the budget --
#   the next build still walks the other datastores before the usage status
#   is sent; fails_when=the first build after the reload uses it up whatever
#   it walked (the next sends the usage status first and, on a storage still
#   dead, re-arms the hold with nothing walked: the reload was for nothing);
#   why_new=pre-landing review (red team), reproduced; seam=none
@pytest.mark.parametrize("late", ["abandoned", "no_walk_time"])
def test_the_reload_keep_back_outlasts_a_build_with_no_walk(monkeypatch, late):
    clock = use_clock(monkeypatch, Clock())
    latency = {  # b's storage is dead: its walk and the usage status hang
        "/status/datastore-usage": math.inf,
        "/admin/datastore/b/namespace": math.inf,
    }
    session = _install_timed(
        monkeypatch,
        _datastores_with(["a", "b"]),
        clock,
        lambda p: latency.get(p, 0.05),
    )
    failure = ("namespaces", "b", None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    if late == "abandoned":
        real = pbs._read_usage

        def stalled(session, target, errors, deadline, listed):
            monkeypatch.setattr(pbs, "_read_usage", real)
            clock.now = deadline + pbs.PBS_HARD_DEADLINE  # a SIGHUP meanwhile
            pbs.reset_timeout_holds()
            return real(session, target, errors, deadline, listed)

        monkeypatch.setattr(pbs, "_read_usage", stalled)
    else:
        pbs.reset_timeout_holds()
        latency.update({"/admin/verify": 9.5, "/admin/prune": 9.5})
    _, sent = _timed_build(monkeypatch, clock, session, gap=30)
    assert _walked(sent) == [] and "/status/datastore-usage" not in sent
    assert pbs._timeout_backoff[pbs._USAGE_BACKOFF][0] == math.inf
    latency.pop("/admin/verify", None)
    latency.pop("/admin/prune", None)
    _, sent = _timed_build(monkeypatch, clock, session, gap=30)
    assert _walked(sent) == ["a"] and "/status/datastore-usage" not in sent
    _, sent = _timed_build(monkeypatch, clock, session, gap=30)
    assert "/status/datastore-usage" in sent  # b still dead: the hold again
    assert pbs._WALK_HOLD in pbs._timeout_backoff


# Value: protects=the reload's keep-back of the usage status lasts until
#   every datastore not deferred has been walked since the reload, over as
#   many builds as that takes; fails_when=a build with one walk uses it up
#   (the next sends the usage status before the other datastores are
#   walked); why_new=pre-landing review (red team); seam=none
def test_the_reload_keep_back_lasts_until_the_walks_went_round(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c", "d"]
    latency = {f"/admin/datastore/{n}/namespace": 8 for n in names}  # one a build
    session = _install_timed(
        monkeypatch, _datastores_with(names), clock, lambda p: latency.get(p, 0.05)
    )
    failure = ("usage", None, None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    walked, usage_sent = [], []
    for _ in range(5):
        _, sent = _timed_build(monkeypatch, clock, session, gap=30)
        walked.append(_walked(sent))
        usage_sent.append("/status/datastore-usage" in sent)
    assert walked[:4] == [["a"], ["b"], ["c"], ["d"]]
    assert usage_sent == [False, False, False, False, True]
    # Value (extension): protects=each reload starts a new round: the walks
    #   counted for an earlier reload do not release the next one's keep-back;
    #   fails_when=the walks are not forgotten by a reload (the usage status
    #   goes first right after the second reload); why_new=pre-landing review
    #   (mutation testing); seam=none
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    usage_sent = []
    for _ in range(4):
        _, sent = _timed_build(monkeypatch, clock, session, gap=30)
        usage_sent.append("/status/datastore-usage" in sent)
    assert usage_sent == [False, False, False, False]


# Value: protects=on a large healthy PBS the reload's keep-back of the usage
#   status ends within a few builds: while it is on, the walks start at the
#   first datastore not walked since the reload; fails_when=they start where
#   the group reads stand (they go round only as fast as the group reads
#   move: 39 builds, ~3.5h without an estimated full date, on 40 datastores
#   of 20 namespaces); why_new=pre-landing review (performance, red team),
#   reproduced; seam=none
def test_the_reload_keep_back_ends_within_a_few_builds_on_a_large_pbs(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i:03d}" for i in range(40)]
    spaces = [""] + [f"n{j:02d}" for j in range(19)]
    responses = _datastores_with(names)
    for store in names:
        responses[f"/admin/datastore/{store}/namespace"] = ok(
            [{"ns": ns} for ns in spaces]
        )
        for ns in spaces[1:]:
            responses[f"/admin/datastore/{store}/groups?ns={ns}"] = ok([])
            responses[f"/admin/datastore/{store}/snapshots?ns={ns}"] = ok([])

    def latency(path):
        if path.endswith("/namespace"):
            return 0.3
        return 0.6 if "/groups" in path or "/snapshots" in path else 0.03

    session = _install_timed(monkeypatch, responses, clock, latency)
    for _ in range(3):
        _timed_build(monkeypatch, clock, session)
    failure = ("namespaces", "s020", None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    usage_sent = []
    for build in range(5):  # about 20 of the 40 datastores walked a build
        _, sent = _timed_build(
            monkeypatch, clock, session, gap=30 if build == 0 else None
        )
        usage_sent.append("/status/datastore-usage" in sent)
    assert True in usage_sent, usage_sent


# Value: protects=a reload that lifts no hold (SIGHUP is also the agent's
#   capability refresh, sent by tooling) does not restart the keep-back's
#   round: the walks done since the reload that lifted the hold still count;
#   fails_when=every reload restarts it (with reloads closer together than a
#   round, the usage status is never read again); why_new=pre-landing review
#   (mutation testing); seam=none
def test_an_unrelated_reload_keeps_the_keep_back_round_going(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c", "d"]
    latency = {f"/admin/datastore/{n}/namespace": 8 for n in names}  # one a build
    session = _install_timed(
        monkeypatch, _datastores_with(names), clock, lambda p: latency.get(p, 0.05)
    )
    failure = ("usage", None, None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    usage_sent = []
    for build in range(5):
        if build == 2:
            pbs.reset_timeout_holds()  # a capability refresh, no hold to lift
        _, sent = _timed_build(monkeypatch, clock, session, gap=30)
        usage_sent.append("/status/datastore-usage" in sent)
    assert usage_sent == [False, False, False, False, True]


# Value: protects=a reload that lifts no hold, once the keep-back's round is
#   complete, never jumps the walks to the suspect datastore before the group
#   reads reach it; fails_when=the ahead start lands on the only datastore not
#   walked -- the deferred one -- and walks it first while the other
#   datastores' namespaces are still unread (on a storage still dead it
#   re-arms the hold before they are read); why_new=scoped review of the
#   ahead start, reproduced; seam=none
def test_an_unrelated_reload_after_the_round_never_walks_the_suspect_first(
    monkeypatch,
):
    clock = use_clock(monkeypatch, Clock())
    names = ["a", "b", "c", "d"]
    responses = _datastores_with(names)
    for store in names:
        responses[f"/admin/datastore/{store}/namespace"] = ok(
            [{"ns": ""}] + [{"ns": f"n{i}"} for i in range(4)]
        )
        for i in range(4):
            responses[f"/admin/datastore/{store}/groups?ns=n{i}"] = ok([])
            responses[f"/admin/datastore/{store}/snapshots?ns=n{i}"] = ok([])

    def latency(path):
        dead = path.startswith("/admin/datastore/b/")
        if dead and path.rsplit("/", 1)[-1].split("?")[0] in (
            "namespace",
            "groups",
            "snapshots",
        ):
            return math.inf  # b's storage is still dead
        if "/groups" in path:
            return 3.0  # the group reads take several builds
        return 1.0 if path.endswith("/namespace") else 0.05

    session = _install_timed(monkeypatch, responses, clock, latency)
    failure = ("namespaces", "b", None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    _, sent = _timed_build(monkeypatch, clock, session, gap=60)
    assert _walked(sent) == ["c", "d", "a"]  # the round, b deferred
    pbs.reset_timeout_holds()  # a capability refresh: no hold to lift
    _, sent = _timed_build(monkeypatch, clock, session, gap=60)
    assert _walked(sent)[:1] != ["b"]
    assert pbs._WALK_HOLD not in pbs._timeout_backoff


# Value: protects=after an agent restart, with a full-scope token and one
#   storage still dead, the operator's reloads walk every healthy datastore;
#   fails_when=the keep-back is used up before the walks went round (the
#   usage status re-arms a hold naming no datastore, the held group reads
#   move the rotation back to the few datastores remembered, and every
#   reload walks the same two: 7 of 9 healthy ones never walked); why_new=
#   pre-landing review (red team), reproduced; seam=none
def test_reloads_after_a_restart_walk_every_healthy_datastore(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    names = [f"s{i:02d}" for i in range(10)]

    def latency(path):
        if "/datastore/s05/" in path or path == "/status/datastore-usage":
            return math.inf  # dead hard-mounted NFS: statfs and readdir hang
        return 3.0 if path.endswith("/namespace") else 0.05

    session = _install_timed(monkeypatch, _datastores_with(names), clock, latency)
    _timed_build(monkeypatch, clock, session)  # restarted: usage first, held
    assert pbs._WALK_HOLD in pbs._timeout_backoff
    walked = set()
    for _ in range(5):
        pbs.reset_timeout_holds()
        for build in range(10):
            gap = 30 if build == 0 else None
            _, sent = _timed_build(monkeypatch, clock, session, gap=gap)
            walked |= set(_walked(sent))
            if pbs._WALK_HOLD in pbs._timeout_backoff:
                break
    assert set(names) - {"s05"} <= walked, sorted(walked)


# Value: protects=a scoped token, which never reads the usage status, never
#   uses up the reload's keep-back either: once the token reaches full scope,
#   its first build still reads each datastore's own status and walks first;
#   fails_when=a scoped build whose walks went round uses it up (the
#   first full-scope build sends the usage status before any walk); why_new=
#   pre-landing review: the keep-back is consumed in _build_block now, which
#   scoped builds run too; seam=none
def test_a_scoped_token_never_uses_up_the_reload_keep_back(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    responses = _datastores_with(["a", "b"])
    scoped = {f"/datastore/{n}": {"Datastore.Audit": True} for n in ("a", "b")}
    session = _install_timed(monkeypatch, responses, clock, lambda p: 0.05)
    failure = ("usage", None, None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    pbs.reset_timeout_holds()
    sent_usage = []
    for perms in (scoped, PERMS_FULL, PERMS_FULL):
        responses["/access/permissions"] = ok(perms)
        _, sent = _timed_build(monkeypatch, clock, session, gap=30)
        sent_usage.append("/status/datastore-usage" in sent)
        if perms is scoped:
            assert pbs._timeout_backoff[pbs._USAGE_BACKOFF][:2] == (math.inf, 0)
    assert sent_usage == [False, False, True]


# Value: protects=while every walk is held, a usage status also backed off
#   is reported as held -- the actionable reason (repair, then reload);
#   fails_when=the backoff skip comes first and blames the walks' time;
#   why_new=coverage audit: no test set both; seam=none
def test_a_held_usage_status_reports_the_hold_even_when_backed_off(monkeypatch):
    clock = use_clock(monkeypatch, Clock())
    session = _install_timed(
        monkeypatch, _datastores_with(["a"]), clock, lambda p: 0.05
    )
    failure = ("usage", None, None, "t")
    pbs._timeout_backoff[pbs._WALK_HOLD] = (math.inf, 1, failure)
    retry_at = clock.now + 10 * pbs.PBS_CACHE_TTL
    pbs._timeout_backoff[pbs._USAGE_BACKOFF] = (retry_at, 1, failure)
    out, _ = _timed_build(monkeypatch, clock, session)
    usage = [e["message"] for e in out["errors"] if e["scope"] == "usage"]
    assert usage == [pbs._TIMEOUT_HOLD_MESSAGE]
