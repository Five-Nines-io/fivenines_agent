"""Tests for the MongoDB collector (#258, server #493).

The contract fixture replays through the real collector with only the pymongo
client replaced (tests/mongodb_fake.py: command in, reply or exception out).
The unit tests below pin each rule the fixture states, independently of it:
config validation, the MongoClient options, the error classification, the lag
and age rules, the section accounting and the two time bounds.
"""

import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from pymongo import errors

from fivenines_agent import mongodb
from tests import mongodb_fake

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "mongodb_contract_payload.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
SCENARIOS = FIXTURE["scenarios"]

ENVELOPE_KEYS = {
    "reachable",
    "error_type",
    "error_message",
    "process",
    "role",
    "version",
    "me",
    "collection",
    "node",
    "replica_set",
    "sharding",
}
FLAGS = ("server_status_ok", "repl_status_ok", "repl_config_ok", "oplog_ok")

# The collector refuses a unix socket host where the OS has none (Windows,
# where windows.yml runs this suite too).
needs_af_unix = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="no unix sockets on this OS"
)

CONFIG = {
    "host": "127.0.0.1",
    "port": 27017,
    "username": "fivenines",
    "password": "fake-password",
    "auth_source": "admin",
    "auth_mechanism": None,
    "tls": False,
    "tls_ca_file": None,
    "tls_certificate_key_file": None,
    "tls_allow_invalid_certificates": False,
}


@pytest.fixture(autouse=True)
def _reset_module_state(monkeypatch):
    monkeypatch.setattr(mongodb, "_last_logged", {})
    monkeypatch.setattr(mongodb, "_stalled_worker", None)
    yield
    # A real client's threads end shortly after close(): let them, or the
    # next test's driver-thread single flight sees them (an agent tick is a
    # minute later).
    for thread in threading.enumerate():
        if thread.name.startswith("pymongo_"):
            thread.join(10)


def resolve(name):
    """A scenario's mongo map with its mongo_base applied."""
    scenario = SCENARIOS[name]
    base = resolve(scenario["mongo_base"]) if "mongo_base" in scenario else {}
    return {**base, **scenario["mongo"]}


def collect(monkeypatch, mongo, **config):
    clients = mongodb_fake.install(monkeypatch, mongo)
    result = mongodb.mongodb_metrics(**{**CONFIG, **config})
    return result, clients


def calls_as_keys(client):
    keys = set()
    for call in client.calls:
        keys.add("oplog" if call.startswith("oplog.") else call)
    return keys


# --- the contract fixture ---------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(n, marks=needs_af_unix) if n == "unix_socket" else n
        for n in SCENARIOS
    ],
)
def test_contract_fixture_round_trip(monkeypatch, name):
    scenario = SCENARIOS[name]
    mongo = resolve(name)
    clients = mongodb_fake.install(monkeypatch, mongo)
    # The TLS file paths are the lab's: their check has its own tests.
    monkeypatch.setattr(mongodb, "_unusable_tls_file", lambda config: None)

    result = mongodb.mongodb_metrics(**scenario["config"]["mongodb"])

    assert result == scenario["payload"]["mongodb"]
    assert json.loads(json.dumps(result)) == result  # plain JSON types only
    if clients:
        (client,) = clients
        # Everything listed was sent, nothing else was.
        assert calls_as_keys(client) == set(mongo) - {"monitor"}
        assert client.closed
        options = client.options
        assert options["directConnection"] is True
        assert options["maxPoolSize"] == 1
        assert options["retryReads"] is False and options["retryWrites"] is False
        assert options["appname"] == "fivenines-agent"
        assert options["serverMonitoringMode"] == "poll"
    else:
        assert mongo == {}


def test_fixture_payloads_keep_the_envelope_shape():
    error_types = set(FIXTURE["error_types"])
    for name, scenario in SCENARIOS.items():
        payload = scenario["payload"]["mongodb"]
        assert set(payload) == ENVELOPE_KEYS, name
        if payload["reachable"]:
            assert payload["error_type"] is None and payload["error_message"] is None
            assert payload["process"] in ("mongod", "mongos")
        else:
            assert payload["error_type"] in error_types, name
            assert 0 < len(payload["error_message"]) <= 500
            assert all(
                payload[k] is None
                for k in ENVELOPE_KEYS - {"reachable", "error_type", "error_message"}
            ), name


def test_fixture_collection_flags_follow_the_role_rules():
    expected_null = {
        "standalone": {"repl_status_ok", "repl_config_ok", "oplog_ok"},
        "mongos": {"repl_status_ok", "repl_config_ok", "oplog_ok"},
        "uninitiated": {"repl_config_ok", "oplog_ok"},
        "removed": {"repl_status_ok", "oplog_ok"},
        "replica_set_member": set(),
        "arbiter": set(FLAGS),
    }
    seen = set()
    for name, scenario in SCENARIOS.items():
        payload = scenario["payload"]["mongodb"]
        if not payload["reachable"]:
            continue
        role = payload["role"]
        seen.add(role)
        collection = payload["collection"]
        if role == "uninitiated" and collection["repl_status_ok"] is None:
            # NotYetInitialized answered: the status section does not apply.
            assert "repl_status" not in collection["errors"], name
        for flag in FLAGS:
            if role == "uninitiated" and flag == "repl_status_ok":
                if collection[flag] is None:
                    continue
            if flag in expected_null[role]:
                assert collection[flag] is None, (name, flag)
            else:
                assert isinstance(collection[flag], bool), (name, flag)
                assert (collection[flag] is False) == (
                    flag[: -len("_ok")] in collection["errors"]
                ), (name, flag)
        assert (payload["node"] is None) == (role == "arbiter"), name
        assert (payload["replica_set"] is not None) == (
            role in ("replica_set_member", "removed")
        ), name
    assert seen == set(expected_null)


def test_member_down_is_the_issue_example():
    """Issue #258's hand-written example, checked on the values a naive
    implementation gets wrong."""
    payload = SCENARIOS["member_down"]["payload"]["mongodb"]
    db1, db2, db3 = payload["replica_set"]["members"]
    assert (db1["lag_s"], db1["ping_ms"]) == (0, 1)
    assert (db1["last_heartbeat_age_s"], db1["last_heartbeat_recv_age_s"]) == (1, 1)
    assert db2["self"] is True
    assert db2["ping_ms"] is None and db2["last_heartbeat_age_s"] is None
    assert db2["sync_source"] == "db1.internal:27017"
    assert db3["health"] == 0 and db3["state"] == 8
    assert db3["lag_s"] is None and db3["ping_ms"] is None
    assert (db3["last_heartbeat_age_s"], db3["last_heartbeat_recv_age_s"]) == (2, 340)
    assert db3["config_version"] == -1 and db3["sync_source"] is None
    assert payload["replica_set"]["replica_set_id"] == "65f0c2a1b3d4e5f60718293a"
    assert payload["node"]["oplog"] == {"window_s": 172800}


def test_registry_entry_splats_the_config_and_ignores_a_later_key():
    from fivenines_agent.collectors import collect_metrics

    data = {}
    collect_metrics({"mongodb": {**CONFIG, "host": "a,b", "future_key": 1}}, data)
    assert data["mongodb"]["error_type"] == "config_error"


def test_pymongo_is_not_imported_until_a_collection_runs():
    """Hosts without MongoDB never pay pymongo's import (~110 ms, ~11 MB)."""
    code = (
        "import sys, fivenines_agent.collectors\n"
        "assert 'pymongo' not in sys.modules, 'pymongo imported at load'\n"
        "assert 'bson' not in sys.modules, 'bson imported at load'\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=60)


# --- config validation and the MongoClient options ----------------------------


def options(**config):
    listener = object()
    built = mongodb._Config(**{**CONFIG, **config}).client_options(listener)
    assert built["event_listeners"] == [listener]
    return built


def test_default_options_are_one_direct_connection():
    built = options()
    assert built == {
        "host": "127.0.0.1",
        "port": 27017,
        "directConnection": True,
        "appname": "fivenines-agent",
        "serverSelectionTimeoutMS": 5000,
        "connectTimeoutMS": 5000,
        "socketTimeoutMS": 10000,
        "maxPoolSize": 1,
        "retryReads": False,
        "retryWrites": False,
        "serverMonitoringMode": "poll",
        "event_listeners": built["event_listeners"],
        "connect": False,
        "username": "fivenines",
        "password": "fake-password",
        "authSource": "admin",
    }


@pytest.mark.parametrize(
    "host, expected",
    [
        (None, "127.0.0.1"),
        ("", "127.0.0.1"),
        ("localhost", "localhost"),
        ("db1.internal", "db1.internal"),
        ("db1.internal.", "db1.internal."),
        ("mongo_db", "mongo_db"),
        ("10.0.0.5", "10.0.0.5"),
        ("::1", "[::1]"),
        ("[2001:db8::1]", "[2001:db8::1]"),
    ],
)
def test_accepted_hosts(host, expected):
    assert options(host=host)["host"] == expected


@pytest.mark.parametrize(
    "host",
    [
        "db1:27017",
        "db1,db2",
        "mongodb://db1",
        "mongodb+srv://cluster.example",
        "user@db1",
        "db1/admin",
        "db1?tls=false",
        "db 1",
        "-db1",
        "mongod.sock",
        "fe80::1%eth0",
        "a" * 254,
        "a" * 64 + ".example",
        # `$` would match before a final newline: the regex must fullmatch.
        "localhost\n",
        "db1.internal\n",
        "127.0.0.1\n",
        27017,
    ],
)
def test_refused_hosts(host):
    with pytest.raises(mongodb.ConfigError):
        options(host=host)


def test_a_unix_socket_is_refused_where_the_os_has_none(monkeypatch):
    """Windows: pymongo would raise a bare ConnectionFailure after its whole
    server selection, read as unknown every tick."""
    monkeypatch.delattr(mongodb.socket, "AF_UNIX", raising=False)
    with pytest.raises(mongodb.ConfigError, match="unix sockets"):
        options(host="/var/run/mongodb/mongodb-27017.sock")


@needs_af_unix
def test_a_unix_socket_is_percent_encoded_and_takes_no_port():
    built = options(host="/var/run/mongodb/mongodb-27017.sock", port=1234)
    assert built["host"] == "mongodb://%2Fvar%2Frun%2Fmongodb%2Fmongodb-27017.sock"
    assert "port" not in built


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/mongodb-27017",
        "/tmp/" + "a" * 100 + ".sock",
        "/tmp/a\nb.sock",
        "/tmp/\udc80.sock",  # a lone surrogate from a JSON escape
    ],
)
def test_refused_socket_paths(path):
    with pytest.raises(mongodb.ConfigError):
        options(host=path)


@pytest.mark.parametrize(
    "port, expected", [(None, 27017), ("", 27017), (27018, 27018), ("27019", 27019)]
)
def test_accepted_ports(port, expected):
    assert options(port=port)["port"] == expected


@pytest.mark.parametrize(
    "port", [0, 65536, -1, "abc", True, 1.5j, [27017], float("inf"), 1e400]
)
def test_refused_ports(port):
    with pytest.raises(mongodb.ConfigError):
        options(port=port)


def test_no_username_means_no_authentication():
    built = options(username=None, password=None)
    assert not {"username", "password", "authSource", "authMechanism"} & set(built)
    built = options(username="", auth_mechanism="SCRAM-SHA-256")
    assert "authMechanism" not in built


def test_auth_source_and_mechanism():
    built = options(auth_source="", auth_mechanism="scram-sha-256")
    assert built["authSource"] == "admin"
    assert built["authMechanism"] == "SCRAM-SHA-256"
    assert options(auth_source="users")["authSource"] == "users"


@pytest.mark.parametrize("mechanism", ["PLAIN", "GSSAPI", "MONGODB-AWS", "x"])
def test_unsupported_mechanisms_are_refused(mechanism):
    with pytest.raises(mongodb.ConfigError, match="auth_mechanism"):
        options(auth_mechanism=mechanism)


@pytest.mark.parametrize("key", ["username", "password", "auth_source", "tls_ca_file"])
def test_string_settings_must_be_strings(key):
    with pytest.raises(mongodb.ConfigError, match=key):
        options(**{key: 5})


def test_x509_needs_tls_and_a_certificate():
    with pytest.raises(mongodb.ConfigError, match="X509"):
        options(auth_mechanism="MONGODB-X509", tls=True)
    with pytest.raises(mongodb.ConfigError, match="X509"):
        options(auth_mechanism="MONGODB-X509", tls_certificate_key_file="/c.pem")
    built = options(
        auth_mechanism="MONGODB-X509",
        tls=True,
        tls_certificate_key_file="/c.pem",
        username=None,
    )
    assert built["authMechanism"] == "MONGODB-X509"
    assert built["tlsCertificateKeyFile"] == "/c.pem"
    assert not {"username", "password", "authSource"} & set(built)
    built = options(
        auth_mechanism="MONGODB-X509",
        tls=True,
        tls_certificate_key_file="/c.pem",
        username="CN=agent",
    )
    assert built["username"] == "CN=agent" and "password" not in built


def test_tls_defaults_to_the_bundled_ca_set():
    import certifi

    built = options(tls=True)
    assert built["tls"] is True
    assert built["tlsCAFile"] == certifi.where()
    assert "tlsAllowInvalidCertificates" not in built


def test_tls_with_a_ca_file_a_client_certificate_or_no_verification():
    built = options(
        tls="true", tls_ca_file="/ca.pem", tls_certificate_key_file="/c.pem"
    )
    assert (built["tlsCAFile"], built["tlsCertificateKeyFile"]) == ("/ca.pem", "/c.pem")
    # Never None: OpenSSL would prompt on the terminal for an encrypted key.
    assert built["tlsCertificateKeyFilePassword"] == ""
    built = options(tls=True, tls_allow_invalid_certificates=True)
    assert built["tlsAllowInvalidCertificates"] is True
    assert "tlsCAFile" not in built


def test_tls_files_are_ignored_without_tls():
    built = options(tls=False, tls_ca_file="/ca.pem")
    assert not {"tls", "tlsCAFile"} & set(built)


@pytest.mark.parametrize(
    "value, expected",
    [
        (True, True),
        (False, False),
        (1, True),
        (0, False),
        (2, False),
        ("true", True),
        (" YES ", True),
        ("on", True),
        ("1", True),
        ("false", False),
        ("no", False),
        ("", False),
        (None, False),
        ([True], False),
    ],
)
def test_flags_need_an_explicit_true(value, expected):
    assert mongodb._flag(value) is expected


@pytest.mark.parametrize("config", [{"port": 1e400}, {"host": "/tmp/\udc80.sock"}])
def test_config_values_no_rule_anticipated_are_still_an_envelope(config):
    from fivenines_agent.collectors import collect_metrics

    data = {}
    collect_metrics({"mongodb": {**CONFIG, **config}}, data)
    assert data["mongodb"]["error_type"] == "config_error"


def test_a_config_error_is_an_envelope_and_sends_nothing(monkeypatch, capsys):
    result, clients = collect(monkeypatch, {}, auth_mechanism="PLAIN")
    assert clients == []
    assert result["reachable"] is False
    assert result["error_type"] == "config_error"
    assert "auth_mechanism" in result["error_message"]
    assert "[ERROR]" in capsys.readouterr().out


def test_a_client_that_cannot_be_built_is_a_config_error(monkeypatch):
    def refuse(_pymongo, _options):
        raise errors.ConfigurationError("A password is required.")

    monkeypatch.setattr(mongodb, "_new_client", refuse)
    result = mongodb.mongodb_metrics(**{**CONFIG, "password": None})
    assert (result["error_type"], result["error_message"]) == (
        "config_error",
        "A password is required.",
    )


# Value: protects=a TLS CA or client certificate file that does not load is a config_error envelope, raised before any connection; fails_when=the client-build except is narrowed to ConfigurationError (pymongo raises a bare FileNotFoundError): it reads unknown; why_new=the test above fakes a ConfigurationError, the one type a narrowed except still catches; seam=none; no_claim=how a present but malformed PEM file is reported
@pytest.mark.parametrize("key", ["tls_ca_file", "tls_certificate_key_file"])
def test_a_tls_file_that_does_not_load_is_a_config_error_with_the_real_driver(key):
    missing = "/nonexistent-fivenines/agent.pem"
    result = mongodb.mongodb_metrics(**{**CONFIG, "tls": True, key: missing})
    assert (result["reachable"], result["error_type"]) == (False, "config_error")
    assert missing in result["error_message"]


# Value: protects=each config shape the validator accepts builds a real MongoClient dialing that address over one direct, poll-monitored connection; fails_when=a host spelling (bracketed IPv6, percent-encoded socket URI) or TLS option mix stops being what pymongo reads that way; why_new=only the default TCP shape reaches a real MongoClient (the refused-port test), the rest are checked against our own dict; seam=none; no_claim=that a TLS handshake or an X.509 login succeeds
@pytest.mark.parametrize(
    "config, seed",
    [
        ({"host": "::1", "port": 1}, ("::1", 1)),
        ({"host": "[::1]", "port": 1}, ("::1", 1)),
        # Characters a URI reads as structure: space, +, %, comma, @, ?.
        pytest.param(
            {"host": "/tmp/a b+c%d,e@f?g.sock"},
            ("/tmp/a b+c%d,e@f?g.sock", None),
            marks=needs_af_unix,
        ),
        ({"port": 1, "tls": True}, ("127.0.0.1", 1)),
        (
            {
                "port": 1,
                "tls": True,
                "tls_allow_invalid_certificates": True,
                "auth_mechanism": "SCRAM-SHA-256",
            },
            ("127.0.0.1", 1),
        ),
    ],
)
def test_every_accepted_shape_builds_a_real_client_dialing_that_address(config, seed):
    import pymongo

    listener = mongodb._hello_recorder(pymongo)
    built = mongodb._Config(**{**CONFIG, **config}).client_options(listener)
    client = pymongo.MongoClient(**built)
    try:
        assert list(client.topology_description.server_descriptions()) == [seed]
        settings = client.options
        assert settings.direct_connection is True
        assert settings.pool_options.max_pool_size == 1
        assert (settings.retry_reads, settings.retry_writes) == (False, False)
        assert settings.server_monitoring_mode == "poll"
        assert settings.server_selection_timeout == 5
        assert settings.pool_options.connect_timeout == 5
        assert settings.pool_options.socket_timeout == 10
        assert listener in settings.event_listeners
    finally:
        client.close()


# --- the driver's own threads ---------------------------------------------------


def test_the_config_is_checked_before_anything_is_dialed(monkeypatch):
    """connect=False: a config error stays config_error even when the host
    does not answer, and building the client resolves nothing."""

    def resolve(*args, **kwargs):
        raise AssertionError("resolved while building the client")

    monkeypatch.setattr(mongodb.socket, "getaddrinfo", resolve)
    result = mongodb.mongodb_metrics(
        **{**CONFIG, "host": "nosuchhost.invalid", "password": None}
    )
    assert (result["error_type"], result["error_message"]) == (
        "config_error",
        "A password is required",
    )


def test_no_client_is_built_while_a_driver_thread_is_alive(monkeypatch):
    release = threading.Event()
    stuck = threading.Thread(
        target=release.wait, name="pymongo_server_monitor_thread", daemon=True
    )
    stuck.start()
    try:
        result, clients = collect(monkeypatch, {"hello": {"arbiterOnly": True}})
        assert clients == []
        assert (result["error_type"], result["error_message"]) == (
            "timeout",
            mongodb._DRIVER_BUSY_MESSAGE,
        )
    finally:
        release.set()
        stuck.join(5)
    result, clients = collect(monkeypatch, {"hello": {"arbiterOnly": True}})
    assert result["role"] == "arbiter" and clients


# Value: protects=a resolver that never answers leaves at most ONE blocked pymongo monitor thread however many ticks run (close() does not join it); fails_when=the driver-thread single flight is dropped: each tick adds a thread; why_new=the fake client starts no thread, only the real driver shows it; seam=none; no_claim=how a real NSS backend hangs (getaddrinfo is stubbed to block)
def test_a_wedged_resolver_leaves_one_monitor_thread_with_the_real_driver(
    monkeypatch,
):
    real = socket.getaddrinfo
    release = threading.Event()

    def wedged(host, *args, **kwargs):
        if host == "wedged.invalid":
            release.wait(30)
            raise socket.gaierror(-3, "Temporary failure in name resolution")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", wedged)
    monkeypatch.setattr(mongodb, "SERVER_SELECTION_TIMEOUT_MS", 300)
    monkeypatch.setattr(mongodb, "HELLO_TIMEOUT_S", 0.3)

    def monitors():
        return [
            t
            for t in threading.enumerate()
            if t.name == "pymongo_server_monitor_thread" and t.is_alive()
        ]

    try:
        results = [
            mongodb.mongodb_metrics(**{**CONFIG, "host": "wedged.invalid"})
            for _ in range(3)
        ]
        assert [r["error_type"] for r in results] == ["timeout"] * 3
        assert results[1]["error_message"] == mongodb._DRIVER_BUSY_MESSAGE
        assert len(monitors()) == 1
    finally:
        release.set()
        for thread in monitors():
            thread.join(10)
    assert monitors() == []


def test_a_regular_tls_file_reaches_the_driver(tmp_path):
    """Past the file-type check, the real driver loads it: garbage is its
    own config_error (a PEM it cannot read)."""
    ca = tmp_path / "ca.pem"
    ca.write_text("not a certificate\n")
    result = mongodb.mongodb_metrics(**{**CONFIG, "tls": True, "tls_ca_file": str(ca)})
    assert result["error_type"] == "config_error"
    assert not result["error_message"].startswith("tls_ca_file")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on this OS")
@pytest.mark.parametrize("key", ["tls_ca_file", "tls_certificate_key_file"])
def test_a_tls_file_that_is_not_a_regular_file_is_refused(monkeypatch, tmp_path, key):
    """open() on a FIFO never returns: the abandoned worker would hold the
    single flight for good."""
    fifo = tmp_path / "ca.pem"
    os.mkfifo(fifo)
    result, clients = collect(monkeypatch, {}, tls=True, **{key: str(fifo)})
    assert clients == []
    assert result["error_type"] == "config_error"
    assert result["error_message"] == f"{key} is not a regular file: {fifo}"


# --- the hello gate's failures --------------------------------------------------


def gate_failure(monkeypatch, hello, monitor=None, **config):
    mongo = {"hello": {"raises": hello}}
    if monitor is not None:
        mongo["monitor"] = monitor
    result, _ = collect(monkeypatch, mongo, **config)
    return result["error_type"], result["error_message"]


def op_failure(code, errmsg="boom", code_name="X", **extra):
    return {
        "type": "OperationFailure",
        "reply": {
            "ok": 0.0,
            "errmsg": errmsg,
            "code": code,
            "codeName": code_name,
            **extra,
        },
    }


SELECTION = {"type": "ServerSelectionTimeoutError", "message": "id 1234 changes"}


@pytest.mark.parametrize(
    "monitor_error, expected",
    [
        (
            {
                "type": "SSLCertVerificationError",
                "message": "certificate verify failed",
            },
            "tls_error",
        ),
        (
            {
                "type": "AutoReconnect",
                "message": "SSL handshake failed: h:1: [Errno 104] reset",
            },
            "tls_error",
        ),
        (
            {
                "type": "AutoReconnect",
                "message": "h:1: [SSL: WRONG_VERSION_NUMBER] wrong version number",
            },
            "tls_error",
        ),
        (
            {"type": "AutoReconnect", "message": "h:1: [SSL] record layer failure"},
            "tls_error",
        ),
        ({"type": "NetworkTimeout", "message": "h:1: timed out"}, "timeout"),
        (
            {"type": "AutoReconnect", "message": "h:1: [Errno 111] Connection refused"},
            "connection_refused",
        ),
        (
            {"type": "AutoReconnect", "message": "h:1: connection closed"},
            "connection_refused",
        ),
        (
            {
                "type": "AutoReconnect",
                "message": "h:1: [Errno -2] Name or service not known",
            },
            "connection_refused",
        ),
        (
            {
                "type": "NotPrimaryError",
                "reply": {"ok": 0.0, "errmsg": "shutting down", "code": 11600},
            },
            "shutting_down",
        ),
        (
            {
                "type": "OperationFailure",
                "reply": {"ok": 0.0, "errmsg": "x", "code": 18},
            },
            "auth_failed",
        ),
        ({"type": "ProtocolError", "message": "garbage"}, "unknown"),
    ],
)
def test_a_selection_timeout_is_classified_from_the_monitor_error(
    monkeypatch, monitor_error, expected
):
    error_type, message = gate_failure(monkeypatch, SELECTION, {"error": monitor_error})
    assert error_type == expected
    # The monitor's message ships, never the selection's (a random topology id).
    assert "1234" not in message


def test_a_selection_timeout_with_no_monitor_error_is_a_timeout(monkeypatch):
    assert gate_failure(monkeypatch, SELECTION, {}) == (
        "timeout",
        "no answer within 5s (server selection timed out)",
    )


@pytest.mark.parametrize(
    "hello, expected",
    [
        (SELECTION, "timeout"),
        ({"type": "ConfigurationError", "message": "wire version 8"}, "config_error"),
    ],
)
def test_a_topology_that_cannot_be_read_still_classifies(monkeypatch, hello, expected):
    class Broken:
        def server_descriptions(self):
            raise RuntimeError("closed")

    clients = mongodb_fake.install(monkeypatch, {"hello": {"raises": hello}})
    original = mongodb_fake.FakeClient.__init__

    def init(self, mongo, options):
        original(self, mongo, options)
        self.topology_description = Broken()

    monkeypatch.setattr(mongodb_fake.FakeClient, "__init__", init)
    result = mongodb.mongodb_metrics(**CONFIG)
    assert result["error_type"] == expected
    assert clients


@pytest.mark.parametrize(
    "hello, expected",
    [
        (
            op_failure(18, "Authentication failed."),
            ("auth_failed", "Authentication failed."),
        ),
        (
            op_failure(11, 'Could not find user "O=lab,CN=x" for db "$external"'),
            ("auth_failed", 'Could not find user "O=lab,CN=x" for db "$external"'),
        ),
        (
            op_failure(334, "Unable to use SCRAM-SHA-256 based authentication"),
            ("auth_failed", "Unable to use SCRAM-SHA-256 based authentication"),
        ),
        (
            op_failure(91, "shutdown in progress"),
            ("shutting_down", "shutdown in progress"),
        ),
        (op_failure(2, "BadValue"), ("unknown", "BadValue")),
        (
            {
                "type": "ExecutionTimeout",
                "reply": {
                    "ok": 0.0,
                    "errmsg": "operation exceeded time limit",
                    "code": 50,
                },
            },
            ("timeout", "operation exceeded time limit"),
        ),
        (
            {"type": "NetworkTimeout", "message": "h:1: timed out"},
            ("timeout", "h:1: timed out"),
        ),
        (
            {"type": "AutoReconnect", "message": "h:1: connection closed"},
            ("connection_refused", "h:1: connection closed"),
        ),
        ({"type": "ConfigurationError", "message": "bad"}, ("config_error", "bad")),
        ({"type": "InvalidURI", "message": "bad uri"}, ("config_error", "bad uri")),
        ({"type": "InvalidOperation", "message": "closed"}, ("unknown", "closed")),
    ],
)
def test_gate_failures(monkeypatch, hello, expected):
    assert gate_failure(monkeypatch, hello) == expected


def test_server_too_old_reads_the_wire_version(monkeypatch):
    too_old = {"type": "ConfigurationError", "message": "reports wire version 8"}
    assert gate_failure(monkeypatch, too_old, {"hello": {"maxWireVersion": 8}})[0] == (
        "server_too_old"
    )
    assert gate_failure(monkeypatch, too_old, {"hello": {"maxWireVersion": 21}})[0] == (
        "config_error"
    )


def test_raw_socket_errors_classify_by_type():
    import pymongo

    assert mongodb._connection_error_type(TimeoutError(), pymongo) == "timeout"
    assert mongodb._connection_error_type(OSError(113, "no route"), pymongo) == (
        "connection_refused"
    )
    assert mongodb._connection_error_type(ValueError(), pymongo) is None


def test_the_password_never_ships_and_messages_are_capped(monkeypatch):
    hello = op_failure(2, "bad value fake-password " + "x" * 3000)
    error_type, message = gate_failure(monkeypatch, hello)
    assert "fake-password" not in message and "[REDACTED]" in message
    assert len(message) <= 500


def test_a_short_password_is_not_redacted_into_messages(monkeypatch):
    """Redacting "1" would garble "127.0.0.1" and show where it occurs."""
    hello = {"type": "AutoReconnect", "message": "127.0.0.1:1: connection closed"}
    _, message = gate_failure(monkeypatch, hello, password="1")
    assert message == "127.0.0.1:1: connection closed"


def test_a_peer_that_is_not_mongodb_gets_a_stable_message(monkeypatch):
    monitor_error = {
        "type": "ProtocolError",
        "message": "Got response id 7 but expected 9",
    }
    assert gate_failure(monkeypatch, SELECTION, {"error": monitor_error}) == (
        "unknown",
        mongodb._PROTOCOL_MESSAGE,
    )


def test_an_exception_with_no_text_ships_its_type_name():
    assert mongodb._message(RuntimeError(), None) == "RuntimeError"


def test_an_arbiter_with_auth_on_is_recognised_from_the_monitor_hello(monkeypatch):
    """Only the monitor's hello (unauthenticated) says arbiterOnly: a plain
    auth failure, or one whose monitor hello is not an arbiter's, stays
    auth_failed."""
    auth = op_failure(18, "Authentication failed.")
    assert gate_failure(monkeypatch, auth, {"hello": {"arbiterOnly": False}})[0] == (
        "auth_failed"
    )
    result, _ = collect(
        monkeypatch,
        {
            "hello": {"raises": auth},
            "monitor": {"hello": {"arbiterOnly": True, "me": "a:1"}},
        },
    )
    assert (result["role"], result["me"]) == ("arbiter", "a:1")
    other = op_failure(13, "unauthorized")
    assert gate_failure(monkeypatch, other, {"hello": {"arbiterOnly": True}})[0] == (
        "unknown"
    )


def test_a_hello_that_is_not_a_document(monkeypatch):
    result, _ = collect(monkeypatch, {"hello": []})
    assert (result["error_type"], result["error_message"]) == (
        "unknown",
        "hello returned no document",
    )


def test_ismaster_is_only_asked_when_hello_does_not_exist(monkeypatch):
    result, clients = collect(
        monkeypatch,
        {
            "hello": {"raises": op_failure(59, "no such command: 'hello'")},
            "isMaster": {"raises": op_failure(18, "Authentication failed.")},
        },
    )
    assert result["error_type"] == "auth_failed"
    assert clients[0].calls == ["hello", "isMaster"]


def test_pymongo_missing_is_an_envelope(monkeypatch):
    def missing():
        raise ImportError("No module named 'pymongo'")

    monkeypatch.setattr(mongodb, "_import_pymongo", missing)
    result = mongodb.mongodb_metrics(**CONFIG)
    assert result["error_type"] == "unknown"
    assert (
        result["error_message"] == "pymongo is not available: No module named 'pymongo'"
    )


# --- sections -----------------------------------------------------------------

MEMBER_HELLO = {"setName": "rs0", "me": "db2:27017", "ok": 1.0}
T = datetime(2026, 11, 2, 10, 0, 0)


def ejson_date(dt):
    return {"$date": dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"}


def status_reply(members, **extra):
    return {
        "set": "rs0",
        "date": ejson_date(T),
        "myState": 2,
        "term": 3,
        "members": members,
        "ok": 1.0,
        **extra,
    }


def config_reply(members, **extra):
    return {
        "config": {"_id": "rs0", "version": 2, "term": 3, "members": members, **extra},
        "ok": 1.0,
    }


def s_member(mid, name, state=2, health=1.0, optime=T, **extra):
    m = {
        "_id": mid,
        "name": name,
        "health": health,
        "state": state,
        "stateStr": "S",
        "uptime": 10,
    }
    if optime is not None:
        m["optimeDate"] = ejson_date(optime)
    m.update(extra)
    return m


def c_member(mid, host, **extra):
    return {
        "_id": mid,
        "host": host,
        "priority": 1.0,
        "votes": 1,
        "hidden": False,
        "arbiterOnly": False,
        "buildIndexes": True,
        "secondaryDelaySecs": 0,
        **extra,
    }


OPLOG = {
    "first": {"ts": {"$timestamp": {"t": 100, "i": 1}}},
    "last": {"ts": {"$timestamp": {"t": 160, "i": 2}}},
}


def member(
    monkeypatch,
    status=None,
    config=None,
    oplog=OPLOG,
    server_status=None,
    hello=MEMBER_HELLO,
):
    mongo = {
        "hello": hello,
        "serverStatus": (
            server_status
            if server_status is not None
            else {"version": "7.0.1", "ok": 1.0}
        ),
        "replSetGetStatus": (
            status
            if status is not None
            else status_reply([s_member(0, "a:1", self=True)])
        ),
        "replSetGetConfig": (
            config if config is not None else config_reply([c_member(0, "a:1")])
        ),
        "oplog": oplog,
    }
    result, _ = collect(monkeypatch, mongo)
    return result


@pytest.mark.parametrize(
    "raises, reason",
    [
        (op_failure(13, "not authorized"), "not_authorized"),
        (op_failure(8, "unknown error"), "refused"),
        (
            {
                "type": "ExecutionTimeout",
                "reply": {"ok": 0.0, "errmsg": "exceeded", "code": 50},
            },
            "timeout",
        ),
        ({"type": "NetworkTimeout", "message": "timed out"}, "timeout"),
        ({"type": "AutoReconnect", "message": "connection closed"}, "error"),
    ],
)
def test_a_refused_command_drops_only_its_section(monkeypatch, raises, reason):
    result = member(monkeypatch, server_status={"raises": raises})
    assert result["reachable"] is True
    assert result["collection"]["server_status_ok"] is False
    assert result["collection"]["errors"] == {"server_status": reason}
    assert result["version"] is None
    assert set(result["node"]) and all(
        v is None for k, v in result["node"].items() if k != "oplog"
    )
    assert result["node"]["oplog"] == {"window_s": 60}
    assert result["collection"]["repl_status_ok"] is True


def test_a_reply_that_is_not_a_document_fails_its_section(monkeypatch):
    result = member(monkeypatch, server_status=[], status=[], config={"ok": 1.0})
    assert result["collection"]["errors"] == {
        "repl_config": "error",
        "repl_status": "error",
        "server_status": "error",
    }
    assert result["replica_set"]["set_name"] == "rs0"  # from hello
    assert result["replica_set"]["members"] is None


def test_an_empty_oplog_fails_the_oplog_section(monkeypatch):
    result = member(monkeypatch, oplog={"first": None, "last": None})
    assert result["collection"]["oplog_ok"] is False
    assert result["collection"]["errors"] == {"oplog": "error"}
    assert result["node"]["oplog"] is None


def test_the_oplog_window_never_goes_negative(monkeypatch):
    backwards = {"first": OPLOG["last"], "last": OPLOG["first"]}
    assert member(monkeypatch, oplog=backwards)["node"]["oplog"] == {"window_s": 0}


def test_members_from_the_config_alone_when_the_status_is_refused(monkeypatch):
    result = member(
        monkeypatch,
        status={"raises": op_failure(13, "no")},
        config=config_reply([c_member(1, "b:1", priority=0.5), c_member(0, "a:1")]),
    )
    assert result["collection"]["errors"] == {"repl_status": "not_authorized"}
    rs = result["replica_set"]
    assert (rs["term"], rs["my_state"], rs["my_state_str"]) == (None, None, None)
    assert rs["config_version"] == 2 and rs["configsvr"] is False
    a, b = rs["members"]
    assert (a["name"], b["name"]) == ("a:1", "b:1")
    assert b["priority"] == 0.5
    assert a["self"] is None and a["health"] is None and a["lag_s"] is None


def test_members_from_the_status_alone_when_the_config_is_refused(monkeypatch):
    result = member(
        monkeypatch,
        status=status_reply(
            [s_member(0, "a:1", self=True), s_member(1, "b:1", pingMs=3)]
        ),
        config={"raises": op_failure(13, "no")},
    )
    rs = result["replica_set"]
    assert (rs["replica_set_id"], rs["configsvr"], rs["config_version"]) == (
        None,
        None,
        None,
    )
    a, b = rs["members"]
    assert a["self"] is True and b["self"] is False and b["ping_ms"] == 3
    assert a["priority"] is None and a["hidden"] is None


def test_a_status_member_missing_from_the_config_is_left_out(monkeypatch):
    result = member(
        monkeypatch,
        status=status_reply([s_member(0, "a:1", self=True), s_member(9, "z:1")]),
        config=config_reply([c_member(0, "a:1"), "junk"]),
    )
    assert [m["name"] for m in result["replica_set"]["members"]] == ["a:1"]


def test_a_member_whose_host_changed_between_the_reads_is_not_lent_its_health(
    monkeypatch,
):
    """A reconfig between replSetGetStatus and replSetGetConfig gave _id 1 to a
    new host: the old member's health must not be reported for it."""
    status = status_reply(
        [s_member(0, "a:1", self=True), s_member(1, "old:1", pingMs=2)]
    )
    config = config_reply([c_member(0, "a:1"), c_member(1, "new:1")])
    members = member(monkeypatch, status=status, config=config)["replica_set"][
        "members"
    ]
    by_name = {m["name"]: m for m in members}
    assert by_name["a:1"]["health"] == 1
    new = by_name["new:1"]
    assert (new["health"], new["state"], new["lag_s"], new["self"]) == (
        None,
        None,
        None,
        None,
    )
    assert new["priority"] == 1  # the config side still reads


def test_members_are_capped_at_fifty(monkeypatch):
    names = [f"m{i:02d}:1" for i in range(60)]
    result = member(
        monkeypatch,
        status=status_reply([s_member(i, n) for i, n in enumerate(names)]),
        config=config_reply([c_member(i, n) for i, n in enumerate(names)]),
    )
    assert [m["name"] for m in result["replica_set"]["members"]] == sorted(names)[:50]


def test_lag_is_measured_from_the_primary(monkeypatch):
    status = status_reply(
        [
            s_member(0, "p:1", state=1, optime=T - timedelta(seconds=5)),
            s_member(1, "s:1", optime=T - timedelta(seconds=17.9)),
            s_member(2, "f:1", optime=T),  # fresher than the primary: clamped
        ]
    )
    lags = {
        m["name"]: m["lag_s"]
        for m in member(monkeypatch, status=status, config={"raises": op_failure(13)})[
            "replica_set"
        ]["members"]
    }
    assert lags == {"p:1": 0, "s:1": 12, "f:1": 0}


def test_with_two_primaries_lag_is_measured_from_the_freshest(monkeypatch):
    """A stale view can list an isolated old primary beside the new one."""
    status = status_reply(
        [
            s_member(0, "old:1", state=1, optime=T - timedelta(seconds=30)),
            s_member(1, "new:1", state=1, optime=T - timedelta(seconds=2)),
            s_member(2, "s:1", optime=T - timedelta(seconds=12)),
        ]
    )
    members = member(monkeypatch, status=status, config={"raises": op_failure(13)})
    lags = {m["name"]: m["lag_s"] for m in members["replica_set"]["members"]}
    assert lags == {"new:1": 0, "old:1": 28, "s:1": 10}


def test_with_no_primary_lag_is_measured_from_the_freshest_healthy_member(monkeypatch):
    status = status_reply(
        [
            s_member(0, "a:1", optime=T - timedelta(seconds=30)),
            s_member(1, "b:1", optime=T - timedelta(seconds=10)),
            # Fresher, but not eligible: neither is a reference.
            s_member(2, "c:1", state=5, optime=T),
            s_member(3, "d:1", health=0.0, state=2, optime=T),
        ]
    )
    lags = {
        m["name"]: m["lag_s"]
        for m in member(monkeypatch, status=status, config={"raises": op_failure(13)})[
            "replica_set"
        ]["members"]
    }
    assert lags == {"a:1": 20, "b:1": 0, "c:1": None, "d:1": None}


@pytest.mark.parametrize("state", [0, 5, 6, 7, 8, 10])
def test_states_without_an_optime_have_no_lag(monkeypatch, state):
    status = status_reply(
        [s_member(0, "p:1", state=1), s_member(1, "x:1", state=state)]
    )
    members = member(monkeypatch, status=status, config={"raises": op_failure(13)})[
        "replica_set"
    ]["members"]
    assert {m["name"]: m["lag_s"] for m in members} == {"p:1": 0, "x:1": None}


def test_a_zero_or_missing_optime_has_no_lag_and_no_member_has_one_without_a_reference(
    monkeypatch,
):
    status = status_reply(
        [
            s_member(0, "a:1", optime=None),
            s_member(1, "b:1", optimeDate={"$date": "1970-01-01T00:00:00Z"}),
        ]
    )
    members = member(monkeypatch, status=status, config={"raises": op_failure(13)})[
        "replica_set"
    ]["members"]
    assert [m["lag_s"] for m in members] == [None, None]


def test_heartbeat_ages_use_the_reply_date(monkeypatch):
    status = status_reply(
        [
            s_member(
                0,
                "a:1",
                self=True,
                lastHeartbeat=ejson_date(T - timedelta(seconds=9)),
                pingMs=4,
            ),
            s_member(
                1,
                "b:1",
                lastHeartbeat=ejson_date(T - timedelta(seconds=2.7)),
                lastHeartbeatRecv={"$date": "1970-01-01T00:00:00Z"},
                pingMs=4,
            ),
            # A heartbeat stamped just after `date`: clamped at 0, never negative.
            s_member(
                2,
                "c:1",
                lastHeartbeat=ejson_date(T + timedelta(seconds=0.3)),
                lastHeartbeatRecv=ejson_date(T - timedelta(seconds=61)),
            ),
        ]
    )
    members = member(monkeypatch, status=status, config={"raises": op_failure(13)})[
        "replica_set"
    ]["members"]
    ages = [
        (m["ping_ms"], m["last_heartbeat_age_s"], m["last_heartbeat_recv_age_s"])
        for m in members
    ]
    assert ages == [(None, None, None), (4, 2, None), (None, 0, 61)]


def test_ages_are_null_when_the_reply_has_no_date(monkeypatch):
    status = status_reply([s_member(1, "b:1", lastHeartbeat=ejson_date(T))])
    del status["date"]
    (m,) = member(monkeypatch, status=status, config={"raises": op_failure(13)})[
        "replica_set"
    ]["members"]
    assert m["last_heartbeat_age_s"] is None


def test_values_of_the_wrong_type_read_as_null(monkeypatch):
    status = status_reply(
        [
            s_member(
                0,
                "a:1",
                health=True,
                state="2",
                uptime=float("nan"),
                configVersion=7.9,
                syncSourceHost=5,
                self=True,
            )
        ],
        term="3",
    )
    config = config_reply(
        [c_member(0, "a:1", priority="high", hidden="no", votes=None)],
        settings={"replicaSetId": "not-an-object-id"},
    )
    result = member(monkeypatch, status=status, config=config)
    (m,) = result["replica_set"]["members"]
    assert (m["health"], m["state"], m["uptime_s"], m["sync_source"]) == (
        None,
        None,
        None,
        None,
    )
    assert m["config_version"] == 7
    assert (m["priority"], m["hidden"], m["votes"]) == (None, None, None)
    assert result["replica_set"]["term"] is None
    assert result["replica_set"]["replica_set_id"] is None


def test_aware_datetimes_are_read_as_utc():
    aware = datetime(2026, 1, 1, 12, tzinfo=timezone(timedelta(hours=2)))
    assert mongodb._date(aware) == datetime(2026, 1, 1, 10)


def test_members_that_are_not_documents_are_skipped(monkeypatch):
    status = status_reply(["junk", s_member(0, "a:1", self=True)])
    status["members"] = ["junk", s_member(0, "a:1", self=True, stateStr="SECONDARY")]
    result = member(monkeypatch, status=status, config={"raises": op_failure(13)})
    assert [m["name"] for m in result["replica_set"]["members"]] == ["a:1"]
    assert result["replica_set"]["my_state_str"] == "SECONDARY"
    status["members"] = "junk"
    result = member(monkeypatch, status=status, config={"raises": op_failure(13)})
    assert result["replica_set"]["members"] is None
    assert result["replica_set"]["my_state_str"] is None


@pytest.mark.parametrize(
    "raises, reason",
    [
        (op_failure(13, "no"), "not_authorized"),
        ({"type": "NetworkTimeout", "message": "timed out"}, "timeout"),
        ({"type": "AutoReconnect", "message": "connection closed"}, "error"),
    ],
)
def test_a_status_not_read_without_a_set_name_says_so(monkeypatch, raises, reason):
    """The role then rests on hello alone (an uninitiated and a removed node
    look alike there): it reads uninitiated, and errors says the status was
    not read, so the server never takes the guess for a reading."""
    mongo = {
        "hello": {"isreplicaset": True, "ok": 1.0},
        "serverStatus": {"ok": 1.0},
        "replSetGetStatus": {"raises": raises},
    }
    result, _ = collect(monkeypatch, mongo)
    assert result["role"] == "uninitiated"
    assert result["collection"]["errors"] == {"repl_status": reason}
    assert result["collection"]["repl_status_ok"] is False
    assert result["replica_set"] is None


def test_a_node_initiated_between_hello_and_status_reads_as_a_member(monkeypatch):
    result = member(monkeypatch, hello={"isreplicaset": True, "ok": 1.0})
    assert result["role"] == "replica_set_member"
    assert result["replica_set"]["set_name"] == "rs0"


@pytest.mark.parametrize(
    "extra, state",
    [
        ({}, (None, None)),  # what MongoDB 4.4 to 8.0 answer
        ({"myState": 10}, (10, None)),
        ({"state": 10, "stateStr": "REMOVED"}, (10, "REMOVED")),
    ],
)
@pytest.mark.parametrize("hello", [{"isreplicaset": True, "ok": 1.0}, MEMBER_HELLO])
def test_a_removed_node_is_recognised_by_its_status_code(
    monkeypatch, extra, state, hello
):
    """InvalidReplicaSetConfig (93) is what tells a removed node from an
    uninitiated one (94): measured, both answer hello alike (isreplicaset, no
    setName) and the 93 reply carries no state."""
    removed = op_failure(
        93,
        "Our replica set config is invalid or we are not a member of it",
        "InvalidReplicaSetConfig",
        **extra,
    )
    result = member(
        monkeypatch,
        hello=hello,
        status={"raises": removed},
        config={"raises": op_failure(13, "no")},
        oplog=None,
    )
    assert result["role"] == "removed"
    rs = result["replica_set"]
    assert (rs["my_state"], rs["my_state_str"]) == state
    assert rs["members"] is None and rs["term"] is None
    collection = result["collection"]
    assert collection["repl_status_ok"] is None
    assert collection["repl_config_ok"] is False
    assert collection["oplog_ok"] is None
    assert collection["errors"] == {"repl_config": "not_authorized"}


def test_a_removed_node_names_its_set_from_its_config(monkeypatch):
    removed = op_failure(93, "not a member", "InvalidReplicaSetConfig")
    config = config_reply(
        [c_member(0, "a:1")],
        settings={"replicaSetId": {"$oid": "65f0c2a1b3d4e5f60718293a"}},
    )
    result = member(
        monkeypatch,
        hello={"isreplicaset": True, "ok": 1.0},
        status={"raises": removed},
        config=config,
        oplog=None,
    )
    rs = result["replica_set"]
    assert (rs["set_name"], rs["replica_set_id"], rs["config_version"]) == (
        "rs0",
        "65f0c2a1b3d4e5f60718293a",
        2,
    )
    assert result["collection"]["repl_config_ok"] is True


def test_tickets_prefer_queues_execution():
    status = {
        "queues": {
            "execution": {"read": {"out": 3, "available": 5}, "write": {"out": 1}}
        },
        "wiredTiger": {"concurrentTransactions": {"read": {"out": 9}}},
    }
    assert mongodb._tickets(status) == {
        "read_out": 3,
        "read_available": 5,
        "write_out": 1,
        "write_available": None,
    }


def test_numbers_keep_fractions_and_drop_non_numbers():
    assert mongodb._num(1.5) == 1.5 and mongodb._num(2.0) == 2
    assert mongodb._num(float("inf")) is None and mongodb._num("3") is None
    assert mongodb._int(7.9) == 7 and mongodb._int(None) is None


def test_sharding_needs_a_set_name():
    for value in ("cfg1:27019,cfg2:27019", "/cfg1:27019", 5, None):
        assert (
            mongodb._sharding({"sharding": {"configsvrConnectionString": value}})
            is None
        )
    assert mongodb._sharding({"sharding": {"configsvrConnectionString": "c/x:1"}}) == {
        "config_server_set": "c"
    }


# --- budget, close, bounds, logging -----------------------------------------------


def test_sections_the_budget_no_longer_covers_read_timeout(monkeypatch):
    clock = iter([0.0, 1.0] + [99.0] * 50)  # __init__, the hello, then late
    monkeypatch.setattr(mongodb, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    result = member(monkeypatch)
    assert result["reachable"] is True
    assert result["collection"]["errors"] == {
        "oplog": "timeout",
        "repl_config": "timeout",
        "repl_status": "timeout",
        "server_status": "timeout",
    }


def test_a_gate_the_budget_no_longer_covers_is_a_timeout(monkeypatch):
    monkeypatch.setattr(mongodb, "COMMAND_BUDGET", 0)
    result, _ = collect(monkeypatch, {"hello": MEMBER_HELLO})
    assert (result["error_type"], result["error_message"]) == (
        "timeout",
        "skipped: the 0s command budget was spent before it",
    )


# Value: protects=a slow mongod costs its sections inside the tick, never an abandoned worker plus a skipped next tick, and the hard bound stays under the watchdog; fails_when=COLLECT_DEADLINE is cut to the budget plus the close or below (15 passes every other test), or raised past WatchdogSec; why_new=every bound test monkeypatches these constants, so none notices the shipped values (test_qemu guards its pair alike); seam=none; no_claim=that all self-bounded collectors together fit one watchdog window
def test_the_shipped_bounds_nest():
    unit = Path(__file__).resolve().parent.parent / "fivenines-agent.service"
    watchdog = re.search(r"^WatchdogSec=(\d+)$", unit.read_text(), re.M)
    assert mongodb.HELLO_TIMEOUT_S <= mongodb.COMMAND_BUDGET
    assert (
        mongodb.COMMAND_BUDGET + mongodb.CLOSE_TIMEOUT
        < mongodb.COLLECT_DEADLINE
        < int(watchdog.group(1))
    )


def test_commands_run_under_the_remaining_budget(monkeypatch):
    seen = []

    class Timeout:
        def __init__(self, seconds):
            seen.append(seconds)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    fake_pymongo = SimpleNamespace(timeout=Timeout)
    client = SimpleNamespace(admin=SimpleNamespace(command=lambda name: {"ok": 1}))
    clock = iter([100.0, 100.0, 109.0, 112.0])
    monkeypatch.setattr(mongodb, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    mongo = mongodb._Mongo(fake_pymongo, client)
    mongo.command("hello", cap=mongodb.HELLO_TIMEOUT_S)
    mongo.command("serverStatus")
    mongo.command("replSetGetStatus")
    assert seen == [5.0, 6.0, 3.0]


def test_a_failing_close_is_swallowed(monkeypatch, capsys):
    monkeypatch.setattr(mongodb, "log_safe", str)
    clients = mongodb_fake.install(monkeypatch, {"hello": {"arbiterOnly": True}})

    def close():
        raise RuntimeError("socket gone")

    monkeypatch.setattr(mongodb_fake.FakeClient, "close", lambda self: close())
    monkeypatch.setenv("LOG_LEVEL", "debug")
    result = mongodb.mongodb_metrics(**CONFIG)
    assert result["role"] == "arbiter" and clients
    assert "Error closing the MongoDB client: socket gone" in capsys.readouterr().out


def test_a_stalled_collection_is_abandoned_and_single_flight(monkeypatch):
    release = threading.Event()
    started = []

    def stuck(config):
        started.append(config)
        release.wait(10)
        return {"late": True}

    monkeypatch.setattr(mongodb, "COLLECT_DEADLINE", 0.05)
    monkeypatch.setattr(mongodb, "_collect", stuck)
    first = mongodb.mongodb_metrics(**CONFIG)
    assert first["error_type"] == "timeout"
    assert "did not finish within 0.05s" in first["error_message"]
    worker = mongodb._stalled_worker
    assert worker is not None and worker.is_alive()

    second = mongodb.mongodb_metrics(**CONFIG)
    assert second == first
    assert len(started) == 1  # no second collection behind the stuck one

    release.set()
    worker.join(5)
    monkeypatch.setattr(
        mongodb,
        "_collect",
        lambda config: {"reachable": True, "collection": {"errors": {}}},
    )
    third = mongodb.mongodb_metrics(**CONFIG)
    assert third["reachable"] is True
    assert mongodb._stalled_worker is None


def test_a_worker_that_cannot_start_is_still_an_envelope(monkeypatch):
    def no_thread(*_args, **_kwargs):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(mongodb, "call_bounded", no_thread)
    result = mongodb.mongodb_metrics(**CONFIG)
    assert (result["error_type"], result["error_message"]) == (
        "unknown",
        "can't start new thread",
    )


def test_a_steady_failure_logs_at_error_once(monkeypatch, capsys):
    monkeypatch.setenv("LOG_LEVEL", "debug")
    refused = {"hello": {"raises": op_failure(18, "Authentication failed.")}}
    collect(monkeypatch, refused)
    collect(monkeypatch, refused)
    lines = [
        line
        for line in capsys.readouterr().out.splitlines()
        if "MongoDB collection failed" in line
    ]
    assert [line.split("]")[0] for line in lines] == ["[ERROR", "[DEBUG"]

    collect(monkeypatch, {"hello": {"arbiterOnly": True}})  # recovered
    collect(monkeypatch, refused)
    lines = [
        line
        for line in capsys.readouterr().out.splitlines()
        if "MongoDB collection failed" in line
    ]
    assert [line.split("]")[0] for line in lines] == ["[ERROR"]


def test_section_errors_log_at_error_once_per_change(monkeypatch, capsys):
    monkeypatch.setenv("LOG_LEVEL", "debug")
    refused = {"raises": op_failure(13, "no")}
    member(monkeypatch, server_status=refused)
    member(monkeypatch, server_status=refused)
    member(monkeypatch)
    member(monkeypatch, server_status=refused)
    lines = [
        line
        for line in capsys.readouterr().out.splitlines()
        if "sections not read" in line
    ]
    assert [line.split("]")[0] for line in lines] == ["[ERROR", "[DEBUG", "[ERROR"]
    assert lines[0].endswith(
        "MongoDB sections not read: server_status (not_authorized)"
    )


# --- the real driver ----------------------------------------------------------


# Value: protects=the arbiter-with-auth rule reads pymongo's REAL heartbeat event: reply.document is the raw hello Mapping; fails_when=the recorder keeps event.reply (a Hello object, no Mapping) or the event shape moves, so an arbiter with auth reads auth_failed; why_new=this test and FakeClient fed a SimpleNamespace built on the same assumption; seam=none; no_claim=that the monitor emits the event
def test_the_real_driver_seams():
    import pymongo
    from pymongo.hello import Hello
    from pymongo.monitoring import ServerHeartbeatSucceededEvent

    assert mongodb._import_pymongo() is pymongo
    recorder = mongodb._hello_recorder(pymongo)
    assert isinstance(recorder, pymongo.monitoring.ServerHeartbeatListener)
    assert type(mongodb._hello_recorder(pymongo)) is type(recorder)
    hello = {"arbiterOnly": True, "me": "a:1", "ok": 1.0}
    recorder.succeeded(
        ServerHeartbeatSucceededEvent(0.001, Hello(hello), ("127.0.0.1", 27017))
    )
    assert recorder.document == hello
    assert isinstance(recorder.document, Mapping)

    fake = SimpleNamespace(MongoClient=MagicMock(return_value="client"))
    assert mongodb._new_client(fake, {"host": "h"}) == "client"
    fake.MongoClient.assert_called_once_with(host="h")


def test_a_refused_port_end_to_end_with_the_real_driver(monkeypatch):
    """The real MongoClient, listener registration, pymongo.timeout() and
    close(), against a port nothing listens on: pins that the monitor still
    records a connection refusal as AutoReconnect (it strips the cause)."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    # A refused loopback connect is retried for ~1-2s on Windows (windows.yml
    # runs this suite there): the monitor must record it before the selection
    # gives up.
    timeout_s = 4 if sys.platform == "win32" else 1.5
    monkeypatch.setattr(mongodb, "SERVER_SELECTION_TIMEOUT_MS", timeout_s * 1000)
    monkeypatch.setattr(mongodb, "HELLO_TIMEOUT_S", timeout_s)

    result = mongodb.mongodb_metrics(**{**CONFIG, "port": port})

    assert result["reachable"] is False
    assert result["error_type"] == "connection_refused"
    assert result["error_message"].startswith(f"127.0.0.1:{port}: ")


def test_ssl_errors_keep_their_type():
    import pymongo

    assert mongodb._connection_error_type(ssl.SSLError(1, "x"), pymongo) == "tls_error"
