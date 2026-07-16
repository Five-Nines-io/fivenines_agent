"""Tests for the Redis/Valkey INFO collector (server issue #491).

Only socket.create_connection is mocked; each scenario feeds a canned INFO
reply back through the real read loop + parser, so the whole
config-in -> parse -> payload-out pipeline is exercised.
"""

import json
import os
from unittest.mock import MagicMock, patch

from fivenines_agent import redis


def _fake_socket(reply_bytes):
    """A socket whose recv() returns the whole reply once, then b'' to end the
    read loop (mirrors Redis closing the connection after QUIT)."""
    sock = MagicMock()
    sock.recv.side_effect = [reply_bytes, b""]
    return sock


# --- _parse_nested --------------------------------------------------------


def test_parse_nested_mixed_numeric_and_string():
    out = redis._parse_nested("ip=10.0.0.2,port=6379,state=online,offset=42,lag=0")
    assert out == {
        "ip": "10.0.0.2",
        "port": 6379.0,
        "state": "online",
        "offset": 42.0,
        "lag": 0.0,
    }


def test_parse_nested_skips_segment_without_equals():
    # A malformed comma segment ('garbage') is dropped, not fatal; the float
    # path (port) and the string fallback (ip/state) both still apply.
    out = redis._parse_nested("ip=10.0.0.2,garbage,port=6379,state=online")
    assert out == {"ip": "10.0.0.2", "port": 6379.0, "state": "online"}


# --- redis_metrics: connection / auth / read loop -------------------------


def test_no_password_omits_auth():
    sent = []
    sock = _fake_socket(b"$21\r\n# Server\r\nrole:master\r\n+OK\r\n")
    sock.sendall.side_effect = sent.append
    with patch("fivenines_agent.redis.socket.create_connection", return_value=sock):
        out = redis.redis_metrics(port=6379)
    assert out == {"role": "master"}
    assert b"AUTH" not in b"".join(sent)


def test_password_sends_auth_before_info():
    sent = []
    sock = _fake_socket(b"$21\r\n# Server\r\nrole:master\r\n+OK\r\n")
    sock.sendall.side_effect = sent.append
    with patch("fivenines_agent.redis.socket.create_connection", return_value=sock):
        out = redis.redis_metrics(port=6379, password="s3cr3t")
    assert out == {"role": "master"}
    wire = b"".join(sent).decode()
    # AUTH is issued, and before INFO/QUIT.
    assert wire.index("AUTH s3cr3t") < wire.index("INFO") < wire.index("QUIT")


def test_socket_error_returns_none():
    # A connection/socket error returns None via the except path (server sees
    # no 'redis' key and skips the block), distinct from a reachable-but-empty
    # reply which returns {}.
    with patch(
        "fivenines_agent.redis.socket.create_connection",
        side_effect=OSError("connection refused"),
    ):
        assert redis.redis_metrics(port=6379) is None


def test_empty_reply_returns_empty_dict():
    sock = MagicMock()
    sock.recv.side_effect = [b""]  # closed immediately, no data
    with patch("fivenines_agent.redis.socket.create_connection", return_value=sock):
        assert redis.redis_metrics(port=6379) == {}


def test_auth_failure_reply_returns_empty_dict():
    reply = b"-WRONGPASS invalid username-password pair or user is disabled.\r\n"
    sock = _fake_socket(reply)
    with patch("fivenines_agent.redis.socket.create_connection", return_value=sock):
        assert redis.redis_metrics(port=6379, password="wrong") == {}


# --- parser resilience & traps --------------------------------------------


def test_malformed_numeric_line_is_skipped_not_fatal():
    # One bad line must not sink the whole payload (per-line resilience).
    reply = b"# Memory\r\nused_memory:notanumber\r\nconnected_clients:7\r\n"
    sock = _fake_socket(reply)
    with patch("fivenines_agent.redis.socket.create_connection", return_value=sock):
        out = redis.redis_metrics(port=6379)
    assert "used_memory" not in out
    assert out["connected_clients"] == 7.0


def test_ipv6_multicolon_slave_line_does_not_crash():
    # The old split(':') 2-tuple unpack would crash here; partition(':', 1)
    # keeps the slaveN value (including IPv6 ip=::) intact.
    reply = (
        b"# Replication\r\nrole:master\r\n"
        b"slave0:ip=fe80::1,port=6379,state=online,offset=1,lag=0\r\n"
    )
    sock = _fake_socket(reply)
    with patch("fivenines_agent.redis.socket.create_connection", return_value=sock):
        out = redis.redis_metrics(port=6379)
    assert out["role"] == "master"
    assert out["slave0"] == {
        "ip": "fe80::1",
        "port": 6379.0,
        "state": "online",
        "offset": 1.0,
        "lag": 0.0,
    }


def test_substring_keys_are_not_captured():
    # Exact-key matching: used_memory must not swallow used_memory_rss/peak,
    # and maxmemory must not swallow maxmemory_policy.
    reply = (
        b"# Memory\r\n"
        b"used_memory:100\r\nused_memory_rss:200\r\nused_memory_peak:300\r\n"
        b"maxmemory:0\r\nmaxmemory_policy:noeviction\r\n"
    )
    sock = _fake_socket(reply)
    with patch("fivenines_agent.redis.socket.create_connection", return_value=sock):
        out = redis.redis_metrics(port=6379)
    assert out == {"used_memory": 100.0, "maxmemory": 0.0}


# --- cross-repo contract (fivenines-server) -------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "redis_contract_payload.json"
)

# Existing keys the pre-#491 server already read (or that shipped in the
# payload) -- must stay byte-compatible in name and shape.
_LEGACY_KEYS = {
    "redis_version",
    "connected_clients",
    "maxclients",
    "blocked_clients",
    "evicted_keys",
    "expired_keys",
    "uptime_in_seconds",
    "evicted_clients",
    "total_connections_received",
    "total_commands_processed",
}

# Fields #491 adds. A parser regression that drops one must fail loudly here.
_NEW_KEYS = {
    "used_memory",
    "maxmemory",
    "mem_fragmentation_ratio",
    "instantaneous_ops_per_sec",
    "keyspace_hits",
    "keyspace_misses",
    "role",
    "connected_slaves",
    "master_repl_offset",
    "rdb_last_save_time",
    "rdb_last_bgsave_status",
    "aof_enabled",
}


def test_contract_fixture_round_trip():
    """SHARED FIXTURE (cross-repo contract): fixtures/redis_contract_payload.json.

    Asserted on both sides:
    - here: redis_metrics(**fixture["config"]) must equal each scenario's
      "payload" with only socket.create_connection mocked (the scenario's raw
      "info" is fed back as the reply), pinning parse -> payload;
    - fivenines-server: spec/requests/api_collect_redis_spec.rb posts each
      "payload" under data["redis"] and asserts Ingesters::Agent ingests it.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)
    config = fixture["config"]

    for name, scenario in fixture["scenarios"].items():
        sock = _fake_socket(scenario["info"].encode())
        with patch("fivenines_agent.redis.socket.create_connection", return_value=sock):
            out = redis.redis_metrics(**config)
        assert out == scenario["payload"], "scenario '{}' drifted".format(name)

    scenarios = fixture["scenarios"]

    # master carries every section: legacy keys stay, new keys arrive, nested
    # db*/slave* shapes hold, and substring traps never leak in.
    master = scenarios["master"]["payload"]
    assert _LEGACY_KEYS <= set(master)
    assert _NEW_KEYS <= set(master)
    assert master["slave0"]["state"] == "online"
    assert master["slave0"]["port"] == 6379.0
    assert set(master["db0"]) == {"keys", "expires", "avg_ttl"}
    for trap in ("used_memory_rss", "used_memory_peak", "maxmemory_policy"):
        assert trap not in master

    # replica exposes the replica-only link fields; a standalone/master must not.
    replica = scenarios["replica"]["payload"]
    assert replica["role"] == "slave"
    assert {
        "master_link_status",
        "slave_repl_offset",
        "master_last_io_seconds_ago",
    } <= (set(replica))
    assert "master_link_status" not in scenarios["standalone"]["payload"]

    # Valkey ships its own version string alongside the compat redis_version.
    valkey = scenarios["valkey"]["payload"]
    assert valkey["valkey_version"] == "8.0.1"
    assert valkey["redis_version"] == "7.2.4"

    # A denied reply degrades to {} (server presence gate skips it).
    assert scenarios["auth_failure"]["payload"] == {}


def test_fixture_config_is_the_documented_shape():
    """The agent receives config["redis"] == {port, password?}; the fixture's
    'config' pins that contract shape (no host, no new keys)."""
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)
    assert set(fixture["config"]) <= {"port", "password"}
    assert fixture["agent_min_version"] == "1.11.0"
