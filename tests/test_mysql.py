"""Tests for fivenines_agent.mysql (the PyMySQL collector).

Three seams:
  - pure helpers, called directly;
  - the driver's connection class replaced by FakeConnection
    (mysql._connection_class patched): the contract fixture and the
    orchestration branches;
  - tests/mysql_fake.FakeMySQL, an in-process MySQL wire-protocol server the
    REAL PyMySQL talks to: connection options, authentication refusals, byte
    decoding and error mapping run against actual packets.

No MySQL/MariaDB is needed; tests/test_mysql_integration.py runs the
collector against a real server when asked to.
"""

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from unittest.mock import MagicMock

import pymysql
import pytest

from fivenines_agent import mysql
from fivenines_agent.bounded import WorkerTimeout
from fivenines_agent.mysql import (
    GALERA_STATUS_SQL,
    REPLICA_STATUS_SQL,
    SLAVE_STATUS_SQL,
    STATUS_SQL,
    VARIABLES_SQL,
    _add_galera_metrics,
    _add_status_metrics,
    _add_variable_metrics,
    _best_effort,
    _buffer_pool_hit_ratio,
    _buffer_pool_usage_pct,
    _build_replication,
    _classify,
    _close,
    _code,
    _connect,
    _connect_detail,
    _default_socket,
    _detail,
    _failure,
    _first,
    _get_replication,
    _missing_package_detail,
    _os_error,
    _password_bytes,
    _refuse_cleartext,
    _rows,
    _status_map,
    _target,
    _text,
    _to_float,
    _to_int,
    _yes,
    mysql_metrics,
)
from tests.mysql_fake import (
    FakeMySQL,
    drop,
    error,
    hang,
    load_local,
    rows,
)

needs_unix_sockets = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="needs AF_UNIX (not on Windows)"
)

STATUS_COLUMNS = ["Variable_name", "Value"]

# ---------------------------------------------------------------------------
# Inline fixtures, as the driver returns them. STATUS/VARIABLES key sets are
# identical on MySQL and MariaDB; only the replica statement/columns diverge.
# ---------------------------------------------------------------------------

MYSQL8_STATUS = [
    ("Threads_connected", "42"),
    ("Queries", "1234567"),
    ("Slow_queries", "12"),
    ("Aborted_connects", "3"),
    ("Uptime", "864000"),
    ("Innodb_buffer_pool_reads", "1300"),
    ("Innodb_buffer_pool_read_requests", "1000000"),
    ("Innodb_buffer_pool_pages_total", "1000"),
    ("Innodb_buffer_pool_pages_free", "358"),
]

MYSQL8_VARS = [("max_connections", "151"), ("version", "8.0.36")]

# MySQL 8.0.22+ SHOW REPLICA STATUS (columns trimmed).
MYSQL8_REPLICA_COLUMNS = [
    "Replica_IO_State",
    "Source_Host",
    "Seconds_Behind_Source",
    "Replica_IO_Running",
    "Replica_SQL_Running",
]
MYSQL8_REPLICA = [("Waiting for source to send event", "10.0.0.1", "5", "Yes", "Yes")]

# MariaDB: read_requests == 0 exercises the div/0 guard (hit ratio -> 100.0);
# equal total/free -> 0.0 usage.
MARIADB_STATUS = [
    ("Threads_connected", "7"),
    ("Queries", "555"),
    ("Slow_queries", "0"),
    ("Aborted_connects", "1"),
    ("Uptime", "3600"),
    ("Innodb_buffer_pool_reads", "0"),
    ("Innodb_buffer_pool_read_requests", "0"),
    ("Innodb_buffer_pool_pages_total", "500"),
    ("Innodb_buffer_pool_pages_free", "500"),
]

MARIADB_VARS = [("max_connections", "100"), ("version", "10.11.6-MariaDB")]

# A Galera node: wsrep_on is the gate of the wsrep statement.
GALERA_VARS = MARIADB_VARS + [("wsrep_on", "ON")]

# What MariaDB WITHOUT Galera answers (measured on 10.11.19, wsrep_on OFF, no
# provider): wsrep rows all the same, a "Disconnected" cluster among them.
MARIADB_NO_GALERA_VARS = [
    ("max_connections", "151"),
    ("version", "10.11.19-MariaDB"),
    ("wsrep_on", "OFF"),
]
MARIADB_NO_GALERA_WSREP = [
    ("wsrep", "0"),
    ("wsrep_applier_thread_count", "0"),
    ("wsrep_cluster_capabilities", ""),
    ("wsrep_cluster_conf_id", "18446744073709551615"),
    ("wsrep_cluster_size", "0"),
    ("wsrep_cluster_state_uuid", ""),
    ("wsrep_cluster_status", "Disconnected"),
    ("wsrep_connected", "OFF"),
    ("wsrep_local_bf_aborts", "0"),
    ("wsrep_local_index", "18446744073709551615"),
    ("wsrep_provider_capabilities", ""),
    ("wsrep_provider_name", ""),
    ("wsrep_provider_vendor", ""),
    ("wsrep_provider_version", ""),
    ("wsrep_ready", "OFF"),
    ("wsrep_rollbacker_thread_count", "0"),
    ("wsrep_thread_count", "0"),
]

# MariaDB / older-MySQL SHOW SLAVE STATUS (columns trimmed).
MARIADB_REPLICA_COLUMNS = [
    "Slave_IO_State",
    "Master_Host",
    "Seconds_Behind_Master",
    "Slave_IO_Running",
    "Slave_SQL_Running",
]
MARIADB_REPLICA = [("Waiting for master to send event", "10.0.0.2", "0", "Yes", "Yes")]

# Broken replication: NULL lag + SQL thread stopped.
NULL_LAG_COLUMNS = [
    "Seconds_Behind_Source",
    "Replica_IO_Running",
    "Replica_SQL_Running",
]
NULL_LAG_REPLICA = [(None, "Yes", "No")]

# Healthy Galera node. Carries two non-whitelisted rows (wsrep_protocol_version,
# wsrep_provider_name) to prove the whitelist drops everything else.
GALERA_WSREP = [
    ("wsrep_protocol_version", "10"),
    ("wsrep_cluster_size", "3"),
    ("wsrep_cluster_status", "Primary"),
    ("wsrep_local_state", "4"),
    ("wsrep_local_state_comment", "Synced"),
    ("wsrep_ready", "ON"),
    ("wsrep_connected", "ON"),
    ("wsrep_flow_control_paused", "0.012"),
    ("wsrep_local_recv_queue_avg", "0.05"),
    ("wsrep_provider_name", "Galera"),
]

# A Galera node reporting a pathological non-finite flow-control gauge.
GALERA_WSREP_NAN = [
    ("wsrep_cluster_size", "3"),
    ("wsrep_cluster_status", "Primary"),
    ("wsrep_local_state", "4"),
    ("wsrep_local_state_comment", "Synced"),
    ("wsrep_ready", "ON"),
    ("wsrep_connected", "ON"),
    ("wsrep_flow_control_paused", "nan"),
    ("wsrep_local_recv_queue_avg", "0.05"),
]


def status(values):
    return rows(STATUS_COLUMNS, values)


def server_results(
    status_rows=MYSQL8_STATUS, variables=MYSQL8_VARS, replica=None, wsrep=None
):
    """FakeMySQL results for one healthy server. `variables` and `wsrep` are
    rows or a scripted reply (error()/hang()/drop()); `replica` is a scripted
    reply, by default an empty SHOW REPLICA STATUS (not a replica)."""

    def reply(value):
        return status(value) if isinstance(value, list) else value

    return {
        STATUS_SQL: status(status_rows),
        VARIABLES_SQL: reply(variables),
        REPLICA_STATUS_SQL: (
            replica if replica is not None else rows(MYSQL8_REPLICA_COLUMNS, [])
        ),
        GALERA_STATUS_SQL: reply(wsrep if wsrep is not None else []),
    }


@pytest.fixture
def short_dir():
    """A short directory for unix sockets (sun_path holds ~104-108 bytes)."""
    path = tempfile.mkdtemp(prefix="my")
    yield path
    shutil.rmtree(path, ignore_errors=True)


def tcp(server, **kwargs):
    """mysql_metrics against a FakeMySQL listening on TCP."""
    return mysql_metrics(host="127.0.0.1", port=server.port, **kwargs)


# ---------------------------------------------------------------------------
# FakeConnection: the driver mocked (fixture + orchestration branches)
# ---------------------------------------------------------------------------


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = None
        self._rows = ()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql):
        self.conn.queries.append(sql)
        reply = self.conn.results.get(sql)
        if reply is None:
            raise pymysql.err.ProgrammingError(
                1064, "You have an error in your SQL syntax"
            )
        if isinstance(reply, BaseException):
            raise reply
        columns, values = reply
        self.description = tuple((name,) for name in columns)
        # As the driver returns them with no converters: bytes, or None.
        self._rows = tuple(
            tuple(None if v is None else str(v).encode("utf-8") for v in row)
            for row in values
        )

    def fetchall(self):
        return self._rows


class FakeConnection:
    def __init__(self, results):
        self.results = results
        self.queries = []
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def close(self):
        self.closed = True


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [("42", 42), ("0", 0), ("NULL", None), ("", None), (None, None), ("x", None)],
)
def test_to_int(value, expected):
    assert _to_int(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("0.012", 0.012),
        ("3", 3.0),
        ("0", 0.0),
        ("1e308", 1e308),  # large but FINITE -> kept
        ("NULL", None),
        ("", None),
        (None, None),
        ("x", None),
        # Non-finite floats are rejected to None: they are valid Python floats
        # but serialize as invalid Infinity/NaN JSON that poisons the whole tick.
        ("inf", None),
        ("-inf", None),
        ("Infinity", None),
        ("nan", None),
        ("NaN", None),
        ("1e999", None),  # overflows float() to inf -> rejected
    ],
)
def test_to_float(value, expected):
    assert _to_float(value) == expected


def test_first_returns_first_present_key():
    row = {"Slave_IO_Running": "Yes"}
    assert _first(row, "Replica_IO_Running", "Slave_IO_Running") == "Yes"
    assert _first(row, "Replica_IO_Running") is None


@pytest.mark.parametrize(
    "value,expected",
    [("Yes", True), ("yes", True), ("No", False), (" YES ", True), (None, False)],
)
def test_yes(value, expected):
    assert _yes(value) is expected


def test_hit_ratio_normal():
    status_map = {
        "Innodb_buffer_pool_reads": "1300",
        "Innodb_buffer_pool_read_requests": "1000000",
    }
    assert _buffer_pool_hit_ratio(status_map) == 99.87


def test_hit_ratio_zero_requests_guarded_to_100():
    status_map = {
        "Innodb_buffer_pool_reads": "0",
        "Innodb_buffer_pool_read_requests": "0",
    }
    assert _buffer_pool_hit_ratio(status_map) == 100.0


def test_hit_ratio_none_when_counters_absent():
    assert _buffer_pool_hit_ratio({}) is None


def test_usage_pct_normal():
    status_map = {
        "Innodb_buffer_pool_pages_total": "1000",
        "Innodb_buffer_pool_pages_free": "358",
    }
    assert _buffer_pool_usage_pct(status_map) == 64.2


def test_usage_pct_zero_total_guarded_to_none():
    status_map = {
        "Innodb_buffer_pool_pages_total": "0",
        "Innodb_buffer_pool_pages_free": "0",
    }
    assert _buffer_pool_usage_pct(status_map) is None


def test_usage_pct_none_when_counters_absent():
    assert _buffer_pool_usage_pct({}) is None


def test_add_status_metrics_full():
    metrics = {}
    _add_status_metrics(metrics, dict(MYSQL8_STATUS))
    assert metrics == {
        "connections": 42,
        "queries": 1234567,
        "slow_queries": 12,
        "aborted_connects": 3,
        "uptime": 864000,
        "innodb_buffer_pool_hit_ratio": 99.87,
        "innodb_buffer_pool_usage_pct": 64.2,
    }


def test_add_status_metrics_omits_absent_keys():
    metrics = {}
    _add_status_metrics(metrics, {"Threads_connected": "5"})
    assert metrics == {"connections": 5}


def test_add_variable_metrics():
    metrics = {}
    _add_variable_metrics(metrics, dict(MYSQL8_VARS))
    assert metrics == {"max_connections": 151, "version": "8.0.36"}


def test_add_variable_metrics_omits_absent():
    metrics = {}
    _add_variable_metrics(metrics, {})
    assert metrics == {}


def test_build_replication_mysql8():
    row = dict(zip(MYSQL8_REPLICA_COLUMNS, MYSQL8_REPLICA[0]))
    assert _build_replication(row) == {
        "lag_seconds": 5,
        "io_running": True,
        "sql_running": True,
        "running": True,
    }


def test_build_replication_mariadb():
    row = dict(zip(MARIADB_REPLICA_COLUMNS, MARIADB_REPLICA[0]))
    assert _build_replication(row) == {
        "lag_seconds": 0,
        "io_running": True,
        "sql_running": True,
        "running": True,
    }


def test_build_replication_null_lag_not_running():
    repl = _build_replication(dict(zip(NULL_LAG_COLUMNS, NULL_LAG_REPLICA[0])))
    assert repl == {
        "lag_seconds": None,
        "io_running": True,
        "sql_running": False,
        "running": False,
    }


def test_add_galera_metrics_whitelist_and_types():
    metrics = {}
    _add_galera_metrics(metrics, dict(GALERA_WSREP))
    assert metrics == {
        "wsrep_cluster_size": 3,
        "wsrep_cluster_status": "Primary",
        "wsrep_local_state": 4,
        "wsrep_local_state_comment": "Synced",
        "wsrep_ready": "ON",
        "wsrep_connected": "ON",
        "wsrep_flow_control_paused": 0.012,
        "wsrep_local_recv_queue_avg": 0.05,
    }
    assert isinstance(metrics["wsrep_cluster_size"], int)
    assert isinstance(metrics["wsrep_flow_control_paused"], float)


def test_add_galera_metrics_empty_is_noop():
    """Non-Galera server: zero wsrep rows -> no keys added (implicit detection)."""
    metrics = {}
    _add_galera_metrics(metrics, {})
    assert metrics == {}


def test_add_galera_metrics_omits_unparseable_numeric():
    """A NULL/garbage numeric gauge is omitted, never fabricated as null."""
    metrics = {}
    _add_galera_metrics(
        metrics,
        {
            "wsrep_cluster_size": "",
            "wsrep_flow_control_paused": "n/a",
            "wsrep_cluster_status": "Primary",
        },
    )
    assert metrics == {"wsrep_cluster_status": "Primary"}


def test_add_galera_metrics_omits_non_finite_and_blank():
    """inf/nan floats and blank status strings drop out; a real 0 / 0.0 stays."""
    metrics = {}
    _add_galera_metrics(
        metrics,
        {
            "wsrep_flow_control_paused": "nan",
            "wsrep_local_recv_queue_avg": "inf",
            "wsrep_cluster_status": "",
            "wsrep_local_state": "0",
            "wsrep_ready": "ON",
        },
    )
    assert metrics == {"wsrep_local_state": 0, "wsrep_ready": "ON"}


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        (b"Primary", "Primary"),
        (bytearray(b"ON"), "ON"),
        (b"Prim\xe4ry", "Prim\ufffdry"),  # a latin-1 byte: replaced, never raised
        (5, "5"),
    ],
)
def test_text(value, expected):
    assert _text(value) == expected


def test_status_map_decodes_strips_and_reads_null_as_blank():
    assert _status_map(
        [
            (b"Threads_connected", b" 42 "),
            (b"wsrep_cluster_status", None),  # NULL -> "" (omitted downstream)
            (None, b"orphan"),  # no name: skipped
            (b"lonely",),  # one column: skipped
        ]
    ) == {"Threads_connected": "42", "wsrep_cluster_status": ""}


@pytest.mark.parametrize(
    "password,expected",
    [
        (None, b""),
        ("", b""),
        ("secret", b"secret"),
        ("p\u00e4ssw\u00f6rd\u20ac", "p\u00e4ssw\u00f6rd\u20ac".encode("utf-8")),
        (1234, b"1234"),
    ],
)
def test_password_bytes_are_utf8(password, expected):
    assert _password_bytes(password) == expected


# ---------------------------------------------------------------------------
# Where to connect: configured socket, localhost -> default socket, TCP
# ---------------------------------------------------------------------------


@needs_unix_sockets
def test_default_socket_returns_the_first_socket(short_dir, monkeypatch):
    regular = os.path.join(short_dir, "regular.sock")
    open(regular, "w").close()
    listening = os.path.join(short_dir, "mysqld.sock")
    with FakeMySQL(unix_path=listening):
        monkeypatch.setattr(
            mysql,
            "_DEFAULT_SOCKETS",
            (os.path.join(short_dir, "missing.sock"), regular, listening),
        )
        assert _default_socket() == listening


def test_default_socket_none_when_no_path_is_a_socket(short_dir, monkeypatch):
    monkeypatch.setattr(mysql, "_DEFAULT_SOCKETS", (os.path.join(short_dir, "x"),))
    assert _default_socket() is None


def test_default_sockets_never_in_a_world_writable_directory():
    """PyMySQL sends a caching_sha2 password in clear over a unix socket:
    a path any local user could create would be a way to collect it."""
    for path in mysql._DEFAULT_SOCKETS:
        assert not path.startswith("/tmp/"), path
        assert not path.startswith("/var/tmp/"), path


def test_target_configured_socket_wins(monkeypatch):
    monkeypatch.setattr(mysql, "_HAS_UNIX_SOCKETS", True)
    assert _target("db.example", 3307, "/srv/mysql.sock") == (
        "/srv/mysql.sock",
        None,
        None,
    )


def test_target_localhost_is_the_default_socket(monkeypatch):
    monkeypatch.setattr(mysql, "_HAS_UNIX_SOCKETS", True)
    monkeypatch.setattr(mysql, "_default_socket", lambda: "/run/mysqld/mysqld.sock")
    assert _target("localhost", 3306, None) == ("/run/mysqld/mysqld.sock", None, None)
    # No host at all is localhost too.
    assert _target(None, 3306, None) == ("/run/mysqld/mysqld.sock", None, None)


def test_target_localhost_without_a_socket_is_tcp(monkeypatch):
    """No local server socket: TCP to the port, what MariaDB's client did with
    -P (a MySQL in Docker with its port published) -- to 127.0.0.1, never the
    name localhost, which can resolve to ::1 first, where any local user may
    listen on a port the server holds on 127.0.0.1 only."""
    monkeypatch.setattr(mysql, "_HAS_UNIX_SOCKETS", True)
    monkeypatch.setattr(mysql, "_default_socket", lambda: None)
    assert _target("localhost", 3306, None) == (None, "127.0.0.1", 3306)


def test_target_localhost_on_another_port_is_tcp(monkeypatch):
    """A port other than 3306 names an instance: never the default socket's."""
    monkeypatch.setattr(mysql, "_HAS_UNIX_SOCKETS", True)
    monkeypatch.setattr(mysql, "_default_socket", lambda: "/run/mysqld/mysqld.sock")
    assert _target("localhost", 3307, None) == (None, "127.0.0.1", 3307)
    assert _target("localhost", None, None) == ("/run/mysqld/mysqld.sock", None, None)


def test_target_localhost_is_tcp_without_unix_sockets(monkeypatch):
    """Windows: no AF_UNIX, so localhost is TCP, as for the client there."""
    monkeypatch.setattr(mysql, "_HAS_UNIX_SOCKETS", False)
    assert _target("localhost", 3306, None) == (None, "127.0.0.1", 3306)


@pytest.mark.parametrize(
    "host,port,expected",
    [
        ("127.0.0.1", 3306, (None, "127.0.0.1", 3306)),
        ("::1", 3306, (None, "::1", 3306)),  # configured: used as given
        ("db.example", "3307", (None, "db.example", 3307)),
        ("db.example", None, (None, "db.example", 3306)),
    ],
)
def test_target_tcp(host, port, expected):
    assert _target(host, port, None) == expected


def test_target_bad_port_raises():
    with pytest.raises(ValueError):
        _target("127.0.0.1", "abc", None)


def _connect_with_options(monkeypatch, *args, **kwargs):
    """_connect's keyword arguments to the driver's connection class."""
    connection_class = MagicMock()
    monkeypatch.setattr(mysql, "_connection_class", lambda driver: connection_class)
    _connect(MagicMock(), *args, **kwargs)
    return connection_class.call_args.kwargs


def test_connect_options_over_tcp(monkeypatch):
    options = _connect_with_options(
        monkeypatch, (None, "10.0.0.5", 3307), "monitor", "pw", "app"
    )
    assert options["host"] == "10.0.0.5"
    assert options["port"] == 3307
    assert "unix_socket" not in options
    assert "ssl_disabled" not in options  # TLS PREFERRED, PyMySQL's default
    assert set(options["auth_plugin_map"]) == {"mysql_clear_password", "dialog"}
    assert options["user"] == "monitor"
    assert options["password"] == b"pw"
    assert options["database"] == "app"
    assert options["charset"] == "utf8mb4"
    assert options["use_unicode"] is False
    assert options["conv"] == {}
    assert options["autocommit"] is None
    assert options["local_infile"] is False
    assert options["connect_timeout"] == mysql.CONNECT_TIMEOUT
    assert options["read_timeout"] == mysql.IO_TIMEOUT
    assert options["write_timeout"] == mysql.IO_TIMEOUT
    assert options["program_name"] == "fivenines-agent"


def test_connect_options_over_tcp_without_tls(monkeypatch):
    """The TLS fallback's second attempt: TLS off, nothing else changed."""
    options = _connect_with_options(
        monkeypatch, (None, "10.0.0.5", 3307), "monitor", "pw", None, tls=False
    )
    assert options["ssl_disabled"] is True
    assert set(options["auth_plugin_map"]) == {"mysql_clear_password", "dialog"}
    assert options["host"] == "10.0.0.5"


def test_configured_socket_without_unix_sockets_is_a_clear_error(monkeypatch):
    """Windows: a socket path cannot be dialed; say so instead of an
    AttributeError about AF_UNIX."""
    monkeypatch.setattr(mysql, "_HAS_UNIX_SOCKETS", False)
    assert mysql_metrics(socket="/run/mysqld/mysqld.sock") == {
        "reachable": False,
        "error": "error",
        "error_detail": "a unix socket is configured, but this platform has no"
        " unix sockets: configure the host and port instead",
    }


def test_connect_options_over_a_unix_socket(monkeypatch):
    options = _connect_with_options(
        monkeypatch, ("/run/mysqld/mysqld.sock", None, None), None, None, None
    )
    assert options["unix_socket"] == "/run/mysqld/mysqld.sock"
    assert options["ssl_disabled"] is True
    assert "auth_plugin_map" not in options  # PAM (dialog) kept on the socket
    assert "host" not in options
    assert options["user"] == "root"
    assert options["password"] == b""
    assert options["database"] is None


def test_refuse_cleartext_raises_before_answering():
    handler = _refuse_cleartext("mysql_clear_password")
    with pytest.raises(pymysql.err.OperationalError) as raised:
        handler(object())
    code, message = raised.value.args
    assert code == 2059
    assert "'mysql_clear_password' refused over TCP" in message


def test_error_codes_are_pymysqls():
    """The collector names the codes itself (PyMySQL loads lazily)."""
    from pymysql.constants import CR, ER

    assert mysql._CR_CONNECTION_ERROR == CR.CR_CONNECTION_ERROR
    assert mysql._CR_CONN_HOST_ERROR == CR.CR_CONN_HOST_ERROR
    assert mysql._CR_UNKNOWN_HOST == CR.CR_UNKNOWN_HOST
    assert mysql._CR_AUTH_PLUGIN_CANNOT_LOAD == CR.CR_AUTH_PLUGIN_CANNOT_LOAD
    assert mysql._AUTH_ERRORS == {
        ER.DBACCESS_DENIED_ERROR,
        ER.ACCESS_DENIED_ERROR,
        ER.HOST_NOT_PRIVILEGED,
        ER.NOT_SUPPORTED_AUTH_MODE,
        1698,  # ER_ACCESS_DENIED_NO_PASSWORD_ERROR, not in PyMySQL's ER
        CR.CR_AUTH_PLUGIN_CANNOT_LOAD,
        CR.CR_AUTH_PLUGIN_ERR,
    }


def test_pymysql_is_not_imported_until_a_collection_runs():
    """Hosts without MySQL never pay PyMySQL's import: with cryptography,
    which its RSA support loads, about 10 MB of RSS."""
    code = (
        "import sys, fivenines_agent.collectors\n"
        "assert 'pymysql' not in sys.modules, 'pymysql imported at load'\n"
        "assert 'cryptography' not in sys.modules, 'cryptography imported at load'\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=60)


def test_close_swallows_a_dead_connection():
    conn = MagicMock()
    conn.close.side_effect = pymysql.err.Error("Already closed")
    _close(conn)
    conn.close.assert_called_once()


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


def _connect_error(os_error):
    exc = pymysql.err.OperationalError(
        2003, f"Can't connect to MySQL server on 'h' ({os_error})"
    )
    exc.original_exception = os_error
    return exc


def _read_error(os_error):
    try:
        try:
            raise os_error
        except OSError as e:
            raise pymysql.err.OperationalError(
                2013, f"Lost connection to MySQL server during query ({e})"
            )
    except pymysql.err.OperationalError as wrapped:
        return wrapped


def test_os_error_sources():
    refused = ConnectionRefusedError(111, "Connection refused")
    assert _os_error(_connect_error(refused)) is refused
    timeout = TimeoutError("timed out")
    assert _os_error(_read_error(timeout)) is timeout
    caused = pymysql.err.OperationalError(2013, "x")
    caused.__cause__ = refused
    assert _os_error(caused) is refused
    assert _os_error(pymysql.err.OperationalError(1045, "denied")) is None


def test_code():
    assert _code(pymysql.err.OperationalError(1045, "denied")) == 1045
    assert _code(pymysql.err.OperationalError("no code")) is None
    assert _code(pymysql.err.InterfaceError()) is None


@pytest.mark.parametrize(
    "exc,expected",
    [
        (pymysql.err.OperationalError(1045, "Access denied"), "auth_failed"),
        (
            pymysql.err.OperationalError(1044, "Access denied to database"),
            "auth_failed",
        ),
        (
            pymysql.err.OperationalError(1698, "Access denied for user 'root'"),
            "auth_failed",
        ),
        (pymysql.err.OperationalError(1130, "Host is not allowed"), "auth_failed"),
        (pymysql.err.OperationalError(1251, "Client does not support"), "auth_failed"),
        (pymysql.err.OperationalError(2059, "plugin refused"), "auth_failed"),
        (pymysql.err.OperationalError(2061, "plugin error"), "auth_failed"),
        # Value: protects=an account-side "Access denied" at login (locked,
        # login-blocked, roles' 1044) reads auth_failed, as the CLI path's match on
        # that text read it; fails_when=such a code is missing from _AUTH_ERRORS and
        # the account reads as a red outage; why_new=no row above is a lock;
        # seam=none; no_claim=expired passwords (1820/1862) and blocked hosts or
        # users (1129/4150), which the CLI path read as error too.
        # Codes from the MySQL 8.4 and MariaDB 11.8 mysqld_error.h.
        (
            pymysql.err.OperationalError(
                3118, "Access denied for user 'm'@'h'. Account is locked."
            ),
            "auth_failed",
        ),
        (
            pymysql.err.OperationalError(
                3955,
                "Access denied for user 'm'@'h'. Account is blocked for 1 day(s)"
                " (1 day(s) remaining) due to 3 consecutive failed logins.",
            ),
            "auth_failed",
        ),
        (
            pymysql.err.OperationalError(4151, "Access denied, this account is locked"),
            "auth_failed",
        ),
        (
            pymysql.err.OperationalError(
                3879, "Access denied for AuthId `m`@`%` to database 'app'."
            ),
            "auth_failed",
        ),
        # A server error without that text stays an outage.
        (pymysql.err.OperationalError(1053, "Server shutdown in progress"), "error"),
        (
            _connect_error(ConnectionRefusedError(111, "Connection refused")),
            "connection_refused",
        ),
        (
            _connect_error(FileNotFoundError(2, "No such file or directory")),
            "connection_refused",
        ),
        (_connect_error(OSError(113, "No route to host")), "connection_refused"),
        (
            _connect_error(socket.gaierror(-2, "Name or service not known")),
            "unreachable",
        ),
        (_connect_error(TimeoutError("timed out")), "timeout"),
        (_read_error(TimeoutError("timed out")), "timeout"),
        (_read_error(ConnectionResetError(104, "reset")), "error"),
        (pymysql.err.OperationalError(2003, "no cause"), "error"),
        (pymysql.err.OperationalError(1049, "Unknown database"), "error"),
        (pymysql.err.InternalError("Packet sequence number wrong"), "error"),
    ],
)
def test_classify(exc, expected):
    assert _classify(exc) == expected


@pytest.mark.parametrize(
    "target,os_error,expected",
    [
        (
            ("/run/mysqld/mysqld.sock", None, None),
            FileNotFoundError(2, "No such file or directory"),
            "ERROR 2002: Can't connect to local MySQL server through socket"
            " '/run/mysqld/mysqld.sock' (No such file or directory)",
        ),
        (
            (None, "db.example", 3306),
            socket.gaierror(-2, "Name or service not known"),
            "ERROR 2005: Unknown MySQL server host 'db.example' (Name or service not known)",
        ),
        (
            (None, "10.0.0.5", 3306),
            ConnectionRefusedError(111, "Connection refused"),
            "ERROR 2003: Can't connect to MySQL server on '10.0.0.5:3306' (Connection refused)",
        ),
        (
            (None, "10.0.0.5", 3306),
            TimeoutError("timed out"),
            "ERROR 2003: Can't connect to MySQL server on '10.0.0.5:3306' (timed out)",
        ),
        (
            (None, "10.0.0.5", 3306),
            OSError(),
            "ERROR 2003: Can't connect to MySQL server on '10.0.0.5:3306' (OSError)",
        ),
    ],
)
def test_connect_detail(target, os_error, expected):
    assert _connect_detail(target, os_error) == expected


def test_detail():
    target = (None, "10.0.0.5", 3306)
    refused = _connect_error(ConnectionRefusedError(111, "Connection refused"))
    assert _detail(refused, target).startswith(
        "ERROR 2003: Can't connect to MySQL server on '10.0.0.5:3306'"
    )
    denied = pymysql.err.OperationalError(
        1045, "Access denied for user 'u'@'h' (using password: YES)"
    )
    # Not redacted: "(using password: YES)" tells the operator a password was sent.
    assert (
        _detail(denied, target)
        == "ERROR 1045: Access denied for user 'u'@'h' (using password: YES)"
    )
    assert _detail(
        pymysql.err.OperationalError("received multiple auth switch requests"), target
    ) == ("received multiple auth switch requests")
    assert _detail(pymysql.err.InterfaceError(), target) == "InterfaceError"


def test_missing_package_detail():
    nacl = RuntimeError("'pynacl' package is required for ed25519_password auth method")
    detail = _missing_package_detail(nacl)
    assert "ed25519" in detail and "use an account with another plugin" in detail
    assert _missing_package_detail(RuntimeError("other")) == "other"


def test_failure_envelope():
    assert _failure("timeout", None) == {"reachable": False, "error": "timeout"}
    assert _failure("error", "") == {"reachable": False, "error": "error"}
    assert _failure("auth_failed", "ERROR 1045: denied") == {
        "reachable": False,
        "error": "auth_failed",
        "error_detail": "ERROR 1045: denied",
    }
    long = _failure("error", "x" * 2000 + "\x00")
    assert len(long["error_detail"]) == mysql.ERROR_DETAIL_MAX


# ---------------------------------------------------------------------------
# Statements: _rows / _best_effort / _get_replication (driver mocked)
# ---------------------------------------------------------------------------


def test_rows_returns_names_and_bytes():
    conn = FakeConnection({STATUS_SQL: (STATUS_COLUMNS, [("Uptime", "5")])})
    assert _rows(conn, STATUS_SQL) == (STATUS_COLUMNS, ((b"Uptime", b"5"),))


def test_best_effort_returns_none_on_any_failure():
    conn = FakeConnection({"BOOM": RuntimeError("Received LOAD_LOCAL packet")})
    assert _best_effort(conn, "BOOM") is None
    assert _best_effort(conn, "UNKNOWN") is None  # syntax error


def test_get_replication_mysql8_replica():
    conn = FakeConnection(
        {REPLICA_STATUS_SQL: (MYSQL8_REPLICA_COLUMNS, MYSQL8_REPLICA)}
    )
    is_replica, repl = _get_replication(conn)
    assert is_replica is True
    assert repl["lag_seconds"] == 5
    assert conn.queries == [REPLICA_STATUS_SQL]


def test_get_replication_falls_back_to_slave():
    conn = FakeConnection(
        {SLAVE_STATUS_SQL: (MARIADB_REPLICA_COLUMNS, MARIADB_REPLICA)}
    )
    is_replica, repl = _get_replication(conn)
    assert is_replica is True
    assert repl["lag_seconds"] == 0
    assert conn.queries == [REPLICA_STATUS_SQL, SLAVE_STATUS_SQL]


def test_get_replication_remembers_working_verb():
    """An old server rejects REPLICA: after the first fallback, SLAVE leads,
    and once the server is upgraded REPLICA takes the lead back."""
    old = FakeConnection({SLAVE_STATUS_SQL: (MARIADB_REPLICA_COLUMNS, [])})
    _get_replication(old)
    old.queries.clear()
    assert _get_replication(old) == (False, None)
    assert old.queries == [SLAVE_STATUS_SQL]

    upgraded = FakeConnection({REPLICA_STATUS_SQL: (MYSQL8_REPLICA_COLUMNS, [])})
    assert _get_replication(upgraded) == (False, None)
    assert upgraded.queries == [SLAVE_STATUS_SQL, REPLICA_STATUS_SQL]
    upgraded.queries.clear()
    _get_replication(upgraded)
    assert upgraded.queries == [REPLICA_STATUS_SQL]


def test_get_replication_not_a_replica():
    conn = FakeConnection({REPLICA_STATUS_SQL: (MYSQL8_REPLICA_COLUMNS, [])})
    assert _get_replication(conn) == (False, None)


def test_get_replication_undetermined_when_both_fail():
    denied = pymysql.err.OperationalError(
        1227, "Access denied; you need REPLICATION CLIENT"
    )
    conn = FakeConnection({REPLICA_STATUS_SQL: denied, SLAVE_STATUS_SQL: denied})
    assert _get_replication(conn) == (None, None)


def test_get_replication_reads_the_last_channel():
    """Multi-source replication lists one row per channel; the CLI path's
    \\G parse let the last row win, and the payload keeps that."""
    channels = [
        ("a", "10.0.0.1", "1", "Yes", "Yes"),
        ("b", "10.0.0.2", None, "Yes", "No"),
    ]
    conn = FakeConnection({REPLICA_STATUS_SQL: (MYSQL8_REPLICA_COLUMNS, channels)})
    assert _get_replication(conn) == (
        True,
        {
            "lag_seconds": None,
            "io_running": True,
            "sql_running": False,
            "running": False,
        },
    )


# ---------------------------------------------------------------------------
# mysql_metrics end to end: the real PyMySQL against FakeMySQL
# ---------------------------------------------------------------------------


def test_metrics_mysql8_full_payload_one_connection():
    results = server_results(replica=rows(MYSQL8_REPLICA_COLUMNS, MYSQL8_REPLICA))
    with FakeMySQL(results=results) as server:
        result = tcp(server, user="monitor", password="pw", database="app")
    assert result == {
        "reachable": True,
        "connections": 42,
        "queries": 1234567,
        "slow_queries": 12,
        "aborted_connects": 3,
        "uptime": 864000,
        "innodb_buffer_pool_hit_ratio": 99.87,
        "innodb_buffer_pool_usage_pct": 64.2,
        "max_connections": 151,
        "version": "8.0.36",
        "galera": False,
        "is_replica": True,
        "replication": {
            "lag_seconds": 5,
            "io_running": True,
            "sql_running": True,
            "running": True,
        },
    }
    # One connection for the whole collection, closed with COM_QUIT.
    assert server.connections == 1
    assert server.quit is True
    assert server.queries == [
        "SET NAMES utf8mb4",
        STATUS_SQL,
        VARIABLES_SQL,
        REPLICA_STATUS_SQL,
    ]  # no wsrep statement: MySQL has no wsrep_on
    assert server.user == "monitor"
    assert server.database == "app"
    assert server.connect_attrs["program_name"] == "fivenines-agent"


def test_metrics_mariadb_full_payload_via_slave_fallback():
    results = server_results(
        status_rows=MARIADB_STATUS,
        variables=MARIADB_VARS,
        replica=error(1064, "You have an error in your SQL syntax", b"42000"),
    )
    results[SLAVE_STATUS_SQL] = rows(MARIADB_REPLICA_COLUMNS, MARIADB_REPLICA)
    with FakeMySQL(results=results) as server:
        result = tcp(server)
    assert result["version"] == "10.11.6-MariaDB"
    assert result["innodb_buffer_pool_hit_ratio"] == 100.0
    assert result["innodb_buffer_pool_usage_pct"] == 0.0
    assert result["is_replica"] is True
    assert result["replication"]["lag_seconds"] == 0


def test_metrics_null_lag_replica():
    results = server_results(replica=rows(NULL_LAG_COLUMNS, NULL_LAG_REPLICA))
    with FakeMySQL(results=results) as server:
        result = tcp(server)
    assert result["is_replica"] is True
    assert result["replication"]["lag_seconds"] is None
    assert result["replication"]["running"] is False


def test_metrics_variables_failure_stays_reachable():
    denied = error(
        1227, "Access denied; you need (at least one of) the PROCESS privilege(s)"
    )
    with FakeMySQL(results=server_results(variables=denied)) as server:
        result = tcp(server)
    assert result["reachable"] is True
    assert "version" not in result
    assert "max_connections" not in result
    assert "galera" not in result  # unknown, never false
    assert result["connections"] == 42


def test_metrics_replication_undetermined_omits_is_replica():
    denied = error(1227, "Access denied; you need REPLICATION CLIENT")
    results = server_results(replica=denied)
    results[SLAVE_STATUS_SQL] = denied
    with FakeMySQL(results=results) as server:
        result = tcp(server)
    assert result["reachable"] is True
    assert "is_replica" not in result
    assert "replication" not in result


def test_metrics_galera_keys_merged_into_payload():
    results = server_results(variables=GALERA_VARS, wsrep=GALERA_WSREP)
    with FakeMySQL(results=results) as server:
        result = tcp(server)
    assert result["connections"] == 42
    assert result["galera"] is True
    assert result["wsrep_cluster_size"] == 3
    assert result["wsrep_cluster_status"] == "Primary"
    assert result["wsrep_flow_control_paused"] == 0.012
    assert "wsrep_provider_name" not in result


def test_metrics_non_galera_omits_wsrep_keys():
    with FakeMySQL(results=server_results()) as server:
        result = tcp(server)
    assert result["reachable"] is True
    assert result["galera"] is False
    assert not any(k.startswith("wsrep_") for k in result)


def test_metrics_mariadb_without_galera_is_not_a_degraded_cluster():
    """MariaDB answers the wsrep statement without Galera: a "Disconnected"
    cluster of size 0 that agents up to 1.24.0 shipped, which reads as a
    degraded Galera cluster server-side. wsrep_on OFF: no statement, no key."""
    results = server_results(
        variables=MARIADB_NO_GALERA_VARS, wsrep=MARIADB_NO_GALERA_WSREP
    )
    with FakeMySQL(results=results) as server:
        result = tcp(server)
    assert result["version"] == "10.11.19-MariaDB"
    # False tells the server to clear what an older agent made it store.
    assert result["galera"] is False
    assert not any(k.startswith("wsrep_") for k in result)
    assert GALERA_STATUS_SQL not in server.queries


def test_metrics_galera_unknown_when_variables_fail():
    """wsrep_on unreadable: the gate stays closed (no-data, never a guess)."""
    denied = error(1227, "Access denied")
    results = server_results(variables=denied, wsrep=GALERA_WSREP)
    with FakeMySQL(results=results) as server:
        result = tcp(server)
    assert result["reachable"] is True
    assert "galera" not in result
    assert not any(k.startswith("wsrep_") for k in result)
    assert GALERA_STATUS_SQL not in server.queries


@pytest.mark.parametrize(
    "variables,expected",
    [
        ({"wsrep_on": "ON"}, True),
        ({"wsrep_on": "on"}, True),
        ({"wsrep_on": "1"}, True),
        ({"wsrep_on": "OFF"}, False),
        ({"wsrep_on": ""}, False),  # NULL
        ({}, False),  # MySQL: no such variable
    ],
)
def test_galera_enabled(variables, expected):
    assert mysql._galera_enabled(variables) is expected


def test_metrics_galera_query_failure_stays_reachable():
    denied = error(1227, "Access denied; you need SUPER")
    results = server_results(variables=GALERA_VARS, wsrep=denied)
    with FakeMySQL(results=results) as server:
        result = tcp(server)
    assert result["reachable"] is True
    # A Galera node whose cluster state could not be read: keep what is stored.
    assert result["galera"] is True
    assert not any(k.startswith("wsrep_") for k in result)


def test_metrics_galera_non_finite_gauge_omitted_keeps_payload_json_safe():
    """A non-finite wsrep float is dropped, never shipped as Infinity/NaN,
    which a strict backend parser would reject with the WHOLE tick."""
    results = server_results(variables=GALERA_VARS, wsrep=GALERA_WSREP_NAN)
    with FakeMySQL(results=results) as server:
        result = tcp(server)
    assert "wsrep_flow_control_paused" not in result
    assert result["wsrep_local_recv_queue_avg"] == 0.05
    json.dumps(result, allow_nan=False)


def test_metrics_a_byte_that_is_not_utf8_is_replaced_not_raised():
    """Values arrive as bytes and are decoded with replacement (#172): a
    latin-1 byte in a status value must not null the collector."""
    wsrep = [("wsrep_cluster_status", b"Prim\xe4ry"), ("wsrep_ready", "ON")]
    results = server_results(variables=GALERA_VARS, wsrep=wsrep)
    with FakeMySQL(results=results) as server:
        result = tcp(server)
    assert result["wsrep_cluster_status"] == "Prim\ufffdry"
    assert result["wsrep_ready"] == "ON"


def test_metrics_tolerates_unknown_config_keys():
    with FakeMySQL(results=server_results()) as server:
        result = tcp(server, future_option="whatever")
    assert result["reachable"] is True


def test_metrics_connection_lost_after_the_probe_keeps_what_was_read():
    with FakeMySQL(results=server_results(variables=drop())) as server:
        result = tcp(server)
    assert result["reachable"] is True
    assert result["connections"] == 42
    for key in ("version", "is_replica", "replication"):
        assert key not in result


def test_metrics_load_data_local_is_refused():
    """A server asking for a local file gets nothing: an error envelope."""
    with FakeMySQL(results={STATUS_SQL: load_local("/etc/passwd")}) as server:
        result = tcp(server)
    assert result["reachable"] is False
    assert result["error"] == "error"
    assert "LOAD_LOCAL" in result["error_detail"]
    assert server.local_file_data is None or b"root:" not in server.local_file_data


# -- failures ---------------------------------------------------------------


def test_metrics_auth_failure_is_config_error_payload():
    denied = error(
        1045,
        "Access denied for user 'root'@'localhost' (using password: YES)",
        b"28000",
    )
    with FakeMySQL(auth_error=denied) as server:
        result = tcp(server, password="wrong")
    assert result == {
        "reachable": False,
        "error": "auth_failed",
        "error_detail": "ERROR 1045: Access denied for user 'root'@'localhost' (using password: YES)",
    }


def test_metrics_host_not_allowed_is_auth_failed():
    """1130 comes instead of the greeting: the account, not an outage."""
    refused = error(
        1130, "Host '10.0.0.9' is not allowed to connect to this MySQL server"
    )
    with FakeMySQL(greeting_error=refused) as server:
        result = tcp(server)
    assert result["error"] == "auth_failed"
    assert result["error_detail"].startswith("ERROR 1130: Host '10.0.0.9'")


def test_metrics_connection_refused_payload():
    with FakeMySQL() as server:
        port = server.port
    result = mysql_metrics(host="127.0.0.1", port=port)
    assert result["reachable"] is False
    assert result["error"] == "connection_refused"
    assert result["error_detail"].startswith(
        f"ERROR 2003: Can't connect to MySQL server on '127.0.0.1:{port}'"
    )


def test_metrics_unknown_host_is_unreachable(monkeypatch):
    def no_such_host(address, *args, **kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(pymysql.connections.socket, "create_connection", no_such_host)
    result = mysql_metrics(host="db.invalid", port=3306)
    assert result == {
        "reachable": False,
        "error": "unreachable",
        "error_detail": "ERROR 2005: Unknown MySQL server host 'db.invalid' (Name or service not known)",
    }


def test_metrics_greeting_timeout(monkeypatch):
    monkeypatch.setattr(mysql, "IO_TIMEOUT", 0.2)
    with FakeMySQL(greeting_hang=0.5) as server:
        result = tcp(server)
    assert result["reachable"] is False
    assert result["error"] == "timeout"
    assert "timed out" in result["error_detail"]


def test_metrics_probe_timeout(monkeypatch):
    monkeypatch.setattr(mysql, "IO_TIMEOUT", 0.2)
    with FakeMySQL(results={STATUS_SQL: hang(0.5)}) as server:
        result = tcp(server)
    assert result == {
        "reachable": False,
        "error": "timeout",
        "error_detail": "ERROR 2013: Lost connection to MySQL server during query (timed out)",
    }


def test_metrics_probe_connection_lost_is_error():
    with FakeMySQL(results={STATUS_SQL: drop()}) as server:
        result = tcp(server)
    assert result["reachable"] is False
    assert result["error"] == "error"
    assert result["error_detail"].startswith("ERROR 2013: Lost connection")


def test_metrics_probe_server_error_still_closes_the_connection():
    # Value: protects=a probe answered with an ERR packet ships "ERROR <code>:
    # <text>" as an error envelope and still ends the tick's connection with
    # COM_QUIT; fails_when=_close() leaves the finally (a connection left open per
    # failed tick) or the ERR code/text is lost; why_new=probe failures are tested
    # only as a hang or a dropped socket, which leave nothing to close; seam=none;
    # no_claim=the category of an expired password (1820), error as under the CLI.
    shutdown = error(1053, "Server shutdown in progress", b"08S01")
    with FakeMySQL(results={STATUS_SQL: shutdown}) as server:
        result = tcp(server)
    assert result == {
        "reachable": False,
        "error": "error",
        "error_detail": "ERROR 1053: Server shutdown in progress",
    }
    assert server.quit is True
    assert server.queries == ["SET NAMES utf8mb4", STATUS_SQL]


def test_metrics_unreachable_omits_wsrep_keys():
    with FakeMySQL() as server:
        port = server.port
    result = mysql_metrics(host="127.0.0.1", port=port)
    assert set(result) == {"reachable", "error", "error_detail"}


def test_metrics_bad_port_is_an_error_envelope():
    result = mysql_metrics(host="127.0.0.1", port="not-a-port")
    assert result["reachable"] is False
    assert result["error"] == "error"


# -- authentication ---------------------------------------------------------


@pytest.mark.parametrize("plugin", ["mysql_clear_password", "dialog"])
def test_cleartext_plugin_switch_refused_over_tcp(plugin):
    """The server asks for the password itself: over TCP nothing is sent."""
    with FakeMySQL(switch_to=(plugin, b"\x04Password: ")) as server:
        result = tcp(server, password="secret")
    assert result["error"] == "auth_failed"
    assert f"'{plugin}' refused over TCP" in result["error_detail"]
    assert server.switch_response is None
    assert b"secret" not in (server.auth_response or b"")


def test_cleartext_plugin_in_the_greeting_refused_over_tcp():
    with FakeMySQL(plugin="mysql_clear_password") as server:
        result = tcp(server, password="secret")
    assert result["error"] == "auth_failed"
    assert server.auth_response == b""


@needs_unix_sockets
def test_cleartext_plugin_allowed_on_a_unix_socket_with_a_utf8_password(short_dir):
    """PAM accounts keep working through the socket, and the password goes
    out as UTF-8 (PyMySQL alone would send latin-1, and raise on the euro)."""
    path = os.path.join(short_dir, "mysqld.sock")
    password = "p\u00e4ssw\u00f6rd\u20ac"
    with FakeMySQL(
        unix_path=path,
        switch_to=("mysql_clear_password", b""),
        results=server_results(),
    ) as server:
        result = mysql_metrics(socket=path, password=password)
    assert result["reachable"] is True
    assert server.switch_response == password.encode("utf-8") + b"\x00"


@needs_unix_sockets
def test_localhost_uses_the_default_socket(short_dir, monkeypatch):
    path = os.path.join(short_dir, "mysqld.sock")
    monkeypatch.setattr(
        mysql, "_DEFAULT_SOCKETS", (os.path.join(short_dir, "none"), path)
    )
    with FakeMySQL(unix_path=path, results=server_results()) as server:
        result = mysql_metrics(host="localhost", port=3306)
    assert result["reachable"] is True
    assert server.connections == 1


def test_localhost_on_another_port_reaches_that_port_over_tcp(monkeypatch):
    """A second instance (or a container) on another port is read, never the
    native server behind the default socket."""
    monkeypatch.setattr(mysql, "_default_socket", lambda: "/run/mysqld/mysqld.sock")
    with FakeMySQL(results=server_results()) as server:
        result = mysql_metrics(host="localhost", port=server.port)
    assert result["reachable"] is True
    assert server.connections == 1


def test_localhost_tcp_failure_names_sockets_the_agent_may_not_see(monkeypatch):
    """A default socket hidden by permissions (SELinux, a 0750 /var/lib/mysql)
    is named, instead of a bare TCP refusal that points the operator away."""
    hidden = mysql._DEFAULT_SOCKETS[2]
    real_stat = os.stat

    def stat(path, *args, **kwargs):
        if path == hidden:
            raise PermissionError(13, "Permission denied")
        if path in mysql._DEFAULT_SOCKETS:
            raise FileNotFoundError(2, "No such file or directory")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(mysql, "_HAS_UNIX_SOCKETS", True)
    monkeypatch.setattr(mysql.os, "stat", stat)
    detail = _connect_detail(
        (None, "127.0.0.1", 3306), ConnectionRefusedError(111, "Connection refused")
    )
    assert detail == (
        "ERROR 2003: Can't connect to MySQL server on '127.0.0.1:3306'"
        f" (Connection refused); the agent may not look for a socket at {hidden}"
        " (permission denied): configure the socket path if the server listens"
        " there"
    )
    # Another host, another port (never a socket's), or nothing hidden: the
    # plain wording.
    other = _connect_detail((None, "db", 3306), ConnectionRefusedError(111, "x"))
    assert "socket" not in other
    port = _connect_detail((None, "127.0.0.1", 3307), ConnectionRefusedError(111, "x"))
    assert "socket" not in port
    monkeypatch.setattr(mysql, "_DEFAULT_SOCKETS", ())
    plain = _connect_detail((None, "127.0.0.1", 3306), ConnectionRefusedError(111, "x"))
    assert "socket" not in plain


@needs_unix_sockets
def test_configured_socket_missing_is_connection_refused(short_dir):
    path = os.path.join(short_dir, "gone.sock")
    result = mysql_metrics(socket=path)
    assert result == {
        "reachable": False,
        "error": "connection_refused",
        "error_detail": f"ERROR 2002: Can't connect to local MySQL server through socket '{path}' (No such file or directory)",
    }


def test_tls_handshake_failure_falls_back_to_an_unencrypted_connection():
    # Value: protects=a server whose TLS the agent cannot negotiate (TLS 1.0/1.1
    # only) is still read, as the client's ssl-mode=PREFERRED reads it;
    # fails_when=the fallback goes and such a server reads as an outage every
    # tick; why_new=the fake offered no TLS before; seam=none; no_claim=a real
    # TLS 1.0 server (the fake answers the handshake with non-TLS bytes).
    with FakeMySQL(tls_broken=True, results=server_results()) as server:
        result = tcp(server, password="pw")
    assert result["reachable"] is True
    assert server.tls_requests == 1
    assert server.connections == 2


def test_only_a_tls_failure_is_retried():
    # Value: protects=a refused login is sent once per tick; fails_when=_open
    # retries every connect failure, so each wrong password counts twice toward
    # MySQL's FAILED_LOGIN_ATTEMPTS lock (3955) and a hung greeting waits twice;
    # why_new=the fallback test checks the TLS case only; seam=none;
    # no_claim=a real server's lock counter (fake server).
    denied = error(1045, "Access denied for user 'root'@'localhost'", b"28000")
    with FakeMySQL(auth_error=denied) as server:
        result = tcp(server, password="wrong")
    assert result["error"] == "auth_failed"
    assert server.connections == 1


def test_tls_fallback_is_remembered_then_retried(monkeypatch):
    # Value: protects=a server whose TLS the agent cannot negotiate gets one
    # doomed handshake per TLS_RETRY_INTERVAL, not one per tick; fails_when=
    # the memo goes, each tick adds an Aborted_connects the agent ships (QA:
    # +1 per tick on a TLS-1.1 MariaDB); why_new=the fallback test is one
    # tick; seam=none; no_claim=a real TLS 1.0 server (fake handshake).
    clock = [1000.0]
    logged = []
    monkeypatch.setattr(mysql.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        mysql, "log", lambda message, level="info": logged.append((level, message))
    )
    with FakeMySQL(tls_broken=True, results=server_results()) as server:
        # Two handshakes in a row fail: TLS is off for the interval.
        assert tcp(server, password="pw")["reachable"] is True
        assert tcp(server, password="pw")["reachable"] is True
        assert (server.tls_requests, server.connections) == (2, 4)
        assert tcp(server, password="pw")["reachable"] is True
        assert (server.tls_requests, server.connections) == (2, 5)
        # The interval over, one more failure turns it off again at once.
        clock[0] += mysql.TLS_RETRY_INTERVAL
        assert tcp(server, password="pw")["reachable"] is True
        assert tcp(server, password="pw")["reachable"] is True
        assert (server.tls_requests, server.connections) == (3, 8)
    infos = [message for level, message in logged if level == "info"]
    assert len(infos) == 2
    assert infos[0].startswith("MySQL TLS handshake failed on 2 connections in a row")
    assert infos[0].endswith(f"connecting without TLS for {mysql.TLS_RETRY_INTERVAL}s")


def test_one_transient_tls_failure_turns_tls_off_for_one_tick():
    # Value: protects=TLS stays on after one handshake failure that does not
    # repeat (a server restarting mid-handshake, a resetting proxy);
    # fails_when=one failure arms the hour without TLS, exposing the auth
    # exchange to a passive observer; why_new=only a persistent failure was
    # tested; seam=none; no_claim=a real transient TLS EOF (fake handshake).
    with FakeMySQL(tls_broken=True, results=server_results()) as server:
        assert tcp(server, password="pw")["reachable"] is True
        server.tls_broken = False  # TLS answers again
        assert tcp(server, password="pw")["reachable"] is True
        assert mysql._plaintext_until == {}
        assert mysql._tls_failures == {}
        server.tls_broken = True  # the count started over
        assert tcp(server, password="pw")["reachable"] is True
        assert mysql._plaintext_until == {}


def test_a_failed_plaintext_connection_ends_the_fallback(monkeypatch):
    # Value: protects=a server that starts requiring TLS inside the window is
    # read again on the next tick; fails_when=the memo outlives the failure,
    # and every tick for up to TLS_RETRY_INTERVAL dials without TLS into a
    # refusal; why_new=no test failed inside the window; seam=none;
    # no_claim=a real REQUIRE SSL account (fake refusal).
    clock = [1000.0]
    monkeypatch.setattr(mysql.time, "monotonic", lambda: clock[0])
    denied = error(1045, "Access denied for user 'm'@'h'", b"28000")
    with FakeMySQL(auth_error=denied) as server:
        target = (None, "127.0.0.1", server.port)
        mysql._plaintext_until[target] = clock[0] + 10
        assert tcp(server, password="pw")["error"] == "auth_failed"
        assert server.connections == 1
    assert mysql._plaintext_until == {}


def test_a_failed_plaintext_retry_arms_nothing():
    """A retry that fails counts nothing: TLS is tried again on every tick."""
    denied = error(1045, "Access denied for user 'm'@'h'", b"28000")
    with FakeMySQL(tls_broken=True, auth_error=denied) as server:
        for tick in (1, 2, 3):
            assert tcp(server, password="pw")["error"] == "auth_failed"
            assert mysql._tls_failures == {}
            assert mysql._plaintext_until == {}
            assert server.tls_requests == tick


@pytest.mark.parametrize("refusal", ["denied", "ed25519"])
def test_a_login_refused_over_working_tls_breaks_the_run(monkeypatch, refusal):
    # Value: protects="in a row" means consecutive connections: two handshake
    # failures apart, with ticks between where TLS worked but the login was
    # refused (a password being rotated), leave TLS on; fails_when=only a
    # full success resets the count and the hour without TLS is armed;
    # why_new=the fix-check reproduced it; seam=_connect stubbed with the
    # errors PyMySQL raises; no_claim=a real rotation.
    pymysql = mysql._import_pymysql()
    outcomes = iter(["handshake", "plaintext", refusal, "handshake", "plaintext"])

    def connect(pymysql_module, target, user, password, database, tls=True):
        outcome = next(outcomes)
        if outcome == "handshake":
            error = pymysql.err.OperationalError(2003, "Can't connect (handshake)")
            error.original_exception = ssl.SSLError(1, "[SSL] unexpected eof")
            raise error
        if outcome == "denied":
            raise pymysql.err.OperationalError(1045, "Access denied for user 'm'@'h'")
        if outcome == "ed25519":  # PyMySQL raises it for a plugin it cannot load
            raise RuntimeError("'pynacl' package is required for ed25519_password auth")
        return FakeConnection(
            {STATUS_SQL: (["Variable_name", "Value"], [("Threads_connected", "1")])}
        )

    monkeypatch.setattr(mysql, "_connect", connect)
    assert mysql_metrics(host="db.example")["reachable"] is True
    assert mysql_metrics(host="db.example")["error"] == "auth_failed"
    assert mysql._tls_failures == {}
    assert mysql_metrics(host="db.example")["reachable"] is True
    assert mysql._plaintext_until == {}
    assert list(mysql._tls_failures.values()) == [1]


def test_a_tls_error_after_the_handshake_is_not_a_fallback(monkeypatch):
    # Value: protects=TLS stays on after a TLS error that is not the
    # handshake's (an alert or a corrupt record while authenticating);
    # fails_when=any SSLError in the chain turns TLS off for the interval,
    # exposing the auth exchange to a passive observer of a remote server;
    # why_new=only handshake failures were tested; seam=_connect stubbed with
    # the error PyMySQL raises there (a 2013 whose context is the SSLError);
    # no_claim=a real TLS alert.
    pymysql = mysql._import_pymysql()
    calls = []

    def connect(pymysql_module, target, user, password, database, tls=True):
        calls.append(tls)
        try:
            raise ssl.SSLError(1, "[SSL: DECRYPTION_FAILED_OR_BAD_RECORD_MAC]")
        except ssl.SSLError:
            raise pymysql.err.OperationalError(
                2013, "Lost connection to MySQL server during query"
            )

    monkeypatch.setattr(mysql, "_connect", connect)
    result = mysql_metrics(host="db.example", password="pw")
    assert result["reachable"] is False
    assert calls == [True]
    assert mysql._plaintext_until == {}


@pytest.mark.parametrize(
    "code,cause,expected",
    [
        (2003, ssl.SSLError(1, "handshake"), True),
        (2003, ConnectionRefusedError(111, "refused"), False),
        (2013, ssl.SSLError(1, "after"), False),
        (2003, None, False),
    ],
)
def test_tls_handshake_error(code, cause, expected):
    exc = mysql._import_pymysql().err.OperationalError(code, "x")
    if cause is not None:
        exc.original_exception = cause
    assert mysql._tls_handshake_error(exc) is (cause if expected else None)


def test_failed_plaintext_retry_names_the_tls_failure():
    """A REQUIRE SSL account reads "Access denied" on the plaintext retry:
    the TLS failure that caused the retry is named with it."""
    denied = error(
        1045, "Access denied for user 'm'@'h' (using password: YES)", b"28000"
    )
    with FakeMySQL(tls_broken=True, auth_error=denied) as server:
        result = tcp(server, password="pw")
    assert result["error"] == "auth_failed"
    assert result["error_detail"].startswith(
        "ERROR 1045: Access denied for user 'm'@'h' (using password: YES)"
        " (after the TLS handshake failed: "
    )
    assert server.tls_requests == 1


@pytest.mark.parametrize(
    "retry,category,detail",
    [
        (
            (1040, "Too many connections"),
            "error",
            "ERROR 1040: Too many connections",
        ),
        (
            (2003, "Can't connect to MySQL server on '127.0.0.1' (refused)"),
            "connection_refused",
            "ERROR 2003: Can't connect to MySQL server on 'db.example:3306'"
            " (Connection refused)",
        ),
    ],
)
def test_the_tls_failure_named_never_decides_the_category(
    monkeypatch, retry, category, detail
):
    # Value: protects=an outage after a TLS failure reads as an outage;
    # fails_when=the TLS text goes into the message _classify reads, and
    # OpenSSL's "tlsv1 alert access denied" makes every coded failure
    # auth_failed (a credentials problem); why_new=the retry was only tested
    # with a real access denial; seam=_connect stubbed with the errors PyMySQL
    # raises; no_claim=a real TLS alert 49.
    pymysql = mysql._import_pymysql()
    alert = ssl.SSLError(
        1, "[SSL: TLSV1_ALERT_ACCESS_DENIED] tlsv1 alert access denied"
    )

    def connect(pymysql_module, target, user, password, database, tls=True):
        if tls:
            error = pymysql.err.OperationalError(2003, "Can't connect (handshake)")
            error.original_exception = alert
            raise error
        error = pymysql.err.OperationalError(*retry)
        if retry[0] == 2003:
            error.original_exception = ConnectionRefusedError(111, "Connection refused")
        raise error

    monkeypatch.setattr(mysql, "_connect", connect)
    result = mysql_metrics(host="db.example", password="pw")
    assert result["error"] == category
    assert result["error_detail"] == (
        f"{detail} (after the TLS handshake failed: {alert})"
    )


def test_an_endless_reply_is_cut_at_the_read_cap():
    # Value: protects=the agent's memory against a listener that streams
    # packets before any authentication; fails_when=the cap goes and PyMySQL
    # joins 16 MB packets until the agent is killed; why_new=no test streamed
    # a reply; seam=none; no_claim=a MySQL server (a raw socket streams).
    listener = socket.create_server(("127.0.0.1", 0))
    sent = [0]

    def stream():
        conn, _ = listener.accept()
        try:
            while sent[0] < 64 << 20:
                conn.sendall(b"\xff\xff\xff\x00" + bytes(1 << 20))
                sent[0] += 1 << 20
        except OSError:
            pass
        conn.close()

    thread = threading.Thread(target=stream, daemon=True)
    thread.start()
    result = mysql_metrics(host="127.0.0.1", port=listener.getsockname()[1])
    thread.join(10)
    listener.close()
    assert result["reachable"] is False
    assert result["error"] == "error"
    assert "exceeded 1048576 bytes" in result["error_detail"]
    assert sent[0] < 32 << 20  # refused at the 16 MB header, not read


def test_the_read_cap_is_checked_before_reading():
    """A header announcing more than the cap is refused unread: nothing of
    the payload is allocated."""
    pymysql = mysql._import_pymysql()
    cls = mysql._connection_class(pymysql)
    conn = cls.__new__(cls)
    conn._sock = None
    conn._rfile = rfile = MagicMock()
    with pytest.raises(pymysql.err.OperationalError, match="exceeded"):
        conn._read_bytes(mysql.MAX_READ_BYTES + 1)
    rfile.read.assert_not_called()
    rfile.close.assert_called_once()  # the connection is closed


def test_a_best_effort_reply_past_the_read_cap_is_logged_at_error(monkeypatch):
    # Value: protects=a section the cap cuts (a multi-source replica's rows)
    # is visible in the log, unlike a denied one no grant can bring back;
    # fails_when=the cap trip reads as a debug line like a missing grant;
    # why_new=the cap was only tested on the probe, whose failure the payload
    # carries; seam=none; no_claim=a real replica's GTID sets.
    monkeypatch.setattr(mysql, "MAX_READ_BYTES", 4096)
    logged = []
    monkeypatch.setattr(
        mysql, "log", lambda message, level="info": logged.append((level, message))
    )
    wide = [("Waiting", "10.0.0.1", "5", "Yes", "x" * 64)] * 100
    results = server_results(replica=rows(MYSQL8_REPLICA_COLUMNS, wide))
    with FakeMySQL(results=results) as server:
        first = tcp(server)
        second = tcp(server)
    assert first["reachable"] is True and "is_replica" not in first
    assert second == first
    errors = [message for level, message in logged if level == "error"]
    assert errors == [
        f"MySQL statement skipped ({REPLICA_STATUS_SQL}): (2013, 'Lost connection"
        " to MySQL server: its reply exceeded 4096 bytes')"
    ]  # once per statement, then at debug


def test_a_large_result_set_is_cut_at_the_read_cap(monkeypatch):
    """The budget counts every packet of the connection, rows included."""
    monkeypatch.setattr(mysql, "MAX_READ_BYTES", 4096)
    many = [("Var_%d" % n, "x" * 64) for n in range(200)]
    with FakeMySQL(results=server_results(status_rows=many)) as server:
        result = tcp(server)
    assert result == {
        "reachable": False,
        "error": "error",
        "error_detail": "ERROR 2013: Lost connection to MySQL server: its reply"
        " exceeded 4096 bytes",
    }


def test_caching_sha2_full_auth_over_tcp_uses_the_server_rsa_key():
    """MySQL 8's default plugin, password not cached, no TLS: the password
    goes RSA-encrypted (pymysql[rsa]), as the bytes the client would send."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    password = "p\u00e4ss\u20ac"
    with FakeMySQL(
        plugin="caching_sha2_password",
        full_auth_key=key,
        results=server_results(),
    ) as server:
        result = tcp(server, password=password)
    assert result["reachable"] is True
    assert server.rsa_password == password.encode("utf-8")


def test_ed25519_without_pynacl_is_auth_failed_with_a_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "nacl", None)  # PyNaCl is not bundled
    with FakeMySQL(switch_to=("client_ed25519", b"s" * 32)) as server:
        result = tcp(server, password="secret")
    assert result["reachable"] is False
    assert result["error"] == "auth_failed"
    assert result["error_detail"].startswith(
        "The account authenticates with MariaDB's ed25519 plugin"
    )
    assert server.switch_response is None


# ---------------------------------------------------------------------------
# The wall-clock bound: single-flight bounded worker
# ---------------------------------------------------------------------------


def test_stalled_worker_is_single_flight(monkeypatch):
    worker = MagicMock()
    worker.is_alive.return_value = True

    def stall(fn, timeout, name=None):
        assert timeout == mysql.COLLECT_DEADLINE
        assert name == "mysql"
        raise WorkerTimeout(worker, timeout)

    monkeypatch.setattr(mysql, "call_bounded", stall)
    expected = {
        "reachable": False,
        "error": "timeout",
        "error_detail": f"MySQL collection still running after {mysql.COLLECT_DEADLINE}s",
    }
    assert mysql_metrics(host="127.0.0.1") == expected
    assert mysql._stalled_worker is worker

    # While it runs, no second worker starts.
    starts = []
    monkeypatch.setattr(
        mysql, "call_bounded", lambda fn, timeout, name=None: starts.append(1)
    )
    assert mysql_metrics(host="127.0.0.1") == expected
    assert starts == []

    # Once it ended, collection resumes.
    worker.is_alive.return_value = False
    monkeypatch.setattr(
        mysql, "call_bounded", lambda fn, timeout, name=None: {"reachable": True}
    )
    assert mysql_metrics(host="127.0.0.1") == {"reachable": True}
    assert mysql._stalled_worker is None


def test_real_stall_is_cut_at_the_deadline(monkeypatch):
    """A greeting that never comes and an IO timeout above the deadline: the
    caller returns at COLLECT_DEADLINE, not when the socket gives up."""
    monkeypatch.setattr(mysql, "COLLECT_DEADLINE", 0.2)
    monkeypatch.setattr(mysql, "IO_TIMEOUT", 0.6)
    with FakeMySQL(greeting_hang=0.8) as server:
        result = tcp(server)
        assert result["error"] == "timeout"
        assert result["error_detail"] == "MySQL collection still running after 0.2s"
        mysql._stalled_worker.join(5)


def test_the_deadline_after_the_probe_keeps_reachability(monkeypatch):
    # Value: protects=a server that answered the probe never reads as an
    # outage because an optional statement was slow; fails_when=the deadline
    # discards the probe and ships reachable false (the CLI collector bounded
    # each statement alone and only lost that section); why_new=the deadline
    # was only tested before the greeting; seam=none; no_claim=a real slow
    # statement (the fake sleeps).
    monkeypatch.setattr(mysql, "COLLECT_DEADLINE", 0.3)
    monkeypatch.setattr(mysql, "IO_TIMEOUT", 0.6)
    results = server_results(variables=hang(0.9))
    with FakeMySQL(results=results) as server:
        result = tcp(server)
        mysql._stalled_worker.join(5)
    assert result == {
        "reachable": True,
        "connections": 42,
        "queries": 1234567,
        "slow_queries": 12,
        "aborted_connects": 3,
        "uptime": 864000,
        "innodb_buffer_pool_hit_ratio": 99.87,
        "innodb_buffer_pool_usage_pct": 64.2,
    }  # the variables, replication and Galera sections not read yet


def test_unexpected_exception_is_an_error_envelope(monkeypatch):
    def boom(fn, timeout, name=None):
        raise RuntimeError("can't start new thread")

    logged = []
    monkeypatch.setattr(mysql, "call_bounded", boom)
    monkeypatch.setattr(
        mysql, "log", lambda message, level="info": logged.append((level, message))
    )
    assert mysql_metrics(host="127.0.0.1") == {
        "reachable": False,
        "error": "error",
        "error_detail": "can't start new thread",
    }
    # Logged at error level: the dispatcher no longer sees the exception.
    assert logged == [("error", "MySQL collection failed: can't start new thread")]


def test_a_repeated_unexpected_failure_logs_at_error_once(monkeypatch):
    """A failure that never goes away (a socket configured on Windows) logs
    at error once, then at debug; another failure, or a success between, is
    an error again."""
    outcomes = iter(
        [
            ValueError("a"),
            ValueError("a"),
            ValueError("b"),
            {"reachable": True},
            ValueError("b"),
        ]
    )

    def bounded(fn, timeout, name=None):
        outcome = next(outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    logged = []
    monkeypatch.setattr(mysql, "call_bounded", bounded)
    monkeypatch.setattr(
        mysql, "log", lambda message, level="info": logged.append(level)
    )
    for _ in range(5):
        mysql_metrics(host="127.0.0.1")
    assert logged == ["error", "debug", "error", "error"]


def test_exception_without_text_names_its_type(monkeypatch):
    def boom(fn, timeout, name=None):
        raise KeyError()

    monkeypatch.setattr(mysql, "call_bounded", boom)
    assert mysql_metrics()["error_detail"] == "KeyError"


# ---------------------------------------------------------------------------
# Cross-repo contract fixture (fivenines-server): mysql_contract_payload.json
# ---------------------------------------------------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "mysql_contract_payload.json"
)

# The eight whitelisted Galera keys, pinned independently of the collector's
# _WSREP_FIELDS so a drift in either side fails loudly.
_EXPECTED_WSREP_KEYS = {
    "wsrep_cluster_size",
    "wsrep_cluster_status",
    "wsrep_local_state",
    "wsrep_local_state_comment",
    "wsrep_ready",
    "wsrep_connected",
    "wsrep_flow_control_paused",
    "wsrep_local_recv_queue_avg",
}


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


_OS_ERRORS = {"ConnectionRefusedError": ConnectionRefusedError}


def _fixture_connect(scenario):
    """pymysql.connect replacement driven by one scenario."""

    def connect(**options):
        assert options["unix_socket"] == "/run/mysqld/mysqld.sock"
        failure = scenario.get("connect_error")
        if failure:
            os_error = _OS_ERRORS[failure["os_error"]]
            raise _connect_error(os_error(failure["errno"], failure["strerror"]))
        results = {
            sql: (result["columns"], result["rows"])
            for sql, result in scenario["results"].items()
        }
        return FakeConnection(results)

    return connect


@pytest.mark.parametrize(
    "name",
    [
        "galera_healthy",
        "galera_degraded",
        "non_galera",
        "mariadb_without_galera",
        "unreachable",
    ],
)
def test_contract_fixture_round_trip(name, monkeypatch):
    """SHARED FIXTURE (cross-repo contract): fixtures/mysql_contract_payload.json.

    Asserted on both sides:
    - here: mysql_metrics(**config) must equal scenario["payload"] with only the
      driver mocked (each scenario's "results" fed back per statement, or its
      "connect_error" raised for the default socket);
    - fivenines-server: spec/requests/api_collect_mysql_spec.rb posts
      scenario["payload"] under data["mysql"] and asserts Ingesters::Mysql
      handles the Galera-present / absent / unreachable-envelope shapes.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    fixture = _load_fixture()
    scenario = fixture["scenarios"][name]
    monkeypatch.setattr(mysql, "_HAS_UNIX_SOCKETS", True)
    monkeypatch.setattr(mysql, "_default_socket", lambda: "/run/mysqld/mysqld.sock")
    monkeypatch.setattr(
        mysql, "_connection_class", lambda driver: _fixture_connect(scenario)
    )
    out = mysql_metrics(**fixture["config"])
    assert out == scenario["payload"], "scenario '{}' drifted".format(name)


def test_fixture_agent_min_version():
    assert _load_fixture()["agent_min_version"] == "1.15.0"


def test_fixture_galera_keys_match_whitelist():
    """The healthy scenario's wsrep_* keys are exactly the documented whitelist."""
    payload = _load_fixture()["scenarios"]["galera_healthy"]["payload"]
    assert {k for k in payload if k.startswith("wsrep_")} == _EXPECTED_WSREP_KEYS


@pytest.mark.parametrize("name", ["non_galera", "mariadb_without_galera"])
def test_fixture_non_galera_has_no_wsrep_keys(name):
    payload = _load_fixture()["scenarios"][name]["payload"]
    assert not any(k.startswith("wsrep_") for k in payload)
    assert payload["galera"] is False  # the server clears stored Galera state
