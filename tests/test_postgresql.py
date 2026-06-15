"""Tests for fivenines_agent.postgresql module.

The collector connects to PostgreSQL with pg8000 (pure-Python driver). These
tests mock at two seams:
  - pg8000.dbapi.connect    -> for _connect routing (TCP vs unix socket)
  - fivenines_agent.postgresql._connect / the helpers -> for orchestration

No real PostgreSQL is needed. The opt-in integration test that exercises a real
socket lives in test_postgresql_integration.py.
"""

import os
import socket
import ssl
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from pg8000.exceptions import DatabaseError, InterfaceError

from fivenines_agent.postgresql import (
    _connect,
    _default_pgpass_path,
    _error_category,
    _get_connection_stats,
    _get_database_sizes,
    _get_database_stats,
    _get_locks_count,
    _get_replication,
    _get_version,
    _pgpass_lookup,
    _query,
    _resolve_password,
    _split_pgpass_line,
    _ssl_context,
    postgresql_metrics,
)


PG = "fivenines_agent.postgresql"


@pytest.fixture(autouse=True)
def _isolate_pg_credentials(monkeypatch, tmp_path):
    """Keep credential/TLS resolution deterministic across tests.

    No PGPASSWORD, no readable .pgpass, no PGSSLMODE/PGSSLROOTCERT. Tests that
    exercise those paths opt back in by setting the env themselves.
    """
    monkeypatch.delenv("PGPASSWORD", raising=False)
    monkeypatch.delenv("PGSSLMODE", raising=False)
    monkeypatch.delenv("PGSSLROOTCERT", raising=False)
    monkeypatch.setenv("PGPASSFILE", str(tmp_path / "does-not-exist.pgpass"))


def cursor_returning(*fetch_results):
    """Fake cursor whose successive fetchall() calls return the given results."""
    cur = MagicMock()
    cur.fetchall.side_effect = list(fetch_results)
    return cur


def with_cause(exc, cause):
    """Attach a __cause__ to an exception, as `raise ... from ...` would."""
    exc.__cause__ = cause
    return exc


# ---------------------------------------------------------------------------
# _connect: TCP vs unix-socket routing (backward compatibility)
# ---------------------------------------------------------------------------


def test_connect_tcp_passes_host_and_port():
    """Normal host routes to a TCP connection (host/port)."""
    with patch(f"{PG}.pg8000.dbapi.connect") as conn:
        _connect("db.example.com", 5432, "postgres", "secret", "appdb")
        kwargs = conn.call_args.kwargs
        assert kwargs["host"] == "db.example.com"
        assert kwargs["port"] == 5432
        assert "unix_sock" not in kwargs
        assert kwargs["user"] == "postgres"
        assert kwargs["password"] == "secret"
        assert kwargs["database"] == "appdb"


def test_connect_socket_timeout_exceeds_statement_timeout():
    """The socket timeout (10s) must exceed statement_timeout (5000ms) so the
    server cancels a slow query before the socket read times out."""
    with patch(f"{PG}.pg8000.dbapi.connect") as conn:
        _connect("localhost", 5432, "postgres", None, "postgres")
        kwargs = conn.call_args.kwargs
        assert kwargs["timeout"] == 10
        assert (
            int(kwargs["startup_params"]["statement_timeout"])
            < kwargs["timeout"] * 1000
        )


def test_connect_safe_port_defaults_when_unparseable():
    """A null/empty port (valid for a socket config) falls back to 5432."""
    with patch(f"{PG}.pg8000.dbapi.connect") as conn:
        _connect("localhost", None, "postgres", None, "postgres")
        assert conn.call_args.kwargs["port"] == 5432
    with patch(f"{PG}.pg8000.dbapi.connect") as conn:
        _connect("/var/run/postgresql", "", "postgres", None, "postgres")
        assert conn.call_args.kwargs["unix_sock"] == "/var/run/postgresql/.s.PGSQL.5432"


def test_connect_path_like_host_routes_to_unix_socket():
    """A path-like host (psql socket directory) routes to pg8000 unix_sock."""
    with patch(f"{PG}.pg8000.dbapi.connect") as conn:
        _connect("/var/run/postgresql", 5432, "postgres", None, "postgres")
        kwargs = conn.call_args.kwargs
        assert kwargs["unix_sock"] == "/var/run/postgresql/.s.PGSQL.5432"
        assert "host" not in kwargs
        assert "port" not in kwargs


def test_connect_unix_socket_strips_trailing_slash():
    """Trailing slash on the socket directory is normalized."""
    with patch(f"{PG}.pg8000.dbapi.connect") as conn:
        _connect("/tmp/", 5433, "postgres", None, "postgres")
        assert conn.call_args.kwargs["unix_sock"] == "/tmp/.s.PGSQL.5433"


def test_connect_non_string_host_uses_tcp():
    """A non-string host (defensive) falls through to the TCP branch."""
    with patch(f"{PG}.pg8000.dbapi.connect") as conn:
        _connect(None, 5432, "postgres", None, "postgres")
        assert "unix_sock" not in conn.call_args.kwargs
        assert conn.call_args.kwargs["host"] is None


def test_connect_forwards_ssl_context(monkeypatch):
    """PGSSLMODE drives the ssl_context passed to pg8000."""
    monkeypatch.setenv("PGSSLMODE", "require")
    with patch(f"{PG}.pg8000.dbapi.connect") as conn:
        _connect("db.example.com", 5432, "postgres", None, "postgres")
        assert isinstance(conn.call_args.kwargs["ssl_context"], ssl.SSLContext)


# ---------------------------------------------------------------------------
# _ssl_context: PGSSLMODE / PGSSLROOTCERT parity (#2)
# ---------------------------------------------------------------------------


def test_ssl_context_default_is_none():
    """No PGSSLMODE -> None (pg8000 default: opportunistic, unverified)."""
    assert _ssl_context("db.example.com") is None


def test_ssl_context_socket_host_disables_tls():
    """TLS is never used on a local Unix socket."""
    assert _ssl_context("/var/run/postgresql") is False


def test_ssl_context_disable(monkeypatch):
    monkeypatch.setenv("PGSSLMODE", "disable")
    assert _ssl_context("h") is False


def test_ssl_context_require_does_not_verify(monkeypatch):
    monkeypatch.setenv("PGSSLMODE", "require")
    ctx = _ssl_context("h")
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_ssl_context_verify_ca_checks_cert_not_hostname(monkeypatch):
    monkeypatch.setenv("PGSSLMODE", "verify-ca")
    ctx = _ssl_context("h")
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is False


def test_ssl_context_verify_full_checks_cert_and_hostname(monkeypatch):
    monkeypatch.setenv("PGSSLMODE", "verify-full")
    ctx = _ssl_context("h")
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


# ---------------------------------------------------------------------------
# _error_category: stable failure categories
# ---------------------------------------------------------------------------


def test_error_category_auth_failed():
    """SQLSTATE 28xxx maps to auth_failed."""
    assert (
        _error_category(DatabaseError({"C": "28P01", "M": "bad pw"})) == "auth_failed"
    )


def test_error_category_other_database_error():
    """A non-28 DatabaseError maps to the generic 'error'."""
    assert _error_category(DatabaseError({"C": "42501", "M": "denied"})) == "error"


def test_error_category_database_error_non_dict_arg():
    """DatabaseError whose arg is not a dict still classifies as 'error'."""
    assert _error_category(DatabaseError("oops")) == "error"


def test_error_category_database_error_no_args():
    """DatabaseError with no args classifies as 'error' (no detail)."""
    err = DatabaseError()
    err.args = ()
    assert _error_category(err) == "error"


def test_error_category_connection_refused():
    """A refused TCP connection maps to connection_refused."""
    exc = with_cause(InterfaceError("x"), ConnectionRefusedError())
    assert _error_category(exc) == "connection_refused"


def test_error_category_timeout():
    """A socket timeout maps to timeout."""
    assert (
        _error_category(with_cause(InterfaceError("x"), socket.timeout())) == "timeout"
    )


def test_error_category_timeout_builtin():
    """A builtin TimeoutError also maps to timeout."""
    assert _error_category(with_cause(InterfaceError("x"), TimeoutError())) == "timeout"


def test_error_category_dns_unreachable():
    """A DNS resolution failure maps to unreachable."""
    exc = with_cause(InterfaceError("x"), socket.gaierror())
    assert _error_category(exc) == "unreachable"


def test_error_category_interface_error_unknown_cause():
    """An InterfaceError with no recognized cause maps to unreachable."""
    assert _error_category(InterfaceError("x")) == "unreachable"


def test_error_category_interface_error_auth_message_is_auth_failed():
    """pg8000 raises InterfaceError (not DatabaseError) when a password is
    required but none was provided -- classify it as auth_failed."""
    exc = InterfaceError(
        "server requesting password authentication, but no password was provided"
    )
    assert _error_category(exc) == "auth_failed"


def test_error_category_unknown_exception():
    """Any other exception type maps to the generic 'error'."""
    assert _error_category(ValueError("boom")) == "error"


# ---------------------------------------------------------------------------
# _query: shared execute/fetch with per-query degradation
# ---------------------------------------------------------------------------


def test_query_returns_rows_on_success():
    cur = cursor_returning([("a", 1)])
    assert _query(cur, "SELECT 1") == [("a", 1)]
    cur.execute.assert_called_once_with("SELECT 1")


def test_query_degrades_server_error_to_none():
    """A server-side error (e.g. privilege denial) degrades that section."""
    cur = MagicMock()
    cur.execute.side_effect = DatabaseError({"C": "42501", "M": "permission denied"})
    assert _query(cur, "SELECT 1") is None


def test_query_propagates_transport_error():
    """A transport/session error is NOT swallowed -> it bubbles to the caller."""
    cur = MagicMock()
    cur.execute.side_effect = InterfaceError("connection dropped")
    with pytest.raises(InterfaceError):
        _query(cur, "SELECT 1")


# ---------------------------------------------------------------------------
# _get_version
# ---------------------------------------------------------------------------


def test_get_version_parses_number():
    assert _get_version(cursor_returning([("16.2",)])) == "16.2"


def test_get_version_strips_suffix():
    assert _get_version(cursor_returning([("16.2 (Debian 16.2-1)",)])) == "16.2"


def test_get_version_none_when_empty():
    assert _get_version(cursor_returning([])) is None


def test_get_version_none_when_blank_value():
    """A blank server_version value does not raise IndexError -> None."""
    assert _get_version(cursor_returning([("   ",)])) is None


def test_get_version_none_when_server_error():
    cur = MagicMock()
    cur.execute.side_effect = DatabaseError({"C": "57014", "M": "canceling statement"})
    assert _get_version(cur) is None


# ---------------------------------------------------------------------------
# _get_connection_stats
# ---------------------------------------------------------------------------


def test_connection_stats_empty_when_no_rows():
    assert _get_connection_stats(cursor_returning([])) == {}


def test_connection_stats_maps_known_states_and_totals():
    rows = [("active", 2), ("idle", 5), ("idle in transaction", 1)]
    stats = _get_connection_stats(cursor_returning(rows))
    assert stats["active"] == 2
    assert stats["idle"] == 5
    assert stats["idle_in_transaction"] == 1
    assert stats["total"] == 8


def test_connection_stats_ignores_unknown_state():
    rows = [("active", 2), ("weird_state", 99)]
    stats = _get_connection_stats(cursor_returning(rows))
    assert stats["active"] == 2
    assert "weird_state" not in stats
    assert stats["total"] == 2


# ---------------------------------------------------------------------------
# _get_database_stats
# ---------------------------------------------------------------------------


def _db_row(name="app", **over):
    base = [name, 3, 100, 7, 10, 990, 1, 1, 1, 1, 0, 0, 0]
    fields = [
        "name",
        "numbackends",
        "xact_commit",
        "xact_rollback",
        "blks_read",
        "blks_hit",
        "tup_returned",
        "tup_fetched",
        "tup_inserted",
        "tup_updated",
        "tup_deleted",
        "conflicts",
        "deadlocks",
    ]
    for k, v in over.items():
        base[fields.index(k)] = v
    return tuple(base)


def test_database_stats_empty_when_no_rows():
    assert _get_database_stats(cursor_returning([])) == []


def test_database_stats_happy_path():
    dbs = _get_database_stats(cursor_returning([_db_row()]))
    assert dbs[0]["name"] == "app"
    assert dbs[0]["connections"] == 3
    assert dbs[0]["cache_hit_ratio"] == 99.0  # 990 / (10 + 990) * 100


def test_database_stats_cache_ratio_zero_blocks_is_100():
    """No reads and no hits -> 100.0 (div-by-zero guard)."""
    row = _db_row(blks_read=0, blks_hit=0)
    assert _get_database_stats(cursor_returning([row]))[0]["cache_hit_ratio"] == 100.0


def test_database_stats_skips_null_datname():
    null_name_row = (None,) + _db_row()[1:]
    rows = [null_name_row, _db_row(name="real")]
    dbs = _get_database_stats(cursor_returning(rows))
    assert [d["name"] for d in dbs] == ["real"]


def test_database_stats_null_numeric_fields_coerce_to_zero():
    row = _db_row(xact_commit=None, blks_read=None, blks_hit=None, deadlocks=None)
    db = _get_database_stats(cursor_returning([row]))[0]
    assert db["xact_commit"] == 0
    assert db["blks_read"] == 0
    assert db["blks_hit"] == 0
    assert db["deadlocks"] == 0
    assert db["cache_hit_ratio"] == 100.0


# ---------------------------------------------------------------------------
# _get_database_sizes
# ---------------------------------------------------------------------------


def test_database_sizes_empty_when_no_rows():
    assert _get_database_sizes(cursor_returning([])) == {}


def test_database_sizes_maps_name_to_bytes():
    sizes = _get_database_sizes(cursor_returning([("app", 1024), ("other", 2048)]))
    assert sizes == {"app": 1024, "other": 2048}


def test_database_sizes_skips_null_name():
    sizes = _get_database_sizes(cursor_returning([(None, 1), ("app", 99)]))
    assert sizes == {"app": 99}


# ---------------------------------------------------------------------------
# _get_replication -> (is_replica, lag_seconds)
# ---------------------------------------------------------------------------


def test_replication_undetermined_when_recovery_query_denied():
    """pg_is_in_recovery() denied/failed -> (None, None), NOT (False, ...)."""
    cur = MagicMock()
    cur.execute.side_effect = DatabaseError({"C": "42501", "M": "denied"})
    assert _get_replication(cur) == (None, None)


def test_replication_primary():
    """pg_is_in_recovery() False -> (False, None)."""
    assert _get_replication(cursor_returning([(False,)])) == (False, None)


def test_replication_replica_with_lag():
    cur = cursor_returning([(True,)], [(1.5,)])
    assert _get_replication(cur) == (True, 1.5)


def test_replication_replica_caught_up_lag_zero():
    cur = cursor_returning([(True,)], [(0,)])
    assert _get_replication(cur) == (True, 0.0)


def test_replication_replica_null_lag_still_marks_replica():
    """A replica whose lag is NULL (e.g. just started) is still is_replica=True
    -- the bug was reporting it as a primary."""
    cur = cursor_returning([(True,)], [(None,)])
    assert _get_replication(cur) == (True, None)


def test_replication_replica_empty_lag_rows():
    cur = cursor_returning([(True,)], [])
    assert _get_replication(cur) == (True, None)


def test_replication_replica_unparseable_lag():
    cur = cursor_returning([(True,)], [("not-a-number",)])
    assert _get_replication(cur) == (True, None)


# ---------------------------------------------------------------------------
# _get_locks_count
# ---------------------------------------------------------------------------


def test_locks_empty_when_no_rows():
    assert _get_locks_count(cursor_returning([])) == {}


def test_locks_maps_modes_with_total():
    locks = _get_locks_count(
        cursor_returning([("AccessShareLock", 3), ("RowExclusiveLock", 1)])
    )
    assert locks["AccessShareLock"] == 3
    assert locks["RowExclusiveLock"] == 1
    assert locks["total"] == 4


# ---------------------------------------------------------------------------
# postgresql_metrics: orchestration
# ---------------------------------------------------------------------------


def fake_conn(cursor=None, cursor_raises=False, close_raises=False):
    conn = MagicMock()
    if cursor_raises:
        conn.cursor.side_effect = RuntimeError("cursor boom")
    else:
        conn.cursor.return_value = cursor if cursor is not None else MagicMock()
    if close_raises:
        conn.close.side_effect = RuntimeError("close boom")
    return conn


@contextmanager
def helpers_patched(**values):
    """Patch all six _get_* helpers with fixed return values for a block."""
    defaults = {
        "_get_version": None,
        "_get_connection_stats": {},
        "_get_database_stats": [],
        "_get_database_sizes": {},
        "_get_replication": (False, None),
        "_get_locks_count": {},
    }
    defaults.update(values)
    patches = [
        patch(f"{PG}.{name}", return_value=val) for name, val in defaults.items()
    ]
    for p in patches:
        p.start()
    try:
        yield
    finally:
        for p in reversed(patches):
            p.stop()


def run_metrics(conn, **helper_values):
    with patch(f"{PG}._connect", return_value=conn), helpers_patched(**helper_values):
        return postgresql_metrics()


def test_metrics_connect_failure_returns_unreachable():
    exc = with_cause(InterfaceError("x"), ConnectionRefusedError())
    with patch(f"{PG}._connect", side_effect=exc):
        assert postgresql_metrics() == {
            "reachable": False,
            "error": "connection_refused",
        }


def test_metrics_happy_path_full_payload():
    db = {
        "name": "app",
        "xact_commit": 100,
        "xact_rollback": 7,
        "deadlocks": 2,
        "blks_hit": 990,
        "blks_read": 10,
    }
    result = run_metrics(
        fake_conn(),
        _get_version="16.2",
        _get_connection_stats={"active": 1, "total": 1},
        _get_database_stats=[db],
        _get_database_sizes={"app": 2048},
        _get_replication=(False, None),
        _get_locks_count={"AccessShareLock": 1, "total": 1},
    )
    assert result["reachable"] is True
    assert result["version"] == "16.2"
    assert result["connections"] == {"active": 1, "total": 1}
    assert result["databases"] == [db]
    assert result["total_xact_commit"] == 100
    assert result["total_xact_rollback"] == 7
    assert result["total_deadlocks"] == 2
    assert result["cache_hit_ratio"] == 99.0
    assert result["database_sizes"] == {"app": 2048}
    assert result["total_size"] == 2048
    assert result["is_replica"] is False
    assert result["locks"] == {"AccessShareLock": 1, "total": 1}


def test_metrics_replica_sets_lag_and_flag():
    result = run_metrics(fake_conn(), _get_version="16.2", _get_replication=(True, 2.5))
    assert result["replication_lag_seconds"] == 2.5
    assert result["is_replica"] is True


def test_metrics_replica_null_lag_marks_replica_without_lag():
    """#6: a replica with no lag yet is is_replica=True, lag key omitted (not a
    primary)."""
    result = run_metrics(
        fake_conn(), _get_version="16.2", _get_replication=(True, None)
    )
    assert result["is_replica"] is True
    assert "replication_lag_seconds" not in result


def test_metrics_replication_undetermined_omits_is_replica():
    """#6: when pg_is_in_recovery() is denied, is_replica is omitted entirely
    rather than defaulted to False."""
    result = run_metrics(
        fake_conn(), _get_version="16.2", _get_replication=(None, None)
    )
    assert "is_replica" not in result
    assert "replication_lag_seconds" not in result


def test_metrics_version_probe_failure_is_unreachable():
    """P1: connect ok but the no-privilege version probe fails -> unreachable.

    Guards against a false-healthy {"reachable": True} with no metrics when the
    session drops or breaks immediately after connect.
    """
    result = run_metrics(fake_conn())  # _get_version defaults to None
    assert result == {"reachable": False, "error": "error"}


def test_metrics_connected_version_only_omits_empty_sections():
    """Version ok but every privileged view empty -> reachable, partial payload."""
    result = run_metrics(fake_conn(), _get_version="16.2")
    assert result == {"reachable": True, "version": "16.2", "is_replica": False}


def test_metrics_cache_ratio_zero_blocks_is_100():
    db = {
        "name": "app",
        "xact_commit": 0,
        "xact_rollback": 0,
        "deadlocks": 0,
        "blks_hit": 0,
        "blks_read": 0,
    }
    result = run_metrics(fake_conn(), _get_version="16.2", _get_database_stats=[db])
    assert result["cache_hit_ratio"] == 100.0


def test_metrics_inner_exception_is_unreachable_with_detail():
    """P1+#13: a generic error after connect -> unreachable, with error_detail."""
    result = run_metrics(fake_conn(cursor_raises=True))
    assert result == {
        "reachable": False,
        "error": "error",
        "error_detail": "cursor boom",
    }


def test_metrics_transport_error_after_version_is_unreachable():
    """#9: a transport error mid-collection bubbles to reachable: False with the
    specific category (not a flat 'error'), and no false-healthy partial."""
    with patch(f"{PG}._connect", return_value=fake_conn()), patch(
        f"{PG}._get_version", return_value="16.2"
    ), patch(f"{PG}._get_connection_stats", side_effect=InterfaceError("dropped")):
        result = postgresql_metrics()
    assert result == {"reachable": False, "error": "unreachable"}


def test_metrics_tolerates_unknown_config_keys():
    """#14: an unexpected backend config key is ignored, not a TypeError->None."""
    with patch(f"{PG}._connect", return_value=fake_conn()), helpers_patched(
        _get_version="16.2"
    ):
        result = postgresql_metrics(host="localhost", future_option="x")
    assert result["reachable"] is True


def test_metrics_closes_connection_on_success():
    conn = fake_conn()
    run_metrics(conn, _get_version="16.2")
    conn.close.assert_called_once()


def test_metrics_swallows_close_error():
    """A failing conn.close() in the finally block does not escape."""
    conn = fake_conn(close_raises=True)
    result = run_metrics(conn, _get_version="16.2")
    assert result["reachable"] is True


# ---------------------------------------------------------------------------
# Backward-compatibility regression (T9)
#
# Existing users monitor PostgreSQL with the previous (psql-based) agent using
# host/port/user/password/database. The driver swap must not break them.
# ---------------------------------------------------------------------------


def test_regression_previous_version_tcp_config_still_connects():
    """Default/previous-version config (TCP host) reaches the driver unchanged."""
    with patch(
        f"{PG}.pg8000.dbapi.connect", return_value=fake_conn()
    ) as conn, helpers_patched(_get_version="16.2"):
        result = postgresql_metrics(
            host="localhost",
            port=5432,
            user="postgres",
            password=None,
            database="postgres",
        )
    assert result["reachable"] is True
    assert conn.call_args.kwargs["host"] == "localhost"


def test_regression_previous_version_socket_dir_config_still_connects():
    """A previous-version socket-directory host keeps working via unix_sock."""
    with patch(
        f"{PG}.pg8000.dbapi.connect", return_value=fake_conn()
    ) as conn, helpers_patched(_get_version="16.2"):
        result = postgresql_metrics(host="/var/run/postgresql", password=None)
    assert result["reachable"] is True
    assert conn.call_args.kwargs["unix_sock"] == "/var/run/postgresql/.s.PGSQL.5432"
    assert conn.call_args.kwargs["password"] is None


# ---------------------------------------------------------------------------
# Password discovery (P2): config -> PGPASSWORD -> ~/.pgpass / PGPASSFILE.
# Restores the libpq behavior the previous psql collector relied on, so an
# install with credentials in .pgpass keeps working after the upgrade.
# ---------------------------------------------------------------------------


def _write_pgpass(tmp_path, content, mode=0o600):
    path = tmp_path / "pgpass"
    path.write_text(content)
    os.chmod(path, mode)
    return str(path)


def test_split_pgpass_line_basic():
    assert _split_pgpass_line("h:5432:db:user:pw") == ["h", "5432", "db", "user", "pw"]


def test_split_pgpass_line_unescapes_colon_and_backslash():
    # password "p:a\\ss" written as p\:a\\ss
    assert _split_pgpass_line("h:5432:db:user:p\\:a\\\\ss") == [
        "h",
        "5432",
        "db",
        "user",
        "p:a\\ss",
    ]


def test_split_pgpass_line_wrong_field_count_returns_none():
    assert _split_pgpass_line("only:three:fields") is None


def test_resolve_password_explicit_config_wins(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "from-env")
    assert _resolve_password("h", 5432, "db", "u", "from-config") == "from-config"


def test_resolve_password_uses_pgpassword_env(monkeypatch):
    monkeypatch.setenv("PGPASSWORD", "env-secret")
    assert _resolve_password("h", 5432, "db", "u", None) == "env-secret"


def test_resolve_password_none_when_nothing_available():
    # autouse fixture cleared PGPASSWORD and pointed PGPASSFILE at a missing file
    assert _resolve_password("h", 5432, "db", "u", None) is None


def test_resolve_password_falls_back_to_pgpass(monkeypatch, tmp_path):
    pgpass = _write_pgpass(tmp_path, "h:5432:db:u:pgpass-secret\n")
    monkeypatch.setenv("PGPASSFILE", pgpass)
    assert _resolve_password("h", 5432, "db", "u", None) == "pgpass-secret"


def test_resolve_password_socket_host_matches_localhost_entry(monkeypatch, tmp_path):
    """A Unix-socket host resolves .pgpass via 'localhost' (libpq behavior),
    not the literal socket directory path."""
    pgpass = _write_pgpass(tmp_path, "localhost:5432:db:u:sockpw\n")
    monkeypatch.setenv("PGPASSFILE", pgpass)
    assert _resolve_password("/var/run/postgresql", 5432, "db", "u", None) == "sockpw"


def test_resolve_password_blank_config_falls_back_to_env(monkeypatch):
    """A blank configured password is treated as unset (old `if password:`)."""
    monkeypatch.setenv("PGPASSWORD", "env-secret")
    assert _resolve_password("h", 5432, "db", "u", "") == "env-secret"


def test_default_pgpass_path_posix(monkeypatch):
    monkeypatch.setattr(os, "name", "posix")
    assert _default_pgpass_path().endswith(".pgpass")


def test_default_pgpass_path_windows(monkeypatch):
    """Windows defaults to %APPDATA%\\postgresql\\pgpass.conf, like libpq."""
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setenv("APPDATA", "APPDATA_DIR")
    assert _default_pgpass_path() == os.path.join(
        "APPDATA_DIR", "postgresql", "pgpass.conf"
    )


def test_pgpass_lookup_wildcards_match(monkeypatch, tmp_path):
    monkeypatch.setenv("PGPASSFILE", _write_pgpass(tmp_path, "*:*:*:*:wild\n"))
    assert _pgpass_lookup("anyhost", 5432, "anydb", "anyuser") == "wild"


def test_pgpass_lookup_strips_crlf(monkeypatch, tmp_path):
    """#3: a CRLF pgpass (Windows default) must not leave \\r on the password."""
    monkeypatch.setenv("PGPASSFILE", _write_pgpass(tmp_path, "h:5432:db:u:secret\r\n"))
    assert _pgpass_lookup("h", 5432, "db", "u") == "secret"


def test_pgpass_lookup_first_match_wins_and_skips_noise(monkeypatch, tmp_path):
    content = (
        "# a comment\n"
        "\n"
        "malformed:line\n"
        "other:5432:db:u:nope\n"
        "h:5432:db:u:right\n"
        "h:5432:db:u:later\n"
    )
    monkeypatch.setenv("PGPASSFILE", _write_pgpass(tmp_path, content))
    assert _pgpass_lookup("h", 5432, "db", "u") == "right"


def test_pgpass_lookup_no_match_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("PGPASSFILE", _write_pgpass(tmp_path, "other:1:x:y:pw\n"))
    assert _pgpass_lookup("h", 5432, "db", "u") is None


def test_pgpass_lookup_empty_password_field(monkeypatch, tmp_path):
    monkeypatch.setenv("PGPASSFILE", _write_pgpass(tmp_path, "*:*:*:*:\n"))
    assert _pgpass_lookup("h", 5432, "db", "u") == ""


def test_pgpass_lookup_missing_file_returns_none(monkeypatch, tmp_path):
    monkeypatch.setenv("PGPASSFILE", str(tmp_path / "nope.pgpass"))
    assert _pgpass_lookup("h", 5432, "db", "u") is None


def test_pgpass_lookup_ignored_when_group_or_world_accessible(monkeypatch, tmp_path):
    # libpq refuses a .pgpass that is not private (0600).
    pgpass = _write_pgpass(tmp_path, "*:*:*:*:secret\n", mode=0o640)
    monkeypatch.setenv("PGPASSFILE", pgpass)
    assert _pgpass_lookup("h", 5432, "db", "u") is None


def test_pgpass_lookup_unreadable_path_returns_none(monkeypatch, tmp_path):
    # A directory at the .pgpass path: stat succeeds, open raises -> None.
    d = tmp_path / "pgpass_dir"
    d.mkdir()
    os.chmod(d, 0o700)
    monkeypatch.setenv("PGPASSFILE", str(d))
    assert _pgpass_lookup("h", 5432, "db", "u") is None
