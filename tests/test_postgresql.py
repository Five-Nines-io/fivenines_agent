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
    _get_replication_lag,
    _get_version,
    _pgpass_lookup,
    _query,
    _resolve_password,
    _split_pgpass_line,
    postgresql_metrics,
)


PG = "fivenines_agent.postgresql"


@pytest.fixture(autouse=True)
def _isolate_pg_credentials(monkeypatch, tmp_path):
    """Keep _resolve_password deterministic: no PGPASSWORD, no readable .pgpass.

    Credential-discovery tests opt back in by setting PGPASSWORD / PGPASSFILE
    themselves; everything else sees "no password available".
    """
    monkeypatch.delenv("PGPASSWORD", raising=False)
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


def test_connect_sets_connect_and_statement_timeout():
    """connect_timeout + statement_timeout (startup param) are always set."""
    with patch(f"{PG}.pg8000.dbapi.connect") as conn:
        _connect("localhost", 5432, "postgres", None, "postgres")
        kwargs = conn.call_args.kwargs
        assert kwargs["timeout"] == 5
        assert kwargs["startup_params"] == {"statement_timeout": "5000"}


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
# _get_replication_lag
# ---------------------------------------------------------------------------


def test_replication_lag_none_when_server_error():
    cur = MagicMock()
    cur.execute.side_effect = DatabaseError({"C": "42501", "M": "denied"})
    assert _get_replication_lag(cur) is None


def test_replication_lag_primary_returns_none():
    """pg_is_in_recovery() False -> primary -> None."""
    assert _get_replication_lag(cursor_returning([(False,)])) is None


def test_replication_lag_replica_returns_seconds():
    cur = cursor_returning([(True,)], [(1.5,)])
    assert _get_replication_lag(cur) == 1.5


def test_replication_lag_replica_caught_up_is_zero():
    cur = cursor_returning([(True,)], [(0,)])
    assert _get_replication_lag(cur) == 0.0


def test_replication_lag_null_replay_returns_none():
    """Replica whose lag expression is NULL -> None."""
    cur = cursor_returning([(True,)], [(None,)])
    assert _get_replication_lag(cur) is None


def test_replication_lag_empty_lag_rows_returns_none():
    cur = cursor_returning([(True,)], [])
    assert _get_replication_lag(cur) is None


def test_replication_lag_unparseable_value_returns_none():
    """A non-numeric lag value is swallowed to None."""
    cur = cursor_returning([(True,)], [("not-a-number",)])
    assert _get_replication_lag(cur) is None


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
        "_get_replication_lag": None,
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
        _get_replication_lag=None,
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
    result = run_metrics(fake_conn(), _get_version="16.2", _get_replication_lag=2.5)
    assert result["replication_lag_seconds"] == 2.5
    assert result["is_replica"] is True


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


def test_metrics_inner_exception_is_unreachable():
    """P1: connected but the session cannot be queried at all -> unreachable."""
    result = run_metrics(fake_conn(cursor_raises=True))
    assert result == {"reachable": False, "error": "error"}


def test_metrics_transport_error_after_version_is_unreachable():
    """A transport error mid-collection bubbles to reachable: False, not a
    false-healthy partial payload (version probe already succeeded)."""
    with patch(f"{PG}._connect", return_value=fake_conn()), patch(
        f"{PG}._get_version", return_value="16.2"
    ), patch(f"{PG}._get_connection_stats", side_effect=InterfaceError("dropped")):
        result = postgresql_metrics()
    assert result == {"reachable": False, "error": "error"}


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
