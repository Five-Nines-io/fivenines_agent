import os
import socket

import pg8000.dbapi
from pg8000.exceptions import DatabaseError, InterfaceError

from fivenines_agent.debug import debug, log


# PostgreSQL metrics collector
#
# Connects directly to PostgreSQL over a socket using pg8000 (a pure-Python
# driver). No `psql` binary is required on the host, so a PostgreSQL running
# inside a Docker container is reachable over its published TCP port.
#
# Metrics collected (one connection per tick, six read-only queries):
#   - server version
#   - connection counts by state (active, idle, idle in transaction, ...)
#   - per-database statistics (transactions, cache hit ratio, tuples, ...)
#   - per-database sizes (bytes)
#   - replication lag (replicas only)
#   - lock counts by mode
#
# Connection routing (backward compatible with the previous psql collector):
#
#   config.host -- starts with "/" --> unix domain socket
#   (psql passed a socket DIRECTORY to `-h`; pg8000 wants the socket FILE,
#    so we append the standard ".s.PGSQL.<port>" name). password=None keeps
#    peer/trust auth working.
#               -- otherwise       --> TCP to host:port (the Docker path)
#
# Failure contract:
#   connect / auth / timeout fails --> {"reachable": False, "error": <category>}
#   connected + version probe OK   --> {"reachable": True, <metrics...>}
#   The no-privilege `SHOW server_version` probe is the liveness gate: if it
#   fails after connect (session dropped or unusable), report reachable: False
#   instead of a false-healthy empty payload. Once it succeeds, a privileged
#   view that fails (e.g. the monitoring role lacks rights) only drops THAT
#   section; reachable stays True (autocommit isolates queries).
#
# Password discovery mirrors the previous psql/libpq behavior so existing
# installs keep working: explicit config password, then PGPASSWORD, then a
# ~/.pgpass / PGPASSFILE lookup. (pg_service.conf / PGSERVICE is not handled.)

# Bounds connection establishment so a dead host cannot stall the loop.
CONNECT_TIMEOUT = 5

# Server-side per-query cap, sent as a startup parameter so it protects EVERY
# query including the first, with no extra round-trip (vs a post-connect SET).
STATEMENT_TIMEOUT_MS = 5000


def _is_socket_host(host):
    """True when host is a Unix socket directory path (psql-style)."""
    return isinstance(host, str) and host.startswith("/")


def _split_pgpass_line(line):
    """Split a .pgpass line into its 5 fields, honoring backslash escapes.

    Returns [host, port, database, user, password], or None when the line does
    not have exactly five colon-separated fields.
    """
    fields = []
    current = []
    i = 0
    while i < len(line):
        char = line[i]
        if char == "\\" and i + 1 < len(line):
            current.append(line[i + 1])
            i += 2
            continue
        if char == ":":
            fields.append("".join(current))
            current = []
            i += 1
            continue
        current.append(char)
        i += 1
    fields.append("".join(current))
    return fields if len(fields) == 5 else None


def _default_pgpass_path():
    """The platform default password file when PGPASSFILE is unset (libpq).

    Windows uses %APPDATA%\\postgresql\\pgpass.conf; elsewhere it is ~/.pgpass.
    """
    if os.name == "nt":
        return os.path.join(os.environ.get("APPDATA", ""), "postgresql", "pgpass.conf")
    return os.path.join(os.path.expanduser("~"), ".pgpass")


def _pgpass_lookup(host, port, database, user):
    """Return the password from the pgpass file matching the target.

    Mirrors libpq: each field supports a '*' wildcard, the file is ignored when
    it is group/world accessible (non-Windows), and the first match wins.
    """
    path = os.environ.get("PGPASSFILE") or _default_pgpass_path()
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return None
    if os.name != "nt" and (mode & 0o077):
        # libpq refuses a .pgpass that group or others can access.
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError:
        return None

    target = [str(host), str(port), str(database), str(user)]
    for raw in lines:
        line = raw.rstrip("\n")
        if not line or line.lstrip().startswith("#"):
            continue
        entry = _split_pgpass_line(line)
        if entry is None:
            continue
        patterns = entry[:4]
        if all(p == "*" or p == t for p, t in zip(patterns, target)):
            return entry[4]
    return None


def _resolve_password(host, port, database, user, password):
    """Resolve the password the way the previous psql/libpq path did.

    Order: explicit config password, then PGPASSWORD, then the pgpass file.
    A blank (falsy) configured password is treated as "unset" and falls back to
    ambient credentials, matching the old `if password:` psql behavior. Returns
    None for peer/trust auth (no password anywhere).
    """
    if password:
        return password
    env_password = os.environ.get("PGPASSWORD")
    if env_password:
        return env_password
    # libpq matches .pgpass on "localhost" for local Unix-socket connections,
    # not the socket directory path. Mirror that so an existing local-socket
    # setup with a "localhost:5432:..." .pgpass entry keeps authenticating.
    lookup_host = "localhost" if _is_socket_host(host) else host
    return _pgpass_lookup(lookup_host, port, database, user)


def _connect(host, port, user, password, database):
    """Open a pg8000 connection, routing path-like hosts to a unix socket."""
    params = {
        "user": user,
        "database": database,
        "password": _resolve_password(host, port, database, user, password),
        "timeout": CONNECT_TIMEOUT,
        "startup_params": {"statement_timeout": str(STATEMENT_TIMEOUT_MS)},
    }
    if _is_socket_host(host):
        # psql-style socket directory -> pg8000 socket file path.
        params["unix_sock"] = "{}/.s.PGSQL.{}".format(host.rstrip("/"), int(port))
    else:
        params["host"] = host
        params["port"] = int(port)
    return pg8000.dbapi.connect(**params)


def _error_category(exc):
    """Map a connection exception to a stable, backend-facing category."""
    if isinstance(exc, DatabaseError):
        detail = exc.args[0] if exc.args else None
        code = detail.get("C") if isinstance(detail, dict) else None
        if code and str(code).startswith("28"):  # SQLSTATE 28xxx = invalid auth
            return "auth_failed"
        return "error"
    cause = getattr(exc, "__cause__", None)
    if isinstance(cause, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(cause, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(cause, socket.gaierror):
        return "unreachable"
    if isinstance(exc, InterfaceError):
        return "unreachable"
    return "error"


def _query(cursor, sql):
    """Run a read-only query on the shared cursor.

    A server-side error (the monitoring role lacks privilege on this view, or
    the query hit statement_timeout) degrades only this section to None and is
    logged at debug -- the session is alive, so the rest of the payload is
    still collected and reachable stays True. Transport/session errors (the
    connection dropped, a protocol failure) are NOT swallowed here: they
    propagate to postgresql_metrics()'s outer handler, which reports
    reachable: False instead of false-healthy partial data.
    """
    try:
        cursor.execute(sql)
        return cursor.fetchall()
    except DatabaseError as e:
        log(f"PostgreSQL query degraded (server error): {e}", "debug")
        return None


def _get_version(cursor):
    """Return the PostgreSQL server version string (e.g. '16.2')."""
    rows = _query(cursor, "SHOW server_version;")
    if rows:
        return str(rows[0][0]).split()[0]
    return None


def _get_connection_stats(cursor):
    """Return connection counts by backend state."""
    rows = _query(
        cursor,
        "SELECT state, count(*) FROM pg_stat_activity "
        "WHERE state IS NOT NULL GROUP BY state;",
    )
    if not rows:
        return {}

    stats = {
        "active": 0,
        "idle": 0,
        "idle_in_transaction": 0,
        "idle_in_transaction_aborted": 0,
        "fastpath_function_call": 0,
        "disabled": 0,
    }
    for state, count in rows:
        key = str(state).replace(" ", "_")
        if key in stats:
            stats[key] = int(count)
    stats["total"] = sum(stats.values())
    return stats


def _get_database_stats(cursor):
    """Return per-database statistics (excluding template databases)."""
    rows = _query(
        cursor,
        "SELECT datname, numbackends, xact_commit, xact_rollback, blks_read, "
        "blks_hit, tup_returned, tup_fetched, tup_inserted, tup_updated, "
        "tup_deleted, conflicts, deadlocks FROM pg_stat_database "
        "WHERE datname NOT LIKE 'template%' ORDER BY datname;",
    )
    if not rows:
        return []

    def num(value):
        return int(value) if value is not None else 0

    databases = []
    for r in rows:
        name = r[0]
        if not name:
            continue
        blks_read = num(r[4])
        blks_hit = num(r[5])
        total_blks = blks_read + blks_hit
        databases.append(
            {
                "name": name,
                "connections": num(r[1]),
                "xact_commit": num(r[2]),
                "xact_rollback": num(r[3]),
                "blks_read": blks_read,
                "blks_hit": blks_hit,
                "cache_hit_ratio": (
                    round((blks_hit / total_blks * 100), 2) if total_blks > 0 else 100.0
                ),
                "tup_returned": num(r[6]),
                "tup_fetched": num(r[7]),
                "tup_inserted": num(r[8]),
                "tup_updated": num(r[9]),
                "tup_deleted": num(r[10]),
                "conflicts": num(r[11]),
                "deadlocks": num(r[12]),
            }
        )
    return databases


def _get_database_sizes(cursor):
    """Return a mapping of database name to size in bytes."""
    rows = _query(
        cursor,
        "SELECT datname, pg_database_size(datname) FROM pg_database "
        "WHERE datname NOT LIKE 'template%' ORDER BY datname;",
    )
    if not rows:
        return {}

    sizes = {}
    for name, size in rows:
        if name:
            sizes[name] = int(size)
    return sizes


def _get_replication_lag(cursor):
    """Return replication lag in seconds for a replica, else None."""
    rows = _query(cursor, "SELECT pg_is_in_recovery();")
    if not rows or not rows[0][0]:
        return None

    lag_rows = _query(
        cursor,
        "SELECT CASE "
        "WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0 "
        "ELSE EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp()) "
        "END;",
    )
    if lag_rows and lag_rows[0][0] is not None:
        try:
            return float(lag_rows[0][0])
        except (ValueError, TypeError):
            return None
    return None


def _get_locks_count(cursor):
    """Return lock counts by mode, plus a total."""
    rows = _query(cursor, "SELECT mode, count(*) FROM pg_locks GROUP BY mode;")
    if not rows:
        return {}

    locks = {}
    for mode, count in rows:
        locks[mode] = int(count)
    locks["total"] = sum(locks.values())
    return locks


@debug("postgresql_metrics")
def postgresql_metrics(
    host="localhost", port=5432, user="postgres", password=None, database="postgres"
):
    """Collect metrics from PostgreSQL over a direct socket connection.

    Args:
        host: TCP host, or a unix socket DIRECTORY path (starts with '/').
        port: PostgreSQL port (default: 5432).
        user: PostgreSQL user (default: postgres).
        password: password, or None for peer/trust auth.
        database: database to connect to (default: postgres).

    Returns:
        dict: {"reachable": True, <metrics...>} when connected (metric sections
        may be partial if a query is denied); {"reachable": False, "error":
        <category>} when the connection or authentication fails.
    """
    try:
        conn = _connect(host, port, user, password, database)
    except Exception as e:
        category = _error_category(e)
        log(f"Cannot connect to PostgreSQL ({category}): {e}", "debug")
        return {"reachable": False, "error": category}

    try:
        # Read-only collection: autocommit isolates each query so a denied
        # view drops only its own section instead of aborting the rest.
        conn.autocommit = True
        cursor = conn.cursor()

        # Liveness gate: SHOW server_version needs no privilege, so if it fails
        # the session is not usable (dropped after connect, broken setup) -- not
        # a per-view privilege denial. Report unreachable instead of a
        # false-healthy empty payload.
        version = _get_version(cursor)
        if version is None:
            return {"reachable": False, "error": "error"}

        metrics: dict = {"reachable": True, "version": version}

        conn_stats = _get_connection_stats(cursor)
        if conn_stats:
            metrics["connections"] = conn_stats

        db_stats = _get_database_stats(cursor)
        if db_stats:
            metrics["databases"] = db_stats
            metrics["total_xact_commit"] = sum(d["xact_commit"] for d in db_stats)
            metrics["total_xact_rollback"] = sum(d["xact_rollback"] for d in db_stats)
            metrics["total_deadlocks"] = sum(d["deadlocks"] for d in db_stats)
            total_hit = sum(d["blks_hit"] for d in db_stats)
            total_read = sum(d["blks_read"] for d in db_stats)
            total_blks = total_hit + total_read
            metrics["cache_hit_ratio"] = (
                round((total_hit / total_blks * 100), 2) if total_blks > 0 else 100.0
            )

        sizes = _get_database_sizes(cursor)
        if sizes:
            metrics["database_sizes"] = sizes
            metrics["total_size"] = sum(sizes.values())

        replication_lag = _get_replication_lag(cursor)
        if replication_lag is not None:
            metrics["replication_lag_seconds"] = replication_lag
            metrics["is_replica"] = True
        else:
            metrics["is_replica"] = False

        locks = _get_locks_count(cursor)
        if locks:
            metrics["locks"] = locks

        return metrics
    except Exception as e:
        # Connected but the session could not be queried at all -- not healthy.
        log(f"Error collecting PostgreSQL metrics: {e}", "error")
        return {"reachable": False, "error": "error"}
    finally:
        try:
            conn.close()
        except Exception as e:
            log(f"Error closing PostgreSQL connection: {e}", "debug")
