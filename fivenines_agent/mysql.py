import shutil
import subprocess

from fivenines_agent.debug import debug, log
from fivenines_agent.subprocess_utils import get_clean_env


# MySQL / MariaDB metrics collector
#
# Shells out to the `mysql` (or `mariadb`) CLI, mirroring the fail2ban/snmp
# collectors rather than adding a Python driver dependency. This keeps unix
# socket auth (cPanel/Plesk boxes) trivial and needs nothing bundled into the
# PyInstaller binary. The trade-off vs the pg8000-based PostgreSQL collector is
# that a client binary must be present on the host; when it is absent we report
# `unknown` (return None), not an outage -- a missing client is a host-config
# issue, not a down database.
#
# Reachability contract (the point of #488 -- PostgreSQL only ever surfaced
# `unknown`/`reachable`, never `unreachable`/`config_error`):
#
#   client binary absent            -> None                (server: unknown)
#   first query (probe) succeeds    -> {"reachable": True, <metrics...>}
#   auth failure (ERROR 1045)       -> {"reachable": False, "error": "auth_failed", ...}
#   connect refused / timeout / DNS -> {"reachable": False, "error": <category>, ...}
#
# The FIRST query (SHOW GLOBAL STATUS) is the liveness gate: it needs no
# privilege, so a failure means the connection/auth failed, not a per-view
# denial. Once it succeeds, every later query is best-effort -- a denied or
# unsupported query (e.g. SHOW REPLICA STATUS without REPLICATION CLIENT) drops
# only its own section and reachable stays True (same posture as PostgreSQL).
#
# `error` is a stable category the backend maps to a host status: only
# `auth_failed` routes to `config_error` (amber, "fix the credentials");
# `connection_refused` / `timeout` / `unreachable` / `error` route to
# `unreachable` (red, outage). `error_detail` carries the raw stderr (the
# backend truncates it) for the operator.

# Per-query CLI timeout (seconds). A dead host must not stall the collection
# loop; also bounds connection establishment.
CLI_TIMEOUT = 10

# error_detail cap. The backend truncates to 500 as well; we cap here so a
# pathological stderr never bloats the payload.
ERROR_DETAIL_MAX = 500

# MySQL 8.0.22+ spelling first, then the MariaDB / older-MySQL alias. We try
# REPLICA and fall back to SLAVE on any error (older servers reject REPLICA
# with a syntax error).
REPLICA_STATUS_SQL = "SHOW REPLICA STATUS"
SLAVE_STATUS_SQL = "SHOW SLAVE STATUS"


def _resolve_binary():
    """Return the client binary to use, preferring `mysql` over `mariadb`.

    MariaDB 10.5+ ships the tool as `mariadb` with a `mysql` symlink, but some
    installs drop the symlink -- so fall back. Returns None when neither is on
    PATH (handled upstream as `unknown`).
    """
    for candidate in ("mysql", "mariadb"):
        if shutil.which(candidate):
            return candidate
    return None


def _classify_error(stderr):
    """Map CLI stderr to a stable, backend-facing error category.

    Only `auth_failed` routes to config_error server-side; everything else is
    treated as an outage (unreachable).
    """
    s = (stderr or "").lower()
    if "access denied" in s or "error 1045" in s:
        return "auth_failed"
    if (
        "can't connect" in s
        or "error 2002" in s
        or "error 2003" in s
        or "refused" in s
    ):
        return "connection_refused"
    if "unknown mysql server host" in s or "error 2005" in s:
        return "unreachable"
    return "error"


def _clean_stderr(stderr):
    """Strip the MYSQL_PWD deprecation warning before surfacing stderr.

    Newer clients print "[Warning] Using a password on the command line
    interface can be insecure." to stderr even when the password comes from the
    environment; it is noise in error_detail.
    """
    if not stderr:
        return ""
    lines = [
        line
        for line in stderr.splitlines()
        if "using a password on the command line" not in line.lower()
    ]
    return "\n".join(lines).strip()


def _run_mysql(binary, sql, conn, vertical=False):
    """Run one query via the mysql/mariadb CLI.

    Returns a (stdout, error_category, stderr) tuple:
      success        -> (stdout, None, stderr)
      non-zero exit  -> (None, <category>, stderr)
      timeout        -> (None, "timeout", "")
      missing binary -> (None, "client_missing", "")

    Tabular mode (-N -B) yields "Name\\tValue" lines. Vertical mode (the SQL
    ends in "\\G", passed with vertical=True) yields "Key: Value" lines and is
    used for SHOW REPLICA STATUS, whose column set is far easier to map than a
    single wide tab row.
    """
    cmd = [binary, "-u", str(conn.get("user", "root"))]
    if conn.get("socket"):
        # Unix socket auth (cPanel/Plesk): host/port are ignored by the client.
        cmd += ["--socket", str(conn["socket"])]
    else:
        cmd += ["-h", str(conn.get("host", "localhost")), "-P", str(conn.get("port", 3306))]
    if conn.get("database"):
        cmd += ["-D", str(conn["database"])]
    if not vertical:
        # -N: no column names, -B: batch (tab-separated) output.
        cmd += ["-N", "-B"]
    cmd += ["-e", sql]

    env = get_clean_env()
    if conn.get("password"):
        # MYSQL_PWD keeps the password out of the process arg list (ps),
        # mirroring PGPASSWORD in the psql path. A blank/None password falls
        # through to socket/peer or no-password auth.
        env["MYSQL_PWD"] = str(conn["password"])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLI_TIMEOUT,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None, "timeout", ""
    except FileNotFoundError:
        # Binary vanished between _resolve_binary() and here (or was passed
        # None). Treated as unknown upstream, not an outage.
        return None, "client_missing", ""
    except OSError as e:
        log(f"mysql command error: {e}", "debug")
        return None, "error", str(e)

    if result.returncode != 0:
        return None, _classify_error(result.stderr), result.stderr
    return result.stdout.strip(), None, result.stderr


def _parse_status(stdout):
    """Parse tabular "Name\\tValue" output (SHOW GLOBAL STATUS/VARIABLES)."""
    result = {}
    for line in (stdout or "").splitlines():
        if "\t" in line:
            key, value = line.split("\t", 1)
            result[key.strip()] = value.strip()
    return result


def _parse_vertical(stdout):
    """Parse "\\G" vertical "Key: Value" output into a dict.

    Skips the "*************************** 1. row ***************************"
    separators. Splits on the first colon only, so values containing colons
    (timestamps, error strings) survive intact.
    """
    result = {}
    for raw in (stdout or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("*"):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def _to_int(value):
    """int(value) or None -- absorbs NULL/blank/None/garbage."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first(row, *keys):
    """Return the first present key's value (handles MySQL/MariaDB spellings)."""
    for key in keys:
        if key in row:
            return row[key]
    return None


def _yes(value):
    """True when a SHOW ... STATUS Yes/No field is "Yes" (case-insensitive)."""
    return str(value).strip().lower() == "yes"


def _buffer_pool_hit_ratio(status):
    """InnoDB buffer pool hit ratio (%), computed on this tick's gauges.

    (1 - reads / read_requests) * 100. read_requests == 0 (nothing requested
    yet) is guarded to 100.0. Returns None when the source counters are absent.
    """
    reads = _to_int(status.get("Innodb_buffer_pool_reads"))
    read_requests = _to_int(status.get("Innodb_buffer_pool_read_requests"))
    if reads is None or read_requests is None:
        return None
    if read_requests == 0:
        return 100.0
    return round((1 - reads / read_requests) * 100, 2)


def _buffer_pool_usage_pct(status):
    """InnoDB buffer pool usage (%), (total - free) / total * 100.

    total == 0 (pool not initialized) is guarded -> None (no meaningful usage).
    Returns None when the source counters are absent.
    """
    total = _to_int(status.get("Innodb_buffer_pool_pages_total"))
    free = _to_int(status.get("Innodb_buffer_pool_pages_free"))
    if total is None or free is None:
        return None
    if total == 0:
        return None
    return round((total - free) / total * 100, 2)


def _add_status_metrics(metrics, status):
    """Fill raw counters + computed InnoDB ratios from SHOW GLOBAL STATUS.

    Counters (queries/slow_queries/aborted_connects) are sent RAW; the backend
    derives per-second rates at query time (the agent is stateless per tick, so
    it cannot compute a delta). Only the cumulative buffer-pool gauges, which
    are meaningful on a single tick, are computed here.
    """
    connections = _to_int(status.get("Threads_connected"))
    if connections is not None:
        metrics["connections"] = connections
    for source, name in (
        ("Queries", "queries"),
        ("Slow_queries", "slow_queries"),
        ("Aborted_connects", "aborted_connects"),
        ("Uptime", "uptime"),
    ):
        value = _to_int(status.get(source))
        if value is not None:
            metrics[name] = value
    hit_ratio = _buffer_pool_hit_ratio(status)
    if hit_ratio is not None:
        metrics["innodb_buffer_pool_hit_ratio"] = hit_ratio
    usage = _buffer_pool_usage_pct(status)
    if usage is not None:
        metrics["innodb_buffer_pool_usage_pct"] = usage


def _add_variable_metrics(metrics, variables):
    """Fill max_connections + version from SHOW GLOBAL VARIABLES."""
    max_connections = _to_int(variables.get("max_connections"))
    if max_connections is not None:
        metrics["max_connections"] = max_connections
    version = variables.get("version")
    if version:
        metrics["version"] = version


def _build_replication(row):
    """Build the replication payload from a parsed SHOW REPLICA/SLAVE STATUS row.

    Reads both the MySQL 8 (`Replica_*`, `Seconds_Behind_Source`) and MariaDB /
    older-MySQL (`Slave_*`, `Seconds_Behind_Master`) spellings. A NULL lag
    (replication broken) parses to None; `running` is the AND of both threads,
    which is already False in the broken case.
    """
    io_running = _yes(_first(row, "Replica_IO_Running", "Slave_IO_Running"))
    sql_running = _yes(_first(row, "Replica_SQL_Running", "Slave_SQL_Running"))
    lag = _to_int(_first(row, "Seconds_Behind_Source", "Seconds_Behind_Master"))
    return {
        "lag_seconds": lag,
        "io_running": io_running,
        "sql_running": sql_running,
        "running": io_running and sql_running,
    }


def _get_replication(binary, conn):
    """Return (is_replica, replication_dict).

    Tries SHOW REPLICA STATUS (MySQL 8.0.22+ / MariaDB 10.5+), falling back to
    SHOW SLAVE STATUS on any error (older servers reject REPLICA). Returns:
      (None, None)  -- status unreadable (both queries failed, e.g. the user
                       lacks REPLICATION CLIENT); undetermined.
      (False, None) -- query succeeded, no rows: not a replica.
      (True, {...}) -- replica; dict has lag_seconds/io_running/sql_running/running.

    A failure here never flips reachable; it only drops the replication section
    (mirrors the PostgreSQL collector's per-view degradation).
    """
    out, err, _ = _run_mysql(binary, REPLICA_STATUS_SQL + "\\G", conn, vertical=True)
    if err:
        out, err, _ = _run_mysql(binary, SLAVE_STATUS_SQL + "\\G", conn, vertical=True)
    if err:
        return None, None
    row = _parse_vertical(out)
    if not row:
        return False, None
    return True, _build_replication(row)


def _failure(category, stderr):
    """Build the unreachable/config_error payload for a failed probe."""
    result = {"reachable": False, "error": category}
    detail = _clean_stderr(stderr)
    if detail:
        result["error_detail"] = detail[:ERROR_DETAIL_MAX]
    return result


@debug("mysql_metrics")
def mysql_metrics(
    host="localhost",
    port=3306,
    user="root",
    password=None,
    database=None,
    socket=None,
    **_kwargs,
):
    """Collect metrics from MySQL / MariaDB via the client CLI.

    Args:
        host: TCP host (ignored when `socket` is set).
        port: TCP port (default 3306; ignored when `socket` is set).
        user: MySQL user (default root).
        password: password, or None for socket/peer/no-password auth.
        database: optional default database to select.
        socket: unix socket path; when set, host/port are ignored.
        **_kwargs: unknown backend config keys are ignored (forward-compatible).

    Returns:
        None when the client binary is absent (server: unknown);
        {"reachable": True, <metrics...>} when the probe succeeds (later
        sections may be partial if a query is denied/unsupported);
        {"reachable": False, "error": <category>, "error_detail": <stderr>}
        when the connection or authentication fails.
    """
    binary = _resolve_binary()
    if binary is None:
        log("mysql/mariadb client not found; skipping MySQL collection", "debug")
        return None

    conn = {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "database": database,
        "socket": socket,
    }

    # Reachability probe. SHOW GLOBAL STATUS needs no privilege, so its outcome
    # is the reachable/error signal for the whole tick.
    status_out, err, stderr = _run_mysql(binary, "SHOW GLOBAL STATUS", conn)
    if err == "client_missing":
        log("mysql/mariadb client not found; skipping MySQL collection", "debug")
        return None
    if err:
        return _failure(err, stderr)

    metrics: dict = {"reachable": True}
    _add_status_metrics(metrics, _parse_status(status_out))

    # Best-effort: max_connections + version. A failure degrades only these
    # keys; reachable stays True.
    vars_out, verr, _ = _run_mysql(
        binary,
        "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('max_connections', 'version')",
        conn,
    )
    if not verr and vars_out is not None:
        _add_variable_metrics(metrics, _parse_status(vars_out))

    # Best-effort: replication (REPLICA -> SLAVE fallback, MySQL 8 + MariaDB).
    is_replica, replication = _get_replication(binary, conn)
    if is_replica is not None:
        metrics["is_replica"] = is_replica
    if replication is not None:
        metrics["replication"] = replication

    return metrics
