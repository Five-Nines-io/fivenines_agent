import functools
import math
import os
import socket
import ssl
import stat
import time

from fivenines_agent.bounded import WorkerTimeout, call_bounded
from fivenines_agent.debug import debug, log
from fivenines_agent.scrub import log_safe, scrub_str

# MySQL / MariaDB metrics collector
#
# Connects with PyMySQL, a pure-Python driver -- the choice the PostgreSQL
# collector made with pg8000 (#70): no `mysql` client is needed on the host, so
# a MySQL running in a Docker container is reached on its published port, and
# the driver bundles into the PyInstaller binary with no shared library. Up to
# agent 1.24.0 this collector shelled out to the `mysql`/`mariadb` client, one
# process and one connection per statement, and reported None (server:
# unknown) on every host without that client. Now one connection per tick
# runs every statement.
#
# Reachability contract (the point of #488 -- PostgreSQL only ever surfaced
# `unknown`/`reachable`, never `unreachable`/`config_error`):
#
#   connect/auth or the probe fails -> {"reachable": False, "error": <category>, "error_detail": ...}
#   first query (probe) succeeds    -> {"reachable": True, <metrics...>}
#
# Never None any more: there is no client binary to be missing.
#
# The FIRST query (SHOW GLOBAL STATUS) is the liveness gate: it needs no
# privilege, so a failure means the connection failed, not a per-view denial.
# Once it succeeds, every later query is best-effort -- a denied or unsupported
# query (e.g. SHOW REPLICA STATUS without REPLICATION CLIENT) drops only its own
# section and reachable stays True (same posture as PostgreSQL). A connection
# lost after the probe drops every section after it.
#
# `error` is a stable category the backend maps to a host status: only
# `auth_failed` routes to `config_error` (amber, "fix the credentials");
# `connection_refused` / `timeout` / `unreachable` / `error` route to
# `unreachable` (red, outage). `error_detail` carries the error text (the
# backend truncates it) for the operator, in the client's `ERROR <code>: ...`
# shape.
#
# What the `mysql` client did implicitly and must not be lost with it:
#
# - "localhost" (the server's default host) does what the clients the old
#   collector ran did with `-h localhost -P <port>` (measured): Oracle's client
#   went through the local server's unix socket whatever the port, MariaDB's
#   (10.6+) over TCP to localhost:<port>. So the socket is used when one exists
#   at a distribution default path (`_DEFAULT_SOCKETS`, the clients'
#   compiled-in paths) and the port is the default 3306 -- 'user'@'localhost'
#   accounts, a server running with skip-networking and MariaDB's unix_socket
#   authentication depend on it -- and TCP to 127.0.0.1:<port> otherwise: a
#   MySQL in Docker with its port published, or a second instance on another
#   port (user decision D2). A host whose Oracle client reached a server on
#   another port through its default socket now dials TCP: configure the
#   socket path there. While the server is stopped its socket is gone and the
#   agent dials TCP, so whatever a local user listens with on that port
#   receives the attempt: the exposure every host with MariaDB's client, and
#   every 127.0.0.1 config, already had (D2). TCP goes to 127.0.0.1, never to
#   the name localhost: it can resolve to ::1 first, where any local user may
#   listen on a port the server holds on 127.0.0.1 only. A socket moved by
#   my.cnf must be configured: option files are not read.
# - TLS is PREFERRED, as `mysql --ssl-mode=PREFERRED` (the client's default and
#   PyMySQL's when given no TLS option): used when the server offers it, its
#   certificate not verified. Not on a unix socket, already a secure transport.
#   A TLS handshake that fails is retried without TLS (_open): Python refuses
#   what an old server may only offer (TLS 1.0/1.1). Once it failed on
#   TLS_FAILURES_BEFORE_PLAINTEXT connections in a row, that target is dialed
#   without TLS for TLS_RETRY_INTERVAL, or until such a connection fails (one
#   transient failure costs one tick without TLS), logged at info. Only the
#   handshake: a TLS error after it (an alert while authenticating) fails the
#   tick, never turning TLS off. Measured on a MariaDB limited to TLS
#   1.1: MySQL's own 8.4 and 9.6 clients fail too (ERROR 2026), MariaDB's
#   clients negotiate it -- the CLI collector worked through whichever client
#   the host had. No new exposure: whoever can break the handshake can strip
#   the TLS offer from the greeting as well.
# - The password goes out as UTF-8, the bytes the client sent; PyMySQL would
#   encode a str password as latin-1, so an account whose password holds a
#   non-ASCII character would stop authenticating.
# - Authentication plugins that send the password itself (mysql_clear_password,
#   dialog: PAM) are refused over TCP -- the client refuses the first unless
#   --enable-cleartext-plugin -- and kept on a unix socket, for PAM accounts.
# - caching_sha2_password (MySQL 8's default) and sha256_password over plain
#   TCP without TLS encrypt the password with the server's RSA key, which
#   PyMySQL asks the server for (the client asks only with
#   --get-server-public-key, refusing otherwise). A rogue listener can answer
#   with its own key -- but it can as well offer TLS, which neither verifies,
#   and receive the password in clear: that exposure is the client's too. RSA
#   needs the `cryptography` package (the pymysql[rsa] dependency).
# - MariaDB's ed25519 plugin needs PyNaCl, which is not bundled: such an
#   account reads auth_failed, with a hint.
# - LOAD DATA LOCAL is refused (local_infile off: PyMySQL raises if the server
#   asks anyway), so a server cannot read the agent's files.
# - Results are read as BYTES (no converters, use_unicode off) and decoded as
#   UTF-8 with replacement, the connection charset being utf8mb4: one stray
#   byte in a row nobody ships (a replica's Last_SQL_Error quoting a duplicate
#   key) must never raise and null the collector (#172).
#
# PyMySQL is imported lazily, on the first tick that carries a mysql config:
# with the cryptography it loads it costs ~10 MB of RSS, which hosts without
# MySQL never pay.
#
# Bounds: CONNECT_TIMEOUT per address, IO_TIMEOUT per socket read or write,
# MAX_READ_BYTES per connection. The timeouts cover neither name resolution
# nor a server that trickles its reply, so the whole collection runs on a
# single-flight bounded.call_bounded worker abandoned after COLLECT_DEADLINE
# (the mongodb posture); the byte cap keeps the memory that abandoned worker
# can grow in check while it runs. A deadline reached after the probe
# answered ships what was read (reachable, the sections read so far): a slow
# optional statement drops its section, as a denied one does.

# TCP connect timeout per address, and per socket read/write (seconds). The CLI
# path bounded each statement, connection included, at 10s.
CONNECT_TIMEOUT = 5
IO_TIMEOUT = 10

# Wall-clock bound of a whole collection (bounded.call_bounded): what no socket
# timeout covers, and a slow server whose round trips add up past it.
COLLECT_DEADLINE = 20

# Bytes one connection may read. A tick reads tens of KB (SHOW GLOBAL STATUS
# is 500-700 rows), but PyMySQL reads without limit -- it joins 16 MB packets
# into one -- so a listener streaming packets, before any authentication,
# would grow the agent's memory until it is killed, the worker abandoned at
# COLLECT_DEADLINE included. The CLI child died at its 10s timeout (D3). What
# is read costs more once parsed into rows (~20x for small rows: 8 MB of rows
# took ~150 MB of RSS, measured), hence a cap far above a tick, far below that.
MAX_READ_BYTES = 1024 * 1024

# How long a target whose TLS handshake keeps failing is dialed without TLS
# before TLS is tried again (seconds): a doomed handshake every tick costs a
# second connection and one Aborted_connects on the server, a counter the
# agent ships. Armed only after TLS_FAILURES_BEFORE_PLAINTEXT handshakes in a
# row failed and the retry without TLS worked, so a transient failure (a
# server restarting mid-handshake) turns TLS off for one tick, not an hour.
TLS_RETRY_INTERVAL = 3600
TLS_FAILURES_BEFORE_PLAINTEXT = 2

DEFAULT_PORT = 3306

# error_detail cap. The backend truncates to 500 as well; we cap here so a
# pathological message never bloats the payload.
ERROR_DETAIL_MAX = 500

STATUS_SQL = "SHOW GLOBAL STATUS"
VARIABLES_SQL = (
    "SHOW GLOBAL VARIABLES WHERE Variable_name IN"
    " ('max_connections', 'version', 'wsrep_on')"
)

# MySQL 8.0.22+ spelling first, then the MariaDB / older-MySQL alias. We try
# REPLICA and fall back to SLAVE on any error (older servers reject REPLICA
# with a syntax error).
REPLICA_STATUS_SQL = "SHOW REPLICA STATUS"
SLAVE_STATUS_SQL = "SHOW SLAVE STATUS"

# Which replication-status spelling this server accepts, remembered across
# ticks, so a server that rejects REPLICA (pre-8.0.22 MySQL / pre-10.5
# MariaDB) is not sent a statement that fails on every tick. Reset to the
# preferred spelling whenever the memoized one stops working (server upgrade
# mid-run).
_replica_status_sql = REPLICA_STATUS_SQL

# Galera / wsrep cluster state (issue #107). One extra statement on the same
# connection as the rest of the collector, sent only when the server's global
# wsrep_on variable reads ON (VARIABLES_SQL reads it): MariaDB 10.1+ is built
# with wsrep and answers this statement WITHOUT Galera too -- measured on
# 10.11 and 11.8 with wsrep_on OFF and no provider: 17 rows, among them
# wsrep_cluster_status 'Disconnected', wsrep_ready 'OFF' and
# wsrep_cluster_size 0 -- which agents up to 1.24.0 shipped as a degraded
# Galera cluster. MySQL has no wsrep_on variable at all. Not Galera, or
# wsrep_on unreadable: the wsrep_* keys are absent (no-data == not clustered).
GALERA_STATUS_SQL = "SHOW GLOBAL STATUS LIKE 'wsrep%'"

# The compiled-in socket paths of the distributions' clients, tried in order
# for "localhost". Only directories that root or the server's own account
# controls: never /tmp, where any local user could create mysql.sock, since
# PyMySQL sends a caching_sha2_password account's password in clear over a
# unix socket (a secure transport for the client too).
_DEFAULT_SOCKETS = (
    "/run/mysqld/mysqld.sock",  # Debian, Ubuntu (MySQL and MariaDB), Alpine, Arch
    "/var/run/mysqld/mysqld.sock",  # the same where /var/run is not /run
    "/var/lib/mysql/mysql.sock",  # RHEL family, Fedora, cPanel
    "/run/mysql/mysql.sock",  # openSUSE
    "/var/run/mysql/mysql.sock",
)

# Windows has no AF_UNIX in Python: "localhost" is TCP there, as for the client.
_HAS_UNIX_SOCKETS = hasattr(socket, "AF_UNIX")

# MySQL error codes, stable across server and client versions (PyMySQL's
# constants hold the same numbers; a test pins them). Client side (CR_*):
_CR_CONNECTION_ERROR = 2002  # local server, through a unix socket
_CR_CONN_HOST_ERROR = 2003  # PyMySQL's code for any failed connect
_CR_UNKNOWN_HOST = 2005
_CR_SERVER_LOST = 2013
_CR_AUTH_PLUGIN_CANNOT_LOAD = 2059

# Error codes that mean "the server is up; the account cannot log in": the
# operator fixes the credentials or the account, not an outage.
_AUTH_ERRORS = frozenset(
    {
        1044,  # ER_DBACCESS_DENIED_ERROR, no access to the configured database
        1045,  # ER_ACCESS_DENIED_ERROR, wrong user or password
        1130,  # ER_HOST_NOT_PRIVILEGED, no account for the agent's address
        1251,  # ER_NOT_SUPPORTED_AUTH_MODE
        1698,  # ER_ACCESS_DENIED_NO_PASSWORD_ERROR, a unix_socket account
        # reached by another OS user
        _CR_AUTH_PLUGIN_CANNOT_LOAD,  # a plugin the agent does not run
        2061,  # CR_AUTH_PLUGIN_ERR
    }
)

# Plugins that send the password itself, refused over TCP.
_CLEARTEXT_PLUGINS = ("mysql_clear_password", "dialog")

_STALLED_MESSAGE = "MySQL collection still running after {}s"

# The worker abandoned at COLLECT_DEADLINE: no second one starts while it runs.
_stalled_worker = None

# {target: monotonic time TLS is tried again}, for the target whose TLS
# handshake kept failing (one entry at most: the agent polls one MySQL).
_plaintext_until: dict = {}

# {target: TLS handshakes failed in a row whose retry without TLS worked}
# (one entry at most); any other outcome of a connection with TLS resets it.
_tls_failures: dict = {}

# The statements whose reply passed MAX_READ_BYTES, logged at error once each.
_read_cap_reported: set = set()

# The last unexpected failure logged at error level: one that repeats every
# tick logs at debug until another one (or a success) comes.
_last_logged_error = None


def _import_pymysql():
    """PyMySQL, imported on first use (see the module comment)."""
    import pymysql
    import pymysql.connections
    import pymysql.err

    return pymysql


@functools.cache
def _connection_class(pymysql):
    """pymysql's Connection, refusing to read past MAX_READ_BYTES.

    _read_bytes is PyMySQL's one read primitive (packet headers and payloads
    alike); the budget is checked before the read, so a header announcing a
    16 MB payload is refused without allocating it.
    """

    class CappedConnection(pymysql.connections.Connection):
        _bytes_read = 0

        def _read_bytes(self, num_bytes):
            self._bytes_read += num_bytes
            if self._bytes_read > MAX_READ_BYTES:
                self._force_close()
                error = pymysql.err.OperationalError(
                    _CR_SERVER_LOST,
                    "Lost connection to MySQL server: its reply exceeded"
                    f" {MAX_READ_BYTES} bytes",
                )
                error.read_cap = True  # _best_effort logs it at error
                raise error
            return super()._read_bytes(num_bytes)

    return CappedConnection


def _refuse_cleartext(plugin):
    """An auth_plugin_map entry that refuses `plugin`.

    PyMySQL constructs the handler when the server names the plugin, before
    any reply to it is written, so raising here sends nothing.
    """

    def handler(_connection):
        raise _import_pymysql().err.OperationalError(
            _CR_AUTH_PLUGIN_CANNOT_LOAD,
            f"Authentication plugin '{plugin}' refused over TCP: it sends the"
            " password in clear text (connect through the unix socket)",
        )

    return handler


_TCP_AUTH_PLUGINS = {name: _refuse_cleartext(name) for name in _CLEARTEXT_PLUGINS}


def _is_socket(path):
    """True when path is a socket, False when it is not or does not exist,
    None when the agent may not look (a directory it cannot search)."""
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except PermissionError:
        return None
    except OSError:
        return False


def _default_socket():
    """The first path of _DEFAULT_SOCKETS that is a socket, or None."""
    for path in _DEFAULT_SOCKETS:
        if _is_socket(path):
            return path
    return None


def _target(host, port, socket_path):
    """(unix socket, host, port), see "localhost" in the module comment.

    A configured socket wins over host/port. Raises ValueError for a socket
    on a platform without unix sockets (Windows), ValueError/TypeError on a
    port that is not a number.
    """
    if socket_path:
        if not _HAS_UNIX_SOCKETS:
            raise ValueError(
                "a unix socket is configured, but this platform has no unix"
                " sockets: configure the host and port instead"
            )
        return str(socket_path), None, None
    host = str(host) if host else "localhost"
    port = int(port) if port is not None else DEFAULT_PORT
    if host != "localhost":
        return None, host, port
    if port == DEFAULT_PORT and _HAS_UNIX_SOCKETS:
        path = _default_socket()
        if path is not None:
            return path, None, None
    return None, "127.0.0.1", port


def _password_bytes(password):
    """The password as the client sent it: UTF-8 (PyMySQL would use latin-1)."""
    if not password:
        return b""
    return str(password).encode("utf-8")


def _connect(pymysql, target, user, password, database, tls=True):
    """Open the tick's connection (see the module comment for each option)."""
    unix_socket, host, port = target
    options = {
        "user": str(user) if user else "root",
        "password": _password_bytes(password),
        "database": str(database) if database else None,
        "charset": "utf8mb4",
        "use_unicode": False,
        "conv": {},
        "autocommit": None,  # the server's default: no SET AUTOCOMMIT round trip
        "local_infile": False,
        "connect_timeout": CONNECT_TIMEOUT,
        "read_timeout": IO_TIMEOUT,
        "write_timeout": IO_TIMEOUT,
        "program_name": "fivenines-agent",
    }
    if unix_socket:
        options["unix_socket"] = unix_socket
        options["ssl_disabled"] = True
    else:
        options["host"] = host
        options["port"] = port
        options["auth_plugin_map"] = _TCP_AUTH_PLUGINS
        if not tls:
            options["ssl_disabled"] = True
    return _connection_class(pymysql)(**options)


def _tls_handshake_error(exc):
    """The SSLError of a TLS handshake that failed, or None.

    PyMySQL reports a failed handshake as a failed connect (2003) whose
    original_exception is the SSLError; a TLS error after the handshake is a
    lost connection with the SSLError as context, never this.
    """
    cause = getattr(exc, "original_exception", None)
    if _code(exc) == _CR_CONN_HOST_ERROR and isinstance(cause, ssl.SSLError):
        return cause
    return None


def _open(pymysql, target, user, password, database):
    """_connect(), retrying without TLS when the TLS handshake fails, and
    dialing that target without TLS for TLS_RETRY_INTERVAL once that happened
    on TLS_FAILURES_BEFORE_PLAINTEXT connections in a row, or until such a
    connection fails (see TLS in the module comment)."""
    if time.monotonic() < _plaintext_until.get(target, 0):
        try:
            return _connect(pymysql, target, user, password, database, tls=False)
        except pymysql.err.MySQLError:
            # The server may require TLS now: the next tick tries it again.
            _plaintext_until.pop(target, None)
            raise
    try:
        conn = _connect(pymysql, target, user, password, database)
    except Exception as e:
        tls_error = _tls_handshake_error(e)
        if tls_error is None:
            # Not a handshake failure (refused, or a login refused after a
            # handshake that worked, ed25519's RuntimeError included): the
            # count is of failures in a row.
            _tls_failures.pop(target, None)
            raise
        log(
            f"MySQL TLS handshake failed, connecting without TLS: {log_safe(e)}",
            "debug",
        )
        try:
            conn = _connect(pymysql, target, user, password, database, tls=False)
        except pymysql.err.MySQLError as retry:
            # A REQUIRE SSL account then reads "Access denied": _detail names
            # the cause. Never in args, which _classify reads: OpenSSL's own
            # text can say "access denied" (alert 49).
            retry.after_tls_failure = str(tls_error)
            raise
        failures = _tls_failures.get(target, 0) + 1
        _tls_failures.clear()
        _tls_failures[target] = failures
        if failures >= TLS_FAILURES_BEFORE_PLAINTEXT:
            _plaintext_until.clear()
            _plaintext_until[target] = time.monotonic() + TLS_RETRY_INTERVAL
            log(
                f"MySQL TLS handshake failed on {failures} connections in a row"
                f" ({log_safe(tls_error)}): connecting without TLS for"
                f" {TLS_RETRY_INTERVAL}s",
                "info",
            )
        return conn
    _tls_failures.pop(target, None)
    return conn


def _close(conn):
    try:
        conn.close()
    except Exception as e:  # already closed by a lost connection
        log(f"MySQL close: {log_safe(e)}", "debug")


def _os_error(exc):
    """The OSError behind a PyMySQL error, if any.

    A failed connect carries it as `original_exception`; a failed socket read
    raises inside the OSError's handler, so it is the implicit __context__.
    """
    for cause in (
        getattr(exc, "original_exception", None),
        exc.__cause__,
        exc.__context__,
    ):
        if isinstance(cause, OSError):
            return cause
    return None


def _code(exc):
    """The MySQL error code of a PyMySQL error, or None."""
    if exc.args and isinstance(exc.args[0], int):
        return exc.args[0]
    return None


def _access_denied(exc):
    """The server's own "Access denied" text: the CLI collector's rule, kept
    for the login refusals no code list names (a locked account, 3118 and
    MariaDB's 4151; one blocked after failed logins, 3955; 3879)."""
    return len(exc.args) > 1 and "access denied" in str(exc.args[1]).lower()


def _classify(exc):
    """Map a PyMySQL error to a stable, backend-facing error category.

    Only `auth_failed` routes to config_error server-side; everything else is
    treated as an outage (unreachable).
    """
    os_error = _os_error(exc)
    if isinstance(os_error, TimeoutError):  # socket.timeout is TimeoutError
        return "timeout"
    code = _code(exc)
    if code in _AUTH_ERRORS or (code is not None and _access_denied(exc)):
        return "auth_failed"
    if code == _CR_CONN_HOST_ERROR and os_error is not None:
        if isinstance(os_error, socket.gaierror):
            return "unreachable"
        return "connection_refused"
    return "error"


def _connect_detail(target, os_error):
    """The client's wording for a connection that never reached the server."""
    unix_socket, host, port = target
    reason = os_error.strerror or str(os_error) or type(os_error).__name__
    if unix_socket:
        return (
            f"ERROR {_CR_CONNECTION_ERROR}: Can't connect to local MySQL server"
            f" through socket '{unix_socket}' ({reason})"
        )
    if isinstance(os_error, socket.gaierror):
        return (
            f"ERROR {_CR_UNKNOWN_HOST}: Unknown MySQL server host '{host}' ({reason})"
        )
    detail = (
        f"ERROR {_CR_CONN_HOST_ERROR}: Can't connect to MySQL server on"
        f" '{host}:{port}' ({reason})"
    )
    if host == "127.0.0.1" and port == DEFAULT_PORT and _HAS_UNIX_SOCKETS:
        # localhost:3306 dials TCP when no default socket could be seen: say
        # which ones the agent may not look at (SELinux, a 0750
        # /var/lib/mysql). Shown for a configured 127.0.0.1:3306 too, where
        # the advice holds as well.
        hidden = [path for path in _DEFAULT_SOCKETS if _is_socket(path) is None]
        if hidden:
            detail += (
                f"; the agent may not look for a socket at {', '.join(hidden)}"
                " (permission denied): configure the socket path if the server"
                " listens there"
            )
    return detail


def _detail(exc, target):
    """error_detail for a failed connection or probe, naming the TLS failure
    that caused a retry without TLS (_open)."""
    os_error = _os_error(exc)
    if _code(exc) == _CR_CONN_HOST_ERROR and os_error is not None:
        detail = _connect_detail(target, os_error)
    elif len(exc.args) == 2 and _code(exc) is not None:
        detail = f"ERROR {exc.args[0]}: {exc.args[1]}"
    else:
        detail = str(exc) or type(exc).__name__
    tls_error = getattr(exc, "after_tls_failure", None)
    if tls_error:
        detail += f" (after the TLS handshake failed: {tls_error})"
    return detail


def _missing_package_detail(exc):
    """error_detail when the account's plugin needs a package not bundled.

    PyMySQL raises RuntimeError naming the package; only PyNaCl (ed25519) is
    expected to be missing, cryptography being a dependency.
    """
    message = str(exc)
    if "pynacl" in message:
        return (
            "The account authenticates with MariaDB's ed25519 plugin, which"
            " the agent does not support: use an account with another plugin"
            f" ({message})"
        )
    return message


def _text(value):
    """A column value as str: bytes decoded as UTF-8 with replacement."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def _rows(conn, sql):
    """(column names, rows) of one statement; values are bytes or None."""
    with conn.cursor() as cursor:
        cursor.execute(sql)
        names = [column[0] for column in cursor.description or ()]
        return names, cursor.fetchall()


def _best_effort(conn, sql):
    """_rows(), or None when the statement fails for any reason.

    A reply past MAX_READ_BYTES is logged at error, once per statement: unlike
    a denied statement, no grant brings that section back.
    """
    try:
        return _rows(conn, sql)
    except Exception as e:  # denied, unsupported, connection lost: drop the section
        level = "debug"
        if getattr(e, "read_cap", False) and sql not in _read_cap_reported:
            _read_cap_reported.add(sql)
            level = "error"
        log(f"MySQL statement skipped ({sql}): {log_safe(e)}", level)
        return None


def _status_map(rows):
    """{Variable_name: Value} from SHOW ... STATUS / VARIABLES rows.

    A NULL value reads as "", which every consumer omits like a missing one.
    """
    result = {}
    for row in rows:
        if len(row) >= 2 and row[0] is not None:
            result[_text(row[0]).strip()] = (_text(row[1]) or "").strip()
    return result


def _to_int(value):
    """int(value) or None -- absorbs NULL/blank/None/garbage."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value):
    """float(value) or None -- absorbs NULL/blank/None/garbage and non-finite.

    inf/-inf/nan (and overflowing magnitudes like "1e999" that float() rounds to
    inf) are valid Python floats but serialize as the non-RFC-8259 tokens
    Infinity/NaN under the synchronizer's json.dumps (default allow_nan=True),
    which a strict backend JSON parser rejects -- poisoning the WHOLE tick
    payload (every collector), not just this key. Rejecting them to None omits
    the gauge (no-data) and keeps a bad wsrep value isolated, matching the
    collector's omit-not-fabricate discipline.
    """
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


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


# Galera / wsrep whitelist merged into data["mysql"]: (payload_key, coercion).
# Numeric gauges are parsed (ints/floats); cluster/health status strings ship
# verbatim (str). Everything here is an instantaneous gauge/status -- nothing to
# rate. A field whose coercion yields None (unparseable/NULL) is omitted, never
# fabricated. Anything outside this list (wsrep_provider, ...) is dropped.
_WSREP_FIELDS = (
    ("wsrep_cluster_size", _to_int),
    ("wsrep_cluster_status", str),
    ("wsrep_local_state", _to_int),
    ("wsrep_local_state_comment", str),
    ("wsrep_ready", str),
    ("wsrep_connected", str),
    ("wsrep_flow_control_paused", _to_float),
    ("wsrep_local_recv_queue_avg", _to_float),
)


def _add_galera_metrics(metrics, status):
    """Merge the whitelisted Galera / wsrep cluster-state gauges.

    `status` is the parsed SHOW GLOBAL STATUS LIKE 'wsrep%' output, read only
    on a server whose wsrep_on is ON (_galera_enabled); zero rows add nothing.
    Present-but-empty values are omitted too: a numeric field that fails to parse
    (NULL / non-finite / garbage) and a blank status string both drop out rather
    than ship a fabricated null or "". Non-blank status strings ship verbatim; a
    real 0 / 0.0 gauge is kept.
    """
    for key, coerce in _WSREP_FIELDS:
        if key in status:
            value = coerce(status[key])
            # Omit missing/blank values: None from a numeric coercion (NULL /
            # non-finite / garbage) or "" from a present-but-empty status field.
            # No-data reads as absent, never a fabricated null or blank string. A
            # real 0 / 0.0 gauge (e.g. local_state 0, no flow control) is kept.
            if value is None or value == "":
                continue
            metrics[key] = value


def _galera_enabled(variables):
    """True when the server's global wsrep_on reads ON: a Galera node."""
    return variables.get("wsrep_on", "").upper() in ("ON", "1")


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


def _get_replication(conn):
    """Return (is_replica, replication_dict).

    Tries SHOW REPLICA STATUS (MySQL 8.0.22+ / MariaDB 10.5+), falling back to
    SHOW SLAVE STATUS on any error (older servers reject REPLICA). Returns:
      (None, None)  -- status unreadable (both statements failed, e.g. the user
                       lacks REPLICATION CLIENT); undetermined.
      (False, None) -- statement succeeded, no rows: not a replica.
      (True, {...}) -- replica; dict has lag_seconds/io_running/sql_running/running.

    A failure here never flips reachable; it only drops the replication section
    (mirrors the PostgreSQL collector's per-view degradation).
    """
    global _replica_status_sql
    first = _replica_status_sql
    second = SLAVE_STATUS_SQL if first == REPLICA_STATUS_SQL else REPLICA_STATUS_SQL
    result = _best_effort(conn, first)
    if result is None:
        result = _best_effort(conn, second)
        if result is not None:
            # The fallback spelling is the one this server speaks; lead with
            # it next tick instead of re-running the failing one forever.
            _replica_status_sql = second
    if result is None:
        return None, None
    names, rows = result
    if not rows:
        return False, None
    # One row per replication channel (MySQL multi-source). The CLI path read
    # the \G output of every row into one dict, so the LAST row won; reading
    # that row keeps the payload as it was.
    return True, _build_replication(dict(zip(names, map(_text, rows[-1]))))


def _failure(category, detail):
    """Build the unreachable/config_error payload for a failed probe."""
    result = {"reachable": False, "error": category}
    detail = scrub_str(detail, ERROR_DETAIL_MAX) if detail else None
    if detail:
        result["error_detail"] = detail
    return result


def _read_metrics(conn, metrics):
    """Add every best-effort statement's section to `metrics`, the probe's
    payload, on the same connection.

    Each section is merged whole (one dict.update), so a copy taken by
    mysql_metrics when the deadline cuts the collection holds whole sections.
    """
    # Best-effort: max_connections + version (+ wsrep_on, the Galera gate). A
    # failure degrades only these keys and the Galera ones; reachable stays True.
    result = _best_effort(conn, VARIABLES_SQL)
    variables = _status_map(result[1]) if result is not None else {}
    section: dict = {}
    _add_variable_metrics(section, variables)
    if result is not None:
        # Whether this server is a Galera node: false is what tells the server
        # to clear the cluster state an older agent stored for it (see
        # GALERA_STATUS_SQL); absent when the variables are unreadable.
        section["galera"] = _galera_enabled(variables)
    metrics.update(section)

    # Best-effort: replication (REPLICA -> SLAVE fallback, MySQL 8 + MariaDB).
    is_replica, replication = _get_replication(conn)
    section = {}
    if is_replica is not None:
        section["is_replica"] = is_replica
    if replication is not None:
        section["replication"] = replication
    metrics.update(section)

    # Best-effort: Galera / wsrep cluster state (one extra statement, issue #107),
    # on a Galera node only (see GALERA_STATUS_SQL). A failure drops only these
    # keys; reachable stays True.
    if _galera_enabled(variables):
        wsrep = _best_effort(conn, GALERA_STATUS_SQL)
        if wsrep is not None:
            section = {}
            _add_galera_metrics(section, _status_map(wsrep[1]))
            metrics.update(section)

    return metrics


def _collect(host, port, user, password, database, socket_path, progress):
    """One collection, run on the bounded worker. Once the probe answered,
    its payload is progress["metrics"], filled as the sections are read."""
    pymysql = _import_pymysql()
    target = _target(host, port, socket_path)
    try:
        conn = _open(pymysql, target, user, password, database)
    except RuntimeError as e:  # a plugin needing a package that is not bundled
        return _failure("auth_failed", _missing_package_detail(e))
    except pymysql.err.MySQLError as e:
        return _failure(_classify(e), _detail(e, target))
    try:
        # Reachability probe. SHOW GLOBAL STATUS needs no privilege, so its
        # outcome is the reachable/error signal for the whole tick.
        try:
            _, status_rows = _rows(conn, STATUS_SQL)
        except pymysql.err.MySQLError as e:
            return _failure(_classify(e), _detail(e, target))
        metrics: dict = {"reachable": True}
        _add_status_metrics(metrics, _status_map(status_rows))
        progress["metrics"] = metrics
        return _read_metrics(conn, metrics)
    finally:
        _close(conn)


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
    """Collect metrics from MySQL / MariaDB over one PyMySQL connection.

    Args:
        host: "localhost" (the default) with port 3306 means the local unix
            socket when one is found at the distributions' default paths,
            else TCP to 127.0.0.1; any other host or port is TCP.
        port: TCP port (default 3306).
        user: MySQL user (default root).
        password: password, or None for socket/peer/no-password auth.
        database: optional default database to select.
        socket: unix socket path; when set, host/port are ignored.
        **_kwargs: unknown backend config keys are ignored (forward-compatible).

    Returns (never None, and never later than COLLECT_DEADLINE):
        {"reachable": True, <metrics...>} when the probe succeeds (later
        sections may be partial if a statement is denied/unsupported, or
        not read yet when COLLECT_DEADLINE cuts the collection);
        {"reachable": False, "error": <category>, "error_detail": <text>}
        when the connection or authentication fails.
    """
    global _stalled_worker, _last_logged_error
    if _stalled_worker is not None:
        if _stalled_worker.is_alive():
            return _failure("timeout", _STALLED_MESSAGE.format(COLLECT_DEADLINE))
        _stalled_worker = None
    progress: dict = {}
    try:
        result = call_bounded(
            lambda: _collect(host, port, user, password, database, socket, progress),
            COLLECT_DEADLINE,
            name="mysql",
        )
    except WorkerTimeout as stalled:
        _stalled_worker = stalled.worker
        log(f"MySQL collection abandoned after {COLLECT_DEADLINE}s", "debug")
        metrics = progress.get("metrics")
        if metrics is not None:
            # The probe answered: the sections not read yet are left out, as
            # a denied statement's are, never reachability (the CLI collector
            # bounded each statement alone). One C-level copy: the worker
            # merges whole sections into it meanwhile. Should that worker
            # still run at the next tick (a statement slower than the tick
            # interval), that tick reads the timeout envelope above.
            return dict(metrics)
        return _failure("timeout", _STALLED_MESSAGE.format(COLLECT_DEADLINE))
    except Exception as e:
        # A bad port, the worker that could not start, or a reply no step
        # anticipated (a server asking for LOAD DATA LOCAL): an envelope,
        # never None. Logged at error once, then at debug while it repeats.
        message = log_safe(e)
        level = "debug" if message == _last_logged_error else "error"
        _last_logged_error = message
        log(f"MySQL collection failed: {message}", level)
        return _failure("error", str(e) or type(e).__name__)
    _last_logged_error = None
    return result
