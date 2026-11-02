"""MongoDB collector (#258, server #493): the local mongod's health and, on a
replica set member, that member's whole view of its set.

Every agent reads only the mongod (or mongos) of its own machine, over ONE
direct connection per tick: never another member, never a discovered topology,
never a write. The server recognises that the agents on db1, db2 and db3
describe the same set (by its replicaSetId) and keeps one view of it, so the
set stays monitored when any one member, its machine or its agent dies: each
member's replSetGetStatus describes every member.

Commands per tick (all read-only, all covered by clusterMonitor@admin, plus
read@local for the oplog):

  hello (isMaster on 4.4.0/4.4.1)   process + role; needs no authentication
  serverStatus                      node, version, sharding (not an arbiter)
  replSetGetStatus                  replica_set (a member, or to tell an
                                    uninitiated or removed node apart)
  replSetGetConfig                  replica_set: identity + member config
  local.oplog.rs first/last ts      node.oplog.window_s (a member)

Contract: tests/fixtures/mongodb_contract_payload.json, which the server
vendors byte-identical. In short:

- data["mongodb"] is NEVER None. reachable is False only when the connection,
  the TLS handshake or the authentication fails (the `hello` gate), with a
  closed error_type and every other key None.
- Once connected, a refused command drops ONLY its section: its collection
  flag goes False and collection.errors names why (not_authorized, refused,
  timeout, error). The server decides which sections it requires.
- Values ship as MongoDB reports them; cumulative counters stay cumulative
  (the server rates them); a field this version or engine lacks is None, never
  0. Replication lag and heartbeat ages are computed inside ONE
  replSetGetStatus reply, against its own optimes and `date`: no agent clock
  value appears anywhere in the payload.

Bounded twice, because the collection loop shares one systemd watchdog
window: every command runs under pymongo.timeout() with what is left of
COMMAND_BUDGET (so a slow mongod costs its sections, not the tick), and the
whole collection runs on a bounded.call_bounded worker abandoned after
COLLECT_DEADLINE, single-flight. Neither bounds the driver's own monitor
thread, which resolves and dials the host and which client.close() does not
join: a resolver that never answers keeps it blocked after the tick returns.
So no client is built while a pymongo thread from an earlier tick is still
alive once given _DRIVER_EXIT_GRACE to end (_driver_thread_alive): at most one
blocked monitor, never one per tick.

pymongo is imported lazily, on the first tick that carries a mongodb config:
it costs ~110 ms and ~11 MB of RSS, which hosts without MongoDB never pay.
"""

import ipaddress
import math
import os
import re
import socket
import ssl
import stat
import threading
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from urllib.parse import quote

from fivenines_agent.bounded import WorkerTimeout, call_bounded
from fivenines_agent.debug import debug, log
from fivenines_agent.scrub import log_safe, scrub_message, scrub_str

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 27017
DEFAULT_AUTH_SOURCE = "admin"

# null negotiates (SCRAM-SHA-256, else SCRAM-SHA-1). Anything else is a
# config_error rather than passed through: PLAIN would send the password in
# clear, and GSSAPI / MONGODB-AWS / MONGODB-OIDC need libraries the binary
# does not bundle.
AUTH_MECHANISMS = ("SCRAM-SHA-1", "SCRAM-SHA-256", "MONGODB-X509")
X509 = "MONGODB-X509"

# Driver timeouts (#258's contract). A command never waits longer than
# SOCKET_TIMEOUT_S, nor longer than what is left of COMMAND_BUDGET.
SERVER_SELECTION_TIMEOUT_MS = 5000
CONNECT_TIMEOUT_MS = 5000
SOCKET_TIMEOUT_S = 10
COMMAND_BUDGET = 15
# The hello gate (selection + connection + authentication + hello).
HELLO_TIMEOUT_S = SERVER_SELECTION_TIMEOUT_MS / 1000

# The hard bound: the collection runs on a worker abandoned at this deadline
# (bounded.call_bounded). Above COMMAND_BUDGET + CLOSE_TIMEOUT, so it only
# fires on what no driver timeout covers (getaddrinfo on a host name).
COLLECT_DEADLINE = 20

# client.close() sends endSessions; bounded so a mongod that stopped
# answering mid-tick cannot hold the close for a server selection + a socket
# timeout (15s).
CLOSE_TIMEOUT = 2

# MongoDB's own maximum number of members in a replica set.
MAX_MEMBERS = 50

# A host name (RFC 1123 labels) or an IPv4 literal. Anything else -- a scheme,
# a path, a port, userinfo, a comma (a seed list), a query -- is refused: the
# value reaches MongoClient(host=...), which parses URIs and host lists.
# Underscores are allowed: Docker and compose name containers with them, and
# its embedded DNS resolves those names.
_LABEL = r"[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})"
# Always fullmatch: `$` would also accept a trailing newline.
_HOSTNAME_RE = re.compile(rf"{_LABEL}(\.{_LABEL})*\.?")
_HOST_MAX_LEN = 253
# AF_UNIX sun_path is 108 bytes on Linux, NUL included.
_SOCKET_PATH_MAX_LEN = 107

# replSetGetStatus member states with no meaningful optime: STARTUP (0),
# STARTUP2 (5, initial sync), UNKNOWN (6), DOWN (8), REMOVED (10). An arbiter
# (7) has none either.
_PRIMARY = 1
_ARBITER = 7
_REMOVED = 10
_NO_OPTIME_STATES = frozenset({0, 5, 6, _ARBITER, 8, _REMOVED})

# Server error codes.
_UNAUTHORIZED = 13
# What a failed authentication answers, measured on 7.0: AuthenticationFailed
# (18) for a wrong user or password (and an X.509 username the certificate does
# not match), UserNotFound (11) for an X.509 certificate subject with no user
# in $external, MechanismUnavailable (334) for a mechanism the user has no
# credentials for (SCRAM-SHA-256 forced for a SCRAM-SHA-1-only user).
_AUTH_FAILED_CODES = frozenset({18, 11, 334})
_COMMAND_NOT_FOUND = 59
_INVALID_REPLICA_SET_CONFIG = 93
_NOT_YET_INITIALIZED = 94
_SHUTDOWN_CODES = frozenset({91, 11600})

# collection.errors values.
NOT_AUTHORIZED = "not_authorized"
REFUSED = "refused"
TIMEOUT = "timeout"
ERROR = "error"

_EPOCH = datetime(1970, 1, 1)

_REDACT_MIN_LEN = 6

# Every pymongo thread is named pymongo_*: the monitor, the kill-cursors
# executor (the agent has no other pymongo user).
_DRIVER_THREAD_PREFIX = "pymongo_"

_DRIVER_BUSY_MESSAGE = (
    "a previous MongoDB connection attempt is still blocked (the driver's "
    "monitor thread, resolving or dialing the host); no new one starts until "
    "it ends"
)

# How long a pymongo thread may take to end before it counts as blocked:
# close() does not join them, and they notice it within their 0.5s sleep
# (measured: both gone ~0.6s after close()), so a collection started right
# after another one would otherwise read a thread that is merely exiting as
# blocked.
_DRIVER_EXIT_GRACE = 1.0

# What the driver reports when the peer is not speaking the MongoDB wire
# protocol (its own text carries random request ids, a new message per tick).
_PROTOCOL_MESSAGE = "the peer does not speak the MongoDB wire protocol"

# How a TLS failure still shows once pymongo has flattened it into an
# AutoReconnect (see _connection_error_type): the prefix pymongo puts on a
# handshake failure, or the "[SSL: REASON]" CPython's ssl module puts in front
# of every OpenSSL error -- a certificate pymongo could not verify carries only
# the latter.
_TLS_FAILURE_RE = re.compile(r"^SSL handshake failed: |\[SSL(: [A-Z0-9_]+)?\]")

# A server selection that gave up before the monitor recorded any error: the
# driver's own message embeds a random topology id, which would make every
# tick's message different.
_NO_ANSWER_MESSAGE = "no answer within {:g}s (server selection timed out)"

_STALLED_MESSAGE = (
    "the MongoDB collection did not finish within {}s (resolving the host "
    "name, or a mongod that stopped answering); no new one starts until it "
    "returns"
)

# The worker of a collection that outlived COLLECT_DEADLINE, while it runs.
_stalled_worker = None

# Last failure logged at error, per kind: a steady failure logs once, then at
# debug, so a mongod down for a day does not write 1440 error lines.
_last_logged: dict = {}


class ConfigError(ValueError):
    """The config cannot be used: config_error, nothing was sent."""


class _BudgetSpent(Exception):
    """COMMAND_BUDGET ran out before a command could be sent."""

    def __init__(self):
        super().__init__(
            f"not sent: the {COMMAND_BUDGET}s command budget was already spent"
        )


class _Config:
    """The validated config: every value MongoClient receives comes from here."""

    def __init__(
        self,
        host,
        port,
        username,
        password,
        auth_source,
        auth_mechanism,
        tls,
        tls_ca_file,
        tls_certificate_key_file,
        tls_allow_invalid_certificates,
    ):
        host = DEFAULT_HOST if host in (None, "") else host
        if not isinstance(host, str):
            raise ConfigError("host must be a string")
        if host.startswith("/"):
            if not hasattr(socket, "AF_UNIX"):
                # pymongo's own check (Windows): refused before any I/O.
                raise ConfigError("unix sockets are not supported on this OS")
            self.host = "mongodb://" + quote(_socket_path(host), safe="")
            self.port = None
        else:
            self.host = _tcp_host(host)
            self.port = _port(port)
        self.username = _optional_str(username, "username")
        self.password = _optional_str(password, "password")
        self.auth_source = (
            _optional_str(auth_source, "auth_source") or DEFAULT_AUTH_SOURCE
        )
        mechanism = _optional_str(auth_mechanism, "auth_mechanism")
        if mechanism is not None and mechanism.upper() not in AUTH_MECHANISMS:
            raise ConfigError(
                "auth_mechanism must be null, " + ", ".join(AUTH_MECHANISMS)
            )
        self.auth_mechanism = mechanism.upper() if mechanism else None
        self.tls = _flag(tls)
        self.tls_ca_file = _optional_str(tls_ca_file, "tls_ca_file")
        self.tls_certificate_key_file = _optional_str(
            tls_certificate_key_file, "tls_certificate_key_file"
        )
        self.tls_allow_invalid_certificates = _flag(tls_allow_invalid_certificates)
        if self.auth_mechanism == X509 and not (
            self.tls and self.tls_certificate_key_file
        ):
            raise ConfigError(
                "MONGODB-X509 needs tls: true and tls_certificate_key_file"
            )

    def client_options(self, listener):
        """MongoClient keyword arguments: one direct, read-only connection."""
        options = {
            "host": self.host,
            "directConnection": True,
            "appname": "fivenines-agent",
            "serverSelectionTimeoutMS": SERVER_SELECTION_TIMEOUT_MS,
            "connectTimeoutMS": CONNECT_TIMEOUT_MS,
            "socketTimeoutMS": SOCKET_TIMEOUT_S * 1000,
            "maxPoolSize": 1,
            "retryReads": False,
            "retryWrites": False,
            # One monitor connection instead of two (the streaming protocol
            # adds an RTT monitor), each a pair of mongod log lines a tick.
            "serverMonitoringMode": "poll",
            "event_listeners": [listener],
            # No thread until the first command: building the client only
            # checks the config (a bad option or TLS file is config_error,
            # never masked by a host that does not answer).
            "connect": False,
        }
        if self.port is not None:
            options["port"] = self.port
        if self.auth_mechanism == X509:
            options["authMechanism"] = X509
            if self.username:
                options["username"] = self.username
        elif self.username:
            options["username"] = self.username
            options["password"] = self.password
            options["authSource"] = self.auth_source
            if self.auth_mechanism:
                options["authMechanism"] = self.auth_mechanism
        if self.tls:
            options["tls"] = True
            if self.tls_allow_invalid_certificates:
                options["tlsAllowInvalidCertificates"] = True
            if self.tls_ca_file:
                options["tlsCAFile"] = self.tls_ca_file
            elif not self.tls_allow_invalid_certificates:
                # The bundled public CA set, like the agent's own API calls and
                # the PBS collector: what the OS store resolves to inside the
                # PyInstaller binary depends on the OpenSSL it bundles. A mongod
                # certificate from an internal CA needs tls_ca_file.
                import certifi

                options["tlsCAFile"] = certifi.where()
            if self.tls_certificate_key_file:
                options["tlsCertificateKeyFile"] = self.tls_certificate_key_file
                # Explicitly no passphrase: with none, OpenSSL prompts on the
                # terminal for an encrypted key (a user install started from
                # a shell would hang); "" makes such a key fail to load, a
                # config_error.
                options["tlsCertificateKeyFilePassword"] = ""
        return options


def _optional_str(value, name):
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value


def _flag(value):
    """An explicit true only: a missing, null or unrecognised value is false."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return False


def _port(value):
    if value is None or value == "":
        return DEFAULT_PORT
    if isinstance(value, bool):
        raise ConfigError("port must be an integer")
    try:
        port = int(value)
    except (TypeError, ValueError, OverflowError):  # OverflowError: 1e400
        raise ConfigError("port must be an integer") from None
    if not 0 < port < 65536:
        raise ConfigError("port must be between 1 and 65535")
    return port


def _tcp_host(host):
    """A host name or an IP literal; an IPv6 literal comes back bracketed,
    the only spelling pymongo's host parser accepts."""
    literal = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        address = ipaddress.ip_address(literal)
    except ValueError:
        address = None
    if address is not None and not getattr(address, "scope_id", None):
        return f"[{address}]" if address.version == 6 else str(address)
    if (
        len(host) > _HOST_MAX_LEN
        or not _HOSTNAME_RE.fullmatch(host)
        # pymongo reads a host ending in .sock as a unix socket path.
        or host.lower().endswith(".sock")
    ):
        raise ConfigError(
            "host must be a host name, an IP address, or a unix socket path "
            "starting with /"
        )
    return host


def _socket_path(path):
    try:
        encoded = path.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate from a JSON escape
        raise ConfigError("a unix socket path must be valid UTF-8") from None
    if (
        len(encoded) > _SOCKET_PATH_MAX_LEN
        or not path.endswith(".sock")
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in path)
    ):
        raise ConfigError(
            "a unix socket host must be an absolute path ending in .sock, "
            f"at most {_SOCKET_PATH_MAX_LEN} bytes"
        )
    return path


# --- the driver ---------------------------------------------------------------


def _import_pymongo():
    """pymongo, imported on first use (see the module docstring)."""
    import pymongo
    import pymongo.common
    import pymongo.errors
    import pymongo.monitoring

    return pymongo


_recorder_class = None


def _hello_recorder(pymongo):
    """A heartbeat listener keeping the monitor's last hello reply.

    The monitor's hello is UNAUTHENTICATED, which matters for one role: an
    arbiter stores no users, so with credentials configured the agent's own
    (authenticated) hello fails with AuthenticationFailed, and by then the
    driver has already marked the server Unknown (the SDAM rule for an auth
    error), so only this reply still says arbiterOnly.
    """
    global _recorder_class
    if _recorder_class is None:

        class _HelloRecorder(pymongo.monitoring.ServerHeartbeatListener):
            def __init__(self):
                self.document = None

            def started(self, event):
                pass

            def succeeded(self, event):
                self.document = event.reply.document

            def failed(self, event):
                pass

        _recorder_class = _HelloRecorder
    return _recorder_class()


def _new_client(pymongo, options):
    """The one MongoClient of a tick (the seam the contract test replaces)."""
    return pymongo.MongoClient(**options)


class _Mongo:
    """The tick's client, every call bounded by what is left of the budget."""

    def __init__(self, pymongo, client):
        self.pymongo = pymongo
        self.client = client
        self.deadline = time.monotonic() + COMMAND_BUDGET

    def _bounded(self, call, cap=SOCKET_TIMEOUT_S):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise _BudgetSpent()
        with self.pymongo.timeout(min(left, cap)):
            return call()

    def command(self, name, cap=SOCKET_TIMEOUT_S):
        return self._bounded(lambda: self.client.admin.command(name), cap)

    def oplog_entry(self, direction):
        """The first (1) or last (-1) oplog entry, projected to its ts."""
        return self._bounded(
            lambda: self.client.local["oplog.rs"].find_one(
                {}, {"ts": 1}, sort=[("$natural", direction)]
            )
        )

    def close(self):
        try:
            with self.pymongo.timeout(CLOSE_TIMEOUT):
                self.client.close()
        except Exception as e:
            log(f"Error closing the MongoDB client: {log_safe(e)}", "debug")


# --- value helpers ------------------------------------------------------------


def _get(doc, *path):
    """doc[path[0]][path[1]]..., or None as soon as a level is missing."""
    for key in path:
        if not isinstance(doc, Mapping):
            return None
        doc = doc.get(key)
    return doc


def _num(value):
    """A number as reported (int, or float when not integral); None otherwise.

    bson's Int64 becomes a plain int; a bool is not a number here.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return int(value) if value.is_integer() else value
    return None


def _int(value):
    """A whole number of seconds/units: floats truncated, None otherwise."""
    number = _num(value)
    return None if number is None else int(number)


def _bool(value):
    return value if isinstance(value, bool) else None


def _str(value):
    return scrub_str(value) if isinstance(value, str) else None


def _date(value):
    """A naive UTC datetime, or None for a missing value or the zero date
    (MongoDB's "never": an unreached member's optime is Timestamp(0, 0))."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value if value > _EPOCH else None


def _seconds_between(later, earlier):
    """Whole seconds from earlier to later, clamped at 0; None if either is
    unknown."""
    if later is None or earlier is None:
        return None
    return max(int((later - earlier).total_seconds()), 0)


def _object_id(value):
    """A replicaSetId as 24 lowercase hex characters, or None."""
    text = str(value) if value is not None else ""
    return text.lower() if re.fullmatch(r"[0-9a-fA-F]{24}", text) else None


def _code(exc):
    """The server error code an exception carries, if any. NotPrimaryError
    (a shutdown answer) keeps it in its details only."""
    code = getattr(exc, "code", None)
    if code is None:
        details = getattr(exc, "details", None)
        if isinstance(details, Mapping):
            code = details.get("code")
    return code if isinstance(code, int) and not isinstance(code, bool) else None


# --- payload builders ---------------------------------------------------------


def _failure(error_type, message):
    return {
        "reachable": False,
        "error_type": error_type,
        "error_message": message,
        "process": None,
        "role": None,
        "version": None,
        "me": None,
        "collection": None,
        "node": None,
        "replica_set": None,
        "sharding": None,
    }


def _payload(
    process, role, me, collection, node, version=None, replica_set=None, sharding=None
):
    return {
        "reachable": True,
        "error_type": None,
        "error_message": None,
        "process": process,
        "role": role,
        "version": version,
        "me": me,
        "collection": collection,
        "node": node,
        "replica_set": replica_set,
        "sharding": sharding,
    }


def _arbiter_payload(hello):
    """An arbiter: hello only. It stores no users, so with auth on nothing
    else is readable; its state reaches the server through the data-bearing
    members' views."""
    collection = {
        "server_status_ok": None,
        "repl_status_ok": None,
        "repl_config_ok": None,
        "oplog_ok": None,
        "errors": {},
    }
    return _payload("mongod", "arbiter", _str(hello.get("me")), collection, None)


def _counters(doc, names):
    """{snake_name: number} for a flat counter document; None if absent."""
    if not isinstance(doc, Mapping):
        return None
    return {key: _num(doc.get(source)) for key, source in names}


_OPCOUNTERS = [
    (name, name)
    for name in ("insert", "query", "update", "delete", "getmore", "command")
]


def _tickets(status):
    """Read/write tickets: queues.execution on 8.0+ (the rename), else
    wiredTiger.concurrentTransactions; None on mongos and non-WiredTiger."""
    for path in (("queues", "execution"), ("wiredTiger", "concurrentTransactions")):
        section = _get(status, *path)
        if isinstance(section, Mapping):
            return {
                "read_out": _num(_get(section, "read", "out")),
                "read_available": _num(_get(section, "read", "available")),
                "write_out": _num(_get(section, "write", "out")),
                "write_available": _num(_get(section, "write", "available")),
            }
    return None


def _wiredtiger(status):
    cache = _get(status, "wiredTiger", "cache")
    if not isinstance(cache, Mapping):
        return None
    return {
        "cache_bytes": _num(cache.get("bytes currently in the cache")),
        "cache_max_bytes": _num(cache.get("maximum bytes configured")),
        "cache_dirty_bytes": _num(cache.get("tracked dirty bytes in the cache")),
        "pages_read_into_cache": _num(cache.get("pages read into cache")),
        "pages_written_from_cache": _num(cache.get("pages written from cache")),
    }


def _op_latencies(status):
    latencies = _get(status, "opLatencies")
    if not isinstance(latencies, Mapping):
        return None
    result = {}
    for kind in ("reads", "writes", "commands"):
        result[f"{kind}_us"] = _num(_get(latencies, kind, "latency"))
        result[f"{kind}_ops"] = _num(_get(latencies, kind, "ops"))
    return result


def _node(status, oplog):
    """The node block: serverStatus fields (None when it was not read) plus
    the oplog window."""
    status = status if isinstance(status, Mapping) else {}
    global_lock = _get(status, "globalLock")
    return {
        "uptime_s": _int(status.get("uptime")),
        "connections": _counters(
            status.get("connections"),
            [
                ("current", "current"),
                ("available", "available"),
                ("total_created", "totalCreated"),
                ("active", "active"),
            ],
        ),
        "opcounters": _counters(status.get("opcounters"), _OPCOUNTERS),
        "opcounters_repl": _counters(status.get("opcountersRepl"), _OPCOUNTERS),
        "network": _counters(
            status.get("network"),
            [
                ("bytes_in", "bytesIn"),
                ("bytes_out", "bytesOut"),
                ("num_requests", "numRequests"),
            ],
        ),
        "memory": _counters(
            status.get("mem"), [("resident_mb", "resident"), ("virtual_mb", "virtual")]
        ),
        "wiredtiger": _wiredtiger(status),
        "tickets": _tickets(status),
        "global_lock": (
            {
                "queue_readers": _num(_get(global_lock, "currentQueue", "readers")),
                "queue_writers": _num(_get(global_lock, "currentQueue", "writers")),
                "active_readers": _num(_get(global_lock, "activeClients", "readers")),
                "active_writers": _num(_get(global_lock, "activeClients", "writers")),
            }
            if isinstance(global_lock, Mapping)
            else None
        ),
        "asserts": _counters(
            status.get("asserts"),
            [
                ("regular", "regular"),
                ("msg", "msg"),
                ("user", "user"),
                ("rollovers", "rollovers"),
            ],
        ),
        "page_faults": _num(_get(status, "extra_info", "page_faults")),
        "cursors": (
            {
                "open_total": _num(_get(status, "metrics", "cursor", "open", "total")),
                "open_no_timeout": _num(
                    _get(status, "metrics", "cursor", "open", "noTimeout")
                ),
                "timed_out": _num(_get(status, "metrics", "cursor", "timedOut")),
            }
            if isinstance(_get(status, "metrics", "cursor"), Mapping)
            else None
        ),
        "documents": _counters(
            _get(status, "metrics", "document"),
            [
                ("inserted", "inserted"),
                ("returned", "returned"),
                ("updated", "updated"),
                ("deleted", "deleted"),
            ],
        ),
        "op_latencies": _op_latencies(status),
        "oplog": oplog,
    }


def _sharding(status):
    """The config server replica set a shard member (or mongos, or config
    server member) belongs to: the set name before the / of
    serverStatus().sharding.configsvrConnectionString."""
    connection = _get(status, "sharding", "configsvrConnectionString")
    if not isinstance(connection, str) or "/" not in connection:
        return None
    name = connection.split("/", 1)[0]
    return {"config_server_set": scrub_str(name)} if name else None


def _oplog_window(first, last):
    """window_s from the first and last oplog entries' ts; raises when the
    oplog is empty or an entry has no Timestamp (the section then fails)."""
    first_ts = _get(first, "ts")
    last_ts = _get(last, "ts")
    first_time = getattr(first_ts, "time", None)
    last_time = getattr(last_ts, "time", None)
    if not isinstance(first_time, int) or not isinstance(last_time, int):
        raise ValueError("the oplog has no first/last entry with a ts Timestamp")
    return {"window_s": max(last_time - first_time, 0)}


def _lag_eligible(member):
    """A member whose optime means something: healthy, data-bearing, and in a
    state that has one. A health-0 member's optime is reset to
    Timestamp(0, 0), which would read as a 56-year lag."""
    return (
        _num(member.get("health")) == 1
        and _int(member.get("state")) not in _NO_OPTIME_STATES
        and _date(member.get("optimeDate")) is not None
    )


def _lag_reference(members):
    """The PRIMARY's optimeDate in this reply, else (no primary) the freshest
    among healthy data-bearing members: the mongosh algorithm."""
    primaries = [
        _date(m.get("optimeDate"))
        for m in members
        if _int(m.get("state")) == _PRIMARY and _lag_eligible(m)
    ]
    if primaries:
        return max(primaries)
    fresh = [_date(m.get("optimeDate")) for m in members if _lag_eligible(m)]
    return max(fresh) if fresh else None


def _member(status_member, config_member, now, reference):
    """One members[] entry: replSetGetStatus fields merged with the member's
    replSetGetConfig fields (each side None when its command failed)."""
    s = status_member if isinstance(status_member, Mapping) else None
    c = config_member if isinstance(config_member, Mapping) else None
    is_self = bool(s.get("self")) if s is not None else None
    name = _str(c.get("host")) if c is not None else None
    if name is None and s is not None:
        name = _str(s.get("name"))
    member_id = _int((c or s or {}).get("_id"))
    entry = {
        "id": member_id,
        "name": name,
        "self": is_self,
        "health": None,
        "state": None,
        "state_str": None,
        "uptime_s": None,
        "lag_s": None,
        "ping_ms": None,
        "last_heartbeat_age_s": None,
        "last_heartbeat_recv_age_s": None,
        "sync_source": None,
        "config_version": None,
        "priority": None,
        "votes": None,
        "hidden": None,
        "arbiter_only": None,
        "secondary_delay_s": None,
        "build_indexes": None,
    }
    if s is not None:
        entry["health"] = _num(s.get("health"))
        entry["state"] = _int(s.get("state"))
        entry["state_str"] = _str(s.get("stateStr"))
        entry["uptime_s"] = _int(s.get("uptime"))
        if _lag_eligible(s):
            entry["lag_s"] = _seconds_between(reference, _date(s.get("optimeDate")))
        if not is_self:
            # An unhealthy member keeps its last pingMs (0 once it is down):
            # stale, so null.
            if entry["health"] == 1:
                entry["ping_ms"] = _num(s.get("pingMs"))
            entry["last_heartbeat_age_s"] = _seconds_between(
                now, _date(s.get("lastHeartbeat"))
            )
            entry["last_heartbeat_recv_age_s"] = _seconds_between(
                now, _date(s.get("lastHeartbeatRecv"))
            )
        # "" is how MongoDB says "no sync source".
        entry["sync_source"] = _str(s.get("syncSourceHost")) or None
        entry["config_version"] = _int(s.get("configVersion"))
    if c is not None:
        delay = c.get("secondaryDelaySecs")
        if delay is None:
            delay = c.get("slaveDelay")  # before 5.0
        entry["priority"] = _num(c.get("priority"))
        entry["votes"] = _num(c.get("votes"))
        entry["hidden"] = _bool(c.get("hidden"))
        entry["arbiter_only"] = _bool(c.get("arbiterOnly"))
        entry["secondary_delay_s"] = _int(delay)
        entry["build_indexes"] = _bool(c.get("buildIndexes"))
    return entry


def _status_for(by_id, config_member):
    """The status entry of a config member: same _id AND same host. A
    reconfig between the two reads can give a replaced member's _id to a new
    host; its health must not be lent to the newcomer (left unknown)."""
    status_member = by_id.get(_int(config_member.get("_id")))
    if status_member is None or status_member.get("name") != config_member.get("host"):
        return None
    return status_member


def _members(status, config):
    """One entry per member of the config (of the status when the config was
    not read), sorted by name, at most MAX_MEMBERS. None when neither was
    read."""
    status_members = _get(status, "members")
    config_members = _get(config, "members")
    status_members = (
        [m for m in status_members if isinstance(m, Mapping)]
        if isinstance(status_members, list)
        else None
    )
    config_members = (
        [m for m in config_members if isinstance(m, Mapping)]
        if isinstance(config_members, list)
        else None
    )
    if status_members is None and config_members is None:
        return None
    now = _date(_get(status, "date"))
    reference = _lag_reference(status_members or [])
    by_id = {}
    for m in status_members or []:
        by_id.setdefault(_int(m.get("_id")), m)
    if config_members is not None:
        pairs = [(_status_for(by_id, c), c) for c in config_members]
    else:
        pairs = [(s, None) for s in status_members or []]
    entries = [_member(s, c, now, reference) for s, c in pairs]
    entries.sort(key=lambda e: (e["name"] is None, e["name"] or "", e["id"] or 0))
    return entries[:MAX_MEMBERS]


def _my_state_str(status):
    members = _get(status, "members")
    for m in members if isinstance(members, list) else []:
        if isinstance(m, Mapping) and m.get("self"):
            return _str(m.get("stateStr"))
    return None


def _replica_set(hello, status, config, removed=None):
    """The member's view of its set. status / config are None when their
    command failed; `removed` is the InvalidReplicaSetConfig reply of a node
    removed from its set (it has no view of the set: members None)."""
    settings = _get(config, "settings")
    set_name = (
        _str(_get(status, "set"))
        or _str(_get(config, "_id"))
        or _str(hello.get("setName"))
    )
    view = {
        "set_name": set_name,
        "replica_set_id": _object_id(_get(settings, "replicaSetId")),
        "configsvr": (
            bool(config.get("configsvr", False))
            if isinstance(config, Mapping)
            else None
        ),
        "config_version": _int(_get(config, "version")),
        "config_term": _int(_get(config, "term")),
        "term": _int(_get(status, "term")),
        "my_state": _int(_get(status, "myState")),
        "my_state_str": _my_state_str(status),
        "majority_vote_count": _int(_get(status, "majorityVoteCount")),
        "write_majority_count": _int(_get(status, "writeMajorityCount")),
        "voting_members_count": _int(_get(status, "votingMembersCount")),
        "writable_voting_members_count": _int(
            _get(status, "writableVotingMembersCount")
        ),
        "members": None,
    }
    if removed is not None:
        # Only what the error reply reports (MongoDB 4.4 to 8.0 report none).
        for key in ("myState", "state"):
            if _int(removed.get(key)) is not None:
                view["my_state"] = _int(removed.get(key))
                break
        view["my_state_str"] = _str(removed.get("stateStr"))
        return view
    view["members"] = _members(status, config)
    return view


# --- error classification -------------------------------------------------------


def _server_error(client):
    """The error the monitor recorded for the (single) server, if any: what
    actually failed behind a ServerSelectionTimeoutError."""
    try:
        descriptions = client.topology_description.server_descriptions()
    except Exception:
        return None
    for description in descriptions.values():
        error = getattr(description, "error", None)
        if error is not None:
            return error
    return None


def _wire_version_too_old(client, pymongo):
    try:
        descriptions = client.topology_description.server_descriptions()
    except Exception:
        return False
    minimum = pymongo.common.MIN_SUPPORTED_WIRE_VERSION
    return any(
        d.is_server_type_known and d.max_wire_version < minimum
        for d in descriptions.values()
    )


def _connection_error_type(error, pymongo):
    """refused / timeout / TLS for a connection error, from its TYPE.

    The monitor strips every error's __cause__ before recording it
    (PYTHON-2433), so the socket error behind an AutoReconnect is gone; what
    survives is the type pymongo chose: the raw ssl.SSLCertVerificationError
    for a certificate it could not verify, NetworkTimeout for a socket
    timeout, and AutoReconnect for the rest. A TLS failure is then only
    visible in the message (_TLS_FAILURE_RE): measured with pymongo 4.18, an
    unverifiable certificate arrives as AutoReconnect("host:port: [SSL:
    CERTIFICATE_VERIFY_FAILED] ..."). Any other AutoReconnect is a refusal, a
    DNS failure, no route, or a connection closed or reset before the
    handshake: nothing usable answered.
    """
    errors = pymongo.errors
    if isinstance(error, (ssl.SSLError, ssl.CertificateError)):
        return "tls_error"
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(error, errors.AutoReconnect):
        if _TLS_FAILURE_RE.search(str(error)):
            return "tls_error"
        return "connection_refused"
    if isinstance(error, OSError):
        return "connection_refused"
    return None


def _classify(exc, client, pymongo):
    """(error_type, the exception or fixed message that ships) for a failure
    of the hello gate."""
    errors = pymongo.errors
    if isinstance(exc, errors.ServerSelectionTimeoutError):
        # The selection only says it gave up; the monitor's error says why.
        cause = _server_error(client)
        if cause is None:
            return "timeout", _NO_ANSWER_MESSAGE.format(HELLO_TIMEOUT_S)
        exc = cause
    code = _code(exc)
    if code in _AUTH_FAILED_CODES:
        return "auth_failed", exc
    if code in _SHUTDOWN_CODES:
        return "shutting_down", exc
    if isinstance(exc, errors.ConfigurationError):
        if _wire_version_too_old(client, pymongo):
            return "server_too_old", exc
        return "config_error", exc
    # _BudgetSpent is a backstop here: the gate is the first command, capped
    # at HELLO_TIMEOUT_S of COMMAND_BUDGET.
    if isinstance(exc, _BudgetSpent) or (
        isinstance(exc, errors.PyMongoError) and exc.timeout
    ):
        return "timeout", exc
    if isinstance(exc, errors.OperationFailure):
        return "unknown", exc
    if isinstance(exc, errors.ProtocolError):
        return "unknown", _PROTOCOL_MESSAGE
    error_type = _connection_error_type(exc, pymongo)
    if error_type is not None:
        return error_type, exc
    return "unknown", exc


def _message(exc, config):
    """A short, stable, redacted error message: an OperationFailure's errmsg
    without the reply dump (which carries $clusterTime), and never the
    configured password."""
    text = exc if isinstance(exc, str) else None
    details = getattr(exc, "details", None)
    if isinstance(details, Mapping) and isinstance(details.get("errmsg"), str):
        text = details["errmsg"]
    if not text:
        text = str(exc) or type(exc).__name__
    # pymongo never echoes a password passed as a keyword argument: this is a
    # backstop, and a short password would only garble a message (and show
    # where it occurs).
    if config is not None and len(config.password or "") >= _REDACT_MIN_LEN:
        text = text.replace(config.password, "[REDACTED]")
    return scrub_message(text)


def _section_reason(exc, pymongo):
    if isinstance(exc, _BudgetSpent):
        return TIMEOUT
    errors = pymongo.errors
    if isinstance(exc, errors.PyMongoError) and exc.timeout:
        return TIMEOUT
    if isinstance(exc, errors.OperationFailure):
        return NOT_AUTHORIZED if exc.code == _UNAUTHORIZED else REFUSED
    return ERROR


# --- the collection -------------------------------------------------------------


class _Sections:
    """Runs each section, recording its collection flag and error reason."""

    def __init__(self, mongo):
        self.mongo = mongo
        self.flags = {
            "server_status_ok": None,
            "repl_status_ok": None,
            "repl_config_ok": None,
            "oplog_ok": None,
        }
        self.errors = {}

    def run(self, name, call):
        """call()'s result, or None with the section marked failed."""
        try:
            result = call()
        except Exception as e:
            self.fail(name, e)
            return None
        self.flags[f"{name}_ok"] = True
        return result

    def fail(self, name, exc):
        self.flags[f"{name}_ok"] = False
        self.errors[name] = _section_reason(exc, self.mongo.pymongo)

    def collection(self):
        return {**self.flags, "errors": dict(sorted(self.errors.items()))}


def _hello(mongo):
    """The gate: the first command selects the server, connects and
    authenticates. Capped at the server selection timeout: under
    pymongo.timeout() the selection waits for the whole timeout instead."""
    try:
        return mongo.command("hello", cap=HELLO_TIMEOUT_S)
    except Exception as e:
        if _code(e) != _COMMAND_NOT_FOUND:
            raise
    # MongoDB 4.4.0 and 4.4.1 predate the hello command.
    return mongo.command("isMaster", cap=HELLO_TIMEOUT_S)


def _read(mongo, recorder, config):
    """Everything after the client exists: the hello gate, then the sections."""
    try:
        hello = _hello(mongo)
    except Exception as e:
        monitor_hello = recorder.document
        if (
            _code(e) in _AUTH_FAILED_CODES
            and isinstance(monitor_hello, Mapping)
            and monitor_hello.get("arbiterOnly") is True
        ):
            return _arbiter_payload(monitor_hello)
        error_type, source = _classify(e, mongo.client, mongo.pymongo)
        return _failure(error_type, _message(source, config))
    if not isinstance(hello, Mapping):
        return _failure("unknown", "hello returned no document")

    if hello.get("arbiterOnly") is True:
        return _arbiter_payload(hello)
    process = "mongos" if hello.get("msg") == "isdbgrid" else "mongod"
    sections = _Sections(mongo)

    status = sections.run(
        "server_status", lambda: _checked(mongo.command("serverStatus"))
    )

    replica_set = None
    oplog = None
    if process == "mongos":
        role = "mongos"
    elif hello.get("setName") is not None or hello.get("isreplicaset") is True:
        role, replica_set, oplog = _read_replica_set(mongo, sections, hello)
    else:
        role = "standalone"

    return _payload(
        process,
        role,
        _str(hello.get("me")),
        sections.collection(),
        _node(status, oplog),
        version=_str(_get(status, "version")),
        replica_set=replica_set,
        sharding=_sharding(status),
    )


def _checked(reply):
    if not isinstance(reply, Mapping):
        raise ValueError("the command returned no document")
    return reply


def _read_replica_set(mongo, sections, hello):
    """(role, replica_set, oplog) for a node started with --replSet."""
    try:
        status = _checked(mongo.command("replSetGetStatus"))
        status_error = None
    except Exception as e:
        status, status_error = None, e
    if _code(status_error) == _NOT_YET_INITIALIZED:
        # Started with --replSet, rs.initiate() not run: no set yet.
        return "uninitiated", None, None
    if _code(status_error) == _INVALID_REPLICA_SET_CONFIG:
        # Measured on 4.4 to 8.0: a node removed from its set answers hello
        # exactly like an uninitiated one (isreplicaset, no setName) and
        # replSetGetStatus with InvalidReplicaSetConfig (93) -- no state. That
        # code is what tells it from an uninitiated node (94). It has no view
        # of the set (repl_status_ok stays null), but its config still names
        # the set that dropped it.
        reply = getattr(status_error, "details", None)
        config = sections.run("repl_config", lambda: _repl_config(mongo))
        removed = reply if isinstance(reply, Mapping) else {}
        return "removed", _replica_set(hello, None, config, removed=removed), None
    if status_error is not None:
        sections.fail("repl_status", status_error)
        if hello.get("setName") is None:
            # Not read (refused, timed out, failed): an uninitiated node and a
            # removed one look alike from hello (isreplicaset without setName),
            # so the role rests on hello alone, and errors says why.
            return "uninitiated", None, None
    else:
        sections.flags["repl_status_ok"] = True

    config = sections.run("repl_config", lambda: _repl_config(mongo))
    oplog = sections.run(
        "oplog",
        lambda: _oplog_window(mongo.oplog_entry(1), mongo.oplog_entry(-1)),
    )
    return "replica_set_member", _replica_set(hello, status, config), oplog


def _repl_config(mongo):
    """replSetGetConfig's config document."""
    return _checked(_get(mongo.command("replSetGetConfig"), "config"))


def _unusable_tls_file(config):
    """Why a configured TLS file cannot be used, or None. Checked on the
    worker before the driver opens it: open() on a FIFO (or a device) never
    returns, and the abandoned worker would then hold the single flight for
    good, whatever the config says later."""
    if not config.tls:
        return None
    for key in ("tls_ca_file", "tls_certificate_key_file"):
        path = getattr(config, key)
        if path is None:
            continue
        try:
            mode = os.stat(path).st_mode
        except OSError as e:
            return scrub_message(f"{key}: {e}")
        if not stat.S_ISREG(mode):
            return scrub_message(f"{key} is not a regular file: {path}")
    return None


def _driver_thread_alive():
    """Whether a pymongo thread from an earlier tick is still running after
    _DRIVER_EXIT_GRACE (shared by every such thread) to end."""
    deadline = time.monotonic() + _DRIVER_EXIT_GRACE
    for thread in threading.enumerate():
        if thread.name.startswith(_DRIVER_THREAD_PREFIX):
            thread.join(max(0.0, deadline - time.monotonic()))
            if thread.is_alive():
                return True
    return False


def _collect(config):
    """One collection, on the worker mongodb_metrics bounds."""
    try:
        pymongo = _import_pymongo()
    except ImportError as e:
        return _failure("unknown", scrub_message(f"pymongo is not available: {e}"))
    unusable = _unusable_tls_file(config)
    if unusable is not None:
        return _failure("config_error", unusable)
    recorder = _hello_recorder(pymongo)
    try:
        client = _new_client(pymongo, config.client_options(recorder))
    except Exception as e:
        # MongoClient does no I/O while it is built (connect=False): whatever
        # it raises is the config (an option, a TLS file that does not load).
        return _failure("config_error", _message(e, config))
    mongo = _Mongo(pymongo, client)
    try:
        return _read(mongo, recorder, config)
    finally:
        mongo.close()


def _log_streak(kind, key, message):
    """Log at error the first time `key` shows up for `kind`, then at debug."""
    level = "debug" if _last_logged.get(kind) == key else "error"
    _last_logged[kind] = key
    log(message, level)


def _log_outcome(result):
    if not result["reachable"]:
        _log_streak(
            "envelope",
            (result["error_type"], result["error_message"]),
            f"MongoDB collection failed ({result['error_type']}): "
            f"{log_safe(result['error_message'])}",
        )
        return
    _last_logged.pop("envelope", None)
    errors = (result.get("collection") or {}).get("errors") or {}
    if errors:
        _log_streak(
            "sections",
            tuple(sorted(errors.items())),
            "MongoDB sections not read: "
            + ", ".join(
                f"{name} ({reason})" for name, reason in sorted(errors.items())
            ),
        )
    else:
        _last_logged.pop("sections", None)


@debug("mongodb_metrics")
def mongodb_metrics(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    username=None,
    password=None,
    auth_source=DEFAULT_AUTH_SOURCE,
    auth_mechanism=None,
    tls=False,
    tls_ca_file=None,
    tls_certificate_key_file=None,
    tls_allow_invalid_certificates=False,
    **_kwargs,
):
    """Collect the local mongod's (or mongos') state; see the module docstring.

    Args mirror config["mongodb"] (the fixture's config_contract); **_kwargs
    ignores a key the server adds later instead of raising a TypeError.

    Never returns None, and never takes longer than COLLECT_DEADLINE.
    """
    global _stalled_worker
    try:
        config = _Config(
            host,
            port,
            username,
            password,
            auth_source,
            auth_mechanism,
            tls,
            tls_ca_file,
            tls_certificate_key_file,
            tls_allow_invalid_certificates,
        )
    except Exception as e:  # ConfigError, or a value no rule anticipated
        result = _failure("config_error", scrub_message(e))
        _log_outcome(result)
        return result

    if _stalled_worker is not None:
        if _stalled_worker.is_alive():
            message = _STALLED_MESSAGE.format(COLLECT_DEADLINE)
            log(f"MongoDB collection skipped: {message}", "debug")
            return _failure("timeout", message)
        _stalled_worker = None
    if _driver_thread_alive():
        # Logged like the stalled worker: the tick that left the thread
        # blocked logged its own failure, and a streak key of this skip's own
        # would alternate with that failure's and log at error every tick.
        log(f"MongoDB collection skipped: {_DRIVER_BUSY_MESSAGE}", "debug")
        return _failure("timeout", _DRIVER_BUSY_MESSAGE)
    try:
        result = call_bounded(
            lambda: _collect(config), COLLECT_DEADLINE, name="mongodb"
        )
    except WorkerTimeout as stalled:
        _stalled_worker = stalled.worker
        result = _failure("timeout", _STALLED_MESSAGE.format(COLLECT_DEADLINE))
    except Exception as e:
        # _collect maps every failure it expects, so this is the worker that
        # could not start (out of threads under a pids limit) or a reply no
        # builder anticipated: still an envelope, never None.
        result = _failure("unknown", _message(e, config))
    _log_outcome(result)
    return result
