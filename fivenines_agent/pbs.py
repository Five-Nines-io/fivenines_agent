"""Proxmox Backup Server (PBS) collector.

The Proxmox VE backups block (proxmox.py, #156) sees PBS backups only THROUGH
PVE: it knows a backup exists and when it was taken, not whether it is intact,
how big it is, whether it is encrypted, or whether the job that copies it
offsite still runs. This collector reads the PBS REST API itself (port 8007)
and ships one object under ``data["pbs"]``:

- per datastore: usage + PBS's own estimated-full date, garbage collection
  status (a GC that keeps failing is a datastore that fills up), maintenance
  mode, the namespaces listed and the ones whose groups could not be read;
- per backup group (datastore, namespace, type, id): the newest FINISHED
  backup, its size, encryption mode and protected flag, the state and time of
  its last verification ON THIS DATASTORE, the newest backup that verified OK
  here, and how many of the group's snapshots failed a local verification (a
  sync copies the source's verification into the copy: see
  _local_verification);
- the sync (offsite copy), verify and prune jobs with their last run state.

Everything was measured against a real PBS 4.2 (agent-side capture) -- except
what older releases do (in 4 and 5), taken from the PBS source (the older_pbs
fixture scenario is SYNTHETIC) -- and each of these shapes the code:

1. A token with too little privilege is NOT refused: PBS answers HTTP 200 with
   EMPTY lists (no datastores, no jobs, no tasks). Empty therefore proves
   nothing, so /access/permissions is read first and a token that cannot
   audit any datastore is an error envelope, never a block of empty arrays.
2. An API token's privileges are the INTERSECTION of the user's ACL and the
   token's ACL: both need the grant (see the README setup).
3. /access/permissions maps each path to {privilege: propagate}. A grant on
   /datastore with propagate OFF reaches no datastore (empty 200s again), so
   only a PROPAGATED grant reaching /datastore (a grant on / is reported there,
   inherited) counts as seeing every datastore.
4. A backup in progress is listed by /snapshots with ``files: []`` and no
   ``size`` (no manifest yet), while /groups keeps ``last-backup`` on the last
   FINISHED backup (PBS >= 4.0.17; before, it folded over an UNSORTED
   directory listing, and an unfinished newest snapshot made it an older one
   or the upload itself); an aborted backup is removed by PBS. One
   exception: a group whose ONLY snapshot is
   uploading reports that upload as ``last-backup``, with no manifest in its
   ``files``, and the agent discards it; and a newer FINISHED snapshot in the
   /snapshots listing wins. So ``last_backup`` can never be a half-uploaded
   snapshot -- the false "backed up" the PVE prune preview cannot rule out.
5. /admin/sync lists only PULL jobs unless asked for ``sync-direction=all``
   (PBS >= 3.3 added push); older PBS rejects the parameter, so it is retried
   without it.
6. /admin/datastore/{store}/status answers total/used/avail = 0 to a token
   scoped to a namespace; /status/datastore-usage omits the keys instead, so
   usage is read there (null, never a false 0).
7. A job is listed only to a token that can audit its datastore: a token
   scoped below /datastore sees no job defined outside its scope, so its job
   lists are flagged partial.

Security posture (the token secret is stored in the fivenines account and
delivered to the agent in its configuration, so it must be worthless beyond
reading backup metadata):

- The token must be READ-ONLY and minimal: any effective privilege other than
  Datastore.Audit and Remote.Audit is refused as ``over_privileged`` and
  nothing is collected. That covers the roles that read backup CONTENT
  (DatastoreReader: a full restore of every guest) or change it
  (DatastoreBackup/PowerUser/Admin), and also Sys.Audit, which reads the PBS
  system journal and syslog. A token pasted "with every right, to make it
  work" is caught on the first tick instead of sitting in config.
- The token is never sent over unverified TLS to a non-loopback host: either
  the certificate verifies against the bundled public CA set (``verify_ssl``,
  requests' certifi bundle), or its SHA-256 ``fingerprint`` is pinned -- the
  Proxmox-native way to trust PBS's default self-signed certificate, and the
  only way to trust an internal CA. ``verify_ssl: false`` alone is honoured
  only for a loopback host, and for the NAME localhost the request then goes
  to 127.0.0.1 (the name resolves through NSS, and DNS without an /etc/hosts
  entry); a pinned or verified localhost keeps its name, which the pin or the
  certificate check already guards. When TLS fails, the fingerprint of
  whatever answered is read with a bare handshake (no request, no token) and
  shipped as
  ``presented_fingerprint`` -- UNVERIFIED by construction (a man in the
  middle, or a local listener while the PBS proxy is down, would present its
  own), so it is a hint to compare with the PBS console, never a value to
  trust automatically.
- Proxy and netrc environment variables are ignored (``trust_env = False``)
  and redirects are refused: nothing but the configured host sees the token.
  The secret itself is removed from every error message before it is logged
  or shipped, in case an error body echoes the request headers.
- After HTTP 401 the agent stops contacting the PBS for PBS_CACHE_TTL (until
  the secret changes): a revoked token would otherwise write an
  authentication failure to the PBS auth log every tick.
- A read that TIMED OUT after it was sent may still be running in PBS: its
  namespace walk never ends while a <store>/ns cannot be read, holding one
  proxy thread for good per request. So the reads that can walk namespaces
  (every datastore's namespace listing; the usage status) share ONE hold:
  once any of them times out, none is sent again until the agent is reloaded
  (SIGHUP) or restarted -- one broken storage pins one proxy thread, however
  many datastores it carries -- and every other read that can take long
  (groups, snapshots, a datastore's own status) is retried on a backoff
  (_timeout_backoff).
- Every request's timeouts are clamped to what is left of the tick's
  wall-clock budget, or of the per-datastore reads' half of it (so the
  collector stays NEAR it: one request can still overrun by its own clamped
  timeouts, and a slow-drip body with a Content-Length by far more, see
  TODOS.md); the TICK is then cut by a HARD bound, as is what no request
  timeout covers -- resolving a host name, and connecting to every address it
  resolves to (PBS_HARD_DEADLINE: the collection runs on a worker abandoned
  there, single-flight, so its PBS reads as a timeout until that worker
  returns); every body is streamed under a byte cap (http_body posture).
- Owners, comments/notes, file lists and encryption-key fingerprints are
  never shipped; every string that is shipped is scrubbed and capped.

Envelope (the rabbitmq/tsdb never-None posture: "PBS unreachable" IS a signal):
a failure is ``{"reachable", "error_type", "error_message"}`` (plus
``presented_fingerprint`` on a TLS failure) with NO ``datastores`` key, so the
server ingests and prunes nothing. A success carries ``scope``,
``datastores``/``groups``/jobs plus ``errors[]``, where every sub-read that
failed or was skipped names its scope (and datastore/namespace). What gates
pruning lives outside ``errors[]`` (that list is capped), with one exception
described below: ``scope`` is "partial" when a datastore or namespace absent
from the block may simply be invisible to the token (and "full" cannot see a
deeper ACL entry hiding one -- unless the token still audits a path below it,
which makes the block "partial": see _check_privileges, _hidden_below); a
datastore's
``namespaces`` is null when its set is unknown and ``unread_namespaces`` lists
every listed namespace whose groups are unknown this build; a group whose
snapshot details could not be read has ``in_progress: null``. An unparseable
row -- a name outside PBS's own identifier schema (_SAFE_ID) included -- makes
its scope unknown, never smaller. Each job list is null when it could not be
read; a list that was read but may be partial carries a "partial:" ``errors``
entry under its own scope -- the ONE pruning signal that lives in ``errors[]``,
appended before any per-datastore or per-namespace read: only the datastore-cap
entry, one usage entry per listed datastore, the datastore_config entry and the
job lists' own entries (a bounded prefix, far under MAX_ERRORS) can come before
it, so the cap never drops it. See tests/fixtures/pbs_contract_payload.json.

The block is rebuilt at most once per PBS_CACHE_TTL and re-emitted with
``age_s`` in between (the proxmox backups posture: /snapshots is the costliest
call and backup state moves in hours), but /version is read EVERY tick, so a
PBS that goes down reads unreachable on the next tick, not after the TTL.
"""

import hashlib
import heapq
import ipaddress
import json
import math
import re
import ssl
import time
import warnings
import zlib
from collections import Counter
from urllib.parse import quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

from fivenines_agent.bounded import WorkerTimeout, call_bounded
from fivenines_agent.cache import TTLCache
from fivenines_agent.debug import debug, log
from fivenines_agent.http_body import read_capped_body
from fivenines_agent.scrub import (
    ERROR_PRE_REDACT_MAX_LEN,
    FIELD_MAX_LEN,
    as_bool,
    as_int,
    log_safe,
    scrub_message,
    scrub_str,
)

DEFAULT_PORT = 8007

# Per-request (connect, read) timeouts, each further clamped to what is left of
# its deadline (the tick's budget, or the per-datastore reads' half of it).
# The read timeout is an INACTIVITY timeout; /snapshots on a big datastore
# loads one manifest per snapshot before it answers.
_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 10

# Byte cap and wall-clock deadline for one response body (read_capped_body).
# /snapshots is the big one: ~400 bytes per snapshot, so 16 MB is ~40k
# snapshots in ONE namespace. Past it that namespace's snapshot details are
# unknown (a scoped error), while /groups still gives its last backups.
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_BODY_READ_DEADLINE_S = 10
# /version is read EVERY tick, cached path included, and answers ~100 bytes: a
# broken PBS must not cost a multi-MB parse per tick.
_VERSION_MAX_BYTES = 64 * 1024
# json.loads of a body of tiny rows takes ~25x its size in memory, so every
# endpoint but the group and snapshot listings -- permissions, the datastore
# listing and config, usage, gc, namespaces, job lists, a few hundred KB at
# every cap -- gets this cap instead of _MAX_RESPONSE_BYTES (_body_cap).
_SMALL_MAX_BYTES = 4 * 1024 * 1024

# The block is re-serialized on EVERY tick for a TTL, on the collection loop
# and outside the hard bound. At every cap a real one is ~3 MB of JSON; the
# free-text fields of a broken PBS could reach ~90 MB (500 astral-plane
# characters each, 12 bytes apiece in JSON): past this the build fails. The
# payload is gzipped, where a real block shrinks ~15x (~0.1 MB) but random
# identifiers barely do, so the gzipped size is bounded too.
_MAX_BLOCK_JSON_BYTES = 8 * 1024 * 1024
_MAX_BLOCK_GZIP_BYTES = 1024 * 1024
# Both are counted while the block is encoded, this many characters at a time
# (_encoded), so the build stops at the first limit crossed.
_ENCODE_BATCH_CHARS = 64 * 1024

# An error response body is only read for its message.
_ERROR_BODY_MAX_BYTES = 4096
_ERROR_BODY_DEADLINE_S = 2

# Rebuild the block at most this often; /version is still read every tick.
PBS_CACHE_TTL = 300

# Wall-clock budget for ONE TICK of this collector: /version, and on a rebuild
# every read of the block. It is checked before each read AND clamps each
# request's timeouts, so the collector as a whole stays near this bound on the
# WatchdogSec=90 collection loop (what no request timeout covers -- resolving
# and connecting to a host name -- is bounded by PBS_HARD_DEADLINE below). A
# read skipped past the budget is recorded under its own scope, never a
# silent gap. Cheap, high-value reads (usage,
# jobs, GC) run before the per-namespace ones, and the next build resumes
# where this one was cut off (see _resume_index).
PBS_COLLECT_DEADLINE = 20
_DEADLINE_MESSAGE = "skipped: pbs collection deadline exceeded"

# The HARD bound on one tick, whatever blocks. The budget above clamps every
# request, but not what happens before a request can time out: resolving a
# host name (no requests timeout covers it) and connecting to EVERY address it
# resolves to (urllib3 tries each with the full connect timeout -- 19
# unreachable ones measured at 95s, past WatchdogSec=90). The collection runs
# on a worker abandoned at this bound (bounded.call_bounded), single-flight:
# until it returns, later ticks report a timeout without starting another --
# whatever the config says meanwhile (the io_topology posture: a stall leaks
# one thread, never one per tick), so a corrected host waits for it too.
PBS_HARD_DEADLINE = 30
_STALLED_MESSAGE = (
    "the PBS collection did not finish within {}s (resolving the host name, "
    "connecting to its addresses, or a PBS that stopped answering); no new "
    "one starts until it returns"
)
_stalled_worker = None
# ...and its progress: a tick skipped behind it reports the reachability of
# the tick that abandoned it (reachable once its /version answered).
_stalled_progress: dict = {}

# Hard caps. A trim is never silent, and never read as a deletion: past the
# datastore cap the block's scope is "partial"; past the namespace cap that
# datastore's namespaces (and unread_namespaces) are null; a namespace whose
# groups the group cap trimmed or never reached is in unread_namespaces; a
# capped job list is flagged "partial:" under its own scope.
MAX_DATASTORES = 100
MAX_NAMESPACES = 1000
MAX_GROUPS = 5000
MAX_JOBS = 200
MAX_ERRORS = 500
# A maintenance message is operator free text.
MAINTENANCE_MESSAGE_MAX_LEN = 200
# Only this much of the listing's maintenance property string is parsed.
_MAINTENANCE_SCAN = 4096
# ...and of a datastore config's backend property (a real one is under 200).
_BACKEND_SCAN = 1024
# One part of a PBS property string: an optional key, then a quoted value
# (closed by a comma or the end) or a plain one.
_PROPERTY_PART_RE = re.compile(
    r'(?:(?!")([^,=]*)=)?(?:"((?:[^"\\]|\\.)*)"(?=,|\Z)|([^,]*))', re.DOTALL
)
_PROPERTY_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)

# The ONLY privileges a monitoring token may hold (see the module docstring).
_ALLOWED_PRIVILEGES = frozenset({"Datastore.Audit", "Remote.Audit"})
# How many unexpected privileges an over_privileged message names, at most: a
# bound on the work, not a promise to name them all (the wire message is capped
# at 500 characters; the remediation comes first).
_MAX_PRIVILEGES_NAMED = 32
# ...each cut to this many characters (after the secret is redacted).
_PRIVILEGE_NAME_MAX_LEN = 64

# PBS's own identifier schemas (pbs-api-types; the same regexes are in the PBS
# 4.2 binary): a group is (host|vm|ct)/<safe id>, a datastore and every
# namespace level a safe id. A real PBS sends nothing else. A hostile one could
# send 500 astral-plane characters, copied into every group row and
# re-serialized every tick (12 bytes each in JSON): such a row is unparseable.
_SAFE_ID = r"[A-Za-z0-9_][A-Za-z0-9._-]{0,254}"
_SAFE_ID_RE = re.compile(_SAFE_ID)
_NAMESPACE_RE = re.compile(rf"(?:{_SAFE_ID}(?:/{_SAFE_ID}){{0,7}})?")
_BACKUP_TYPE_RE = re.compile(r"vm|ct|host")

_TOKEN_ID_RE = re.compile(
    r"[^\s:/]+@[A-Za-z][A-Za-z0-9._-]*![A-Za-z0-9_][A-Za-z0-9._-]*"
)
_TOKEN_SECRET_RE = re.compile(r"[\x21-\x7e]{1,256}")
_HOSTNAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
_FINGERPRINT_RE = re.compile(r"[0-9A-Fa-f]{64}")
# A PBS task id carries its start time as hex. This length cap only bounds the
# int() parse of a hostile id; the value must still fit the i64 PBS keeps it
# in (_as_int64).
_UPID_TIME_RE = re.compile(r"[0-9A-Fa-f]{1,16}")
# A task id escapes ':' (and other bytes) in its worker id as \xNN.
_UPID_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
# Only this much of a worker id is decoded to find its datastore: a PBS
# datastore name is at most 32 characters, 4x that escaped (128); the rest is
# deliberate headroom, still small enough to bound a hostile id.
_WORKER_ID_SCAN = 1024
# A backup time is a dict key: past 2**61 - 1 CPython's int hash stops being
# the identity, so a hostile PBS could send colliding times (a quadratic
# summary, minutes of CPU). Far beyond any real epoch.
_MAX_BACKUP_TIME = 2**53
# A PBS has ONE node name; a hostile listing must not fill this set.
_MAX_LOCAL_NODES = 16

# The manifest every finished snapshot carries; the crypt mode of a snapshot is
# read from its archives, not from the manifest (which is only ever signed).
_MANIFEST = "index.json.blob"

_cache = TTLCache()

# Where the next build starts its per-namespace reads (an index into the
# sorted (store, ns) list) and its per-datastore reads (an index into the
# sorted datastores): see _resume_index. Positional: while those sets
# are unchanged. A datastore or namespace added or removed in between shifts
# the start for one build; the next cut re-aims it.
_rotation = 0
_store_rotation = 0

# (cache_key, secret digest, retry-after monotonic time, message) after HTTP
# 401, or None. One configured PBS per agent, so one slot.
_auth_backoff = None

# (error_type, message) of the last failure envelope logged at error level, so
# a steady failure logs once, not every tick (the qemu refused-URI posture).
_last_logged_failure = None

# urllib3 registers InsecureRequestWarning as "always", so an unverified request
# prints one warning PER REQUEST (a dozen journal lines per build). This filter
# is deliberately PROCESS-WIDE and loopback-only: this collector only ever
# allows unverified TLS to a loopback host (see _Target), where it is a
# documented setup, and the same holds for any other collector that talks to
# its own host unverified. An unverified request to any other host still warns.
_LOOPBACK_WARNING = r"Unverified HTTPS request is being made to host '(localhost|127(\.\d{1,3}){3}|::1)'"


def _silence_loopback_insecure_warning():
    warnings.filterwarnings(
        "ignore", message=_LOOPBACK_WARNING, category=InsecureRequestWarning
    )


_silence_loopback_insecure_warning()


class _PbsError(Exception):
    """A classified failure: the wire error_type, a message, whether PBS
    answered at all, and the HTTP status when it did. `skipped` names a read
    the agent did not (fully) make -- "deadline": past the budget, never sent
    or answered too late; "backoff": held back by _timeout_backoff -- which
    is no evidence about the PBS either way. `pending`: sent, and not answered
    in time (a read timeout that waited its whole read timeout -- never a
    connect one, nor a stalled TLS handshake urllib3 reports as a read one),
    so PBS may still be running it."""

    def __init__(
        self, error_type, message, reachable, status=None, skipped=None, pending=False
    ):
        super().__init__(message)
        self.error_type = error_type
        self.message = message
        self.reachable = reachable
        self.status = status
        self.skipped = skipped
        self.pending = pending


def _config_error(message):
    return _PbsError("config_error", message, reachable=False)


class _Target:
    """A validated connection target. Built from untrusted config, so every
    field is checked before a single byte goes on the wire."""

    def __init__(self, host, port, token_id, token_secret, verify_ssl, fingerprint):
        # An explicit null or blank host or port from the server means
        # "unset", like an absent key: the documented default applies.
        self.host, url_host, loopback = _url_host(
            "localhost" if host in (None, "") else host
        )
        self.port = _valid_port(DEFAULT_PORT if port in (None, "") else port)
        self.authorization = _authorization(token_id, token_secret)
        self._secret = token_secret
        self.secret_digest = hashlib.sha256(token_secret.encode()).hexdigest()
        self.fingerprint = _normalize_fingerprint(fingerprint)
        if self.fingerprint is not None:
            self.verify = False
        elif _config_bool(verify_ssl):
            self.verify = True
        elif loopback:
            self.verify = False
            if self.host.lower() == "localhost":
                # The NAME resolves through NSS and, without an /etc/hosts
                # entry, DNS: unverified TLS goes to the loopback literal only.
                self.host = url_host = "127.0.0.1"
        else:
            raise _config_error(
                "refusing to send the API token to a non-loopback host without "
                "TLS verification: enable verify_ssl or set the certificate "
                "fingerprint"
            )
        self.base = f"https://{url_host}:{self.port}/api2/json"
        # The secret is deliberately not part of the key (the proxmox
        # _backups_cache_key posture): it must never sit in a cache key, and a
        # rotated secret on the same token serves the same PBS's block.
        self.cache_key = (self.base, str(token_id), self.verify, self.fingerprint)

    def redact(self, text):
        """`text` with the token secret removed. An error body can echo the
        request headers (a proxy or WAF debug page), and the generic redaction
        rules do not recognise the PBSAPIToken form; the agent knows the exact
        secret, so it does not have to guess. NUL is dropped first (a secret
        is printable ASCII, and the wire scrub deletes NUL AFTER this, which
        would rejoin a secret a hostile answer split with one)."""
        return str(text).replace("\x00", "").replace(self._secret, "[REDACTED]")


def _url_host(host):
    """(bare host, host as it goes in the URL, whether it is loopback), or a
    config_error.

    The host is server-pushed and lands in a URL: only a hostname or an IP
    literal is accepted, so it can never smuggle a path, a userinfo or a port.
    """
    if not isinstance(host, str):
        raise _config_error("host must be a string")
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        if getattr(address, "scope_id", None):
            raise _config_error("scoped IPv6 addresses are not supported")
        bare = address.compressed
        url_host = f"[{bare}]" if address.version == 6 else bare
        return bare, url_host, address.is_loopback
    if not _HOSTNAME_RE.fullmatch(candidate):
        raise _config_error("host is not a valid hostname or IP address")
    return candidate, candidate, candidate.lower() == "localhost"


def _valid_port(port):
    value = as_int(port)
    if value is None or not 0 < value < 65536:
        raise _config_error("port must be an integer between 1 and 65535")
    return value


def _authorization(token_id, token_secret):
    """The PBSAPIToken header value. Only an API TOKEN is accepted (a user
    password would be a ticket login, and a far wider credential), and both
    halves are checked -- printable ASCII only -- so neither can inject into
    the header or carry control characters into a log line."""
    if not token_id or not token_secret:
        raise _config_error("no API token configured")
    if not isinstance(token_id, str) or not isinstance(token_secret, str):
        raise _config_error("token_id and token_secret must be strings")
    if (
        not token_id.isascii()
        or not token_id.isprintable()
        or not _TOKEN_ID_RE.fullmatch(token_id)
    ):
        raise _config_error("token_id must look like user@realm!tokenname")
    if not _TOKEN_SECRET_RE.fullmatch(token_secret):
        raise _config_error("token_secret contains invalid characters")
    return f"PBSAPIToken={token_id}:{token_secret}"


def _normalize_fingerprint(fingerprint):
    """None, or the SHA-256 fingerprint in PBS's own lowercase colon form."""
    if fingerprint is None or fingerprint == "":
        return None
    if not isinstance(fingerprint, str):
        raise _config_error("fingerprint must be a string")
    digits = fingerprint.strip().replace(":", "")
    if not _FINGERPRINT_RE.fullmatch(digits):
        raise _config_error("fingerprint must be a SHA-256 certificate fingerprint")
    return bytes.fromhex(digits).hex(":")


def _config_bool(value):
    """verify_ssl is a security switch: only an explicit false turns it off.
    None, garbage or a missing key keep verification ON."""
    if value is False or (
        isinstance(value, int) and not isinstance(value, bool) and value == 0
    ):
        return False
    if isinstance(value, str) and value.strip().lower() in ("0", "false", "no", "off"):
        return False
    return True


class _PinnedAdapter(HTTPAdapter):
    """Accept exactly one certificate: urllib3 checks the peer's SHA-256
    against the pinned fingerprint on every new connection, whatever CA (or
    none) signed it."""

    def __init__(self, fingerprint):
        self._fingerprint = fingerprint
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self._fingerprint
        super().init_poolmanager(*args, **kwargs)


def _new_session(target):
    """A keep-alive session for one tick. A test seam."""
    session = requests.Session()
    session.trust_env = False
    session.headers["Authorization"] = target.authorization
    session.verify = target.verify
    if target.fingerprint is not None:
        session.mount("https://", _PinnedAdapter(target.fingerprint))
    return session


def _certificate_fingerprint(der):
    return hashlib.sha256(der).digest().hex(":")


def _peer_fingerprint(response):
    """SHA-256 of the certificate the server presented on this response's
    connection, in PBS's colon form -- the key PVE pins in storage.cfg, so the
    server can line this PBS up with the PVE storages that point at it. Read
    before the body (the connection returns to the pool once it is consumed);
    None whenever it cannot be read, e.g. when the response closes its
    connection (``Connection: close``, as a reverse proxy may send)."""
    try:
        der = response.raw.connection.sock.getpeercert(binary_form=True)
    except Exception:
        return None
    if not der:
        return None
    return _certificate_fingerprint(der)


def _presented_fingerprint(target, deadline):
    """The fingerprint of the certificate `target` presents, from a bare TLS
    handshake (no HTTP request, so no token), for a TLS failure envelope: after
    a certificate renewal the operator sees exactly what to pin. None when the
    handshake itself fails."""
    timeout = max(min(_CONNECT_TIMEOUT, deadline - time.monotonic()), 0.1)
    try:
        pem = ssl.get_server_certificate((target.host, target.port), timeout=timeout)
        return _certificate_fingerprint(ssl.PEM_cert_to_DER_cert(pem))
    except Exception:
        return None


def _error_body(response, timeout_s=_ERROR_BODY_DEADLINE_S):
    """The (bounded) text of an error response, for the message only."""
    try:
        raw = read_capped_body(response, _ERROR_BODY_MAX_BYTES, timeout_s)
    except Exception:
        return ""
    return raw.decode("utf-8", errors="replace").strip()


# urllib3 exception texts embed the connection object's address and the
# (clamped, so fractional) timeout, which change on every tick: stripped, so a
# steady failure is one message -- deduplicated in the log, stable on the wire.
_VOLATILE = (
    (re.compile(r" at 0x[0-9A-Fa-f]+"), ""),
    (re.compile(r"\((connect|read) timeout=[^)]*\)"), r"(\1 timeout)"),
    # read_capped_body names its (clamped, so fractional) body deadline.
    (re.compile(r"exceeded [0-9.e+-]+s deadline"), "exceeded its deadline"),
)


def _transport_message(target, exc):
    """A transport or body-read failure as one stable, bounded message. The
    secret is removed LAST: the substitutions delete characters, which would
    rejoin a secret a hostile answer split around one of their patterns. The
    cap comes after it (a cut cannot expose part of a secret already gone):
    urllib3 quotes whole status lines and headers, 64 KB each, and a message
    is kept in the log-dedup set until the next build."""
    text = str(exc)
    for pattern, replacement in _VOLATILE:
        text = pattern.sub(replacement, text)
    return target.redact(text)[:ERROR_PRE_REDACT_MAX_LEN]


def _remaining(deadline):
    """Seconds left before `deadline` (the tick's budget, or the per-datastore
    phase's half of it); a timeout _PbsError when none."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _PbsError("timeout", _DEADLINE_MESSAGE, True, skipped="deadline")
    return remaining


def _body_cap(path):
    """The byte cap for a body of `path`: only the group and snapshot
    listings grow with the backups, and get _MAX_RESPONSE_BYTES; /version,
    read every tick, gets _VERSION_MAX_BYTES."""
    if path == "/version":
        return _VERSION_MAX_BYTES
    if path.endswith(("/groups", "/snapshots")):
        return _MAX_RESPONSE_BYTES
    return _SMALL_MAX_BYTES


def _get(
    session,
    target,
    path,
    params=None,
    on_response=None,
    deadline=None,
    min_wait=0,
):
    """GET one API path -> the envelope's ``data``, or a classified _PbsError
    whose message never carries the token secret. With a `deadline`, the
    request's timeouts are clamped to what is left of it, and so is the body
    read, measured again once the headers are in -- except that the read
    timeout never drops below `min_wait`: a request PBS may keep running after
    the agent gave up (_timeout_backoff) must have had a real wait before a
    timeout means anything (the tick may then run over its budget by that
    much, still inside PBS_HARD_DEADLINE). The body cap is _body_cap(path)."""
    max_bytes = _body_cap(path)
    connect, read = _CONNECT_TIMEOUT, _READ_TIMEOUT
    if deadline is not None:
        remaining = _remaining(deadline)
        connect, read = min(connect, remaining), max(min(read, remaining), min_wait)
    if min_wait:
        # A TLS handshake that stalls takes the TCP connect plus the connect
        # timeout -- under twice the connect timeout, for one address -- and
        # urllib3 reports it as a READ timeout: half the read timeout at most
        # keeps it short of `pending` below, however little budget is left. (A
        # host resolving to several dead addresses before the live one can
        # still read as pending: a hold, the safe side for the PBS.)
        connect = min(connect, read / 2)
    sent = time.monotonic()
    try:
        response = session.get(
            target.base + path,
            params=params,
            timeout=(connect, read),
            stream=True,
            allow_redirects=False,
        )
    except requests.exceptions.SSLError as e:
        raise _PbsError("tls_error", _transport_message(target, e), reachable=False)
    except requests.exceptions.ReadTimeout as e:
        # Sent, and not answered in time: PBS may still be running it -- but
        # urllib3 also reports a TLS handshake that stalled, within the
        # connect timeout, as a read timeout, and that request never reached
        # PBS. Only one that waited the whole read timeout was sent.
        message = _transport_message(target, e)
        pending = time.monotonic() - sent >= read
        raise _PbsError("timeout", message, reachable=False, pending=pending)
    except requests.exceptions.Timeout as e:  # connecting: never reached PBS
        raise _PbsError("timeout", _transport_message(target, e), reachable=False)
    except requests.exceptions.ConnectionError as e:
        raise _PbsError(
            "connection_refused", _transport_message(target, e), reachable=False
        )
    except requests.exceptions.RequestException as e:
        raise _PbsError("http_error", _transport_message(target, e), reachable=False)

    status = response.status_code
    body = _BODY_READ_DEADLINE_S
    error_body = _ERROR_BODY_DEADLINE_S
    if deadline is not None:
        # Measured again once the headers are in. An ANSWERED error keeps its
        # status even past the budget -- what an HTTP status decides (a
        # namespace unread on a /snapshots error, the 401 backoff) must not
        # depend on timing -- and only its body is skipped (so a 400 past the
        # budget reads as a handler error, not as an old PBS's sync rejection).
        remaining = deadline - time.monotonic()
        if remaining <= 0 and status == 200:
            response.close()
            raise _PbsError("timeout", _DEADLINE_MESSAGE, True, skipped="deadline")
        body, error_body = min(body, remaining), min(error_body, remaining)
    if status != 200:
        if error_body > 0:
            detail = _error_body(response, error_body)
        else:
            response.close()
            detail = ""
        message = target.redact(f"HTTP {status}: {detail}")
        error_type = "auth_failed" if status == 401 else "http_error"
        raise _PbsError(error_type, message, reachable=True, status=status)
    if on_response is not None:
        on_response(response)
    try:
        raw = read_capped_body(response, max_bytes, body)
    except Exception as e:
        raise _PbsError(
            "http_error",
            f"body read failed: {_transport_message(target, e)}",
            reachable=True,
        )
    try:
        # Decoded as json.loads would, then the bytes dropped BEFORE parsing:
        # at the byte cap, bytes + text + objects would otherwise all be live.
        text = raw.decode(json.detect_encoding(raw), "surrogatepass")
        del raw
        document = json.loads(text)
    except (ValueError, RecursionError):
        # RecursionError: a pathologically nested body (well under the byte
        # cap) must be one failed read, not an exception that sinks the tick.
        raise _PbsError("http_error", "invalid JSON response", reachable=True)
    if not isinstance(document, dict) or "data" not in document:
        raise _PbsError("http_error", "unexpected response envelope", reachable=True)
    return document["data"]


def _failure(error_type, message, reachable, presented_fingerprint=None):
    envelope = {
        "reachable": reachable,
        "error_type": error_type,
        "error_message": scrub_message(message),
    }
    if error_type == "tls_error":
        envelope["presented_fingerprint"] = presented_fingerprint
    return envelope


def _auth_backoff_message(target):
    """The auth_failed message while a 401 backoff holds for this target and
    secret, else None."""
    if _auth_backoff is None:
        return None
    key, digest, retry_at, message = _auth_backoff
    if key != target.cache_key or digest != target.secret_digest:
        return None
    if time.monotonic() >= retry_at:
        return None
    return message


def _log_failure(error_type, message):
    """Error level when the failure changes, debug while it repeats."""
    global _last_logged_failure
    level = "debug" if _last_logged_failure == (error_type, message) else "error"
    _last_logged_failure = (error_type, message)
    log(f"PBS collection failed ({error_type}): {log_safe(message)}", level)


@debug("pbs_metrics")
def pbs_metrics(
    host="localhost",
    port=DEFAULT_PORT,
    token_id=None,
    token_secret=None,
    verify_ssl=True,
    fingerprint=None,
    **_kwargs,
):
    """Collect one Proxmox Backup Server's state; see the module docstring.

    Args:
        host / port: the PBS API (default localhost:8007, the agent installed
            on the PBS itself).
        token_id / token_secret: a READ-ONLY API token (user@realm!name).
        verify_ssl: verify the certificate against the bundled public CA set.
        fingerprint: SHA-256 certificate fingerprint to pin instead.
        **_kwargs: unknown config keys are ignored (forward-compatible: a key
            the server adds later must not TypeError an older agent).

    Never returns None: every failure is the error envelope. Never takes
    longer than PBS_HARD_DEADLINE either (see there).
    """
    global _stalled_worker, _stalled_progress
    # A stall that repeats logs at error once, then debug: keyed on the
    # previous tick's stall, not on _last_logged_failure, which the abandoned
    # worker's own late outcome also writes (the two would alternate).
    was_stalled = _stalled_worker is not None
    if _stalled_worker is not None:
        if _stalled_worker.is_alive():
            message = _STALLED_MESSAGE.format(PBS_HARD_DEADLINE)
            log(f"PBS collection skipped: {message}", "debug")
            answered = bool(_stalled_progress.get("answered"))
            return _failure("timeout", message, reachable=answered)
        _stalled_worker, _stalled_progress = None, {}
    # Set by the worker once /version answered: a stall after that is a slow
    # PBS, not an unreachable one (the envelope's own rule, below).
    progress = {}
    try:
        result = call_bounded(
            lambda: _collect(
                host, port, token_id, token_secret, verify_ssl, fingerprint, progress
            ),
            PBS_HARD_DEADLINE,
            name="pbs",
        )
    except WorkerTimeout as stalled:
        _stalled_worker, _stalled_progress = stalled.worker, progress
        message = _STALLED_MESSAGE.format(PBS_HARD_DEADLINE)
        level = "debug" if was_stalled else "error"
        log(f"PBS collection failed (timeout): {message}", level)
        return _failure("timeout", message, reachable=bool(progress.get("answered")))
    except Exception as e:
        # _collect maps every failure of its own, so this is the worker that
        # could not start (out of threads under a pids limit): still an
        # envelope, never null.
        message = f"the collection could not run: {e}"
        _log_failure("http_error", message)
        return _failure("http_error", message, reachable=False)
    return result


def _collect(host, port, token_id, token_secret, verify_ssl, fingerprint, progress):
    """One collection, on the worker pbs_metrics bounds (which reads
    progress["answered"] if the worker outlives it)."""
    global _auth_backoff, _last_logged_failure
    session = None
    target = None
    answered = False
    deadline = time.monotonic() + PBS_COLLECT_DEADLINE
    try:
        target = _Target(host, port, token_id, token_secret, verify_ssl, fingerprint)
        backoff = _auth_backoff_message(target)
        if backoff is not None:
            # No request at all: the PBS would log one more auth failure.
            return _failure("auth_failed", backoff, reachable=True)
        session = _new_session(target)
        seen = {}
        version = _get(
            session,
            target,
            "/version",
            on_response=lambda response: seen.update(
                fingerprint=_peer_fingerprint(response)
            ),
            deadline=deadline,
        )
        answered = progress["answered"] = True
        computed_at, block = _cache.get_or_compute(
            target.cache_key,
            PBS_CACHE_TTL,
            lambda: _build_block(session, target, deadline),
        )
        if "too_large" in block:  # cached too: one such build per TTL
            raise _PbsError("http_error", block["too_large"], reachable=True)
        _auth_backoff = None
        _last_logged_failure = None
        if not isinstance(version, dict):
            version = {}
        return {
            "reachable": True,
            "version": scrub_str(version.get("version")),
            "release": scrub_str(version.get("release")),
            "fingerprint": seen.get("fingerprint") or target.fingerprint,
            "age_s": max(int(time.monotonic() - computed_at), 0),
            **block,
        }
    except _PbsError as e:
        # Also names PBS data (over_privileged lists the privileges it found).
        message = e.message if target is None else target.redact(e.message)
        if e.error_type == "auth_failed":
            _auth_backoff = (
                target.cache_key,
                target.secret_digest,
                time.monotonic() + PBS_CACHE_TTL,
                message,
            )
        _log_failure(e.error_type, message)
        presented = None
        if e.error_type == "tls_error":
            presented = _presented_fingerprint(target, deadline)
        # /version answered this tick: a later failure (a rebuild's read
        # timing out) is a slow or broken PBS, not an unreachable one.
        reachable = e.reachable or answered
        return _failure(e.error_type, message, reachable, presented)
    except Exception as e:
        message = target.redact(e) if target is not None else str(e)
        _log_failure("http_error", message)
        return _failure("http_error", message, reachable=answered)
    finally:
        if session is not None:
            session.close()


# --- the block -------------------------------------------------------------


class _Errors(list):
    """A build's errors[]. Past MAX_ERRORS an entry is only COUNTED, never
    built: building one means redacting its message, and a hostile body of
    thousands of rows (a manifest error per group) would otherwise spend
    seconds of CPU on the watchdog-bounded loop on entries the cap then
    drops. `redact` removes the token secret from every message, including
    ones that quote PBS data (a usage row's error, a group id): a PBS holding
    the token could echo it there."""

    dropped = 0

    def __init__(self, redact):
        super().__init__()
        self.redact = redact


def _error(errors, scope, message, store=None, ns=None):
    """Append one structured failure. Diagnostic detail for the server; what
    gates pruning is carried outside this (capped) list -- the block's scope,
    each datastore's namespaces / unread_namespaces, the groups' in_progress
    -- except a job list's "partial:" flag, appended early (see below).
    Entries are appended in read order and the cap drops the TAIL, so the
    block-level ones (datastores, jobs) always survive it."""
    if len(errors) >= MAX_ERRORS:
        errors.dropped += 1
        return
    message = errors.redact(message)
    errors.append(
        {
            "scope": scope,
            "store": scrub_str(store),
            "ns": scrub_str(ns),
            "message": scrub_message(message),
        }
    )


def _deadline_hit(deadline, errors, scope, store=None, ns=None):
    """True (and one `errors` entry) once `deadline` (the tick's budget, or the
    per-datastore phase's half of it) has passed."""
    if time.monotonic() < deadline:
        return False
    _error(errors, scope, _DEADLINE_MESSAGE, store=store, ns=ns)
    return True


def _cap(rows, room, errors, noun, limit=None, store=None):
    """`rows` trimmed to `room`, with a 'cap' error naming what was dropped.
    `limit` is the cap to report when `room` is what is left of a shared one."""
    if len(rows) <= room:
        return rows
    _error(
        errors,
        "cap",
        f"{noun} capped at {room if limit is None else limit}: "
        f"{len(rows) - room} dropped",
        store=store,
    )
    return rows[:room]


# Sub-read failures of the last COMPLETED build and of the one in progress: a
# read that keeps failing (a scoped token's 403 on gc, an offline datastore)
# logs at error when it starts failing, then at debug on every rebuild after
# that. A build that raises publishes nothing, so one transient failure of the
# token check does not re-log every steady one; a build that skips the read
# past its budget does forget it.
_read_failures: dict = {"previous": set(), "current": set()}
# At most this many of them log at error level per build, the rest at debug
# plus one count at the end (errors[] has its own cap): a PBS failing every
# namespace read with a varying body would otherwise write a thousand journal
# and telemetry lines per rebuild.
_MAX_READ_FAILURE_LINES = 20
# This build's error-level lines, and the failures quieted past the cap.
_read_failure_lines = {"error": 0, "quieted": 0}

# The node names this PBS's OWN tasks carry (its GC, its jobs), learned during
# a build: an OK verification is this PBS's only if its task ran on one of
# them -- when any was learned (else only the datastore is checked:
# _local_verification).
_local_nodes: set = set()


def _log_read_failure(scope, message, store=None, ns=None):
    key = (scope, store, ns, message)
    level = "debug" if key in _read_failures["previous"] else "error"
    if level == "error":
        if _read_failure_lines["error"] >= _MAX_READ_FAILURE_LINES:
            level = "debug"
            _read_failure_lines["quieted"] += 1
        else:
            _read_failure_lines["error"] += 1
    _read_failures["current"].add(key)
    where = ""
    if store is not None:
        where = f" on {log_safe(store)}" + (f"/{log_safe(ns)}" if ns else "")
    log(f"PBS {scope} read failed{where}: {log_safe(message)}", level)


_UNSET = object()

# After a read TIMED OUT, PBS may still be running it. A slow read ends, so it
# waits: one rebuild at first, twice as long after each further timeout, at
# most _TIMEOUT_BACKOFF_MAX; a success clears it. Meanwhile it is skipped like
# a failed read (its scope unknown, an errors[] entry; its log line stays at
# debug on a later identical failure).
#
# But PBS's namespace iterator never ends while reading a <store>/ns keeps
# failing (an NFS datastore gone stale, EACCES, EIO): list_namespaces spins on
# the proxy's own runtime thread for good, and so does /status/datastore-usage
# (reproduced on PBS 4.2, one pinned proxy thread per request). Every re-send
# of a walk that never ends pins ONE MORE proxy thread, for good, and the
# proxy has one per core: two kill a 2-vCPU PBS. So the reads that can walk
# namespaces -- every datastore's namespace listing, and the usage status,
# which walks every datastore the token cannot audit (all of them for a scoped
# token; for a full-scope one, any a deeper ACL entry hides, which the agent
# cannot always see) -- share ONE hold (_WALK_HOLD): once any of them times
# out, NONE is sent again until the agent is reloaded (SIGHUP:
# reset_timeout_holds) or restarted, the operator's signal that the storage is
# repaired. One dead NAS under several datastores, or a scoped token whose
# usage status and namespace listing both walk the same broken datastore,
# then pins one proxy thread, not one per datastore or per read. The other
# reads that can take long all END (PBS source: /groups reads one level,
# never walking namespaces; a datastore's status is one statfs), so holding
# them for good would only blind a PBS that is slow: they retry on the
# backoff above.
# {(path, params) or _WALK_HOLD: (retry-after monotonic time -- inf for the
#  hold --, timeouts, the _read_failures key of its failure)}. Keyed on the
# request alone, not on the PBS's address, token or TLS policy: the stuck walk
# pins that PBS's proxy whoever asks and however its host is spelled
# (localhost, 127.0.0.2, ::1, its FQDN), so no configuration change may
# re-send it -- only a reload or a restart. After a move to another PBS, the
# hold waits for that reload too.
_timeout_backoff: dict = {}
_TIMEOUT_BACKOFF_MAX = 6 * 3600
# The one key every namespace walk is held under.
_WALK_HOLD = ("namespace walks", ())
# One build backs off at most this many reads -- a status per datastore, a
# /groups and a /snapshots per namespace -- plus the walk hold. Past it the
# oldest retry is dropped, never the hold: that would re-send a walk that
# never ends.
_TIMEOUT_BACKOFF_ENTRIES = MAX_DATASTORES + 2 * MAX_NAMESPACES + 1
# The read timeout a held or backed-off read always gets (see _get): its
# timing out then means PBS did not answer, not that the budget ran out.
_TIMEOUT_BACKOFF_MIN_WAIT = _CONNECT_TIMEOUT
_TIMEOUT_BACKOFF_MESSAGE = (
    "skipped: this read timed out before and PBS may still be running it; "
    "retried later"
)
_TIMEOUT_HOLD_MESSAGE = (
    "skipped: a namespace walk timed out and PBS may still be running it (a "
    "walk stuck on an unreadable datastore holds a proxy thread for good), so "
    "no walk (namespace listing, usage status) is sent again until the agent "
    "is reloaded (SIGHUP) -- if a datastore is broken, repair it and restart "
    "proxmox-backup-proxy first"
)


def _timeout_backoff_key(path, params):
    return (path, tuple(sorted((params or {}).items())))


def _arm_timeout_backoff(key, failure, hold):
    timeouts = _timeout_backoff.get(key, (0, 0, None))[1] + 1
    if (
        key not in _timeout_backoff
        and len(_timeout_backoff) >= _TIMEOUT_BACKOFF_ENTRIES
    ):
        # The oldest retry; never the one hold (the cap leaves room for it).
        del _timeout_backoff[
            next(k for k, v in _timeout_backoff.items() if v[0] != math.inf)
        ]
    if hold:
        _timeout_backoff[key] = (math.inf, timeouts, failure)
        # Only the namespace listings (their datastore) and the usage status
        # are held: none has a namespace.
        scope, store, _, _ = failure
        where = "" if store is None else f" on {log_safe(store)}"
        log(f"PBS {scope} read{where} held: {_TIMEOUT_HOLD_MESSAGE}", "error")
        return
    delay = min(PBS_CACHE_TTL * 2**timeouts, _TIMEOUT_BACKOFF_MAX)
    _timeout_backoff[key] = (time.monotonic() + delay, timeouts, failure)


def _forget_stale_backoffs():
    """Retries expired this long ago (never sent again: the namespace or
    datastore is gone) are dropped. The one hold never expires (a SIGHUP or
    a restart clears it)."""
    now = time.monotonic()
    for key in [
        key
        for key, (retry_at, _, _) in _timeout_backoff.items()
        if now - retry_at > _TIMEOUT_BACKOFF_MAX
    ]:
        del _timeout_backoff[key]


def reset_timeout_holds():
    """SIGHUP: the operator repaired a datastore (and restarted
    proxmox-backup-proxy), so every held or backed-off read is sent again --
    on the next tick: the cached block, which still reports them held, is
    dropped too."""
    global _cache
    _timeout_backoff.clear()
    _cache = TTLCache()


def _sub_read(
    session,
    target,
    errors,
    deadline,
    scope,
    path,
    params=None,
    store=None,
    ns=None,
    kind=list,
    missing=_UNSET,
    on_error=None,
    backoff=False,
):
    """One read whose failure is an `errors` entry, not the whole tick: the
    data when it is a `kind` (list or dict), else None -- skipped past the
    budget or behind its timeout `backoff` ("retry" or "hold", see
    _timeout_backoff), failed, or not the documented shape. A 404 returns
    `missing` when one is given (an endpoint an older PBS does not have);
    `on_error` receives the failure, a backoff skip included, for a caller
    that must know what happened."""
    if backoff == "hold":
        key = _WALK_HOLD  # one hold for every walk (see _timeout_backoff)
    else:
        key = _timeout_backoff_key(path, params) if backoff else None
    waiting = _timeout_backoff.get(key)
    if waiting is not None and time.monotonic() < waiting[0]:
        _read_failures["current"].add(waiting[2])  # stays quiet on retry
        message = (
            _TIMEOUT_HOLD_MESSAGE
            if waiting[0] == math.inf
            else _TIMEOUT_BACKOFF_MESSAGE
        )
        if on_error is not None:
            on_error(_PbsError("timeout", message, True, skipped="backoff"))
        _error(errors, scope, message, store=store, ns=ns)
        return None
    if _deadline_hit(deadline, errors, scope, store=store, ns=ns):
        return None
    min_wait = _TIMEOUT_BACKOFF_MIN_WAIT if backoff else 0
    try:
        data = _get(session, target, path, params, deadline=deadline, min_wait=min_wait)
    except _PbsError as e:
        if key is not None and e.pending:
            failure = (scope, store, ns, e.message)
            _arm_timeout_backoff(key, failure, hold=backoff == "hold")
        if missing is not _UNSET and e.status == 404:
            return missing
        if on_error is not None:
            on_error(e)
        if e.skipped is None:  # a skip, like _deadline_hit's, is not logged
            _log_read_failure(scope, e.message, store=store, ns=ns)
        _error(errors, scope, e.message, store=store, ns=ns)
        return None
    _timeout_backoff.pop(key, None)
    if not isinstance(data, kind):
        shape = "a list" if kind is list else "an object"
        _error(
            errors,
            scope,
            f"unexpected response shape (not {shape})",
            store=store,
            ns=ns,
        )
        return None
    return data


def _check_privileges(permissions, redact=str):
    """(sync jobs visible, every datastore visible); raises when the token
    must not be used.

    The map is the token's EFFECTIVE privileges ({path: {privilege:
    propagate}}), already intersected with its user's. Both answers exist
    because PBS hides what a token may not audit instead of refusing it:
    - sync jobs are listed only with Remote.Audit reaching every remote;
    - datastores, and the jobs defined on them, are listed only to a token
      that can audit them, so only a PROPAGATED Datastore.Audit reaching
      /datastore (granted there or on /, which PBS reports at /datastore as
      inherited) makes an empty listing mean "none". PBS leaves paths where a
      token has NO privilege out of this map entirely, and an ACL entry below
      /datastore or /remote on the token or its user makes one when its role
      lacks the audited privilege: a deeper entry REPLACES the inherited role
      (a NoAccess, or a DatastoreBackup the user also holds, leaves the token
      nothing there). That path is then invisible here -- unless, below
      /datastore, the token can still audit a path below it (_hidden_below)
      -- so the README gives the token's user no other ACL.
    A grant on /datastore/<store>[/ns] is a scoped token whatever its
    propagate flag: it audits at least that path.
    """
    if not isinstance(permissions, dict):
        raise _PbsError("http_error", "unexpected permissions shape", reachable=True)
    grants = {
        str(path): privileges
        for path, privileges in permissions.items()
        if isinstance(privileges, dict)
    }
    extra = {
        str(privilege)
        for privileges in grants.values()
        for privilege in privileges
        if privilege not in _ALLOWED_PRIVILEGES
    }
    if extra:
        # Named up to a bound: the map is PBS data, and a hostile one could
        # list a million "privileges" -- sorted, joined and kept for log
        # dedup on every tick. A real admin token holds about 20.
        shown = heapq.nsmallest(_MAX_PRIVILEGES_NAMED, extra)
        # Redacted BEFORE each name is cut: a cut first would leave a prefix
        # of the token secret a PBS echoed in a name past what redaction
        # matches. The remediation comes first, so the wire cap (500) can
        # only ever trim the list, never the instruction.
        names = ", ".join(
            scrub_str(redact(name), _PRIVILEGE_NAME_MAX_LEN) for name in shown
        )
        if len(extra) > len(shown):
            names += f" and {len(extra) - len(shown)} more"
        raise _PbsError(
            "over_privileged",
            "the API token holds privileges beyond Datastore.Audit and "
            "Remote.Audit: grant it the DatastoreAudit and RemoteAudit roles "
            "only (it holds " + names + ")",
            reachable=True,
        )

    def propagated(privilege, paths):
        return any(grants.get(path, {}).get(privilege) is True for path in paths)

    # PBS ALWAYS evaluates /datastore and /remote (default paths of
    # list_permissions) and leaves a path out only when the token has NO
    # privilege there: a propagated grant on / shows up at both, inherited.
    # A grant on / with /datastore ABSENT therefore means an entry at
    # /datastore replaced it -- every datastore hidden, not "none exists".
    full_scope = propagated("Datastore.Audit", ("/datastore",))
    scoped = any(
        path.startswith("/datastore/") and "Datastore.Audit" in privileges
        for path, privileges in grants.items()
    )
    if not full_scope and not scoped:
        raise _PbsError(
            "no_datastore_access",
            "the API token cannot audit any datastore (grant DatastoreAudit on "
            "/datastore with propagation): PBS would answer every listing with "
            "an empty list",
            reachable=True,
        )
    return propagated("Remote.Audit", ("/remote",)), full_scope


def _hidden_below(permissions):
    """(whether some path below /datastore is hidden from the token, the
    datastores it cannot audit at the datastore level) -- the deeper ACL
    entries _check_privileges cannot see, in the one case where they show:
    PBS puts every node of its ACL tree in this map, a node's ancestors are
    nodes too, and it leaves out only a node where the token holds NO
    privilege. So a path present under an absent one names a deeper entry
    that took the token's privilege away there (below /datastore only: an
    entry hiding a remote shows nothing). Such a datastore is listed only
    when the token has an ACL entry of its own below it -- then without its
    root namespace or groups, and its own status answers 0/0/0 -- and is
    simply absent otherwise; either way the block is partial.

    Linear in the map (PBS input, up to _SMALL_MAX_BYTES): the shallowest
    present node below an absent ancestor has an absent PARENT, so each path
    checks its parent and its datastore only, never every ancestor."""
    paths = {
        str(path)
        for path, privileges in permissions.items()
        if isinstance(privileges, dict)
    }
    hidden, unaudited = False, set()
    for path in paths:
        parts = path.split("/", 3)  # "", "datastore", store, ns path
        if len(parts) < 4 or parts[1] != "datastore":
            continue
        if "/".join(parts[:3]) not in paths:
            hidden = True
            unaudited.add(parts[2])
        elif path.rpartition("/")[0] not in paths:
            hidden = True
    return hidden, unaudited


def _is_name(value, namespace=False):
    """A datastore (or, with `namespace`, a namespace: "" is the root) name as
    PBS's own schema spells it (_SAFE_ID). Anything else -- a lone surrogate
    from a JSON "\\udcXX" escape, which requests cannot even encode, or
    astral-plane padding -- reads as an unparseable row, not a crash of the
    whole block."""
    if not isinstance(value, str) or len(value) > FIELD_MAX_LEN:
        # Longer than the wire cap, two names could ship as one (PBS itself
        # caps a namespace's length well below it).
        return False
    pattern = _NAMESPACE_RE if namespace else _SAFE_ID_RE
    return pattern.fullmatch(value) is not None


def _datastore_entries(listing):
    """The /admin/datastore rows, sorted by name. ONE unparseable row makes the
    whole listing untrustworthy: a datastore silently dropped would read as
    removed."""
    if (
        not isinstance(listing, list)
        or not all(
            isinstance(entry, dict) and _is_name(entry.get("store"))
            for entry in listing
        )
        # PBS lists a datastore once: a repeat would ship its groups twice.
        or len({entry["store"] for entry in listing}) != len(listing)
    ):
        raise _PbsError(
            "http_error", "unexpected datastore listing shape", reachable=True
        )
    # PBS lists datastores (and jobs, and namespaces) in no stable order;
    # sorting keeps the payload, and which datastores and jobs a cap trims,
    # deterministic. (The namespace and group caps are block-wide totals,
    # spent in rotation order.)
    return sorted(listing, key=lambda entry: entry["store"])


def _epoch():
    """The agent's wall clock, whole seconds (the block's built_at)."""
    return int(time.time())


def _build_block(session, target, deadline):
    """One full pass: (computed_at, block). Raises _PbsError when nothing
    trustworthy can be built (the token check or the datastore listing); every
    other failure is an `errors` entry and the block is still emitted."""
    _read_failures["current"] = set()
    _read_failure_lines.update(error=0, quieted=0)
    _local_nodes.clear()
    _forget_stale_backoffs()
    permissions = _get(session, target, "/access/permissions", deadline=deadline)
    remote_audit, full_scope = _check_privileges(permissions, target.redact)
    hidden, unaudited = _hidden_below(permissions)
    del permissions
    stores = _datastore_entries(
        _get(session, target, "/admin/datastore", deadline=deadline)
    )
    if not stores and not full_scope:
        # A scoped token whose grants reach no existing datastore: the empty
        # listing proves nothing.
        raise _PbsError(
            "no_datastore_access",
            "the API token's Datastore.Audit grants reach no existing datastore",
            reachable=True,
        )
    errors = _Errors(target.redact)
    kept_stores = _cap(stores, MAX_DATASTORES, errors, "datastores")
    # "partial": a datastore or namespace absent from this block may exist and
    # simply not be visible to this token (or past the datastore cap, or
    # hidden from it by a deeper ACL entry).
    whole = full_scope and not hidden and len(kept_stores) == len(stores)
    scope = "full" if whole else "partial"
    del stores  # past the cap, not kept alive for the whole build
    usage, usage_failed = _read_usage(
        session,
        target,
        errors,
        deadline,
        {entry["store"] for entry in kept_stores},
    )
    backends = _read_backends(session, target, errors, deadline, kept_stores, usage)
    sync_jobs = _read_sync_jobs(session, target, errors, deadline, remote_audit)
    verify_jobs = _read_jobs(
        session, target, errors, deadline, "verify_jobs", "/admin/verify", _verify_job
    )
    prune_jobs = _read_jobs(
        session, target, errors, deadline, "prune_jobs", "/admin/prune", _prune_job
    )
    # PBS lists a job only to a token that can audit its datastore (or
    # namespace): below full scope, or with part of /datastore hidden, a job
    # list may be short.
    if not full_scope or hidden:
        why = (
            "the API token's Datastore.Audit is scoped below /datastore, so jobs "
            "outside that scope are not listed"
            if not full_scope
            else "a deeper ACL entry hides part of /datastore from the API token, "
            "so jobs defined there are not listed"
        )
        for name, rows in (
            ("sync_jobs", sync_jobs),
            ("verify_jobs", verify_jobs),
            ("prune_jobs", prune_jobs),
        ):
            if rows is not None:
                _error(errors, name, "partial: " + why)

    datastores, units = _read_datastores(
        session,
        target,
        errors,
        deadline,
        kept_stores,
        usage,
        full_scope and usage_failed,
        backends,
        unaudited,
    )
    # After the job lists and the GC reads: they teach _local_nodes, which
    # decides which verifications the group rows count.
    groups = _read_all_groups(session, target, errors, deadline, units, datastores)
    groups.sort(key=lambda g: (g["store"], g["ns"], g["type"] or "", g["id"] or ""))
    for datastore in datastores.values():
        if datastore["unread_namespaces"] is not None:
            datastore["unread_namespaces"].sort()
    if errors.dropped:
        keep = MAX_ERRORS - 1
        dropped = errors.dropped + len(errors) - keep
        del errors[keep:]
        _error(errors, "cap", f"errors capped at {MAX_ERRORS}: {dropped} dropped")
    block = {
        "scope": scope,
        "datastores": [datastores[name] for name in sorted(datastores)],
        "groups": groups,
        "sync_jobs": sync_jobs,
        "verify_jobs": verify_jobs,
        "prune_jobs": prune_jobs,
        "errors": list(errors),
        # The build's identity: every re-emission of a cached block carries
        # the same value, so the server counts BUILDS (its two-absences prune
        # rule), never payloads (a block is re-emitted ~5 times per TTL).
        "built_at": _epoch(),
        # Every namespace walk is held (_WALK_HOLD) until a reload: every
        # datastore's namespaces are null and no group is read, so what the
        # server stored for this PBS is of UNKNOWN freshness -- the one signal
        # it needs for that, outside the capped errors[].
        "walks_held": _WALK_HOLD in _timeout_backoff,
    }
    too_large = _oversize(block)
    if too_large is not None:
        # Returned, not raised: cached like a block (a failed build is not),
        # so a broken PBS costs one such build per TTL, not one per tick.
        block = {
            "too_large": f"block too large to ship: {too_large} (a working "
            "PBS keeps its fields short)"
        }
    _read_failures["previous"] = _read_failures["current"]
    if _read_failure_lines["quieted"]:
        log(
            f"PBS: {_read_failure_lines['quieted']} more read failure(s) this "
            "build, logged at debug",
            "error",
        )
    # Stamped AFTER the reads, like TTLCache's own timestamp.
    return (time.monotonic(), block)


def _encoded(block):
    """`block` as json.dumps encodes it (ASCII), in pieces of about
    _ENCODE_BATCH_CHARS: one zlib call each, not one per JSON token."""
    pieces, length = [], 0
    for piece in json.JSONEncoder().iterencode(block):
        pieces.append(piece)
        length += len(piece)
        if length >= _ENCODE_BATCH_CHARS:
            yield "".join(pieces)
            pieces, length = [], 0
    yield "".join(pieces)


def _oversize(block):
    """Which limit `block` crosses, or None. Its JSON and gzipped sizes are
    counted as it is encoded and the count stops at the first limit crossed,
    so the block of a broken PBS (~90 MB of JSON) is never built whole, in
    either form."""
    packer = zlib.compressobj(1, zlib.DEFLATED, 31)  # gzip, like the payload
    size = packed = 0
    for text in _encoded(block):
        size += len(text)  # ASCII: characters are bytes
        if size > _MAX_BLOCK_JSON_BYTES:
            return f"over {_MAX_BLOCK_JSON_BYTES} bytes of JSON"
        packed += len(packer.compress(text.encode()))
        if packed > _MAX_BLOCK_GZIP_BYTES:
            break
    else:
        packed += len(packer.flush())
    if packed > _MAX_BLOCK_GZIP_BYTES:
        return f"over {_MAX_BLOCK_GZIP_BYTES} bytes gzipped"
    return None


def _resume_index(order_length, start, cut):
    """Where the next build starts: where this one started when nothing was
    cut; else at the first item it cut -- the budget or a cap ran out inside
    it, or before it was even started -- so that item is read FIRST next time,
    unless it already was the first item of this build (it had the whole
    budget or cap and did not finish -- or none was left for any item): the
    next build starts past it, or it would starve the rest on every build. A
    read that merely FAILED is not a cut and does not move the start."""
    if cut is None:
        return start
    return (start + max(cut, 1)) % order_length


def _read_datastores(
    session,
    target,
    errors,
    deadline,
    stores,
    usage,
    per_store_usage,
    backends,
    unaudited,
):
    """(name -> datastore, sorted (store, ns) units).

    The per-datastore reads (usage fallback, gc, namespaces) get at most HALF
    of the budget left, so a wedged datastore (a hung NFS mount) can never
    leave the per-namespace reads with nothing; they start at
    `_store_rotation`, and the next build resumes at the first datastore this
    one could not finish (see _resume_index), so one wedged datastore cannot
    starve the ones after it on every build either. `per_store_usage`: the
    aggregate usage read FAILED (PBS fails it whole when ONE datastore's
    statfs errors) and the token is full-scope, so each datastore's own status
    is read instead -- for a FILESYSTEM datastore only: any other backend's
    usage is withheld anyway -- and never for one in `unaudited`, which PBS
    answers with 0/0/0 (_hidden_below).
    """
    global _store_rotation
    datastores = {}
    units = []
    if not stores:
        return datastores, units
    now = time.monotonic()
    phase_deadline = now + max(deadline - now, 0) / 2
    start = _store_rotation % len(stores)
    order = stores[start:] + stores[:start]
    cut = None
    for index, entry in enumerate(order):
        name = entry["store"]
        if usage is not None:
            row = usage.get(name, {})
        elif (
            per_store_usage
            and backends.get(name) == "filesystem"
            and name not in unaudited
        ):
            # Only where it can ship: any other backend's usage is withheld.
            row = _read_store_status(session, target, errors, phase_deadline, name)
        else:
            row = {}
        datastore = _datastore(entry, row, backends.get(name))
        datastore["gc"] = _read_gc(session, target, errors, phase_deadline, name)
        namespaces = _read_namespaces(session, target, errors, phase_deadline, name)
        trimmed = False
        if namespaces is not None:
            kept = _cap(
                namespaces,
                MAX_NAMESPACES - len(units),
                errors,
                "namespaces",
                MAX_NAMESPACES,
                store=name,
            )
            trimmed = len(kept) < len(namespaces)
            if not trimmed:
                datastore["namespaces"] = [scrub_str(ns) for ns in namespaces]
                datastore["unread_namespaces"] = []
            # else: the namespace set itself is incomplete, so it stays null
            # (unknown) while the groups of the namespaces kept still ship.
            units.extend((name, ns) for ns in kept)
        datastores[name] = datastore
        incomplete = datastore["gc"] is None or namespaces is None
        if cut is None and (
            trimmed or (incomplete and time.monotonic() >= phase_deadline)
        ):
            cut = index
    _store_rotation = _resume_index(len(stores), start, cut)
    return datastores, sorted(units)


def _read_store_status(session, target, errors, deadline, store):
    """One datastore's own usage, for when /status/datastore-usage failed as a
    whole. Only read for a full-scope token (to a token scoped below the
    datastore this endpoint answers 0/0/0, measurement 6) and a filesystem
    datastore."""
    status = _sub_read(
        session,
        target,
        errors,
        deadline,
        "usage",
        _store_path(store, "status"),
        store=store,
        kind=dict,
        backoff="retry",
    )
    return {} if status is None else status


def _read_all_groups(session, target, errors, deadline, units, datastores):
    """The groups of every (store, ns) unit, starting at `_rotation`.

    A unit whose GROUPS are unknown -- its /groups read failed, a malformed
    row, its /snapshots not read as a list (see _read_groups), trimmed by the
    group cap, or never reached (budget spent, or the group cap full) -- is
    added to its datastore's unread_namespaces. The next build starts at the
    first unit this one cut (see _resume_index).
    """
    global _rotation

    def unread(store, ns):
        pending = datastores[store]["unread_namespaces"]
        if pending is not None:
            pending.append(scrub_str(ns))

    def skip_rest(skipped, message):
        for name, count in sorted(Counter(store for store, _ in skipped).items()):
            _error(
                errors,
                "cap" if message is None else "groups",
                (
                    f"groups capped at {MAX_GROUPS}: {count} namespace(s) not read"
                    if message is None
                    else f"{message} ({count} namespace(s) not read)"
                ),
                store=name,
            )
        for store, ns in skipped:
            unread(store, ns)

    groups = []
    if not units:
        return groups
    start = _rotation % len(units)
    order = units[start:] + units[:start]
    cut = None
    for index, (store, ns) in enumerate(order):
        if time.monotonic() >= deadline:
            skip_rest(order[index:], _DEADLINE_MESSAGE)
            cut = index
            break
        if len(groups) >= MAX_GROUPS:
            skip_rest(order[index:], None)
            cut = index
            break
        result = _read_groups(
            session, target, errors, deadline, store, ns, MAX_GROUPS - len(groups)
        )
        finished = False
        if result is None:
            unread(store, ns)
        else:
            rows, complete, detailed, over = result
            if over:
                _error(
                    errors,
                    "cap",
                    f"groups capped at {MAX_GROUPS}: {over} dropped",
                    store=store,
                    ns=ns,
                )
            if not complete or over:
                unread(store, ns)
            groups.extend(rows)
            if over:
                # The group cap trimmed this unit: the next build resumes here
                # (or past it, if it was first: see _resume_index).
                after = index + 1
                skip_rest(order[after:], None)
                cut = index
                break
            finished = complete and detailed
        if not finished and time.monotonic() >= deadline:
            # The budget ran out INSIDE this unit: the next build resumes here
            # (or past it, if it was first: see _resume_index).
            after = index + 1
            skip_rest(order[after:], _DEADLINE_MESSAGE)
            cut = index
            break
    _rotation = _resume_index(len(units), start, cut)
    return groups


def _store_path(store, leaf):
    return f"/admin/datastore/{quote(store, safe='')}/{leaf}"


def _ns_params(ns):
    # The root namespace is "", which PBS spells by omitting the parameter.
    return {"ns": ns} if ns else None


def _read_usage(session, target, errors, deadline, listed):
    """(store -> its /status/datastore-usage row, or None when unread; whether
    the read FAILED -- an HTTP or transport error, a body that is not the
    JSON envelope, or a read skipped by the walk hold (_WALK_HOLD, armed by
    ANY namespace walk that timed out) -- rather than being skipped past the
    budget or answering a well-formed non-list, which is when a per-datastore
    fallback is worth trying). The endpoint omits what a scoped token may not
    see (measurement 6). A row's own error is recorded once per datastore in
    `listed` (at most MAX_DATASTORES), however many rows name it: a flood of
    rows must not crowd the job lists' 'partial:' flags out of the capped
    errors[]. PBS walks the namespaces of every datastore the token cannot
    audit (all of them for a scoped token; for a full-scope one, any a deeper
    ACL entry hides), which never ends on an unreadable one: a timeout of
    any walk holds every walk, this one included (_timeout_backoff), and a
    full-scope token then reads each datastore's own status instead."""
    failures = []
    rows = _sub_read(
        session,
        target,
        errors,
        deadline,
        "usage",
        "/status/datastore-usage",
        on_error=failures.append,
        backoff="hold",
    )
    if rows is None:
        # A 200 whose headers came in past the budget is a skip, not a failure;
        # one held back by its timeout backoff is still worth the fallback.
        return None, any(e.skipped != "deadline" for e in failures)
    usage = {}
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("store"), str):
            usage[row["store"]] = row
    # One entry per listed datastore, however many rows name it.
    for store in sorted(listed):
        error = usage.get(store, {}).get("error")
        if error:
            # e.g. "datastore 'x' is unavailable: offline maintenance mode"
            _error(errors, "usage", error, store=store)
    return usage, False


def _read_backends(session, target, errors, deadline, stores, usage):
    """store -> its backend type ('filesystem', 's3', ...), or None when
    unknown. S3 datastores exist since PBS 4.0.4, but the listing names the
    backend only since 4.1.7 and the usage status since 4.1.6: in between, an
    S3 datastore looks like any other while its usage measures the local CACHE
    disk. So a backend neither names is read from /config/datastore (filtered
    by Datastore.Audit, like the listing), where a datastore with no
    `backend` property is a filesystem one -- as is every datastore of a PBS
    older than S3."""
    backends = {}
    for entry in stores:
        name = entry["store"]
        backend = entry.get("backend-type")
        if backend is None and usage is not None:
            backend = usage.get(name, {}).get("backend-type")
        backends[name] = backend if isinstance(backend, str) else None
    if all(backends.values()):
        return backends
    rows = _sub_read(
        session, target, errors, deadline, "datastore_config", "/config/datastore"
    )
    # Each pending datastore is parsed once, whatever it parses to: a body
    # repeating one name must not cost a parse per row.
    pending = {name for name, backend in backends.items() if backend is None}
    for row in rows or []:
        if not pending:
            break
        name = row.get("name") if isinstance(row, dict) else None
        if isinstance(name, str) and name in pending:
            pending.discard(name)
            backends[name] = _backend_type(row.get("backend"))
    return backends


def _backend_type(value):
    """The type a datastore config's `backend` property string names
    ('type=s3,client=...,bucket=...'), 'filesystem' when it has none, None
    when it cannot be read."""
    if value is None:
        return "filesystem"
    if not isinstance(value, str):
        return None
    fields = _property_fields(value[:_BACKEND_SCAN])
    return (fields.get("type") or fields.get(None) or "").strip() or None


def _as_int64(value):
    """An integer PBS sent, when it fits an i64 (what PBS itself uses): a
    broken or hostile PBS could send 4300-digit ones, re-serialized and
    gzipped on every tick while the block is cached."""
    number = as_int(value)
    if number is None or not -(2**63) <= number < 2**63:
        return None
    return number


def _property_fields(value):
    """The fields of a PBS property string, parsed as PBS does (proxmox-schema
    next_property): key=value parts in ANY order, split on commas; a part with
    no key belongs to the default key (None); a double quote opens a quoted
    value only at the START of a value, and a quoted value (which may hold
    commas) has its \\" \\\\ \\n escapes undone."""
    fields, pos = {}, 0
    while pos < len(value):
        match = _PROPERTY_PART_RE.match(value, pos)
        key, quoted, plain = match.groups()
        if quoted is None:
            text = plain.strip()
        else:
            text = _PROPERTY_ESCAPE_RE.sub(
                lambda m: "\n" if m[1] == "n" else m[1], quoted
            )
        fields.setdefault(None if key is None else key.strip(), text)
        pos = match.end() + 1
    return fields


def _maintenance(value):
    """(mode, message) from the listing's `maintenance` property string,
    e.g. "offline,message=disk swap tonight", "read-only", or -- PBS 2.2 to
    3.1 store it exactly as sent -- "message=disk swap,type=offline". The mode
    is the `type` field or the keyless one; null when there is none."""
    if not isinstance(value, str) or not value:
        return None, None
    fields = _property_fields(value[:_MAINTENANCE_SCAN])
    mode = fields.get("type") or fields.get(None)
    return (
        scrub_str(mode) or None,
        scrub_str(fields.get("message"), max_len=MAINTENANCE_MESSAGE_MAX_LEN) or None,
    )


def _datastore(entry, row, backend):
    name = entry["store"]
    mode, message = _maintenance(entry.get("maintenance"))
    if backend != "filesystem":
        # PBS measures usage on the datastore's base path: for an S3 backend
        # that is the local CACHE disk, not the datastore, and a cache is meant
        # to fill. Not shipped as the datastore's capacity -- nor when the
        # backend is unknown (see _read_backends).
        row = {}
    return {
        "store": scrub_str(name),
        "backend_type": scrub_str(backend),
        "mount_status": scrub_str(entry.get("mount-status")),
        "maintenance_mode": mode,
        "maintenance_message": message,
        # Absent (a token scoped below the datastore, or an unread usage) is
        # null, never 0: 0 would read as an empty or a full datastore.
        "total": _as_int64(row.get("total")),
        "used": _as_int64(row.get("used")),
        "avail": _as_int64(row.get("avail")),
        # Verbatim: PBS sends 0 as its "no fill expected" sentinel (flat
        # usage), and a past date when usage shrinks.
        "estimated_full_date": _as_int64(row.get("estimated-full-date")),
        "gc": None,
        "namespaces": None,
        "unread_namespaces": None,
    }


_GC_COUNTERS = (
    ("index-file-count", "index_file_count"),
    ("index-data-bytes", "index_data_bytes"),
    ("disk-bytes", "disk_bytes"),
    ("disk-chunks", "disk_chunks"),
    ("pending-bytes", "pending_bytes"),
    ("pending-chunks", "pending_chunks"),
    ("removed-bytes", "removed_bytes"),
    ("removed-chunks", "removed_chunks"),
    ("removed-bad", "removed_bad"),
    ("still-bad", "still_bad"),
)


def _read_gc(session, target, errors, deadline, store):
    """The datastore's garbage-collection status, or None when unread.
    index_data_bytes / disk_bytes is the deduplication factor.

    last_run_starttime and the counters come from the last SUCCESSFUL GC
    (PBS keeps its status only when a run succeeds), last_run_state and
    last_run_endtime from the last run, whatever its outcome. So: all null =
    no successful GC known (it may have run and failed); a start time with a
    null state = a PBS older than 3.2 (which reports no state), or a GC
    running now; a failed state next to an older start time = the last run
    failed, and `duration` then spans from that older start.
    """
    status = _sub_read(
        session,
        target,
        errors,
        deadline,
        "gc",
        _store_path(store, "gc"),
        store=store,
        kind=dict,
    )
    if status is None:
        return None
    _note_local_task(status.get("upid"))
    gc = {
        "schedule": scrub_str(status.get("schedule")),
        "next_run": _as_int64(status.get("next-run")),
        "last_run_starttime": _upid_starttime(status.get("upid")),
        "last_run_state": scrub_str(status.get("last-run-state")),
        "last_run_endtime": _as_int64(status.get("last-run-endtime")),
        "duration": _as_int64(status.get("duration")),
    }
    # Until a GC has SUCCEEDED, PBS answers its status struct's defaults:
    # every counter 0, never measured. Without the (dated) task id of a
    # successful run the counters are unknown, so "all null" holds.
    measured = gc["last_run_starttime"] is not None
    for source, key in _GC_COUNTERS:
        gc[key] = _as_int64(status.get(source)) if measured else None
    return gc


def _read_namespaces(session, target, errors, deadline, store):
    """The namespaces the token can see, sorted, or None when unread. A PBS
    older than namespaces (2.2) answers 404 on the endpoint: root only. ONE
    unparseable row makes the whole set unknown: a namespace silently dropped
    would read as deleted, with all its groups."""
    rows = _sub_read(
        session,
        target,
        errors,
        deadline,
        "namespaces",
        _store_path(store, "namespace"),
        store=store,
        missing=[{"ns": ""}],
        backoff="hold",
    )
    if rows is None:
        return None
    if not all(
        isinstance(row, dict) and _is_name(row.get("ns"), namespace=True)
        for row in rows
    ):
        _error(errors, "namespaces", "unparseable namespace row", store=store)
        return None
    names = sorted(row["ns"] for row in rows)
    if len(set(names)) != len(names):
        # PBS lists a namespace once: a repeat would ship its groups twice.
        _error(errors, "namespaces", "repeated namespace row", store=store)
        return None
    return names


def _read_groups(session, target, errors, deadline, store, ns, room):
    """(rows, complete, detailed, over) for one namespace, or None when
    /groups itself could not be read (the namespace is then unknown). At most
    `room` rows are built (what the group cap has left); ``over`` counts the
    valid groups past it, which a hostile listing would otherwise make cost a
    row each.

    /groups is the membership list and the primary source of last_backup; a
    newer FINISHED snapshot in /snapshots overrides it (see _group_row).
    ``complete`` is False when a /groups row could not be parsed or repeats a
    group, and whenever /snapshots did not come back as a list (below): the
    rows still ship, but the namespace is unread, since a group silently
    skipped would read as deleted. /snapshots also ENRICHES the rows
    (``detailed``): when it fails, the groups ship with their last backup and
    every snapshot detail null -- in_progress null included, which is how a
    row says "details unknown" rather than "never verified" -- plus a
    "snapshots" error naming the namespace.
    """
    params = _ns_params(ns)
    listing = _sub_read(
        session,
        target,
        errors,
        deadline,
        "groups",
        _store_path(store, "groups"),
        params,
        store=store,
        ns=ns,
        backoff="retry",
    )
    if listing is None:
        return None
    wanted = []
    malformed = 0
    over = 0
    seen = set()
    for group in listing:
        btype = group.get("backup-type") if isinstance(group, dict) else None
        bid = group.get("backup-id") if isinstance(group, dict) else None
        if not (
            isinstance(btype, str)
            and _BACKUP_TYPE_RE.fullmatch(btype)
            and isinstance(bid, str)
            and _SAFE_ID_RE.fullmatch(bid)
        ):
            malformed += 1
            continue
        if (btype, bid) in seen:
            # PBS lists a group once. A repeat is unparseable (the namespace
            # is then unread), and never re-scans the shared snapshot summary:
            # thousands of repeats would otherwise cost minutes of CPU.
            malformed += 1
            continue
        seen.add((btype, bid))
        if len(wanted) >= room:
            over += 1
            continue
        wanted.append((btype, bid, group))
    # Only the kept groups stay alive while /snapshots is read and parsed.
    del listing, seen
    snapshots = _sub_read(
        session,
        target,
        errors,
        deadline,
        "snapshots",
        _store_path(store, "snapshots"),
        params,
        store=store,
        ns=ns,
        backoff="retry",
    )
    # PBS LEAVES OUT of /groups a group whose snapshot directory it failed to
    # read and still answers 200; /snapshots fails on that same group (HTTP
    # 400, like every PBS handler error) -- but only once its scan reaches it,
    # so on a big namespace the agent may see a timeout instead. The
    # namespace is therefore read only when /snapshots came back as a list:
    # an HTTP error, a timeout, a reset, a budget skip or a backoff all leave
    # it unread. A group whose OWNER file cannot be read is left out of BOTH
    # listings with 200: nothing here can see that one (pruning_contract).
    answered = snapshots is not None
    summaries = None
    if answered:
        keys = {(btype, bid) for btype, bid, _ in wanted}
        summaries, unparseable = _summarize_snapshots(snapshots, store, keys)
        del snapshots
        if unparseable:
            _error(
                errors,
                "snapshots",
                f"{unparseable} unparseable snapshot row(s): details unknown",
                store=store,
                ns=ns,
            )
            summaries = None
    rows = []
    for btype, bid, group in wanted:
        summary = None if summaries is None else summaries.get((btype, bid), {})
        row = _group_row(store, ns, group, summary)
        if summary is not None and row["in_progress"] is None:
            _error(
                errors,
                "snapshots",
                f"{btype}/{bid}: last backup {row['last_backup']} has no "
                "readable manifest in the snapshot listing",
                store=store,
                ns=ns,
            )
        rows.append(row)
    if malformed:
        _error(
            errors,
            "groups",
            f"{malformed} unparseable group row(s) skipped",
            store=store,
            ns=ns,
        )
    return rows, not malformed and answered, summaries is not None, over


def _crypt_mode(files):
    """One snapshot's crypt mode from its archives ("encrypt", "sign-only",
    "none", or "mixed"); the manifest is signed even when the archives are
    encrypted, so it is left out."""
    modes = set()
    for item in files if isinstance(files, list) else ():
        if isinstance(item, dict) and item.get("filename") != _MANIFEST:
            mode = item.get("crypt-mode")
            if isinstance(mode, str):
                modes.add(mode)
    if not modes:
        return None
    if len(modes) > 1:
        return "mixed"
    return scrub_str(modes.pop())


def _upid_starttime(upid):
    """The start time a PBS task id carries (UPID:node:pid:pstart:task:
    STARTTIME:type:id:user:, hex), or None -- also when it does not fit the
    i64 PBS itself keeps it in (like every integer, see _as_int64)."""
    if not isinstance(upid, str):
        return None
    parts = upid.split(":", 9)
    if len(parts) < 9 or parts[0] != "UPID":
        return None
    if not _UPID_TIME_RE.fullmatch(parts[5]):
        return None
    return _as_int64(int(parts[5], 16))


def _upid_origin(upid):
    """(node, datastore) a PBS task id names -- its node, and the datastore
    its worker id starts with (a verification: 'store', 'store:ns',
    'store:type/id[/time]' or 'store:jobid') -- or None."""
    if not isinstance(upid, str):
        return None
    parts = upid.split(":", 9)
    if len(parts) < 9 or parts[0] != "UPID":
        return None
    worker_id = _UPID_ESCAPE_RE.sub(
        lambda m: chr(int(m.group(1), 16)), parts[7][:_WORKER_ID_SCAN]
    )
    return parts[1], worker_id.split(":", 1)[0]


def _note_local_task(upid):
    """Remember the node of a task this PBS ran itself (a GC, a job)."""
    origin = _upid_origin(upid)
    if origin is not None and len(_local_nodes) < _MAX_LOCAL_NODES:
        _local_nodes.add(origin[0])


def _local_verification(verification, store):
    """`verification` when it ran on THIS datastore -- and, for an OK, on a
    node of THIS PBS -- else {}.

    PBS pull sync copies a snapshot's manifest verbatim, verification state
    included, so a synced copy carries the SOURCE's verification -- another
    datastore, often another PBS -- and PBS's own verify jobs then skip it by
    default (ignore-verified), so the copy is never verified locally. The task
    id names both: its worker id must start with this datastore, and its node
    must be one this PBS's own tasks carry, when any is known (else only the
    datastore can be checked: a same-named datastore on another PBS passes).
    The node check applies to an OK only: a FAILED verification of this
    datastore counts whatever node ran it, because a PBS renamed or
    reinstalled (or a removable datastore moved) keeps its own past
    verifications under the old node name, and hiding a real failure is
    missed corruption, while a copied one is at worst a false alarm. A
    verification without a readable task id is not provably this one's. A
    HEURISTIC against copies, not a security control: nodes are compared by
    name, and the sync source writes the copied task id (it could name this
    PBS's node and datastore) -- nothing a read-only token can read proves a
    verify task ran here."""
    if not isinstance(verification, dict):
        return {}
    origin = _upid_origin(verification.get("upid"))
    if origin is None:
        return {}
    node, verified_store = origin
    if verified_store != store:
        return {}
    local_node = not _local_nodes or node in _local_nodes
    if not local_node and verification.get("state") != "failed":
        return {}
    return verification


def _summarize_snapshots(snapshots, store, wanted=None):
    """(type, id) -> what the snapshot listing says about that group -- for
    the groups in `wanted` only, when given (the ones the group cap kept).

    A snapshot is FINISHED when it carries a size: measured on PBS 4.2, an
    upload in progress is listed with no manifest (files [], no size), and so
    is a snapshot whose manifest cannot be read. Returns (summaries, the
    number of rows that could not be parsed): a row skipped could have been a
    failed verification or the newest upload, so the caller treats any as
    "details unknown". Only verifications that ran on `store` count (see
    _local_verification).
    """
    summaries = {}
    unparseable = 0
    for snap in snapshots:
        btype = snap.get("backup-type") if isinstance(snap, dict) else None
        bid = snap.get("backup-id") if isinstance(snap, dict) else None
        when = _as_int64(snap.get("backup-time")) if isinstance(snap, dict) else None
        if (
            not isinstance(btype, str)
            or not isinstance(bid, str)
            or when is None
            or not 0 <= when < _MAX_BACKUP_TIME
        ):
            unparseable += 1
            continue
        if wanted is not None and (btype, bid) not in wanted:
            continue
        summary = summaries.setdefault(
            (btype, bid),
            {
                "finished": {},
                "newest_unfinished": None,
                "last_verified_ok": None,
                "verify_failed_count": 0,
            },
        )
        if _as_int64(snap.get("size")) is None:
            if (
                summary["newest_unfinished"] is None
                or when > summary["newest_unfinished"]
            ):
                summary["newest_unfinished"] = when
            continue
        summary["finished"][when] = snap
        state = _local_verification(snap.get("verification"), store).get("state")
        if state == "failed":
            summary["verify_failed_count"] += 1
        elif state == "ok" and (
            summary["last_verified_ok"] is None or when > summary["last_verified_ok"]
        ):
            summary["last_verified_ok"] = when
    return summaries, unparseable


def _group_row(store, ns, group, summary):
    """One shipped group. `summary` is None when /snapshots was not read, or
    {} when the group had no snapshot row. Every snapshot detail -- in_progress
    included -- stays null when the listing was not read, or when last_backup
    is set but the snapshot it names was not found FINISHED in it: a manifest
    that cannot be read, or a listing that raced a prune, must read as
    "unknown", never as "never verified". A group with no finished backup
    (last_backup null) still gets in_progress and its verification counts."""
    last_backup = _as_int64(group.get("last-backup"))
    if last_backup is not None and last_backup <= 0:
        # Measured: a group whose only sync failed is listed with last-backup
        # 0 and backup-count 0. That is "no finished backup", not 1970.
        last_backup = None
    files = group.get("files")
    if last_backup is not None and isinstance(files, list) and _MANIFEST not in files:
        # Measured: a group whose ONLY snapshot is still uploading reports that
        # upload as last-backup (PBS skips its finished filter for a single
        # snapshot), with no manifest among its files: not a finished backup.
        last_backup = None
    row = {
        "store": scrub_str(store),
        "ns": scrub_str(ns),
        "type": scrub_str(group.get("backup-type")),
        "id": scrub_str(group.get("backup-id")),
        "last_backup": last_backup,
        # PBS's own count: it includes a snapshot still being uploaded.
        "count": _as_int64(group.get("backup-count")),
        "in_progress": None,
        "in_progress_since": None,
        "size": None,
        "crypt_mode": None,
        "protected": None,
        "verify_state": None,
        "verify_time": None,
        "last_verified_ok": None,
        "verify_failed_count": None,
    }
    if summary is None:
        return row
    finished = summary.get("finished", {})
    # PBS < 4.0.17 folds last-backup over an UNSORTED directory listing: an
    # unfinished newest snapshot makes it an OLDER finished one (or the upload
    # itself, discarded above). A newer finished snapshot in the listing is
    # the real last backup (on every PBS, a snapshot with a manifest is
    # finished).
    newest = max(finished) if finished else None
    if newest is not None and (last_backup is None or newest > last_backup):
        last_backup = newest
        row["last_backup"] = last_backup
    snap = finished.get(last_backup)
    if last_backup is not None and snap is None:
        return row
    newest_unfinished = summary.get("newest_unfinished")
    row["in_progress"] = newest_unfinished is not None and (
        last_backup is None or newest_unfinished > last_backup
    )
    if row["in_progress"]:
        # Its BACKUP time, not when writing started: a long backup keeps its
        # start time, and a pull sync writes the source's (days old while the
        # sync is live). PBS also keeps an upload orphaned by a crash (prune
        # keeps the newest unfinished snapshot). Age alone cannot tell a dead
        # upload from a live one, and what can depends on the uploader: a
        # pull sync's running job row here, a PVE backup's vzdump task on the
        # PVE host (through the pbs join key); a proxmox-backup-client upload
        # or a push from another PBS leaves nothing this token can see.
        row["in_progress_since"] = newest_unfinished
    row["last_verified_ok"] = summary.get("last_verified_ok")
    row["verify_failed_count"] = summary.get("verify_failed_count", 0)
    if snap is not None:
        verification = _local_verification(snap.get("verification"), store)
        row["size"] = _as_int64(snap.get("size"))
        row["crypt_mode"] = _crypt_mode(snap.get("files"))
        row["protected"] = as_bool(snap.get("protected", False))
        row["verify_state"] = scrub_str(verification.get("state"))
        row["verify_time"] = _upid_starttime(verification.get("upid"))
    return row


# --- jobs ------------------------------------------------------------------


def _job_common(job):
    _note_local_task(job.get("last-run-upid"))
    return {
        "id": scrub_str(job.get("id")),
        "store": scrub_str(job.get("store")),
        "ns": scrub_str(job.get("ns")) or "",
        "max_depth": _as_int64(job.get("max-depth")),
        "schedule": scrub_str(job.get("schedule")),
        "next_run": _as_int64(job.get("next-run")),
        # From the last run's task id. PBS reports a job that is RUNNING with
        # this set and no state or end time: a sync hung for days is visible.
        "last_run_starttime": _upid_starttime(job.get("last-run-upid")),
        "last_run_state": scrub_str(job.get("last-run-state")),
        "last_run_endtime": _as_int64(job.get("last-run-endtime")),
    }


def _sync_job(job):
    row = _job_common(job)
    row.update(
        {
            # No remote is a local sync between two datastores of this PBS.
            "remote": scrub_str(job.get("remote")),
            "remote_store": scrub_str(job.get("remote-store")),
            "remote_ns": scrub_str(job.get("remote-ns")) or "",
            "direction": scrub_str(job.get("sync-direction")) or "pull",
        }
    )
    return row


def _verify_job(job):
    row = _job_common(job)
    row.update(
        {
            "outdated_after": _as_int64(job.get("outdated-after")),
            # Absent means true: PBS's schema default, and what its verify
            # job does (verify_job.rs: ignore_verified.unwrap_or(true)).
            "ignore_verified": as_bool(job.get("ignore-verified", True)),
        }
    )
    return row


def _prune_job(job):
    row = _job_common(job)
    row["disabled"] = as_bool(job.get("disable", False))
    return row


def _job_sort_key(job):
    """A job row's place in its list: (store, id) as _job_common ships them."""
    return (scrub_str(job.get("store")) or "", scrub_str(job.get("id")) or "")


def _job_rows(listing, errors, scope, shape):
    """The shaped, sorted job rows. A list trimmed by the cap is flagged
    'partial:' under its own scope, like one a scoped token reads. Only the
    rows the cap keeps are shaped: a hostile listing of millions of tiny rows
    costs a sort key each, not a shaped row (2M rows: 2.8s and 1 GB)."""
    jobs = [job for job in listing if isinstance(job, dict)]
    if len(jobs) < len(listing):
        _error(
            errors,
            scope,
            f"partial: {len(listing) - len(jobs)} unparseable job row(s) skipped",
        )
    if len(jobs) > MAX_JOBS:
        _error(
            errors,
            scope,
            f"partial: capped at {MAX_JOBS}: {len(jobs) - MAX_JOBS} dropped",
        )
    # heapq.nsmallest is sorted(...)[:n], ties included.
    return [shape(job) for job in heapq.nsmallest(MAX_JOBS, jobs, key=_job_sort_key)]


def _read_jobs(session, target, errors, deadline, scope, path, shape):
    listing = _sub_read(session, target, errors, deadline, scope, path)
    if listing is None:
        return None
    return _job_rows(listing, errors, scope, shape)


def _read_sync_jobs(session, target, errors, deadline, remote_audit):
    """Sync jobs, or None when unread. PBS lists a sync job only to a token
    holding Remote.Audit, and answers [] otherwise, so without it the list is
    unknown (null + an error naming the privilege), never an empty one."""
    if not remote_audit:
        _error(
            errors,
            "sync_jobs",
            "the API token lacks Remote.Audit on /remote (with propagation): "
            "sync jobs are not visible",
        )
        return None
    if _deadline_hit(deadline, errors, "sync_jobs"):
        return None
    try:
        listing = _get(
            session,
            target,
            "/admin/sync",
            {"sync-direction": "all"},
            deadline=deadline,
        )
    except _PbsError as e:
        if e.status != 400 or "sync-direction" not in e.message:
            if e.skipped is None:  # a skip, like _deadline_hit's
                _log_read_failure("sync_jobs", e.message)
            _error(errors, "sync_jobs", e.message)
            return None
        # A PBS older than push sync (3.3) rejects the parameter ("parameter
        # verification failed - 'sync-direction': ..."); it only has pull
        # jobs, which is what the bare listing returns. Any OTHER 400 is a
        # handler error (PBS answers them all with 400): falling back then
        # would ship the pull jobs alone as the complete list.
        listing = _sub_read(
            session, target, errors, deadline, "sync_jobs", "/admin/sync"
        )
        if listing is None:
            return None
    if not isinstance(listing, list):
        _error(errors, "sync_jobs", "unexpected response shape (not a list)")
        return None
    return _job_rows(listing, errors, "sync_jobs", _sync_job)
