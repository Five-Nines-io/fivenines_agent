"""OpenVPN per-instance collector (agent #145, server #1103).

The second half of the VPN axis, after WireGuard (#127) and the privilege
rework (#144). OpenVPN is the other VPN an MSP or hosting customer runs to a
site, and unlike WireGuard its state does NOT come from one fixed kernel
command: there is one daemon per instance, each with its own view, behind an
interface the operator has to enable. That is why this collector is
instance-shaped and why the payload is a list rather than a host-wide blob.

DATA SOURCE: the MANAGEMENT UNIX SOCKET, given the HAProxy stats-socket
treatment. OpenVPN exposes state two ways -- a periodically rewritten status
file (`status <path> [n]`, three formats) or the management interface -- and we
read the socket because:

- the path is operator-chosen inside the daemon's own runtime dir, so
  DISCOVERY IS A GLOB over :data:`RUNTIME_DIRS` and no config parsing is
  needed. Server confs carry inline ``<key>`` blocks and are root-only, so
  parsing one for a `status` path would need the privilege #144 just removed;
- the socket answers ``status 3`` (tab-separated, carrying Username, Client ID,
  Peer ID and Data Channel Cipher) AND ``state``, so ONE reader covers server
  and client mode and every status-file format variant is avoided;
- access is a group gate on the socket rather than sudo: no wildcard sudoers
  rule (#144 forbids them) and no per-instance rule.

THE HONEST CAVEAT, stated here and in the README rather than hidden: the
management interface has NO read-only level. A process holding the socket can
``client-kill`` and ``signal SIGTERM``. That is the same trust the HAProxy
``level operator`` socket already grants the agent (enable/disable a server),
and it is bounded to whoever the operator names in ``management-client-group``.
TCP management (``management 127.0.0.1 7505``) is deliberately NOT read: it is
reachable by every local user with at best an optional password file, so
supporting it would mean documenting a worse posture than the unix socket.

MEASURED, not read off the man page (Debian 12 / OpenVPN 2.6.14, Rocky 9 /
OpenVPN 2.5.11 -- see the README):

1. The socket file is created **mode 0777 root:root**: OpenVPN calls
   ``umask(0)`` before ``bind()``. So ``os.access()`` on it is meaningless --
   every user on the box passes -- and neither the collector nor the capability
   probe may use it as an authorization check.
2. Authorization is enforced at ``accept()`` from SO_PEERCRED against the
   peer's **primary GID**, NOT its supplementary groups. A user with
   ``fivenines`` as a secondary group is REJECTED
   ("GID of socket peer (998) doesn't match required value (999)"). The agent's
   own account is created with ``useradd --system --user-group fivenines``, so
   its primary group IS ``fivenines`` and the documented config line works --
   but a user-level install must name the primary group of the account the
   agent runs as, and ``usermod -aG`` does not help.
3. A rejected peer's ``connect()`` still SUCCEEDS. The daemon closes the
   connection immediately afterwards without sending its greeting, so the
   refusal is visible only as EOF before the first byte -- which is exactly
   what :data:`_REJECTED_REASON` reports.

CONTRACT (fixture: tests/fixtures/openvpn_contract_payload.json). ``data
["openvpn"]`` is ``{"instances": [...]}`` or the sentinel ``None``:

- ``None`` is a COLLECTION FAILURE (the glob itself failed, or OpenVPN is
  running while no socket is readable). The server prunes nothing. Rule 2 of
  wireguard.py, unchanged.
- ``{"instances": []}`` means a successful read of a host with nothing to
  monitor: no socket AND no ``openvpn`` process. That is the documented
  PRUNE-ALL, so it must never be reported for a host that merely forgot the
  two config lines -- see :func:`_openvpn_is_running`.
- A socket that exists but cannot be read is listed with an ``error`` and NO
  ``clients`` key: a PER-INSTANCE null that freezes that instance's rows and
  its trigger. One broken instance is never folded into a host-wide ``None``,
  because the other instances are a real reading.
- AGES, NOT TIMESTAMPS (rule 3 of wireguard.py), computed from the agent clock
  and anchored server-side to ``received_at``. A negative age -- a host whose
  clock stepped backwards -- is ``None``, never 0.
- Bytes are per-session counters that reset on reconnect; they ship RAW and the
  server rates them with counter-reset handling.
- Secrets never travel. Nothing in ``status 3`` / ``state`` is secret, but the
  ``version`` banner is trimmed to ``OpenVPN <version>`` (see
  :func:`_parse_version`) and no ``management-*`` password is ever sent or
  read.
"""

import glob
import os
import socket
import stat
import time

import psutil

from fivenines_agent.debug import debug, log

# Runtime directories globbed for management sockets, in report order. These are
# the conventional per-instance runtime dirs, created by the openvpn package's
# tmpfiles.d rather than by a unit's RuntimeDirectory= (measured: Debian 12 and
# Ubuntu 24.04 ship no RuntimeDirectory= in any openvpn unit).
#
# Their modes differ per distro and BOTH are hostile to an unprivileged reader,
# in different ways -- see the README for the per-distro recipe:
#   Debian/Ubuntu  /run/openvpn-server, /run/openvpn-client  0710 root:root
#                  /run/openvpn                              0755 root:root
#   RHEL-family    /run/openvpn-server, /run/openvpn-client  0750 root:openvpn
#                  (no /run/openvpn at all)
# 0710 root:root has no group to join, so on Debian only /run/openvpn is
# reachable without an operator override. This is why an unreadable directory
# must never be mistaken for an empty one -- see _discover_sockets.
#
# The directory a socket sits in is NOT used to decide the instance's mode --
# that comes from the daemon's own `status` answer -- it is only where we look.
RUNTIME_DIRS = (
    "/run/openvpn-server",
    "/run/openvpn",
    "/run/openvpn-client",
)

# Socket filename pattern inside those directories.
_SOCKET_GLOB = "*.sock"

# Per-instance socket timeout (seconds). The management interface answers from
# memory in microseconds; the ceiling exists only so a wedged daemon -- the
# exact state this collector reports on -- cannot eat the collect tick.
_SOCKET_TIMEOUT = 5

# Wall-clock budget for the WHOLE instance loop (seconds), the docker
# COLLECT_DEADLINE posture. _SOCKET_TIMEOUT alone is not enough: it bounds one
# instance, and a host with several wedged daemons would multiply it straight
# past the unit's WatchdogSec=90. Instances not reached before the deadline are
# still LISTED, with an error -- never dropped, which would read as a prune.
_COLLECT_DEADLINE = 25

# Wall-clock budget for the capability PROBE's whole loop (seconds). The probe
# needs its own, and needs it to be tighter: it runs inside PermissionProbe,
# which has no timeout wrapper of its own, on the same watchdog-bounded loop --
# so an unbounded probe is the same outage as an unbounded collection, reached
# through a different door. Without it the cost is _SOCKET_TIMEOUT per socket
# with nothing capping the total: 64 sockets x 5s = 320s, comfortably past the
# unit's WatchdogSec=90.
#
# This does not need a WEDGED daemon to happen. The management interface serves
# ONE client at a time, so any other attached client -- an operator's `nc`, a
# second monitoring tool -- leaves the agent's read queued in the listen backlog
# until the per-socket timeout fires, on every socket, on every probe.
#
# The probe and the collector can land in the SAME watchdog window (the
# permission refresh runs immediately before _collect_metrics, between two
# wd.notify() calls) alongside ping's 30s and docker's 25s, so the total stays
# small. But it must NOT equal _SOCKET_TIMEOUT: the probe stops at the first
# socket that greets it, so one stalled socket sorting first would then consume
# the entire budget and every later socket would hit the spent-budget bail --
# reporting the capability unavailable on a host whose other instances answer
# fine. The per-socket timeout is shortened instead, so the budget covers
# several attempts. A healthy daemon greets in microseconds; these only bound a
# pathological one.
_PROBE_SOCKET_TIMEOUT = 2
_PROBE_DEADLINE = 10

# Hard ceiling on how many sockets one tick will look at. Past it the tick is a
# COLLECTION FAILURE rather than a truncated list: a short `instances` array is
# indistinguishable from a shrunken one, so the server would prune every
# instance past the cut (the wireguard "do not cap the peers array" rule). The
# realistic ceiling is an MSP running a few dozen instances on one box, and
# these directories are root-owned, so exceeding this means something is wrong.
_MAX_INSTANCES = 64

# Cap on the bytes read from one instance's connection. A status answer for a
# large server is under a megabyte; this only stops an unbounded read from
# OOM-ing the agent. Hitting it errors THAT instance (frozen, safe) rather than
# shipping a truncated client list (pruned, unsafe).
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Socket read chunk size, in bytes.
_RECV_CHUNK_BYTES = 64 * 1024

# Ceiling on any single string copied out of the daemon's answer (common names,
# addresses, ciphers, error reasons). Real values are far shorter; the bound
# keeps one absurd field from riding the whole tick.
_MAX_FIELD_CHARS = 200

# The management protocol's line vocabulary.
#
# `>`-prefixed lines are ASYNCHRONOUS REAL-TIME NOTIFICATIONS (`>INFO:` on
# connect, plus `>CLIENT:`, `>LOG:`, `>STATE:`, `>BYTECOUNT:`, `>HOLD:`, ...)
# which the daemon can interleave with a command's answer at any time. They are
# skipped everywhere a response is read; treating one as a data line is how a
# parser ends up shipping a phantom row.
_ASYNC_PREFIX = ">"
_END = "END"
# The unsolicited greeting the daemon writes the instant it ACCEPTS a peer, and
# the only positive proof of authorization available before sending anything.
# Measured verbatim: ">INFO:OpenVPN Management Interface Version 5 -- type
# 'help' for more info".
_GREETING_PREFIX = ">INFO:"
_ERROR_PREFIX = "ERROR:"
_SUCCESS_PREFIX = "SUCCESS:"

# What the daemon writes (with no trailing newline, so it never completes a
# line) when `management ... unix` is guarded by a password file. The agent
# never sends one, so the read would otherwise just stall until the timeout and
# report a uselessly generic reason.
_PASSWORD_PROMPT = "ENTER PASSWORD"  # nosec B105  # the management protocol's prompt text, not a credential

# The reason reported when the daemon closes the connection before sending its
# `>INFO:` greeting. Measured (see the module docstring): that is precisely what
# a `management-client-group` mismatch looks like from this side, since the
# connect() itself succeeds against a 0777 socket.
_REJECTED_REASON = (
    "closed by the daemon before the greeting "
    "(management-client-group must name the agent's primary group)"
)

# `status 3` is TAB-separated; `state` is COMMA-separated regardless of the
# status format. Two different separators in one protocol, both measured.
_STATUS_SEP = "\t"
_STATE_SEP = ","

# `status 3` line tags we read. Everything else the answer carries
# (ROUTING_TABLE rows, GLOBAL_STATS, the TITLE banner) is deliberately ignored:
# the routing table is a second view of the same sessions keyed by virtual
# address, and re-deriving clients from it would double-count under duplicate-cn.
_STATUS_TIME = "TIME"
_STATUS_HEADER = "HEADER"
_STATUS_CLIENT_LIST = "CLIENT_LIST"

# First line of a NON-server instance's status answer. A client / point-to-point
# instance does not go through OpenVPN's multi-client status writer at all: it
# prints this statistics block instead, in every status format. Its presence is
# how "client mode" is positively identified rather than assumed from the
# absence of a client list -- see _parse_status.
_STATUS_CLIENT_BANNER = "OpenVPN STATISTICS"

# `status 3` CLIENT_LIST columns, mapped BY HEADER NAME and never by index (the
# HAProxy CSV lesson): the column set grew across 2.x -- Client ID / Peer ID in
# 2.4, Data Channel Cipher in 2.5 -- so a positional read silently shifts every
# value on an older daemon.
_COL_COMMON_NAME = "Common Name"
_COL_REAL_ADDRESS = "Real Address"
_COL_VIRTUAL_ADDRESS = "Virtual Address"
_COL_USERNAME = "Username"
_COL_BYTES_RECEIVED = "Bytes Received"
_COL_BYTES_SENT = "Bytes Sent"
_COL_CONNECTED_SINCE = "Connected Since (time_t)"
_COL_CIPHER = "Data Channel Cipher"

# OpenVPN's "this field has no value" sentinel, written into CLIENT_LIST cells
# that are not set (no --auth-user-pass-verify username, no negotiated cipher).
# It maps to "" -- the daemon reported no value -- which is deliberately
# DIFFERENT from None, which this collector reserves for "this daemon version
# has no such column at all". The two are genuinely different operator actions
# ("nothing to see" vs "upgrade OpenVPN to see it").
_UNDEF = "UNDEF"

# Prefix of the `version` answer line we keep.
_VERSION_LINE_PREFIX = "OpenVPN Version:"

# Process names that mean "OpenVPN is running on this host". Only consulted when
# the glob found NOTHING, to tell an honest empty host from one whose instances
# simply have no management socket configured. See _openvpn_is_running.
_OPENVPN_PROCESS_NAMES = frozenset({"openvpn", "openvpn.exe"})

# How long the "is an openvpn process running" answer is reused (seconds).
# Whether OpenVPN is installed and running is near-static, and this scan is only
# reached on hosts with no socket to read -- where without a cache it is a full
# process walk every tick, forever, to learn the same thing. Staleness costs at
# most one refresh window of delay in switching between null and [].
_PROCESS_SCAN_TTL = 300

# Rotating start offset for the instance loop; see _rotated. The modulus is
# large and independent of the instance count -- it exists only to keep the
# counter bounded in a process that runs for months.
_ROTATION_MODULUS = 2**31
_rotation = 0

# Cache backing _openvpn_is_running: (monotonic stamp, last answer).
_process_scan_at = 0.0
_process_scan_result = None


class _DiscoveryError(Exception):
    """A runtime directory we could not read, so the glob cannot be trusted.

    Distinct from :class:`_InstanceError` because the blast radius is different:
    an instance error is one frozen instance, this is the whole host's reading.
    It exists so "blind" can never be reported as "empty" -- see
    :func:`_discover_sockets`.
    """


class _InstanceError(Exception):
    """An instance we could not read. Its message becomes the entry's ``error``.

    Deliberately PER-INSTANCE. Every failure this collector meets in practice --
    a refused socket, a wedged daemon, a status answer in a shape we do not
    understand -- concerns one daemon, and the other instances on the host are a
    perfectly real reading. Folding one of these into a host-wide ``None`` would
    throw away good data; folding it into a SILENT OMISSION would be far worse,
    because the instance would vanish from a list the server reads as complete.
    """


# --- discovery -------------------------------------------------------------


def _discover_sockets():
    """Return the management socket paths to read, in a stable order.

    Sorted within each runtime directory (so a tick's instance order does not
    depend on directory iteration order) and de-duplicated by real path, which
    matters on hosts where /var/run is a symlink to /run or where an operator
    has symlinked one instance's socket into a second directory.

    An UNREADABLE runtime directory raises, and that is load-bearing rather than
    tidiness. ``glob.glob`` swallows EACCES and returns ``[]``, which is the same
    answer it gives for a host with no OpenVPN at all -- so without this check
    the measured RHEL case (the openvpn RPM ships /run/openvpn-server as 0750
    root:openvpn, and the agent is not in that group until an operator adds it)
    would come back "empty" rather than "blind". On a host where the daemon is
    also invisible to the process scan, that empty read is the documented
    PRUNE-ALL. Blind must never be able to masquerade as empty.

    Only real sockets are returned. Anything else in the directory -- a lock
    file, a leftover regular file, a dangling symlink -- is skipped rather than
    dialled, so the agent never opens something that merely matched the glob.

    Returns ``(paths, blind)``. ``blind`` is the unreadable directories, and the
    caller must SURFACE them rather than drop them: finding a socket elsewhere
    does not make an unreadable directory harmless, because the instances inside
    it would otherwise vanish from an array the server reads as the complete set
    -- the same silent prune :func:`_is_socket` refuses to perform one level
    down. They become per-directory error entries, so a partially-blind tick is
    never indistinguishable from a complete one.
    """
    paths = []
    seen = set()
    blind = []
    for directory in RUNTIME_DIRS:
        if os.path.isdir(directory) and not os.access(directory, os.R_OK | os.X_OK):
            # Note it, but KEEP GOING. Aborting here would throw away sockets
            # already found in the other directories, and on Debian that is the
            # normal case, not an edge one: /run/openvpn-server and
            # /run/openvpn-client ship 0710 root:root, so an unreadable
            # directory sits next to the readable /run/openvpn that actually
            # holds the operator's socket.
            blind.append(directory)
            continue
        # Explicit "/" rather than os.path.join: these are Linux-only absolute
        # paths, so on Windows (where the full suite runs in CI) os.path.join
        # would build "/run/openvpn-server\\*.sock" through ntpath. glob accepts
        # forward slashes on every platform.
        for path in sorted(glob.glob(f"{directory}/{_SOCKET_GLOB}")):
            if not _is_socket(path):
                continue
            key = os.path.realpath(path)
            if key in seen:
                continue
            seen.add(key)
            paths.append(path)

    if blind and not paths:
        # Nothing found anywhere AND something unreadable: we cannot tell an
        # empty host from a blind one, so the whole tick fails.
        raise _DiscoveryError(f"not readable: {', '.join(blind)}")
    return paths, blind


def _is_socket(path):
    """True when *path* is a unix socket, or when we could not tell.

    The error handling is asymmetric on purpose, because the two failures mean
    opposite things. A path that is GONE (unlinked between the glob and the
    stat, or a dangling symlink) is genuinely nothing to dial, so it is skipped.
    Any OTHER stat failure -- EACCES on a symlink into a directory the agent
    cannot traverse, which is precisely the operator workaround the realpath
    dedup exists for -- is NOT evidence of absence, and skipping it would drop
    the instance out of an array the server reads as the complete set, pruning
    its rows and false-resolving its incidents. So it is kept, dialled, and
    reported as a per-instance error instead: frozen, not deleted.
    """
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError:
        return True


def _openvpn_is_running():
    """True when an ``openvpn`` process exists on this host.

    Consulted ONLY when the glob found no socket at all, and it is what keeps
    the two empty-looking outcomes apart:

    - no socket and no process -> ``{"instances": []}``, an honest reading of a
      host with no OpenVPN, which the server may prune against;
    - no socket but a RUNNING daemon -> ``None``, a collection failure. This is
      the host that forgot (or lost) the two config lines, and reporting "zero
      instances" for it would prune every instance row and false-resolve every
      open incident for a VPN that is up and carrying traffic.

    A full process scan is not free (measured: ~12ms at 700 processes, ~33ms at
    2000), and the docstring used to claim it was paid "only on a
    misconfiguration". That was wrong: the dominant population under "no socket"
    is a host where the operator enabled the collector fleet-wide and simply has
    no OpenVPN installed, which answers the same constant False forever -- and
    the no-match branch is the one with no early exit, so it always pays the
    FULL scan. So the answer is cached for :data:`_PROCESS_SCAN_TTL`, the
    packages.py / ip.py precedent: "is an openvpn process running" is near-static
    and a few minutes of staleness only delays the null-vs-[] distinction by one
    refresh. A match still returns as soon as it is found.
    """
    global _process_scan_at, _process_scan_result
    monotonic = time.monotonic()
    if (
        _process_scan_result is not None
        and monotonic - _process_scan_at < _PROCESS_SCAN_TTL
    ):
        return _process_scan_result

    running = False
    for process in psutil.process_iter(["name"]):
        name = (process.info.get("name") or "").lower()
        if name in _OPENVPN_PROCESS_NAMES:
            running = True
            break
    _process_scan_at = monotonic
    _process_scan_result = running
    return running


# --- management protocol ---------------------------------------------------


class _Management:
    """Line reader over one instance's management connection.

    Bounded on three axes, because each guards a different failure: a WALL-CLOCK
    deadline (a scalar ``settimeout`` is per-recv and resets on every chunk, so
    a trickling daemon could otherwise read for far longer than the budget --
    the haproxy ``_socket_show_stat`` lesson), a TOTAL BYTE cap, and EOF
    detection that distinguishes "closed before saying anything" (the group
    rejection) from "closed mid-answer".
    """

    def __init__(self, sock, deadline):
        self._sock = sock
        self._deadline = deadline
        self._buffer = bytearray()
        self._received = 0
        self._eof = False

    def _remaining(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise _InstanceError(self._stall_reason("timed out"))
        return remaining

    def _stall_reason(self, fallback):
        """Name the stall precisely when the pending bytes explain it."""
        pending = bytes(self._buffer).decode("utf-8", "replace")
        if _PASSWORD_PROMPT in pending:
            return "management password required (the agent never sends one)"
        return fallback

    def _fill(self):
        remaining = self._remaining()
        self._sock.settimeout(remaining)
        try:
            chunk = self._sock.recv(_RECV_CHUNK_BYTES)
        except socket.timeout:
            raise _InstanceError(self._stall_reason("timed out"))
        except OSError as e:
            raise _InstanceError(f"socket error: {_short(e)}")
        if not chunk:
            self._eof = True
            return
        self._received += len(chunk)
        if self._received > _MAX_RESPONSE_BYTES:
            # Never the partial bytes: a truncated client list would read as a
            # shrunken one and prune the clients we simply did not receive.
            raise _InstanceError("response exceeded the byte cap")
        self._buffer += chunk

    def _read_line(self):
        while True:
            index = self._buffer.find(b"\n")
            if index >= 0:
                line = bytes(self._buffer[:index])
                del self._buffer[: index + 1]
                return line.decode("utf-8", "replace").rstrip("\r")
            if self._eof:
                if self._received == 0:
                    raise _InstanceError(_REJECTED_REASON)
                raise _InstanceError(self._stall_reason("connection closed before END"))
            self._fill()

    def command(self, text):
        """Send one command and return its answer as a list of data lines.

        A command answers either with a block terminated by ``END`` or with a
        single ``SUCCESS:`` / ``ERROR:`` line, and the daemon may interleave
        ``>``-prefixed real-time notifications into either. An answer that never
        reaches a terminator raises rather than returning what arrived so far --
        a half-read ``status`` is a short client list, which is the one shape
        that must never reach the server as if it were complete.
        """
        try:
            self._sock.settimeout(self._remaining())
            self._sock.sendall(text.encode("ascii") + b"\n")
        except OSError as e:
            # A peer the daemon already rejected can fail here with EPIPE before
            # a single byte has arrived; that is the group mismatch, not an
            # anonymous socket fault.
            if self._received == 0:
                raise _InstanceError(_REJECTED_REASON)
            raise _InstanceError(f"socket error: {_short(e)}")

        lines = []
        while True:
            line = self._read_line()
            if line.startswith(_ASYNC_PREFIX):
                continue
            if line == _END or line.startswith(_SUCCESS_PREFIX):
                return lines
            if line.startswith(_ERROR_PREFIX):
                raise _InstanceError(f"'{text}' refused: {_short(line)}")
            lines.append(line)

    def read_greeting(self):
        """Read the daemon's first line without sending anything.

        Used only by :func:`probe_management_access`. Shares the byte cap, the
        deadline and -- crucially -- the EOF-before-the-first-byte handling with
        every other read, so the probe reports :data:`_REJECTED_REASON` in
        exactly the case the collector does.
        """
        return self._read_line()

    def quit(self):
        """Best-effort ``quit`` so the daemon closes its side cleanly.

        Never raises and never waits for the answer: by this point the data is
        already collected, and a failure here would turn a good read into an
        error entry.
        """
        try:
            self._sock.sendall(b"quit\n")
        except OSError:
            pass


# --- parsing ---------------------------------------------------------------


def _short(value):
    """Bound any string copied out of the daemon's answer."""
    return str(value).strip()[:_MAX_FIELD_CHARS]


def _cell(record, column):
    """Read a CLIENT_LIST cell by column name.

    ``None`` when the daemon's HEADER has no such column (an older OpenVPN that
    cannot report it), ``""`` when the column exists and the daemon wrote
    nothing or its ``UNDEF`` sentinel. The distinction is the whole reason this
    helper exists -- see :data:`_UNDEF`.
    """
    if column not in record:
        return None
    value = record[column].strip()
    if value == _UNDEF:
        return ""
    return value[:_MAX_FIELD_CHARS]


def _as_int(value):
    """Parse a counter cell to int, or ``None`` when absent/unparseable."""
    if value is None:
        return None
    try:
        return int(value.strip())
    except (AttributeError, TypeError, ValueError):
        return None


def _age(value, now):
    """Seconds since a unix timestamp cell, or ``None``.

    ``None`` covers an absent, empty or unparseable timestamp AND a NEGATIVE age
    -- a timestamp in the future, which happens when the clock steps backwards
    (NTP correcting a skewed host, a VM restored from a snapshot). Clamping that
    to 0 is the dangerous option, not the safe one: the server reconstructs
    ``connected_at = received_at - age``, so a 0 would report every session as
    having just connected and would silently reset the uptime of a tunnel that
    has been up for months. ``None`` means "no reading this tick" and the server
    keeps what it already knows.
    """
    timestamp = _as_int(value)
    if timestamp is None:
        return None
    age = int(now) - timestamp
    if age < 0:
        return None
    return age


def _parse_version(lines):
    """Extract ``OpenVPN <version>`` from the ``version`` answer, or ``None``.

    The answer's first line is the FULL build banner --
    ``OpenVPN 2.6.14 aarch64-unknown-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4]
    [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]`` -- and only the first two
    tokens of it travel. The remainder is build platform and compiled-in
    feature flags: it is of no use to the dashboard and is exactly the kind of
    detail worth not accumulating in a database, so the trim is part of the
    contract rather than cosmetic.
    """
    for line in lines:
        if line.startswith(_VERSION_LINE_PREFIX):
            banner = line.removeprefix(_VERSION_LINE_PREFIX).strip()
            return " ".join(banner.split()[:2])[:_MAX_FIELD_CHARS] or None
    return None


def _parse_status(lines, now):
    """Parse a ``status 3`` answer into ``(mode, status_age_s, client rows)``.

    MODE IS POSITIVELY IDENTIFIED, never inferred from an absence. A server
    instance always emits the ``HEADER<TAB>CLIENT_LIST`` line -- unconditionally,
    even with zero clients connected -- and a client / point-to-point instance
    emits the ``OpenVPN STATISTICS`` block instead. An answer carrying NEITHER
    is a shape we do not understand and errors the instance, because the
    tempting fallback ("no client list, so it must be a client") would report a
    server whose answer we mis-read as a healthy client with zero sessions.

    A CLIENT_LIST row whose field count disagrees with its own HEADER raises:
    the two come from the same daemon in the same answer, so a mismatch means
    the format is not what we think it is, and mapping the cells anyway would
    feed shifted values into the byte counters the server rates.

    ROUTING_TABLE rows and GLOBAL_STATS are ignored on purpose: the routing
    table is a second view of the same sessions, and folding it in would
    double-count every session under duplicate-cn.
    """
    header = None
    rows = []
    status_age = None
    is_server = False
    is_client = False

    for line in lines:
        if line.strip() == _STATUS_CLIENT_BANNER:
            is_client = True
            continue

        fields = line.split(_STATUS_SEP)
        tag = fields[0].strip()

        if tag == _STATUS_TIME and len(fields) >= 3:
            status_age = _age(fields[2], now)
        elif (
            tag == _STATUS_HEADER
            and len(fields) >= 2
            and fields[1].strip() == _STATUS_CLIENT_LIST
        ):
            header = [f.strip() for f in fields[2:]]
            is_server = True
        elif tag == _STATUS_CLIENT_LIST:
            if header is None:
                raise _InstanceError("CLIENT_LIST row before its HEADER")
            if len(fields) - 1 != len(header):
                raise _InstanceError(
                    f"CLIENT_LIST row has {len(fields) - 1} fields, "
                    f"HEADER declares {len(header)}"
                )
            rows.append(dict(zip(header, fields[1:])))

    if is_server:
        return "server", status_age, rows
    if is_client:
        return "client", status_age, []
    raise _InstanceError("unrecognized 'status 3' answer")


def _identity(row):
    """Return ``(collapse key, identity value, identity source)`` for a row.

    Identity is Common Name, else Username.

    Keying on the Common Name alone looks obviously right and is wrong on a
    deployment that is completely ordinary: a server running
    ``--verify-client-cert none`` (username/password auth, no client certs)
    writes OpenVPN's ``UNDEF`` sentinel into the Common Name column for EVERY
    session, and puts the real identity in ``Username``. With a CN-only key all
    of those sessions share one entry -- summed bytes, one name, and, because
    the server reads a non-empty ``clients`` array as the COMPLETE set, every
    other client row on that instance pruned on every tick. A silent
    under-report that renders as one healthy client.

    So the Username is the fallback identity, which is exactly what OpenVPN's
    own ``--username-as-common-name`` would have written into the CN column.
    Only when NEITHER column carries an identity is the row genuinely ambiguous,
    and then the instance is refused rather than guessed at -- the same answer
    ambiguity gets at the socket boundary. A missing Common Name COLUMN
    (``_cell`` -> None on a daemon too old to report it) lands here too: absent
    is not an identity either.
    """
    for source, column in (("cn", _COL_COMMON_NAME), ("user", _COL_USERNAME)):
        value = _cell(row, column)
        if value:
            # The key is namespaced by SOURCE, so a username can never collapse
            # into a certificate CN that happens to spell the same. On a
            # --verify-client-cert optional instance both kinds of session share
            # one daemon, and merging them would prune the second real client
            # and misreport the merged row as duplicate-cn.
            #
            # The source TRAVELS, as `identity_source`. Keeping the namespace
            # agent-side only would have moved the collision rather than removed
            # it: the server keys a row on common_name, so it would see two
            # entries under one key and be back where it started. It is also
            # worth knowing on its own -- "this identity came from a
            # certificate" and "this identity came from a login" are different
            # facts about a client.
            return (source, value), value, source
    raise _InstanceError(
        f"CLIENT_LIST row carries no identity in '{_COL_COMMON_NAME}' "
        f"or '{_COL_USERNAME}'"
    )


def _collapse_clients(rows, now):
    """Fold CLIENT_LIST rows into one entry per (identity, identity source).

    ``duplicate-cn`` lets several sessions share a Common Name (a site that
    reconnects while the old session is still open, a customer using one profile
    on laptop and phone). The CN is the identity the server keys a row on, so
    shipping one entry per SESSION would mint a brand-new row on every roaming
    reconnect and leave the old one to be pruned -- the row's history would
    restart each time the link flapped.

    So sessions collapse: ``sessions`` counts them, bytes are SUMMED, and
    ``connected_age_s`` is the OLDEST session's (the largest age), which is the
    honest answer to "how long has this site been connected". The descriptive
    fields come from that same oldest session, so they never mix two sessions'
    values.

    IDENTITY IS CN, THEN USERNAME -- see :func:`_identity`. Keying on the CN
    alone is wrong on one very ordinary deployment, and wrong in the direction
    that destroys data.
    """
    collapsed = {}
    for row in rows:
        key, name, source = _identity(row)
        age = _age(row.get(_COL_CONNECTED_SINCE), now)
        received = _as_int(row.get(_COL_BYTES_RECEIVED))
        sent = _as_int(row.get(_COL_BYTES_SENT))

        entry = collapsed.get(key)
        if entry is None:
            collapsed[key] = {
                "common_name": name,
                "identity_source": source,
                "real_address": _cell(row, _COL_REAL_ADDRESS),
                "virtual_address": _cell(row, _COL_VIRTUAL_ADDRESS),
                "username": _cell(row, _COL_USERNAME),
                "sessions": 1,
                "connected_age_s": age,
                "bytes_received": received,
                "bytes_sent": sent,
                "cipher": _cell(row, _COL_CIPHER),
            }
            continue

        entry["sessions"] += 1
        entry["bytes_received"] = _add(entry["bytes_received"], received)
        entry["bytes_sent"] = _add(entry["bytes_sent"], sent)
        # Strictly older wins, so the descriptive fields and the age stay
        # consistent with each other (and a tie keeps the first row seen).
        if age is not None and (
            entry["connected_age_s"] is None or age > entry["connected_age_s"]
        ):
            entry["connected_age_s"] = age
            entry["real_address"] = _cell(row, _COL_REAL_ADDRESS)
            entry["virtual_address"] = _cell(row, _COL_VIRTUAL_ADDRESS)
            entry["username"] = _cell(row, _COL_USERNAME)
            entry["cipher"] = _cell(row, _COL_CIPHER)

    return list(collapsed.values())


def _add(left, right):
    """Sum two counters where either may be ``None`` (absent column)."""
    if left is None:
        return right
    if right is None:
        return left
    return left + right


def _parse_state(lines, now):
    """Parse the ``state`` answer, or ``None`` when it carries no state.

    COMMA-separated (the `status 3` tab separator does not apply here), with the
    fields ``time, name, description, local IPv4, remote address, remote port,
    local address, local port, local IPv6``. Everything after the state name is
    optional and routinely empty -- a client in ``CONNECTING`` has no addresses
    yet -- so only ``name`` is required.

    Returns the FIRST parseable line, which is correct only because the bare
    ``state`` command answers with exactly one: the CURRENT state. (``state N``
    would return the last N oldest-first, where taking the first line would
    report history as current -- so if this ever sends an argument, this reads
    the last line instead.)
    """
    for line in lines:
        fields = [f.strip() for f in line.split(_STATE_SEP)]
        if len(fields) < 2 or not fields[1]:
            continue
        local_ip = _pick(fields, 3) or _pick(fields, 8)
        return {
            "name": _short(fields[1]),
            "description": _pick(fields, 2),
            "local_ip": local_ip,
            "remote": _remote(_pick(fields, 4), _pick(fields, 5)),
            "age_s": _age(_pick(fields, 0), now),
        }
    return None


def _pick(fields, index):
    """Optional `state` field by position, or ``None`` when absent/empty."""
    if index >= len(fields):
        return None
    return fields[index][:_MAX_FIELD_CHARS] or None


def _remote(address, port):
    """Join the remote server's address and port the way the payload wants it.

    An IPv6 literal is BRACKETED, because a bare join produces
    ``2001:db8::1:1194`` -- from which no consumer can recover the host or the
    port. This is not hypothetical shape-lawyering: ``proto udp6`` with an IPv6
    ``remote`` is an ordinary client config. Brackets also make this field agree
    with ``clients[].real_address``, which OpenVPN itself writes bracketed, so
    one payload does not carry two encodings of the same concept.
    """
    if not address:
        return None
    if not port:
        return address
    host = f"[{address}]" if ":" in address else address
    return f"{host}:{port}"[:_MAX_FIELD_CHARS]


# --- per-instance read -----------------------------------------------------


def _instance_name(path):
    """Instance name: the socket's filename without its extension."""
    return os.path.splitext(os.path.basename(path))[0][:_MAX_FIELD_CHARS]


def _connect(path, deadline):
    """Open the management socket, or raise :class:`_InstanceError`.

    Note that succeeding here proves nothing about authorization: the socket is
    mode 0777 (OpenVPN umask(0)s before bind), so every local user connects and
    an unauthorized one is dropped immediately afterwards. That refusal surfaces
    in :meth:`_Management._read_line` as :data:`_REJECTED_REASON`.
    """
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        # Non-POSIX platform. OpenVPN on Windows has TCP management only, which
        # this collector deliberately does not read, so there is nothing here.
        raise _InstanceError("unix sockets are unavailable on this platform")
    remaining = min(_SOCKET_TIMEOUT, deadline - time.monotonic())
    if remaining <= 0:
        # The collection budget is already spent. Bail out BEFORE opening the
        # socket: settimeout(0) would not mean "give up instantly", it would put
        # the socket in NON-BLOCKING mode and report the expired budget as a
        # confusing EAGAIN. This reports the same "timed out" the read path does.
        raise _InstanceError("timed out")
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(remaining)
        sock.connect(path)
    except OSError as e:
        _close(sock)
        raise _InstanceError(f"connect failed: {_short(e)}")
    return sock


def _close(sock):
    try:
        sock.close()
    except OSError:  # pragma: no cover - close() on a dead socket is a no-op
        pass


def _read_instance(path, now, deadline):
    """Read one instance, returning its full payload entry.

    Raises :class:`_InstanceError` with the operator-facing reason, which the
    caller turns into the entry's ``error``.
    """
    sock = _connect(path, deadline)
    try:
        client = _Management(sock, deadline)
        version = _parse_version(client.command("version"))
        mode, status_age, rows = _parse_status(client.command("status 3"), now)
        # `state` is asked only of a client instance, and reported only for one.
        # A server's state machine sits at CONNECTED from startup to shutdown,
        # so it carries no signal there, while for a client it IS the signal:
        # RECONNECTING / WAIT / AUTH is how a down tunnel shows up.
        state = _parse_state(client.command("state"), now) if mode == "client" else None
        client.quit()
        return {
            "name": _instance_name(path),
            "socket": path,
            "mode": mode,
            "version": version,
            "status_age_s": status_age,
            "clients": _collapse_clients(rows, now),
            "state": state,
        }
    finally:
        _close(sock)


def _blind_entry(directory):
    """A per-DIRECTORY error entry for a runtime dir we could not read.

    The instances inside it cannot even be enumerated, so they cannot be listed
    individually -- but leaving the directory out entirely would make a
    partially-blind tick indistinguishable from a complete one, and the server
    reads `instances` as the complete set. This entry says "there is something
    here I could not read" in the vocabulary the contract already has for that,
    so the operator sees it and the server does not conclude the instances were
    removed. ``socket`` carries the directory rather than a socket path: it is
    the most specific thing we can honestly name.
    """
    return {
        "name": os.path.basename(directory.rstrip("/")),
        "socket": directory,
        "error": "runtime directory not readable",
    }


def _error_entry(path, reason):
    """A per-instance null: listed, named, with no ``clients`` key.

    The missing ``clients`` key is the contract: the server keeps this
    instance's rows untouched and freezes its trigger rather than resolving it.
    An entry with ``clients: []`` would instead say "this instance is up and
    nobody is connected", which is the false all-clear.
    """
    return {"name": _instance_name(path), "socket": path, "error": _short(reason)}


def _rotated(paths):
    """Return *paths* rotated by one position further than the last tick.

    The instance loop shares ONE wall-clock budget, so with a fixed start the
    same prefix is read every tick and everything behind a slow instance is
    starved DETERMINISTICALLY -- at _SOCKET_TIMEOUT=5 only five instances fit in
    _COLLECT_DEADLINE=25, while _MAX_INSTANCES allows 64. That is not a slow
    tick, it is a permanent blind spot: the starved instances ship an `error`
    every tick, which the server reads as a per-instance null and FREEZES, so a
    perfectly healthy VPN behind a wedged one never reports again and its open
    incidents never resolve.

    Rotating the start offset is the same fix `agent._rotated_ping_targets`
    already applies to the ping map for the same reason. Every instance is still
    LISTED every tick (the array stays complete, so nothing is pruned); the
    rotation only decides which ones get READ when the budget runs short, so
    over K ticks each instance gets its turn. The caller re-orders the results
    back into discovery order, so the payload itself stays stable.
    """
    if not paths:
        return paths
    global _rotation
    start = _rotation % len(paths)
    # Advance independently of the CURRENT count. Folding the cursor into
    # len(paths) resets its phase whenever an instance appears or disappears,
    # and a periodically flapping instance (a crash-looping daemon whose socket
    # comes and goes) then pins the cursor near zero -- measured: with the count
    # alternating 2/3, the third instance went unread for 40 straight ticks,
    # which is the permanent blind spot this function exists to prevent.
    _rotation = (_rotation + 1) % _ROTATION_MODULUS
    return paths[start:] + paths[:start]


@debug("openvpn")
def openvpn_metrics():
    """Collect every OpenVPN instance exposing a management unix socket.

    Returns ``{"instances": [...]}`` or ``None``. See the module docstring for
    what each shape commits the server to.

    DO NOT add an agent-side cap on an instance's ``clients`` array. It looks
    like the obvious defense for a hub with thousands of sessions, but a
    truncated array is indistinguishable from a shrunken one, so the server
    would vanish-prune every client past the cut. The bound belongs server-side,
    where a capped tick can also be marked unsafe to prune.
    """
    try:
        paths, blind = _discover_sockets()
    except (_DiscoveryError, OSError) as e:
        # An unreadable runtime directory is a collection failure: we cannot
        # tell an empty host from a blind one, and guessing "empty" is the
        # documented prune-all.
        log(f"OpenVPN: could not list the runtime directories: {e}", "error")
        return None

    if blind:
        # An operator-visible level, not debug: this is a step they have to take
        # (see the README's per-distro recipe), and the default log level is
        # info, so a debug line would never reach them.
        log(
            "OpenVPN: runtime directories not readable, so any instances inside "
            f"them go unreported: {', '.join(blind)}",
            "error",
        )

    if not paths:
        try:
            running = _openvpn_is_running()
        except Exception as e:
            log(f"OpenVPN: could not enumerate processes: {e}", "error")
            return None
        if running:
            log(
                "OpenVPN: a daemon is running but no management socket was found "
                f"in {', '.join(RUNTIME_DIRS)}; add 'management <path> unix' and "
                "'management-client-group' to each instance",
                "error",
            )
            return None
        return {"instances": [_blind_entry(d) for d in blind]}

    if len(paths) > _MAX_INSTANCES:
        # Reporting the first _MAX_INSTANCES would prune the rest, so the whole
        # tick fails instead.
        log(
            f"OpenVPN: found {len(paths)} management sockets, more than the "
            f"{_MAX_INSTANCES} an instance list may carry",
            "error",
        )
        return None

    now = time.time()
    budget = time.monotonic() + _COLLECT_DEADLINE
    by_path = {}
    # Read in ROTATED order so a slow instance cannot starve the tail forever,
    # but emit in DISCOVERY order below: which instances get read when the
    # budget runs short should vary, the payload's shape should not.
    for path in _rotated(paths):
        deadline = min(budget, time.monotonic() + _SOCKET_TIMEOUT)
        try:
            by_path[path] = _read_instance(path, now, deadline)
        except _InstanceError as e:
            log(f"OpenVPN: instance {path} unreadable: {e}", "error")
            by_path[path] = _error_entry(path, e)
        except Exception as e:
            # Defensive: one unexpected fault must cost one instance, never the
            # whole host's reading.
            log(f"OpenVPN: instance {path} failed: {e}", "error")
            by_path[path] = _error_entry(path, f"{type(e).__name__}: {e}")
    return {
        "instances": [by_path[path] for path in paths]
        + [_blind_entry(d) for d in blind]
    }


# --- capability probe ------------------------------------------------------


def probe_management_access():
    """Return ``(available, reason)`` for the ``openvpn`` capability probe.

    PUBLIC and living here, next to the collector, for the same reason
    :data:`wireguard.WG_DUMP_ARGV` does: the probe and the read must not be two
    independent spellings of "can we get at this", one of which quietly stops
    describing the other. Discovery, the connect and the rejection semantics are
    literally the same code.

    No command is sent -- the HAProxy ``_can_access_*`` light-probe posture --
    but the greeting IS read, and that part is not optional here the way it
    would be for an ordinary service. Measured: the socket is mode 0777 (OpenVPN
    ``umask(0)``s before ``bind()``), so ``connect()`` succeeds for every local
    user, and a peer whose primary GID does not match
    ``management-client-group`` is dropped immediately afterwards without a
    byte. A connect-only probe -- or one built on ``os.access()`` -- would
    therefore report this capability AVAILABLE on every host that merely HAS a
    socket, including ones where every single tick is refused. That is the exact
    failure mode #144 called out for a probe shorter than its read.

    The FIRST reachable instance wins: the capability answers "can this agent
    read OpenVPN at all", while an individual instance that refuses is reported
    per-instance by the collector. The first failure's reason is the one kept,
    since it names a concrete socket the operator can go and look at.
    """
    try:
        paths, blind = _discover_sockets()
    except (_DiscoveryError, OSError) as e:
        return False, f"could not list the runtime directories: {_short(e)}"
    if not paths:
        # `blind` is necessarily empty here: _discover_sockets raises when it
        # found nothing AND something was unreadable, so that case never
        # reaches this branch.
        return False, f"no management socket in {', '.join(RUNTIME_DIRS)}"

    reason = None
    budget = time.monotonic() + _PROBE_DEADLINE
    for path in paths[:_MAX_INSTANCES]:
        deadline = min(budget, time.monotonic() + _PROBE_SOCKET_TIMEOUT)
        try:
            sock = _connect(path, deadline)
        except _InstanceError as e:
            reason = reason or f"{path}: {e}"
            continue
        try:
            line = _Management(sock, deadline).read_greeting()
            if line.startswith(_GREETING_PREFIX):
                return True, None
            reason = reason or f"{path}: not an OpenVPN management socket"
        except _InstanceError as e:
            reason = reason or f"{path}: {e}"
        finally:
            _close(sock)
    return False, reason
