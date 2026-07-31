"""Memcached stats-snapshot collector (server issue #497).

Memcached backs Keystone token/catalog caching in the OpenStack underlay (the
OpenMetal plan), so a saturated or heavily-evicting cache surfaces as slow auth
across the whole control plane. This collector opens one TCP connection, sends a
single ``stats`` command, reads the ``STAT <key> <value>`` lines up to the
``END`` terminator, and ships a flat whitelisted snapshot under
``data["memcached"]``. No dependency -- the memcached text protocol is a few
lines of socket I/O.

The payload is one of TWO outcomes (the php_fpm null discipline, minus the
array):

* a snapshot object -- the reachable tick; every whitelisted STAT the server
  reported, counters shipped RAW;
* ``None`` -- COLLECTION FAILURE (connection refused / timeout / a reply that is
  not a valid, ``END``-terminated stats response). The server skips the tick
  entirely rather than ingesting a zero: there is no status axis here, so
  process-down alerting stays on the generic host_port / systemd paths, and a
  merely-unreachable cache is never mistaken for an empty one.

Every ``*_total`` field is a RAW cumulative counter: the server derives the hit
ratio and per-second rates from deltas. Never diff or derive agent-side. The
whitelist is tolerant of unknown/extra STAT keys so the one extractor works
across memcached versions.
"""

import socket
import time

from fivenines_agent.debug import debug, log

# Socket timeout (seconds), matching the other single-shot TCP collectors
# (redis.py). A wedged endpoint must never hang the whole collect tick.
_TIMEOUT = 5

# The bare terminator line memcached writes at the end of a ``stats`` reply. Its
# presence is our proof of a complete, trustworthy response.
_END_LINE = "END"

# Safety cap on the accumulated reply (a real ``stats`` reply is a few KiB; this
# only guards against a wrong / hostile endpoint streaming past the ceiling
# without ever sending ``END`` -- unbounded growth would OOM the agent or, under
# the per-recv timeout, hang the whole collect tick). Matches php_fpm's
# _FCGI_MAX_BODY. Hitting it stops the read with no END, so the caller reports a
# collection failure (None).
_MAX_REPLY_BYTES = 1 << 20

# memcached STAT key -> outgoing payload key. Iteration order defines the
# snapshot's key order and must match the contract fixture. The six *_total
# keys are RAW cumulative counters (get_hits / get_misses / cmd_get / cmd_set /
# evictions / expired_unfetched); the server rate()s and ratios them, never the
# agent. Every other STAT memcached emits (pid, time, threads, the slab / item
# breakdowns, ...) is dropped: not ingested, keep the payload exact.
_FIELD_MAP = {
    "version": "version",
    "uptime": "uptime",
    "curr_connections": "curr_connections",
    "bytes": "bytes",
    "limit_maxbytes": "limit_maxbytes",
    "get_hits": "get_hits_total",
    "get_misses": "get_misses_total",
    "cmd_get": "cmd_get_total",
    "cmd_set": "cmd_set_total",
    "evictions": "evictions_total",
    "expired_unfetched": "expired_unfetched_total",
}

# The only string-valued field; every other whitelisted STAT is an integer
# counter / gauge coerced through int().
_STRING_KEYS = frozenset({"version"})


@debug("memcached_metrics")
def memcached_metrics(host="127.0.0.1", port=11211):
    """Return the memcached stats snapshot dict, or None on collection failure.

    See the module docstring for the snapshot-vs-None contract.
    """
    try:
        port = int(port)
    except (TypeError, ValueError) as e:
        # A mis-typed pushed port (None / list / dict) can never connect; keep
        # this narrow so it cannot mask a bug elsewhere in the read path.
        log(f"Error collecting Memcached metrics: invalid port {port!r}: {e}", "error")
        return None
    try:
        raw = _read_stats(host, port)
    except OSError as e:
        # Any connection / read failure -> the documented None, not an escape.
        log(f"Error collecting Memcached metrics: {e}", "error")
        return None

    # memcached frames every line with CRLF; split on "\r\n" only -- NOT
    # str.splitlines(), which also breaks on bare \n / \r / Unicode separators a
    # hostile STAT value could smuggle a phantom END line through. This keeps the
    # parse boundary identical to the read loop's byte-level END detection.
    lines = raw.decode("utf-8", errors="replace").split("\r\n")
    if _END_LINE not in lines:
        # No END terminator: the connection dropped mid-reply, the read cap /
        # deadline was hit, or the endpoint is not memcached. A truncated reply
        # is a collection failure (None), never a half-snapshot the server trusts.
        log(f"Memcached reply from {host}:{port} lacked an END terminator", "error")
        return None
    # END is a hard parse boundary: drop anything after it so a misbehaving
    # endpoint cannot append STAT lines that override the real counters.
    snapshot = _build_snapshot(_parse_stats(lines[: lines.index(_END_LINE)]))
    if "version" not in snapshot:
        # A real memcached ``stats`` reply always carries ``version``; its
        # absence means a degenerate or non-memcached endpoint (e.g. a bare
        # ``END``). Per the null contract there is no empty-but-reachable
        # snapshot -- an untrustworthy reply is a collection failure (None).
        log(f"Memcached reply from {host}:{port} carried no version stat", "error")
        return None
    return snapshot


def _read_stats(host, port):
    """Open the connection, send ``stats``, read up to the END terminator.

    Returns the raw reply bytes. Raises OSError on any socket failure, which the
    caller turns into a None (collection failure) payload.
    """
    sock = socket.create_connection((host, port), timeout=_TIMEOUT)
    try:
        sock.settimeout(_TIMEOUT)
        sock.sendall(b"stats\r\n")
        # A plain per-recv timeout RESETS every chunk, so an endpoint dribbling
        # one byte just under the timeout never trips socket.timeout and never
        # sends END -- holding the synchronous collect tick open past the systemd
        # watchdog. Bound the TOTAL read with a wall-clock deadline and shrink
        # each recv's timeout to the remaining budget, so no single blocking read
        # can run past it (the byte cap below bounds only memory, not time).
        deadline = time.monotonic() + _TIMEOUT
        data = b""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # Slow-trickle guard: no END within the total budget -> give up
                # (no END -> the caller reports a collection failure).
                log(
                    f"Memcached read from {host}:{port} exceeded the {_TIMEOUT}s deadline",
                    "error",
                )
                break
            sock.settimeout(remaining)
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            # The reply ends with a bare "END\r\n" line; stop as soon as we see
            # it rather than waiting out the socket timeout. The "\r\n" prefix
            # anchors END to its own line, so a STAT value that happens to end in
            # "END" cannot trip the check early.
            if data.startswith(b"END\r\n") or b"\r\nEND\r\n" in data:
                break
            if len(data) > _MAX_REPLY_BYTES:
                # An endpoint streaming past the ceiling without an END is wrong
                # or hostile; stop reading (no END -> collection failure) rather
                # than growing the buffer unbounded or hanging the tick.
                log(
                    f"Memcached reply from {host}:{port} exceeded {_MAX_REPLY_BYTES} bytes",
                    "error",
                )
                break
        return data
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _parse_stats(lines):
    """Parse ``STAT <key> <value>`` lines into a ``{key: value}`` dict.

    Splits each line into at most three fields so a value containing spaces
    stays intact; non-STAT lines (blank, END, an ERROR reply) are skipped.
    """
    stats = {}
    for line in lines:
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[0] == "STAT":
            stats[parts[1]] = parts[2]
    return stats


def _build_snapshot(stats):
    """Whitelist-extract the contract fields from the parsed STAT dict.

    Present keys are emitted in ``_FIELD_MAP`` order (numeric ones int()-coerced,
    ``version`` kept as a string); a whitelisted STAT that is absent or
    non-numeric is dropped, never fabricated -- version tolerance without
    inventing zeros the server would read as real.
    """
    snapshot = {}
    for stat_key, payload_key in _FIELD_MAP.items():
        if stat_key not in stats:
            continue
        if stat_key in _STRING_KEYS:
            snapshot[payload_key] = stats[stat_key]
            continue
        value = _as_int(stats[stat_key])
        if value is not None:
            snapshot[payload_key] = value
    return snapshot


def _as_int(value):
    """int(value), or None when it is not an integer (drop that one key)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
