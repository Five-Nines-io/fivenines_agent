"""HAProxy stats collector (server issue #494).

HAProxy fronts every HA control plane (an OpenStack underlay puts it in front of
each API), so "a backend is down" and "5xx / retries are climbing" are the two
signals operators page on. This collector reads HAProxy's ``show stat`` CSV --
one row per frontend / backend / server -- and ships it under ``data["haproxy"]``;
the server persists the rows, writes series, and drives the ``haproxy_backend_down``
trigger (fanned out per backend; MAINT/DRAIN never page).

Two transports, selected by config (``stats_socket`` preferred, ``stats_url`` the
fallback -- see :func:`_read_stats`):

* the **stats socket** -- a plain ``AF_UNIX`` stream: connect, write
  ``show stat\\n``, read the CSV back until EOF. No web exposure of the stats page
  is needed, which is why it is preferred. Linux only (needs ``AF_UNIX``).
* the **HTTP CSV endpoint** -- ``requests.get`` of the stats URL with ``;csv``
  appended (HAProxy's CSV modifier) and optional HTTP basic auth. Cross-platform;
  the fallback when the socket is unavailable or the operator only exposes HTTP.

The payload mirrors the zfs / php_fpm null-vs-empty discipline (the server's
dispatch gate keys on the shape):

* a **list of row objects** -- the trustworthy tick: every frontend, backend and
  server row (servers under the cap, see below);
* ``[]`` -- the stats endpoint was reachable and there are genuinely zero proxies
  (safe for the server to prune every row);
* ``None`` -- COLLECTION FAILURE (socket refused / timed out, HTTP error / non-200,
  or a body that is not parseable stats CSV). The server skips ingestion entirely
  so rows are never pruned and open ``haproxy_backend_down`` incidents cannot
  falsely resolve -- an unreachable HAProxy is not "every backend recovered".

The capped-tick sharp edge: frontend and backend rows always ship in full (they
are bounded in practice and are the trigger's subject), but ``server`` rows are
capped at :data:`_SERVER_CAP`, sorted problems-first (DOWN / MAINT / DRAIN ahead
of UP) so a capped tick keeps problem servers ahead of healthy ones (up to the
cap -- a mass outage larger than the cap can still lose some). When the cap bites the
payload becomes the wrapper ``{"rows": [...], "servers_capped": True}`` instead of
a bare list; the flag tells the server it must NOT prune ``server`` rows this tick
(a server merely absent because it was capped is not "removed"). frontend/backend
rows stay complete, so the server may still prune those. An uncapped tick is a
plain list with no flag.

Status strings are passed through **verbatim** (``UP`` / ``DOWN`` / ``MAINT`` /
``DRAIN`` / ``no check`` / transitional ``UP 1/3`` forms); the server normalizes
them, and MAINT/DRAIN must stay distinguishable from DOWN so maintenance never
pages. The ``*_total`` fields are RAW cumulative counters -- the server rates
them; never reset or diff here. CSV columns are mapped **by header name**, never
by index, because the column set shifts across HAProxy versions.
"""

import socket
import time

import requests

from fivenines_agent.debug import debug, log

# Shared transport timeout (seconds), matching apache.py / php_fpm.py: a wedged
# HAProxy -- the exact state this collector exists to report -- must never hang
# the whole collect tick.
_TIMEOUT = 5

# Conventional admin socket path, used when the collector is enabled with no
# explicit transport -- i.e. ``haproxy: true`` (an empty dict ``{}`` is falsy and
# is skipped by the collector registry, so it never reaches here). Matches the
# config contract's documented default.
_DEFAULT_STATS_SOCKET = "/run/haproxy/admin.sock"

# Safety cap on the accumulated response (both transports). A large fleet's raw
# CSV can be a few MiB before the server cap is applied; 16 MiB is far above any
# real output and only guards against an unbounded read that would OOM the agent.
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

# Read chunk size for the socket recv and the HTTP stream, in bytes.
_RECV_CHUNK_BYTES = 64 * 1024

# Max number of ``server`` rows shipped per tick. frontend/backend rows are never
# capped. Module-level so tests can shrink it without synthesising 400+ rows.
_SERVER_CAP = 400

# HAProxy CSV ``type`` column (numeric) -> row type string. 3 (listener/bind
# socket) and any unknown value are intentionally dropped: they are per-bind
# noise, redundant with the frontend aggregate for the backend-down trigger.
_TYPE_MAP = {0: "frontend", 1: "backend", 2: "server"}

# The ``server`` row type: the only type subject to the per-tick server cap
# (frontend/backend rows always ship in full). Listeners are already dropped
# upstream in _build_row via _TYPE_MAP.
_SERVER_TYPE = "server"

# A status is "healthy" (deprioritised under the server cap) when it starts with
# one of these; everything else -- DOWN, MAINT, DRAIN, NOLB, transitional
# DOWN n/m, or an empty/unknown value -- sorts problems-first so the cap keeps
# every problem. ``no check`` servers cannot be down-detected, so they are
# healthy for cap purposes. Compared upper-cased.
_HEALTHY_STATUS_PREFIXES = ("UP", "OPEN", "NO CHECK")


@debug("haproxy_metrics")
def haproxy_metrics(
    stats_socket=None, stats_url=None, username=None, password=None, **_kwargs
):
    """Read ``show stat`` and return the row list | wrapper | ``[]`` | ``None``.

    See the module docstring for the full contract. ``**_kwargs`` absorbs any
    extra keys the server may echo in the ``haproxy`` config block so an added
    field never turns the whole tick into a spurious collection failure.
    """
    try:
        text = _read_stats(stats_socket, stats_url, username, password)
        if text is None:
            # Transport failure (socket refused/timeout/truncated, HTTP error).
            return None

        rows = _parse_stat_csv(text)
        if rows is None:
            # Reachable, but the body was not parseable stats CSV -> collection
            # failure, not "zero proxies" (which is a valid, parseable [] tick).
            log("HAProxy stats response was not parseable CSV", "error")
            return None

        return _apply_cap(rows)
    except Exception as e:  # defensive: a collector must never crash the tick
        log(f"Error collecting HAProxy stats: {e}", "error")
        return None


# --- transport -------------------------------------------------------------


def _read_stats(stats_socket, stats_url, username, password):
    """Pick the transport and return the raw CSV text, or ``None`` on failure.

    ``stats_socket`` wins when set (no web exposure needed); ``stats_url`` is the
    fallback. A failing transport is reported as failure -- there is deliberately
    no socket->URL failover, so a broken socket surfaces honestly rather than
    silently masking behind HTTP. With neither configured (enabled with
    defaults) the conventional admin socket is used.
    """
    if stats_socket:
        return _socket_show_stat(stats_socket)
    if stats_url:
        return _http_show_stat(stats_url, username, password)
    return _socket_show_stat(_DEFAULT_STATS_SOCKET)


def _socket_show_stat(path):
    """Run ``show stat`` over the stats socket; return CSV text or ``None``.

    HAProxy answers a single command then closes the connection, so the response
    is read until EOF. Note: ``show stat`` CSV has no end-of-stream marker, so a
    clean EOF part-way through (HAProxy closing after a partial write, without an
    error) is indistinguishable from a complete response and would parse as a
    short-but-valid list. A mid-write failure normally surfaces as an OSError
    (-> None) instead; a truly silent partial close is an accepted, undetectable
    gap of the protocol.

    A single ``settimeout`` is NOT enough: it is a PER-recv timeout that resets
    on every chunk, so a slow-trickle HAProxy -- GC-stalled during the very
    backend-down incident this collector watches -- could read for far longer
    than ``_TIMEOUT`` and blow past the systemd watchdog into a restart loop. So
    the read is bounded by a WALL-CLOCK deadline, with each recv's timeout shrunk
    to the remaining budget. Truncation (deadline hit OR ``_MAX_RESPONSE_BYTES``
    exceeded) returns ``None``, never the partial bytes: a truncated CSV would
    drop its tail rows and make the server prune servers it simply did not
    receive -- a false-resolve. Only a clean EOF read yields the CSV.
    """
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        # Non-POSIX platform: HAProxy socket mode is Linux-only. Operators on
        # Windows use stats_url (CSV over HTTP) instead.
        log("HAProxy stats socket requires AF_UNIX (Linux only)", "error")
        return None

    deadline = time.monotonic() + _TIMEOUT
    sock = None
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(_TIMEOUT)
        sock.connect(path)
        sock.sendall(b"show stat\n")
        chunks = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                log(f"HAProxy stats socket read exceeded {_TIMEOUT}s ({path})", "error")
                return None
            sock.settimeout(remaining)
            chunk = sock.recv(_RECV_CHUNK_BYTES)
            if not chunk:
                break
            chunks += chunk
            if len(chunks) > _MAX_RESPONSE_BYTES:
                log(f"HAProxy stats response exceeded byte cap ({path})", "error")
                return None
        return chunks.decode("utf-8", "replace") or None
    except OSError as e:
        log(f"HAProxy stats socket error ({path}): {e}", "error")
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _http_show_stat(url, username, password):
    """Fetch the HTTP CSV stats endpoint; return CSV text or ``None``.

    The body is streamed under a wall-clock deadline and the
    :data:`_MAX_RESPONSE_BYTES` cap, and truncation returns ``None`` (never
    partial CSV) -- a realistically wedged endpoint stalls on the CSV body, which
    the deadline covers. The bound is best-effort and NOT as tight as the socket
    path: ``requests`` exposes only a scalar inactivity ``timeout``, so the
    connect + response-header phase runs inside ``requests.get`` before the
    deadline loop begins, and each body read still uses the full ``timeout`` (so
    the loop can overshoot the deadline by up to one ``_TIMEOUT``). An adversarial
    header-trickle can therefore still stall inside ``requests.get`` -- the
    preferred socket transport has no such gap. Redirects are refused and
    compression is declined (``Accept-Encoding: identity``) so a compromised
    endpoint cannot bounce the fetch to an internal address (SSRF) or amplify a
    chunk with a decompression bomb.
    """
    url = _ensure_csv(url)
    auth = (username, password or "") if username else None
    deadline = time.monotonic() + _TIMEOUT
    response = None
    try:
        response = requests.get(
            url,
            timeout=_TIMEOUT,
            auth=auth,
            stream=True,
            allow_redirects=False,
            headers={"Accept-Encoding": "identity"},
        )
        if response.status_code != 200:
            log(f"HAProxy stats HTTP {response.status_code} ({url})", "error")
            return None
        chunks = bytearray()
        for chunk in response.iter_content(chunk_size=_RECV_CHUNK_BYTES):
            if time.monotonic() > deadline:
                log(f"HAProxy stats HTTP read exceeded {_TIMEOUT}s ({url})", "error")
                return None
            if not chunk:
                continue
            chunks += chunk
            if len(chunks) > _MAX_RESPONSE_BYTES:
                log(f"HAProxy stats HTTP response exceeded byte cap ({url})", "error")
                return None
        return chunks.decode("utf-8", "replace") or None
    except Exception as e:
        log(f"HAProxy stats HTTP error ({url}): {e}", "error")
        return None
    finally:
        if response is not None:
            response.close()


def _ensure_csv(url):
    """Append HAProxy's ``;csv`` modifier when absent.

    HAProxy serves the machine-readable CSV when ``;csv`` is appended to the
    stats URI (``/haproxy?stats;csv``, ``/stats;csv``). Append it defensively --
    the apache ?auto / php_fpm ?json lesson -- so a URL configured without it
    still yields CSV rather than the HTML stats page.
    """
    return url if ";csv" in url else url + ";csv"


# --- parse -----------------------------------------------------------------


def _parse_stat_csv(text):
    """Parse ``show stat`` CSV into row objects, mapping columns by header name.

    Returns a list of rows (possibly empty when the endpoint is reachable with
    zero proxies), or ``None`` when the body is not parseable stats CSV (no
    ``# ...pxname...`` header) -- a collection failure distinct from ``[]``.

    HAProxy CSV is strictly comma-separated and unquoted, so a plain split is
    correct (and safer than the csv module's quote handling). Every mapped column
    sits ahead of the free-text tail, so a later field containing a comma cannot
    shift the values we read.

    Lines are split on the exact ``\\n`` delimiter HAProxy emits, never
    ``str.splitlines()`` (which also breaks on bare ``\\r`` / form feed / Unicode
    line separators -- an exotic byte in a proxy or check field would otherwise
    inject a phantom row). A trailing ``\\r`` from a CRLF body is absorbed by the
    per-cell ``strip()``.
    """
    lines = text.split("\n")
    header_idx = _find_header(lines)
    if header_idx is None:
        return None

    field_names = [h.strip() for h in lines[header_idx].lstrip("#").split(",")]
    # pxname/svname/type are all load-bearing: without 'type' every row would be
    # dropped by _build_row and the tick would collapse to [] (prune ALL) instead
    # of None (collection failure) -- a false-resolve. A body missing any of the
    # three is not trustworthy stats CSV (wrong endpoint / unknown schema).
    if not {"pxname", "svname", "type"}.issubset(field_names):
        return None

    rows = []
    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        record = dict(zip(field_names, line.split(",")))
        row = _build_row(record)
        if row is not None:
            rows.append(row)
    return rows


def _find_header(lines):
    """Index of the first ``#``-prefixed header line, or ``None`` if absent."""
    for i, line in enumerate(lines):
        if line.startswith("#"):
            return i
    return None


def _build_row(record):
    """Map one CSV record (column-name -> value) to a payload row, or ``None``.

    ``None`` drops the row: a listener (type 3) or any unknown/absent type, which
    are not part of the frontend/backend/server contract. All fourteen keys are
    always present with ``None`` where the column is empty or absent, so every
    row carries the full, fixed schema the server ingests.
    """
    type_code = _as_int(record.get("type"))
    if type_code is None:
        return None
    row_type = _TYPE_MAP.get(type_code)
    if row_type is None:
        return None
    return {
        "proxy": _as_str(record.get("pxname")),
        "server": _as_str(record.get("svname")),
        "type": row_type,
        "status": _as_str(record.get("status")),
        "sessions_current": _as_int(record.get("scur")),
        "sessions_limit": _as_int(record.get("slim")),
        "queue_current": _as_int(record.get("qcur")),
        "http_4xx_total": _as_int(record.get("hrsp_4xx")),
        "http_5xx_total": _as_int(record.get("hrsp_5xx")),
        "retries_total": _as_int(record.get("wretr")),
        "bytes_in_total": _as_int(record.get("bin")),
        "bytes_out_total": _as_int(record.get("bout")),
        "check_status": _as_str(record.get("check_status")),
        "check_duration_ms": _as_int(record.get("check_duration")),
    }


def _as_int(value):
    """Parse a CSV cell to int; empty/absent/non-numeric -> ``None``."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return int(float(value))
        except (ValueError, OverflowError):
            # OverflowError guards int(float("inf")); a non-finite or absurd
            # cell degrades to None instead of raising out of the parse loop.
            return None


def _as_str(value):
    """Return the stripped cell verbatim; empty/absent -> ``None``."""
    if value is None:
        return None
    value = value.strip()
    return value or None


# --- server cap ------------------------------------------------------------


def _apply_cap(rows):
    """Return the list unchanged, or the capped wrapper when servers overflow.

    Under the cap: the plain row list (no flag). Over it: every frontend/backend
    row plus the first :data:`_SERVER_CAP` server rows sorted problems-first, as
    ``{"rows": [...], "servers_capped": True}`` so the server skips pruning server
    rows this tick.
    """
    servers = [r for r in rows if r["type"] == _SERVER_TYPE]
    if len(servers) <= _SERVER_CAP:
        return rows

    others = [r for r in rows if r["type"] != _SERVER_TYPE]
    # Stable sort on a 0/1 problem rank: problems first, original order preserved
    # within each rank (so every DOWN/MAINT/DRAIN server survives the cap).
    kept = sorted(servers, key=lambda r: 0 if _is_problem_status(r["status"]) else 1)
    return {"rows": others + kept[:_SERVER_CAP], "servers_capped": True}


def _is_problem_status(status):
    """True when a server status is not clearly healthy (sorts first under cap)."""
    normalized = (status or "").strip().upper()
    return not normalized.startswith(_HEALTHY_STATUS_PREFIXES)
