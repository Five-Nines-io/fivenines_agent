"""PHP-FPM per-pool status collector (server issue #490).

PHP-FPM is the PHP runtime behind every LEMP/LAMP stack, and per-pool
saturation -- ``max children reached`` climbing, a growing ``listen queue`` --
is the single most common "my WordPress site is slow/down" root cause. This
collector polls the FPM status page for every pool it can reach and ships an
array of per-pool status objects under ``data["php_fpm"]``; the server turns
that into per-pool rows, VictoriaMetrics series, and the ``php_fpm_saturation``
trigger.

Three transports, selected by the configured ``status_page_url``:

* ``http(s)://`` -- scrape the status page exposed through the web server,
  exactly like ``nginx.py`` / ``apache.py`` (Phase A). One URL == one pool.
* ``unix://`` / ``tcp://`` -- talk FastCGI directly to an FPM socket via the
  tiny pure-Python client below, no web-server exposure of ``/status`` needed
  (Phase B, the security-friendlier setup). A ``unix://`` value points at the
  socket file (conventionally ``*.sock``) with the ``pm.status_path`` appended:
  ``unix:///run/php/php8.2-fpm.sock/status``; ``tcp://127.0.0.1:9000/status``
  gives host, port and status path directly.
* the sentinel ``"auto"`` -- discover every pool from the FPM pool.d configs and
  poll each over its own socket (Phase B multi-pool). This is where the array
  payload earns its shape: N pools ride free.

The payload is one of THREE outcomes, mirroring the zfs null-vs-empty contract
(the server's dispatch gate is ``is_a?(Array)``):

* a non-empty array -- the trustworthy tick, every known pool responded;
* ``[]`` -- the scrape succeeded and there are genuinely zero pollable pools
  (auto-discovery found none), so the server prunes all rows;
* ``None`` -- COLLECTION FAILURE (endpoint unreachable / timeout / non-200 /
  malformed JSON, OR ANY single known pool's fetch failed). The server skips
  ingestion entirely so rows are never pruned and open saturation incidents
  cannot falsely resolve.

The partial-failure -> ``None`` rule is the sharp edge: a pool silently missing
from the array reads as "the operator deleted that pool" and resolves its open
incident, so ANY known pool failing sinks the whole tick to ``None`` (unknown !=
recovered). A pool the operator genuinely removed simply stops being discovered
and drops out of a fully-successful array -- the server prunes it, which is
correct.
"""

import glob
import json
import socket
import struct
from urllib.parse import parse_qs, urlsplit

import requests

from fivenines_agent.debug import debug, log

# Shared transport timeout (seconds), matching apache.py / nginx.py. A wedged
# pool must never hang the whole collect tick.
_TIMEOUT = 5

# Sentinel status_page_url that switches the collector into pool.d
# auto-discovery mode (case-insensitive).
_AUTO = "auto"

# FPM's status JSON uses space-separated keys; normalise to the snake_case wire
# contract. Insertion order is the JSON key order and must match the payload
# fixture. Cumulative counters (max_children_reached, slow_requests,
# accepted_connections) are shipped RAW -- the server rate()s them and derives
# the durable saturation signal; never reset or diff them here. Every other FPM
# key (start time / start since / listen queue len / max active processes / the
# "full" per-process array) is dropped: not ingested, keep the payload exact.
_FIELD_MAP = {
    "pool": "name",
    "process manager": "process_manager",
    "active processes": "active_processes",
    "idle processes": "idle_processes",
    "total processes": "total_processes",
    "listen queue": "listen_queue",
    "max listen queue": "max_listen_queue",
    "max children reached": "max_children_reached",
    "slow requests": "slow_requests",
    "accepted conn": "accepted_connections",
}

# Where FPM pool definitions live across distributions. Module-level so tests can
# point discovery at a fixture directory.
_POOL_CONFIG_GLOBS = [
    "/etc/php/*/fpm/pool.d/*.conf",
    "/etc/php-fpm.d/*.conf",
    "/usr/local/etc/php-fpm.d/*.conf",
]


@debug("php_fpm_metrics")
def php_fpm_metrics(status_page_url="http://127.0.0.1/status?json"):
    """Poll every reachable FPM pool; return the per-pool array | ``[]`` | ``None``.

    See the module docstring for the null-vs-empty contract. The single-endpoint
    forms (http/unix/tcp) degenerate to: success -> ``[pool]``, failure ->
    ``None``; only auto-discovery ever yields ``[]``.
    """
    try:
        endpoints = _resolve_endpoints(status_page_url)
    except Exception as e:  # defensive: resolution must never raise upward
        log(f"Error resolving PHP-FPM endpoints: {e}", "error")
        return None

    if endpoints is None:
        # The configuration could not be turned into a pollable endpoint
        # (unknown scheme / unparsable) -- a collection failure, not "no pools".
        return None
    if not endpoints:
        # Auto-discovery ran and found genuinely zero pollable pools.
        return []

    pools = []
    for endpoint in endpoints:
        status = _fetch_pool_status(endpoint)
        if status is None:
            # ANY known pool's fetch failed -> sink the whole tick to null so
            # the server never prunes a pool that is merely unreachable.
            log(f"PHP-FPM pool fetch failed for {_endpoint_label(endpoint)}", "error")
            return None
        pools.append(_normalize_pool(status))
    return pools


# --- endpoint resolution ---------------------------------------------------


def _resolve_endpoints(status_page_url):
    """Turn the configured status_page_url into the list of endpoints to poll.

    Returns a (possibly empty) list of endpoints, or ``None`` when the value
    could not be resolved to anything pollable (unknown scheme / unparsable),
    which the caller reports as a collection failure.
    """
    target = (status_page_url or "").strip()
    if target.lower() == _AUTO:
        return _discover_pools()
    endpoint = _endpoint_from_url(target)
    if endpoint is None:
        return None
    return [endpoint]


def _endpoint_from_url(url):
    """Parse a single explicit status_page_url into an endpoint dict, or None."""
    scheme = urlsplit(url).scheme.lower()
    if scheme in ("http", "https"):
        return {"kind": "http", "url": _ensure_json_query(url)}
    if scheme == "unix":
        return _unix_endpoint_from_url(url)
    if scheme == "tcp":
        return _tcp_endpoint_from_url(url)
    log(f"Unsupported PHP-FPM status_page_url scheme: {scheme or '(none)'}", "error")
    return None


def _ensure_json_query(url):
    """Append ``json`` to the query string when absent (defensively).

    FPM only emits JSON when the status request carries the ``json`` flag. Scope
    the check to the parsed query string so a host or path that merely contains
    the substring "json" (e.g. /jsonstatus) is not mistaken for the flag already
    being present -- the apache ?auto lesson.
    """
    query = urlsplit(url).query
    if "json" in parse_qs(query, keep_blank_values=True):
        return url
    sep = "&" if query else "?"
    return f"{url}{sep}json"


def _unix_endpoint_from_url(url):
    """Split ``unix:///socket/path/status`` into socket file + SCRIPT_NAME.

    The documented form has an empty authority (``unix:///path``). If a caller
    writes ``unix://path`` (two slashes), urlsplit parses the first path segment
    as the authority; fold it back so the (always absolute) socket path keeps its
    leading component instead of silently losing it.
    """
    parts = urlsplit(url)
    path = parts.path
    if parts.netloc:
        path = "/" + parts.netloc + path
    return _split_unix_path(path)


def _split_unix_path(path):
    """Separate the FPM socket file from the trailing status path.

    FPM sockets conventionally end in ``.sock``; everything after that marker is
    the FastCGI SCRIPT_NAME (the ``pm.status_path``). Without a ``.sock`` marker
    the split is inherently ambiguous, so fall back to treating the last path
    segment as the status path -- prefer the ``.sock`` naming or auto-discovery,
    which avoids the ambiguity entirely.
    """
    marker = ".sock"
    idx = path.find(marker)
    if idx != -1:
        end = idx + len(marker)
        return {"kind": "unix", "address": path[:end], "script_name": path[end:] or "/status"}
    parent, sep, last = path.rpartition("/")
    if sep and parent and last:
        return {"kind": "unix", "address": parent, "script_name": "/" + last}
    return None


def _tcp_endpoint_from_url(url):
    """Parse ``tcp://host:port/status`` into a TCP FastCGI endpoint, or None."""
    parts = urlsplit(url)
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if not host or not port:
        return None
    return {"kind": "tcp", "host": host, "port": port, "script_name": parts.path or "/status"}


# --- pool.d auto-discovery -------------------------------------------------


def _discover_pools():
    """Discover pollable pools from the FPM pool.d configs.

    Returns a list of endpoints (possibly empty -- genuinely zero pollable
    pools, which the server prunes), or ``None`` if ANY matched config file
    could not be read. An unreadable config means the discovered set may be
    incomplete, and a pollable pool silently dropping out reads as "the operator
    removed it" so its open saturation incident false-resolves. A read failure
    therefore sinks the whole tick to a collection failure (None) -- the same
    unknown-!=-recovered discipline as a per-pool fetch failure, never a silently
    short array. Only pools declaring BOTH a ``listen`` socket and a
    ``pm.status_path`` are pollable (FPM 404s otherwise); duplicate endpoints
    across files are polled once.
    """
    endpoints = []
    seen = set()
    for path in _pool_config_files():
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            # A matched-but-unreadable config makes discovery untrustworthy:
            # fail the tick to None rather than under-report and false-prune.
            log(f"PHP-FPM pool config unreadable ({path}): {e}", "error")
            return None
        for pool in _parse_pool_file(text):
            endpoint = _endpoint_from_listen(pool.get("listen"), pool.get("status_path"))
            if endpoint is None:
                continue
            key = _endpoint_key(endpoint)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(endpoint)
    return endpoints


def _pool_config_files():
    """Glob the pool.d config paths, de-duplicated and sorted for determinism."""
    files = []
    for pattern in _POOL_CONFIG_GLOBS:
        files.extend(glob.glob(pattern))
    return sorted(set(files))


def _parse_pool_file(text):
    """Parse an FPM pool config into ``[{name, listen, status_path}, ...]``.

    A minimal INI reader tolerant of FPM's quirks (``;`` comments, inline
    comments, quoted values, the ``[global]`` pseudo-section, options repeated
    across pools) -- configparser is too strict for real-world pool files.
    """
    pools = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and "]" in line:
            end = line.index("]")
            current = {"name": line[1:end].strip(), "listen": None, "status_path": None}
            pools.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = _clean_value(value)
        if key == "listen":
            current["listen"] = value
        elif key == "pm.status_path":
            current["status_path"] = value
    return pools


def _clean_value(value):
    """Strip an inline ``;`` comment, surrounding whitespace, then a quote pair."""
    value = value.split(";", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


def _endpoint_from_listen(listen, status_path):
    """Build a FastCGI endpoint from a pool's ``listen`` + ``pm.status_path``."""
    if not listen or not status_path:
        return None
    script = status_path if status_path.startswith("/") else "/" + status_path
    if "/" in listen:
        # An absolute path -> unix domain socket.
        return {"kind": "unix", "address": listen, "script_name": script}
    hostport = _split_host_port(listen)
    if hostport is None:
        return None
    host, port = hostport
    return {"kind": "tcp", "host": host, "port": port, "script_name": script}


def _split_host_port(listen):
    """Parse an FPM ``listen`` address into (host, port), defaulting host.

    Accepts ``host:port``, ``:port``, a bare ``port`` (FPM binds 127.0.0.1), and
    ``[ipv6]:port``. Returns None when no valid port can be read.
    """
    listen = listen.strip()
    if listen.startswith("["):  # [ipv6]:port
        host, sep, rest = listen.partition("]")
        if not sep or not rest.startswith(":"):
            return None
        port = _safe_port(rest[1:])
        host = host[1:]
        return (host, port) if host and port else None
    if ":" in listen:  # host:port or :port
        host, _, port = listen.rpartition(":")
        port = _safe_port(port)
        return (host or "127.0.0.1", port) if port else None
    port = _safe_port(listen)  # bare port
    return ("127.0.0.1", port) if port else None


def _safe_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _endpoint_key(endpoint):
    """Hashable identity for de-duplicating discovered endpoints."""
    kind = endpoint["kind"]
    if kind == "http":
        return ("http", endpoint["url"])
    if kind == "unix":
        return ("unix", endpoint["address"], endpoint["script_name"])
    return ("tcp", endpoint["host"], endpoint["port"], endpoint["script_name"])


def _endpoint_label(endpoint):
    """Human-readable endpoint id for logs and test transport keying."""
    kind = endpoint["kind"]
    if kind == "http":
        return endpoint["url"]
    if kind == "unix":
        return f"unix:{endpoint['address']}{endpoint['script_name']}"
    return f"tcp:{endpoint['host']}:{endpoint['port']}{endpoint['script_name']}"


# --- fetch + normalise -----------------------------------------------------


def _fetch_pool_status(endpoint):
    """Fetch one pool's raw FPM status dict, or None on any failure."""
    body = _fetch_status_body(endpoint)
    if body is None:
        return None
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _fetch_status_body(endpoint):
    """Transport seam: return the raw status body text, or None on failure."""
    if endpoint["kind"] == "http":
        return _http_status_body(endpoint["url"])
    return _fcgi_status_body(endpoint)


def _http_status_body(url):
    try:
        response = requests.get(url, timeout=_TIMEOUT)
    except Exception as e:
        log(f"PHP-FPM HTTP error for {url}: {e}", "error")
        return None
    if response.status_code != 200:
        return None
    return response.text


def _normalize_pool(status):
    """Map the space-separated FPM keys to the snake_case wire contract.

    Unmapped FPM fields are dropped; a missing mapped field yields None (real
    FPM always emits the full set, so a healthy scrape has no None values).
    """
    return {payload_key: status.get(fpm_key) for fpm_key, payload_key in _FIELD_MAP.items()}


# --- FastCGI client --------------------------------------------------------
#
# A tiny pure-Python FastCGI responder client (no new dependency). It sends one
# BEGIN_REQUEST + PARAMS + empty STDIN GET for the status path and reads STDOUT
# until END_REQUEST. See https://fastcgi-archives.github.io/FastCGI_Specification.html

_FCGI_VERSION = 1
_FCGI_BEGIN_REQUEST = 1
_FCGI_END_REQUEST = 3
_FCGI_PARAMS = 4
_FCGI_STDIN = 5
_FCGI_STDOUT = 6
_FCGI_RESPONDER = 1
_FCGI_REQUEST_ID = 1
# Safety cap on accumulated STDOUT (status JSON is < 1 KiB; this only guards a
# misbehaving backend from unbounded growth -- the socket timeout bounds time).
_FCGI_MAX_BODY = 1 << 20


def _fcgi_status_body(endpoint):
    """Fetch the status page over FastCGI; return body text or None on failure."""
    script = endpoint.get("script_name") or "/status"
    params = {
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "REQUEST_METHOD": "GET",
        "SCRIPT_NAME": script,
        "SCRIPT_FILENAME": script,
        "DOCUMENT_URI": script,
        "REQUEST_URI": f"{script}?json",
        "QUERY_STRING": "json",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "SERVER_SOFTWARE": "fivenines-agent",
        "REMOTE_ADDR": "127.0.0.1",
    }
    sock = None
    try:
        sock = _fcgi_connect(endpoint)
        raw = _fcgi_exchange(sock, params)
    except OSError as e:
        log(f"PHP-FPM FastCGI error for {_endpoint_label(endpoint)}: {e}", "error")
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return _fcgi_body(raw)


def _fcgi_connect(endpoint):
    if endpoint["kind"] == "unix":
        family = getattr(socket, "AF_UNIX", None)
        if family is None:  # non-POSIX platform; FPM is Linux-only anyway
            raise OSError("AF_UNIX unavailable on this platform")
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(_TIMEOUT)
        sock.connect(endpoint["address"])
        return sock
    sock = socket.create_connection((endpoint["host"], endpoint["port"]), _TIMEOUT)
    sock.settimeout(_TIMEOUT)
    return sock


def _fcgi_exchange(sock, params):
    begin = struct.pack("!HB5x", _FCGI_RESPONDER, 0)  # role, flags=0 (no keep-conn)
    sock.sendall(_fcgi_record(_FCGI_BEGIN_REQUEST, begin))
    payload = b"".join(_fcgi_pair(k, v) for k, v in params.items())
    sock.sendall(_fcgi_record(_FCGI_PARAMS, payload))
    sock.sendall(_fcgi_record(_FCGI_PARAMS, b""))  # empty PARAMS terminates the stream
    sock.sendall(_fcgi_record(_FCGI_STDIN, b""))  # empty STDIN: a GET with no body
    return _fcgi_read_stdout(sock)


def _fcgi_record(rec_type, content):
    # Params/status bodies are tiny, so a single record (content < 65536) is
    # always sufficient; no multi-record chunking needed on the send side.
    header = struct.pack("!BBHHBB", _FCGI_VERSION, rec_type, _FCGI_REQUEST_ID, len(content), 0, 0)
    return header + content


def _fcgi_pair(name, value):
    nb = name.encode("utf-8")
    vb = value.encode("utf-8")
    out = bytearray()
    for length in (len(nb), len(vb)):
        if length < 128:
            out += struct.pack("!B", length)
        else:
            out += struct.pack("!I", length | 0x80000000)
    out += nb
    out += vb
    return bytes(out)


def _fcgi_read_stdout(sock):
    """Read records until END_REQUEST, accumulating STDOUT (STDERR ignored)."""
    stdout = bytearray()
    while True:
        header = _recv_exact(sock, 8)
        if len(header) < 8:
            break  # connection closed early / truncated
        _, rec_type, _, content_len, pad_len, _ = struct.unpack("!BBHHBB", header)
        content = _recv_exact(sock, content_len) if content_len else b""
        if pad_len:
            _recv_exact(sock, pad_len)
        if rec_type == _FCGI_STDOUT:
            stdout += content
            if len(stdout) > _FCGI_MAX_BODY:
                break
        elif rec_type == _FCGI_END_REQUEST:
            break
    return bytes(stdout)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _fcgi_body(raw):
    """Strip the CGI headers FPM prepends, returning the JSON body text."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            start = idx + len(sep)
            return raw[start:].decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")
