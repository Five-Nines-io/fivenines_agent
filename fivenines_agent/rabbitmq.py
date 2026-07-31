"""RabbitMQ management API collector (server issue #499).

RabbitMQ is the RPC/message bus under an HA OpenStack control plane (and countless
app stacks), so per-queue backlog and node-level resource alarms are the two
signals that predict an outage before it lands. This collector polls the RabbitMQ
management HTTP API and ships ONE object under ``data["rabbitmq"]``: a
reachability envelope + local-node health (memory/disk alarms, fd/socket usage) +
a bounded array of per-queue stats. The server turns that into per-queue rows,
VictoriaMetrics series, and the ``rabbitmq_queue_backlog`` trigger (fires while
depth >= threshold OR consumers == 0 with depth > 0).

Transport is plain HTTP with basic auth (nginx/caddy posture) -- pure Python,
cross-platform, config-driven, no capability probe. ``rabbitmq_enabled`` defaults
false server-side, so releasing the agent before or after the server is safe.

Reachability envelope (postgresql posture, NOT the php_fpm null contract): a dead
broker IS the signal on a control plane, so it rides the payload rather than
collapsing to ``None``.

  reachable:
    {"reachable": true, "version": ..., "node": {...}, "queues_total": N,
     "queues": [ {vhost, name, messages, messages_unacked, consumers,
                  publish_total?, deliver_total?}, ... ]}
  unreachable:
    {"reachable": false, "error_type": "connection_refused|timeout|auth_failed|
     http_error", "error_message": "..."}   -- NO "queues" key, so the server
     skips ingestion entirely: rows are never pruned and open backlog incidents
     cannot falsely resolve.

Two contract sharp edges:

* ``queues`` is BOUNDED -- top-N by ``messages`` UNION top-N by
  ``messages_unacked`` UNION ``include_queues``. Each ranked dimension fetches one
  page of ``_QUEUE_PAGE_SIZE`` rows, so the ranked union is at most ~2x that
  (typically ~1x, since RabbitMQ's ``messages`` already includes unacked and the
  two pages overlap heavily), plus the bounded include_queues tail;
  ``queues_total`` carries the broker's TRUE count (the SNMP ``interface_count``
  precedent). We fetch the two ranked dimensions with server-side sort +
  pagination so a broker with tens of thousands of queues costs two small
  requests, never a full enumeration. The unacked dimension is not redundant with
  ``messages`` (which already includes unacked): a small queue whose consumers
  are stuck -- high unacked, low total -- can miss top-N-by-messages yet is
  exactly the ``consumers == 0 with depth > 0`` case the trigger exists for.

* PARTIAL LISTINGS DEGRADE TO UNREACHABLE. The server prunes queue rows absent
  from a trustworthy tick, so a partially-fetched queue list (a paginated call
  that failed midway) MUST produce ``reachable: false`` for the whole tick, never
  a short array -- a silently-missing queue reads as "operator deleted it" and
  resolves its open incident (unknown != recovered, the php_fpm rule adapted).
  Any endpoint fetch failing therefore sinks the tick to the unreachable
  envelope.

``publish_total`` / ``deliver_total`` come from ``message_stats`` RAW cumulative
counters -- the server rate()s them; never diff or reset agent-side (#97 lesson).
A queue with no ``message_stats`` (idle, never published) omits both keys.
"""

import time
from urllib.parse import quote

import requests

from fivenines_agent.debug import debug, log

# Per-request timeout (seconds). A wedged broker must never stall the collect
# loop; also bounds connection establishment on a dead host.
_TIMEOUT = 5

# Wall-clock budget (seconds) for the whole collector's HTTP work. The four
# fixed requests are each _TIMEOUT-bounded (~20s worst case), but the
# include_queues tail is a variable number of lookups; a COUNT cap alone does
# not bound TIME (cap * _TIMEOUT could reach hundreds of seconds on a slow
# broker -- exactly the mem_alarm broker being monitored). Since all collectors
# run between two systemd watchdog feeds and a tick past WatchdogSec=90 SIGABRTs
# the agent into a Restart=always loop, the include tail stops once this deadline
# is hit (the below-cap watched queues simply do not refresh this tick). Mirrors
# the memcached collector's wall-clock-deadline fix.
_COLLECT_DEADLINE_S = 25

# Page size per ranking dimension (NOT the output cap -- the shipped array is the
# union of the two ranked pages plus include_queues, so it can reach ~2x this).
# queues_total carries the TRUE broker count regardless (SNMP interface_count
# precedent). RabbitMQ's `messages` already includes unacked, so the two pages
# overlap heavily and the union is typically ~1x; it reaches ~2x only when the
# ready-heavy and unacked-heavy tops are disjoint. Kept modest so a huge broker's
# tick stays cheap.
_QUEUE_PAGE_SIZE = 100

# Cap on per-queue include_queues lookups per tick. include_queues is a
# server-pushed watch list; a pathologically long one must never turn into
# hundreds of sequential (up to _TIMEOUT-each) round-trips that stall the collect
# loop past its interval. In practice the count is ~0 (a watched high-depth queue
# is already in the top-N ranked page), so this only guards the tail.
_INCLUDE_QUEUES_CAP = 100

# error_message cap. The backend treats error_message as opaque (only error_type
# is semantic) and truncates too; cap here so a pathological body never bloats
# the payload.
_ERROR_MESSAGE_MAX = 500

# Columns requested from /api/queues -- collapses each row to just the ingested
# fields so a broker with many queues returns a tiny body. message_stats.* are
# RAW cumulative counters the server rates. Dotted paths select nested fields;
# RabbitMQ omits message_stats entirely for a queue that has none.
_QUEUE_COLUMNS = (
    "vhost,name,messages,messages_unacknowledged,consumers,"
    "message_stats.publish,message_stats.deliver_get"
)

# Columns requested from /api/nodes -- just the alarm + resource-headroom fields.
_NODE_COLUMNS = (
    "name,mem_alarm,disk_free_alarm,fd_used,fd_total,sockets_used,sockets_total"
)

# Columns requested from /api/overview -- version + the name of the node serving
# this request (used to select the LOCAL node from /api/nodes on a cluster).
_OVERVIEW_COLUMNS = "rabbitmq_version,node"

_DEFAULT_URL = "http://127.0.0.1:15672"


class _RabbitError(Exception):
    """A classified transport failure carrying the wire error_type + message."""

    def __init__(self, error_type, message):
        self.error_type = error_type
        self.message = message
        super().__init__(message)


@debug("rabbitmq_metrics")
def rabbitmq_metrics(
    url=_DEFAULT_URL,
    username=None,
    password=None,
    vhost=None,
    include_queues=None,
    **_kwargs,
):
    """Poll the RabbitMQ management API; return the reachability envelope.

    Args:
        url: management API base URL (default http://127.0.0.1:15672).
        username / password: basic-auth credentials for the monitoring user.
        vhost: None (or empty) = all vhosts; a name scopes collection to it.
        include_queues: queue names always collected even outside the top-N cap
            (the server echoes trigger watch lists here).
        **_kwargs: unknown backend config keys are ignored (forward-compatible).

    Returns:
        {"reachable": True, "version", "node", "queues_total", "queues"} on a
        trustworthy tick; {"reachable": False, "error_type", "error_message"}
        when any endpoint fetch fails (a dead broker or a partial queue listing).
        Never returns None -- the envelope is always the signal.
    """
    session = None
    try:
        # Inside the try so a malformed config (e.g. a non-string url whose
        # .rstrip raises) becomes the reachable:false envelope, never an escaping
        # exception that the collector wrapper would turn into None.
        base = str(url or _DEFAULT_URL).rstrip("/")
        session = _new_session(username, password)
        deadline = time.monotonic() + _COLLECT_DEADLINE_S
        overview = _request(session, f"{base}/api/overview?columns={_OVERVIEW_COLUMNS}")
        node = _fetch_node(session, base, overview.get("node"))
        queues, queues_total = _fetch_queues(
            session, base, vhost, include_queues, deadline
        )
        return {
            "reachable": True,
            "version": overview.get("rabbitmq_version"),
            "node": node,
            "queues_total": queues_total,
            "queues": queues,
        }
    except _RabbitError as e:
        return _unreachable(e.error_type, e.message)
    except Exception as e:
        # Never emit None: an unexpected failure talking to the API is still a
        # "cannot trust this tick" signal, and the server only understands the
        # reachable:true / reachable:false envelope for RabbitMQ.
        log(f"RabbitMQ collection error: {e}", "error")
        return _unreachable("http_error", str(e))
    finally:
        if session is not None:
            session.close()


def _new_session(username, password):
    """Build a keep-alive session with basic auth applied when credentials exist.

    Reusing one session across the handful of per-tick requests to the same host
    avoids a fresh TCP+TLS handshake each call. A test seam: swapped for a fake
    session so the round-trip test mocks only the HTTP transport.
    """
    session = requests.Session()
    if username is not None:
        session.auth = (username, password or "")
    return session


def _http_get(session, url):
    """GET *url*, raising a classified _RabbitError on a network-layer failure.

    Every failure maps onto one of the four wire error_types; on success the raw
    Response is returned for the caller to interpret its status code.
    """
    try:
        return session.get(url, timeout=_TIMEOUT)
    except requests.exceptions.Timeout as e:
        raise _RabbitError("timeout", str(e))
    except requests.exceptions.ConnectionError as e:
        # Refused / DNS / no route all collapse to the network-down category;
        # the contract offers no finer bucket and connection_refused is the
        # closest "broker is not answering" signal.
        raise _RabbitError("connection_refused", str(e))
    except requests.exceptions.RequestException as e:
        raise _RabbitError("http_error", str(e))


def _check_status(status):
    """Raise the classified _RabbitError for a non-200 status; else return."""
    if status in (401, 403):
        raise _RabbitError("auth_failed", f"HTTP {status}")
    if status != 200:
        raise _RabbitError("http_error", f"HTTP {status}")


def _parse_json(response):
    """Parse a 200 body as JSON, mapping a malformed body to http_error."""
    try:
        return response.json()
    except ValueError:
        raise _RabbitError("http_error", "invalid JSON response")


def _request(session, url):
    """GET *url* -> parsed JSON, raising a classified _RabbitError on any failure."""
    response = _http_get(session, url)
    _check_status(response.status_code)
    return _parse_json(response)


def _request_optional(session, url):
    """Like _request, but return None on a 404 instead of raising.

    Used for the per-queue include lookup: a 404 means the watched queue was
    genuinely deleted (skip it, let the server prune) rather than a transport
    failure that would sink the whole tick to unreachable.
    """
    response = _http_get(session, url)
    if response.status_code == 404:
        return None
    _check_status(response.status_code)
    return _parse_json(response)


def _fetch_node(session, base, node_name):
    """Return the local node's health dict from /api/nodes, or None if absent.

    A cluster's /api/nodes lists every node; we select the one whose name matches
    the node serving the management request (from /api/overview) so the reported
    alarms/headroom are the LOCAL broker's, falling back to the first node when
    the name is unknown. Alarms default to False; resource gauges pass through
    (None when the field is absent) rather than being invented. Returns None when
    /api/nodes has no usable (dict) node so the whole tick stays reachable with
    node omitted -- a missing node section must never crash into a fabricated
    "http_error" outage for a broker that actually answered.
    """
    nodes = _request(session, f"{base}/api/nodes?columns={_NODE_COLUMNS}")
    if not isinstance(nodes, list):
        return None
    selected = None
    if node_name:
        for node in nodes:
            if isinstance(node, dict) and node.get("name") == node_name:
                selected = node
                break
    if selected is None:
        # Fall back to the first *dict* node -- the same isinstance guard the
        # match loop applies, so a non-dict entry can't crash the .get() calls.
        selected = next((node for node in nodes if isinstance(node, dict)), None)
    if selected is None:
        return None
    return {
        "mem_alarm": bool(selected.get("mem_alarm", False)),
        "disk_free_alarm": bool(selected.get("disk_free_alarm", False)),
        "fd_used": selected.get("fd_used"),
        "fd_total": selected.get("fd_total"),
        "sockets_used": selected.get("sockets_used"),
        "sockets_total": selected.get("sockets_total"),
    }


def _fetch_queues(session, base, vhost, include_queues, deadline=float("inf")):
    """Return (bounded queues array, queues_total) for the configured scope.

    Fetches the two ranked dimensions (top-N by messages, top-N by unacked) with
    server-side sort + pagination, unions them by (vhost, name), then guarantees
    every include_queues name is present (bounded by _INCLUDE_QUEUES_CAP and the
    wall-clock *deadline*). queues_total is the broker's true count from the
    pagination metadata, independent of how many rows we ship.

    TRUST GATE: we always request ?page=1, so a trustworthy response is the
    paginated OBJECT (a dict carrying a list `items`) of dict rows. Any other 200
    -- a dict without a list `items`, a bare value, or a listing with a non-dict
    row -- means we did NOT get a real queue listing (a reverse-proxy / SSO
    gateway 200, a cached error page), so we sink the tick to unreachable rather
    than coerce it to an empty array: reachable:true + queues:[] tells the server
    "every queue is gone", pruning the rows and false-resolving every open
    backlog incident. Any fetch failing likewise raises upward -> unreachable.
    """
    path = "/api/queues"
    if vhost:
        path = f"/api/queues/{quote(vhost, safe='')}"
    base_query = f"page=1&page_size={_QUEUE_PAGE_SIZE}&columns={_QUEUE_COLUMNS}"

    by_messages = _request(
        session, f"{base}{path}?{base_query}&sort=messages&sort_reverse=true"
    )
    by_unacked = _request(
        session,
        f"{base}{path}?{base_query}&sort=messages_unacknowledged&sort_reverse=true",
    )

    merged = {}
    for page in (by_messages, by_unacked):
        for item in _page_items(page):
            if not isinstance(item, dict):
                raise _RabbitError(
                    "http_error", "non-object row in /api/queues listing"
                )
            key = (item.get("vhost"), item.get("name"))
            if key not in merged:
                merged[key] = _normalize_queue(item)

    _add_include_queues(session, base, vhost, include_queues, merged, deadline)
    return list(merged.values()), _total_count(by_messages)


def _page_items(page):
    """Return the item list from a paginated /api/queues response.

    Raises _RabbitError (-> unreachable) when the shape is not the expected
    paginated object (a dict with a list `items`). We never coerce an unexpected
    200 to an empty list: that would false-heal a proxied / error-page response
    into "zero queues" and prune every row server-side.
    """
    if isinstance(page, dict) and isinstance(page.get("items"), list):
        return page["items"]
    raise _RabbitError("http_error", "unexpected /api/queues response shape")


def _total_count(page):
    """The broker's true queue count from pagination metadata.

    *page* has already cleared _page_items' trust gate (a dict with a list
    `items`), so a missing/non-int total_count falls back to the fetched length
    rather than fabricating a count.
    """
    total = page.get("total_count")
    if isinstance(total, int) and not isinstance(total, bool):
        return total
    return len(page.get("items") or [])


def _add_include_queues(session, base, vhost, include_queues, merged, deadline=float("inf")):
    """Guarantee each include_queues name is present in *merged*.

    A watched queue already in the ranked union (typically true -- an open
    incident means high depth) needs nothing. One that has dropped below the cap
    is fetched by exact identity so it keeps updating and can resolve. A 404
    (queue deleted) is skipped; a transport error propagates -> unreachable.

    The lookup loop stops at whichever comes first: _INCLUDE_QUEUES_CAP lookups,
    or the wall-clock *deadline*. A COUNT cap alone does not bound TIME (cap *
    _TIMEOUT could reach hundreds of seconds against a slow broker), which would
    stall the collect loop past the systemd watchdog into a restart loop. The
    deadline is checked before each lookup, so the include tail runs until at most
    the deadline plus one in-flight _TIMEOUT (~30s total with the defaults) --
    comfortably under WatchdogSec=90 regardless of the watch-list length. Stopping
    early just skips refreshing the tail this tick.

    Presence is keyed on (lookup_vhost, name), NOT the bare name: a queue name is
    unique only within a vhost, so a same-named queue in a DIFFERENT vhost that
    happens to be in the ranked union must not suppress the identity fetch of the
    actually-watched below-cap queue (that would drop it from the array and let
    the server false-resolve its open incident).

    LIMITATION: the lookup vhost is the configured scope, defaulting to "/" when
    collection spans all vhosts (vhost=None). include_queues carries bare names,
    so under all-vhosts scope a watched queue living in a NON-default vhost is
    looked up at "/" and 404s (silently dropped). Scope collection to that vhost
    to force-include it reliably; extending include_queues to (vhost, name) pairs
    is a contract change deferred to the server side.
    """
    names = _include_names(include_queues)
    if not names:
        return
    lookup_vhost = vhost or "/"
    fetched = 0
    for name in names:
        if (lookup_vhost, name) in merged:
            continue  # already collected for this vhost by the ranked union
        if fetched >= _INCLUDE_QUEUES_CAP or time.monotonic() >= deadline:
            log(
                f"RabbitMQ include_queues lookups stopped early (cap "
                f"{_INCLUDE_QUEUES_CAP} or {_COLLECT_DEADLINE_S}s deadline); "
                "remaining watch-list entries not refreshed this tick",
                "error",
            )
            break
        fetched += 1
        queue = _fetch_single_queue(session, base, lookup_vhost, name)
        if queue is None:
            continue
        merged[(queue.get("vhost"), queue.get("name"))] = _normalize_queue(queue)


def _include_names(include_queues):
    """Normalize the include_queues config to a clean list of NAME STRINGS.

    Trusts the server contract (a JSON array of strings) but defends against a
    misconfigured/forward-compat value: a bare string is wrapped (so it is not
    iterated character by character), and a non-string element -- an int, or the
    {vhost, name} dict a future contract might send -- is dropped rather than
    crashing quote() into a per-tick false outage.
    """
    if not include_queues:
        return []
    if isinstance(include_queues, str):
        return [include_queues]
    if isinstance(include_queues, (list, tuple)):
        return [name for name in include_queues if isinstance(name, str) and name]
    return []


def _fetch_single_queue(session, base, vhost, name):
    """Fetch one queue by exact (vhost, name).

    Returns the queue dict, or None only for a genuine 404 (the queue no longer
    exists -> safe to let it drop and be pruned). A 200 whose body is NOT a queue
    object is an untrustworthy response (a reverse-proxy / cached error page), so
    it raises -> unreachable, NOT a silent "queue deleted" that would drop the
    watched below-cap queue and false-resolve its incident (the same trust gate
    the ranked pages apply in _page_items).
    """
    url = (
        f"{base}/api/queues/{quote(vhost, safe='')}/{quote(name, safe='')}"
        f"?columns={_QUEUE_COLUMNS}"
    )
    queue = _request_optional(session, url)
    if queue is None:
        return None  # 404: genuinely deleted
    if not isinstance(queue, dict):
        raise _RabbitError("http_error", "unexpected /api/queues/<name> response shape")
    return queue


def _normalize_queue(item):
    """Map a raw RabbitMQ queue object to the snake_case wire contract.

    Insertion order is the contract field order and must match the fixture.
    publish_total / deliver_total are emitted ONLY when message_stats carries
    them (an idle queue omits both), and are shipped RAW.
    """
    queue = {
        "vhost": item.get("vhost"),
        "name": item.get("name"),
        "messages": item.get("messages"),
        "messages_unacked": item.get("messages_unacknowledged"),
        "consumers": item.get("consumers"),
    }
    stats = item.get("message_stats")
    if isinstance(stats, dict):
        if "publish" in stats:
            queue["publish_total"] = stats["publish"]
        if "deliver_get" in stats:
            queue["deliver_total"] = stats["deliver_get"]
    return queue


def _unreachable(error_type, message):
    """Build the unreachable envelope -- deliberately NO queues/node/version key."""
    return {
        "reachable": False,
        "error_type": error_type,
        "error_message": (message or "")[:_ERROR_MESSAGE_MAX],
    }
