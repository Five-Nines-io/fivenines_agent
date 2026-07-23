"""MQTT broker subscription collector (persistent background clients).

This is the agent's first long-lived-connection subsystem. Unlike every other
collector -- which polls once per tick and returns -- MQTT keeps a paho-mqtt
client per broker alive across ticks, lets paho's own network thread absorb the
socket/reconnect novelty, maintains per-topic freshness state in memory, and
snapshots a bounded view every tick under ``data["mqtt"]``.

Delivery seam
-------------
The desired state is pushed by the server on ``/collect`` under the top-level
``mqtt`` config key (the same seam as ``snmp_targets``), a list of brokers::

    "mqtt": [
      {"broker_id": "b1", "host": "...", "port": 8883, "tls": true,
       "username": "...", "password": "...",
       "monitors": [{"id": "m1", "topic_filter": "iot/+/status",
                     "capture_payload": true}]}
    ]

Each tick the manager diffs desired-vs-current and acts ONLY on change: start a
new client, stop a removed one, resubscribe on a monitor edit. It never
reconnects on an unchanged config -- connection churn is not free on brokers,
and a clean-session reconnect re-triggers retained-message replays every time.
Key absent / falsy / malformed tears every client down.

Honesty contract (why this feature exists)
-------------------------------------------
- RETAIN=1 deliveries update ``last_message_age_s`` but NEVER
  ``last_live_seen_age_s``: a stored status replay is not proof the device is
  alive. This is the Uptime-Kuma flaw we refuse to ship.
- Failure is distinguishable from emptiness. A broker that cannot connect (or
  is still connecting, or authing) reports a ``status`` of ``error`` /
  ``auth_error`` with an ``error`` detail and never fabricates topic entries. A
  ``connected`` broker with ``topics: {}`` genuinely means "subscribed, nothing
  published yet". ``auth_error`` maps to the server's amber ``config_error``.
- Everything is reported as ages, not timestamps. The server anchors freshness
  to its own ``received_at``, so agent clock drift is irrelevant, and
  ``subscribed_age_s`` is the server's alarm-arming input (don't alarm on a
  topic we've only just started listening to).

Absence vs null
---------------
``mqtt_metrics`` returns ``None`` when MQTT is unconfigured (no brokers, no live
clients) so the agent omits ``data["mqtt"]`` entirely -- old servers are
unaffected and the key never appears as a bare ``null``. Once at least one
broker is configured it returns ``{"brokers": {broker_id: {...}}}``.

Bounds
------
QoS 0, clean session, MQTT 3.1.1, TCP or TLS, username/password auth. Out of
scope for v1: MQTT 5, WebSockets, mTLS client certs, publishing. Per-monitor
topic discovery is capped (``MAX_TOPICS_PER_MONITOR``) with a ``capped`` flag;
payloads are truncated to ``PAYLOAD_MAX_BYTES`` and decoded with ``replace`` so
non-UTF-8 bytes serialize safely.
"""

import threading
import time

import paho.mqtt.client as mqtt_client
from paho.mqtt.client import topic_matches_sub

from fivenines_agent.debug import debug, log

# Per-monitor concrete-topic cap. Under a topic storm (a wildcard fanning out to
# thousands of device topics) discovery stops at this many and the monitor's
# ``capped`` flag is raised; already-tracked topics keep updating.
MAX_TOPICS_PER_MONITOR = 500

# Captured payloads are truncated to this many bytes before buffering, so a
# large retained blob cannot bloat memory or the payload.
PAYLOAD_MAX_BYTES = 1024

# paho network-loop keepalive + reconnect backoff bounds (paho owns the retry).
CONNECT_KEEPALIVE = 60
RECONNECT_MIN_DELAY = 1
RECONNECT_MAX_DELAY = 120

# Default broker port when the config omits one (1883 plaintext; TLS brokers set
# 8883 explicitly in config).
DEFAULT_PORT = 1883

# Process-wide singleton, created lazily on first configured tick.
_manager = None
_manager_lock = threading.Lock()


def _monotonic():
    """Single patchable time seam so tests can drive a deterministic clock for
    both recording marks and computing ages."""
    return time.monotonic()


def _age(mark, now):
    """Seconds between a recorded monotonic mark and ``now``, or None when the
    mark was never set. Clamped at 0 so a tiny clock skew never reports a
    negative age."""
    if mark is None:
        return None
    return round(max(0.0, now - mark), 3)


def _coerce_port(value):
    """Best-effort int port, falling back to the default on garbage."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return DEFAULT_PORT


def _truncate_payload(payload):
    """<= PAYLOAD_MAX_BYTES, JSON-safe str for a captured payload.

    paho hands ``bytes``; a str (defensive / tests) is encoded first, ``None``
    becomes empty. Truncation happens on the raw bytes and the result is decoded
    with ``errors="replace"`` so a split multibyte sequence or genuinely
    non-UTF-8 payload can never raise at JSON-encode time.
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8", "replace")
    if not isinstance(payload, (bytes, bytearray)):
        payload = b""
    return bytes(payload[:PAYLOAD_MAX_BYTES]).decode("utf-8", "replace")


def _reason_value(reason_code):
    """Numeric value of a paho2 ReasonCode, or the raw int (paho1 / tests)."""
    return getattr(reason_code, "value", reason_code)


def _reason_name(reason_code):
    """Human-readable reason string (paho2 stringifies to the name)."""
    if reason_code is None:
        return "unknown"
    return str(reason_code)


def _connect_status(reason_code):
    """Map a CONNACK outcome to ``(status, error_detail)``.

    Success -> ``("connected", None)``. Auth rejections route to ``auth_error``
    (the server's amber config_error); anything else is a hard ``error``.
    Handles both the paho2 ReasonCode (value 0 ok; 134 bad user/pass, 135 not
    authorized) and the plain-int MQTT v3 convention (0 ok; 4 bad user/pass, 5
    not authorized) so the classifier is version-tolerant and trivially mockable.
    """
    value = _reason_value(reason_code)
    if value == 0:
        return "connected", None
    name = _reason_name(reason_code)
    lname = name.lower()
    if (
        value in (4, 5, 134, 135)
        or "not authorized" in lname
        or "bad user" in lname
        or "password" in lname
    ):
        return "auth_error", name
    return "error", name


def _connection_signature(cfg):
    """Identity of a broker's CONNECTION params. A change here forces a full
    client restart; a change only in ``monitors`` is applied in place (see
    ``MQTTManager.reconcile``)."""
    return (
        cfg.get("host"),
        _coerce_port(cfg.get("port", DEFAULT_PORT)),
        bool(cfg.get("tls", False)),
        cfg.get("username"),
        cfg.get("password"),
    )


class _MonitorState:
    """In-memory freshness state for one monitor (one subscription filter),
    keyed by the concrete topics seen under it."""

    def __init__(self, topic_filter, capture_payload):
        self.topic_filter = topic_filter
        self.capture_payload = bool(capture_payload)
        # Set when the filter is (re)subscribed on a live connection; None while
        # disconnected. The server's arming input.
        self.subscribed_at: float | None = None
        # Raised once discovery hits MAX_TOPICS_PER_MONITOR.
        self.capped = False
        # concrete topic -> {first_seen, last_message_at, last_live_at,
        #                    payload, payload_retained}
        self.topics = {}


class _BrokerClient:
    """Owns one paho client + its in-memory state for a single broker.

    paho's loop thread calls the on_* callbacks from a DIFFERENT thread than the
    per-tick ``snapshot`` on the main loop, so every read/write of the mutable
    state below is guarded by ``self._lock``.
    """

    def __init__(self, config):
        self.broker_id = config.get("broker_id")
        self.host = config.get("host")
        self.port = _coerce_port(config.get("port", DEFAULT_PORT))
        self.tls = bool(config.get("tls", False))
        self.username = config.get("username")
        self.password = config.get("password")

        self._lock = threading.Lock()
        self._closing = False
        self._connected = False
        # Filters currently subscribed on the wire (deduped across monitors that
        # share a filter), so a monitor edit only sub/unsubs the delta.
        self._subscribed_filters = set()

        # Until the first CONNACK we are legitimately not connected, so the
        # honest envelope is an error one ("still connecting" is not "healthy").
        self.status = "error"
        self.error: str | None = "connecting"
        self.connected_at: float | None = None

        self.monitors = {}
        for mon in config.get("monitors") or []:
            if not isinstance(mon, dict):
                continue
            mid = mon.get("id")
            if mid is None:
                continue
            self.monitors[mid] = _MonitorState(
                mon.get("topic_filter"), mon.get("capture_payload")
            )

        self._client = self._build_client()

    def connection_signature(self):
        return (self.host, self.port, self.tls, self.username, self.password)

    def _build_client(self):
        client = mqtt_client.Client(
            mqtt_client.CallbackAPIVersion.VERSION2,
            # Empty client id + clean session: the broker assigns one and keeps
            # no session state, so a reconnect never resurrects stale queues.
            client_id="",
            clean_session=True,
            protocol=mqtt_client.MQTTv311,
        )
        if self.username is not None:
            client.username_pw_set(self.username, self.password)
        if self.tls:
            # Default secure context: system CAs + hostname verification. No
            # client cert (mTLS is out of scope for v1).
            client.tls_set()
        client.reconnect_delay_set(RECONNECT_MIN_DELAY, RECONNECT_MAX_DELAY)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message
        return client

    def start(self):
        """Kick off the background connect. ``connect_async`` does no network
        I/O on this thread, so a dead broker never stalls the collection loop --
        paho's loop thread connects and retries with backoff."""
        try:
            self._client.connect_async(
                self.host, self.port, keepalive=CONNECT_KEEPALIVE
            )
            self._client.loop_start()
        except Exception as e:
            with self._lock:
                self.status = "error"
                self.error = str(e)
            log(f"MQTT broker {self.broker_id} failed to start: {e}", "error")

    def stop(self):
        """Tear the client down: no more callbacks mutate state, the loop thread
        is joined, and the socket is closed. Idempotent and never raises."""
        with self._lock:
            self._closing = True
        try:
            self._client.disconnect()
        except Exception as e:  # pragma: no cover - defensive, paho rarely raises
            log(f"MQTT broker {self.broker_id} disconnect error: {e}", "debug")
        try:
            self._client.loop_stop()
        except Exception as e:  # pragma: no cover - defensive, paho rarely raises
            log(f"MQTT broker {self.broker_id} loop_stop error: {e}", "debug")

    # --- paho callbacks (run on paho's network thread) --------------------

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        status, detail = _connect_status(reason_code)
        now = _monotonic()
        with self._lock:
            if self._closing:
                return
            self.status = status
            self.error = detail
            if status == "connected":
                self._connected = True
                self.connected_at = now
            else:
                self._connected = False
                self.connected_at = None
        # Clean session means the broker forgot our subscriptions across the
        # reconnect, so (re)subscribe every current filter. Outside the lock:
        # the wire calls don't touch our state and shouldn't hold it.
        if status == "connected":
            self._resubscribe_all()

    def _on_disconnect(
        self, client, userdata, flags, reason_code, properties=None
    ):
        with self._lock:
            self._connected = False
            self.connected_at = None
            self._subscribed_filters.clear()
            # Not subscribed while down: re-arm on the next connect.
            for mon in self.monitors.values():
                mon.subscribed_at = None
            if self._closing:
                return
            # We can no longer vouch for freshness, so surface the drop. paho
            # will reconnect (reconnect_on_failure) and on_connect flips us back.
            self.status = "error"
            self.error = f"disconnected: {_reason_name(reason_code)}"

    def _on_message(self, client, userdata, message):
        """Route one delivery to every monitor whose filter matches, using
        paho's own matcher (so the agent -- not the server -- owns wildcard
        matching, and overlapping/duplicate filters all fire)."""
        now = _monotonic()
        topic = message.topic
        retained = bool(message.retain)
        payload = message.payload
        with self._lock:
            for mon in self.monitors.values():
                if not mon.topic_filter:
                    continue
                if not topic_matches_sub(mon.topic_filter, topic):
                    continue
                self._record(mon, topic, retained, payload, now)

    def _record(self, mon, topic, retained, payload, now):
        """Update one monitor's state for a delivery. Caller holds the lock."""
        entry = mon.topics.get(topic)
        if entry is None:
            if len(mon.topics) >= MAX_TOPICS_PER_MONITOR:
                # Stop discovering new topics; flag it so the server knows the
                # per-monitor view is truncated.
                mon.capped = True
                return
            entry = {
                "first_seen": now,
                "last_message_at": now,
                "last_live_at": None,
                "payload": None,
                "payload_retained": None,
            }
            mon.topics[topic] = entry
        entry["last_message_at"] = now
        # THE honesty line: retained replays never count as live activity.
        if not retained:
            entry["last_live_at"] = now
        if mon.capture_payload:
            entry["payload"] = _truncate_payload(payload)
            entry["payload_retained"] = retained

    # --- subscription management ------------------------------------------

    def _resubscribe_all(self):
        """Subscribe every current monitor filter and arm the monitors whose
        SUBSCRIBE paho actually accepted. Called on each (re)connect."""
        now = _monotonic()
        with self._lock:
            filters = {
                mon.topic_filter
                for mon in self.monitors.values()
                if mon.topic_filter
            }
        subscribed = {f for f in filters if self._wire_subscribe(f)}
        with self._lock:
            self._subscribed_filters = set(subscribed)
            # Arm only monitors whose filter went out; a filter paho refused
            # (e.g. NO_CONN on a same-tick drop) stays disarmed, so
            # subscribed_age_s is null until the next connect resubscribes it.
            for mon in self.monitors.values():
                armed = bool(mon.topic_filter) and mon.topic_filter in subscribed
                mon.subscribed_at = now if armed else None

    def _wire_subscribe(self, topic_filter):
        """Send a SUBSCRIBE; return True only if paho accepted it.

        subscribe() does NOT raise when the socket is down -- it returns
        ``(MQTT_ERR_NO_CONN, None)`` -- so a truthful ``subscribed_at`` has to
        gate on the return code, not just the exception path.
        """
        try:
            rc, _mid = self._client.subscribe(topic_filter, qos=0)
        except Exception as e:  # pragma: no cover - defensive
            log(f"MQTT subscribe {self.broker_id} {topic_filter}: {e}", "error")
            return False
        if rc != mqtt_client.MQTT_ERR_SUCCESS:
            log(
                f"MQTT subscribe {self.broker_id} {topic_filter} not sent: rc={rc}",
                "debug",
            )
            return False
        return True

    def _wire_unsubscribe(self, topic_filter):
        try:
            self._client.unsubscribe(topic_filter)
        except Exception as e:  # pragma: no cover - defensive
            log(f"MQTT unsubscribe {self.broker_id} {topic_filter}: {e}", "error")

    def update_monitors(self, new_monitors):
        """Apply a monitor-list change IN PLACE on the live connection.

        Preserves freshness state for unchanged monitors (an unrelated edit must
        not reset their ``last_live_seen``) and only sub/unsubscribes the filter
        delta -- no reconnect, so retained replays are not re-triggered for
        untouched topics.
        """
        desired = {}
        for mon in new_monitors or []:
            if not isinstance(mon, dict):
                continue
            mid = mon.get("id")
            if mid is None:
                continue
            desired[mid] = {
                "topic_filter": mon.get("topic_filter"),
                "capture_payload": bool(mon.get("capture_payload")),
            }

        now = _monotonic()
        with self._lock:
            connected = self._connected
            for mid in list(self.monitors):
                if mid in desired:
                    continue
                self.monitors.pop(mid)
            fresh_ids = []
            for mid, spec in desired.items():
                current = self.monitors.get(mid)
                if current is None or current.topic_filter != spec["topic_filter"]:
                    # New monitor or changed filter: fresh state. Armed below,
                    # once its SUBSCRIBE is accepted (not at intent time).
                    self.monitors[mid] = _MonitorState(
                        spec["topic_filter"], spec["capture_payload"]
                    )
                    fresh_ids.append(mid)
                else:
                    # Same filter: a capture_payload toggle needs no wire change,
                    # and must NOT reset an unchanged monitor's subscribed_at.
                    current.capture_payload = spec["capture_payload"]
            # Recompute the wire subscription set from the new monitor list.
            wanted = {
                mon.topic_filter
                for mon in self.monitors.values()
                if mon.topic_filter
            }
            already = set(self._subscribed_filters)
            to_subscribe = (wanted - already) if connected else set()
            to_unsubscribe = (already - wanted) if connected else set()

        for topic_filter in to_unsubscribe:
            self._wire_unsubscribe(topic_filter)
        newly = {f for f in to_subscribe if self._wire_subscribe(f)}

        if not connected:
            return
        with self._lock:
            # Filters live after this edit: the still-wanted ones already on the
            # wire, plus the newly-accepted ones (a refused SUBSCRIBE is excluded
            # so its monitor stays disarmed).
            active = (already & wanted) | newly
            self._subscribed_filters = set(active)
            for mid in fresh_ids:
                mon = self.monitors.get(mid)
                if mon and mon.topic_filter and mon.topic_filter in active:
                    mon.subscribed_at = now

    # --- snapshot (runs on the main collection thread) --------------------

    def snapshot(self):
        """A bounded, JSON-safe view of this broker's state for one tick.

        All ages are computed against a single ``now`` so the snapshot is
        internally consistent (and deterministic under a patched clock).
        """
        now = _monotonic()
        with self._lock:
            monitors_out = {}
            for mid, mon in self.monitors.items():
                topics_out = {}
                for topic, entry in mon.topics.items():
                    view = {
                        "first_seen_age_s": _age(entry["first_seen"], now),
                        "last_message_age_s": _age(entry["last_message_at"], now),
                        "last_live_seen_age_s": _age(entry["last_live_at"], now),
                    }
                    if mon.capture_payload:
                        view["last_payload"] = entry["payload"]
                        view["last_payload_retained"] = entry["payload_retained"]
                    topics_out[topic] = view
                monitors_out[mid] = {
                    "subscribed_age_s": _age(mon.subscribed_at, now),
                    "capped": mon.capped,
                    "topics": topics_out,
                }
            return {
                "status": self.status,
                "error": self.error,
                "connected_age_s": _age(self.connected_at, now),
                "monitors": monitors_out,
            }


class MQTTManager:
    """Owns the live broker clients and reconciles them against desired config.

    ``reconcile`` and ``snapshot`` run only on the main collection thread (once
    per tick, sequentially), so the ``_brokers`` dict itself needs no lock --
    only the per-broker state touched by paho's threads does.
    """

    def __init__(self):
        self._brokers = {}

    def reconcile(self, brokers):
        """Diff desired brokers against the live ones and act only on change.

        ``brokers`` absent / falsy / malformed -> tear everything down. A new
        broker is started; a removed one is stopped; an existing broker whose
        connection params changed is restarted; otherwise only its monitor list
        is re-applied in place.
        """
        desired = {}
        if isinstance(brokers, list):
            for cfg in brokers:
                if not isinstance(cfg, dict):
                    continue
                bid = cfg.get("broker_id")
                if bid is None:
                    continue
                desired[bid] = cfg

        for bid in list(self._brokers):
            if bid not in desired:
                self._brokers.pop(bid).stop()

        for bid, cfg in desired.items():
            existing = self._brokers.get(bid)
            if existing is None:
                self._start_broker(bid, cfg)
            elif existing.connection_signature() != _connection_signature(cfg):
                # A reconnect loses topic state, but the operator changed the
                # endpoint/credentials -- the old state no longer applies. Drop
                # the stopped client BEFORE rebuilding: if constructing the
                # replacement raises, the broker is then absent from the snapshot
                # (honest) instead of lingering with the old client's stale
                # status (a stopped client's on_disconnect no-ops while closing,
                # so it would otherwise keep reporting "connected").
                existing.stop()
                self._brokers.pop(bid, None)
                self._start_broker(bid, cfg)
            else:
                existing.update_monitors(cfg.get("monitors"))

    def _start_broker(self, bid, cfg):
        # Isolate construction failures per broker: a client that cannot even be
        # built (e.g. an exotic TLS/env error) is skipped and retried next tick,
        # so one bad broker never aborts reconcile and hides the healthy ones.
        try:
            client = _BrokerClient(cfg)
        except Exception as e:
            log(f"MQTT broker {bid} could not be created: {e}", "error")
            return
        self._brokers[bid] = client
        client.start()

    def snapshot(self):
        """``{"brokers": {broker_id: envelope}}``, or None when no broker is
        configured (so the agent omits ``data["mqtt"]`` entirely)."""
        if not self._brokers:
            return None
        return {
            "brokers": {bid: bc.snapshot() for bid, bc in self._brokers.items()}
        }

    def shutdown(self):
        """Stop every client (loop_stop + disconnect); no thread leaks."""
        for bid in list(self._brokers):
            self._brokers.pop(bid).stop()


def _get_manager():
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = MQTTManager()
        return _manager


@debug("mqtt")
def mqtt_metrics(brokers):
    """Per-tick entry point (special-case collector, wired in agent.py).

    Reconciles the persistent client pool to ``brokers`` -- so passing None/[]
    when the config key disappears tears every client down -- and returns the
    snapshot, or None when nothing is configured (agent omits the key).
    """
    manager = _get_manager()
    manager.reconcile(brokers)
    return manager.snapshot()


def shutdown_mqtt():
    """Tear down all MQTT clients on agent shutdown. Called from Agent._cleanup."""
    global _manager
    with _manager_lock:
        if _manager is not None:
            _manager.shutdown()
            _manager = None
