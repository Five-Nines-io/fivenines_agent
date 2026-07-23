"""Tests for the persistent MQTT subscription collector (agent issue #92).

paho's network stack is never exercised: ``mqtt_client.Client`` is mocked so no
socket is opened, callbacks are invoked directly (as paho's loop thread would),
and ``_monotonic`` is patched to a deterministic clock so ages are exact. That
lets the whole lifecycle -- create / connect / subscribe / message / reconfigure
/ reconnect / teardown -- plus the retained-vs-live honesty be pinned without a
broker.

The cross-repo contract lives in fixtures/mqtt_contract_payload.json and is
asserted by test_contract_fixture_round_trip (the same discipline as
test_redis.py): each scenario's events are replayed and the snapshot must equal
the pinned payload the server ingests.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.reasoncodes import ReasonCode

from fivenines_agent import mqtt as m


# --- harness ---------------------------------------------------------------


def _rc(name):
    """A real paho CONNACK ReasonCode by name (Success / Not authorized / ...)."""
    return ReasonCode(PacketTypes.CONNACK, name)


class Harness:
    """Deterministic clock + a fresh MagicMock paho client per broker."""

    def __init__(self):
        self.clock = {"t": 0.0}
        self.clients = []

    def set_time(self, t):
        self.clock["t"] = float(t)

    def now(self):
        return self.clock["t"]

    def _make_client(self, *args, **kwargs):
        c = MagicMock(name="paho_client")
        c.subscribe.return_value = (0, 1)
        c.unsubscribe.return_value = (0, 1)
        self.clients.append(c)
        return c


@pytest.fixture
def h():
    harness = Harness()
    with patch.object(m, "_monotonic", harness.now), patch.object(
        m.mqtt_client, "Client", side_effect=harness._make_client
    ):
        yield harness


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Keep the process-wide manager from leaking across tests."""
    m._manager = None
    yield
    m._manager = None


def _connect(bc, reason="Success"):
    bc._on_connect(bc._client, None, None, _rc(reason), None)


def _disconnect(bc, reason="Keep alive timeout"):
    # on_disconnect only stringifies the reason, so a plain string stands in for
    # a paho DISCONNECT ReasonCode (whose names differ from CONNACK's).
    bc._on_disconnect(bc._client, None, None, reason, None)


def _deliver(bc, topic, payload="x", retain=False):
    msg = MagicMock()
    msg.topic = topic
    msg.payload = payload.encode() if isinstance(payload, str) else payload
    msg.retain = 1 if retain else 0
    bc._on_message(bc._client, None, msg)


def _broker(broker_id="b1", monitors=None, **overrides):
    cfg = {
        "broker_id": broker_id,
        "host": "broker.example.com",
        "port": 1883,
        "tls": False,
        "monitors": monitors
        if monitors is not None
        else [{"id": "m1", "topic_filter": "a/+/c", "capture_payload": True}],
    }
    cfg.update(overrides)
    return cfg


# --- pure helpers ----------------------------------------------------------


def test_monotonic_is_real_clock():
    # Everything else patches _monotonic; cover the real body once.
    assert isinstance(m._monotonic(), float)


def test_age_none_mark_is_none():
    assert m._age(None, 100.0) is None


def test_age_positive_and_clamped():
    assert m._age(90.0, 100.0) == 10.0
    # Negative skew is clamped to 0, never a negative age.
    assert m._age(105.0, 100.0) == 0.0


def test_coerce_port_valid_and_garbage():
    assert m._coerce_port(8883) == 8883
    assert m._coerce_port("1883") == 1883
    assert m._coerce_port("nope") == m.DEFAULT_PORT
    assert m._coerce_port(None) == m.DEFAULT_PORT


def test_truncate_payload_str_bytes_none_and_nonutf8():
    assert m._truncate_payload("hello") == "hello"
    assert m._truncate_payload(b"hello") == "hello"
    assert m._truncate_payload(None) == ""
    # Non-UTF-8 bytes are scrubbed to the replacement char (U+FFFD), never raise.
    assert m._truncate_payload(b"\xff\xfe") == "\ufffd\ufffd"


def test_truncate_payload_caps_bytes():
    big = b"z" * (m.PAYLOAD_MAX_BYTES + 500)
    out = m._truncate_payload(big)
    assert len(out) == m.PAYLOAD_MAX_BYTES
    assert out == "z" * m.PAYLOAD_MAX_BYTES


def test_reason_value_and_name_variants():
    assert m._reason_value(_rc("Success")) == 0
    assert m._reason_value(5) == 5  # plain int (paho1 / test convention)
    assert m._reason_name(None) == "unknown"
    assert m._reason_name(_rc("Not authorized")) == "Not authorized"


def test_connect_status_success():
    assert m._connect_status(_rc("Success")) == ("connected", None)


def test_connect_status_auth_by_reasoncode():
    # paho2 maps CONNACK 'Not authorized' -> value 135, 'Bad user...' -> 134.
    assert m._connect_status(_rc("Not authorized"))[0] == "auth_error"
    assert m._connect_status(_rc("Bad user name or password"))[0] == "auth_error"


def test_connect_status_auth_by_int_convention():
    # Plain-int MQTT v3 return codes: 4 bad user/pass, 5 not authorized.
    assert m._connect_status(4)[0] == "auth_error"
    assert m._connect_status(5)[0] == "auth_error"


def test_connect_status_auth_by_name_when_value_not_in_set():
    # A reason code whose value is not a known auth code but whose text says so
    # still routes to auth_error (the string fallback branch).
    class _FakeReason:
        value = 200

        def __str__(self):
            return "Client not authorized here"

    assert m._connect_status(_FakeReason()) == (
        "auth_error",
        "Client not authorized here",
    )


def test_connect_status_generic_error():
    status, detail = m._connect_status(_rc("Server unavailable"))
    assert status == "error"
    assert detail == "Server unavailable"


def test_connection_signature_tracks_conn_params_only():
    a = _broker(host="h", port=8883, tls=True, username="u", password="p")
    b = dict(a, monitors=[{"id": "x", "topic_filter": "z/#"}])  # monitors differ
    assert m._connection_signature(a) == m._connection_signature(b)
    c = dict(a, port=1884)
    assert m._connection_signature(a) != m._connection_signature(c)


# --- client construction ---------------------------------------------------


def test_build_client_sets_auth_and_tls(h):
    bc = m._BrokerClient(
        _broker(tls=True, username="u", password="p", monitors=[])
    )
    bc._client.username_pw_set.assert_called_once_with("u", "p")
    bc._client.tls_set.assert_called_once()
    bc._client.reconnect_delay_set.assert_called_once()


def test_build_client_no_auth_no_tls(h):
    bc = m._BrokerClient(_broker(monitors=[]))
    bc._client.username_pw_set.assert_not_called()
    bc._client.tls_set.assert_not_called()


def test_init_skips_malformed_monitors(h):
    bc = m._BrokerClient(
        _broker(
            monitors=[
                "not-a-dict",
                {"no_id": True},
                {"id": "ok", "topic_filter": "t/#", "capture_payload": False},
            ]
        )
    )
    assert list(bc.monitors) == ["ok"]


# --- start ----------------------------------------------------------------


def test_start_connects_async_and_starts_loop(h):
    bc = m._BrokerClient(_broker(host="mqtt.host", port=8883, monitors=[]))
    bc.start()
    bc._client.connect_async.assert_called_once_with(
        "mqtt.host", 8883, keepalive=m.CONNECT_KEEPALIVE
    )
    bc._client.loop_start.assert_called_once()


def test_start_failure_sets_error_envelope(h):
    bc = m._BrokerClient(_broker(monitors=[]))
    bc._client.connect_async.side_effect = OSError("dns boom")
    bc.start()
    assert bc.status == "error"
    assert "dns boom" in bc.error


# --- connect / disconnect callbacks ---------------------------------------


def test_on_connect_success_subscribes_all_and_arms(h):
    h.set_time(100.0)
    bc = m._BrokerClient(
        _broker(monitors=[{"id": "m1", "topic_filter": "a/+/c"}])
    )
    _connect(bc)
    assert bc.status == "connected"
    assert bc.error is None
    assert bc.connected_at == 100.0
    bc._client.subscribe.assert_called_once_with("a/+/c", qos=0)
    assert bc.monitors["m1"].subscribed_at == 100.0


def test_on_connect_auth_failure_does_not_subscribe(h):
    bc = m._BrokerClient(_broker())
    _connect(bc, reason="Not authorized")
    assert bc.status == "auth_error"
    assert bc.error == "Not authorized"
    assert bc.connected_at is None
    bc._client.subscribe.assert_not_called()


def test_on_connect_generic_error(h):
    bc = m._BrokerClient(_broker())
    _connect(bc, reason="Server unavailable")
    assert bc.status == "error"
    assert bc.connected_at is None


def test_on_connect_ignored_while_closing(h):
    bc = m._BrokerClient(_broker())
    bc._closing = True
    _connect(bc)
    # Early return: no connected state, no subscribe.
    assert bc.status == "error"
    bc._client.subscribe.assert_not_called()


def test_on_disconnect_marks_error_and_disarms(h):
    h.set_time(200.0)
    bc = m._BrokerClient(_broker())
    _connect(bc)
    assert bc._connected is True
    _disconnect(bc, reason="Keep alive timeout")
    assert bc.status == "error"
    assert "disconnected" in bc.error
    assert bc.connected_at is None
    assert bc._subscribed_filters == set()
    assert bc.monitors["m1"].subscribed_at is None


def test_on_disconnect_while_closing_leaves_status(h):
    bc = m._BrokerClient(_broker())
    _connect(bc)
    bc._closing = True
    _disconnect(bc)
    # Teardown disconnect: state disarmed but status not flipped to error.
    assert bc.status == "connected"
    assert bc.connected_at is None


# --- message handling & honesty -------------------------------------------


def test_live_message_sets_live_and_message_ages(h):
    h.set_time(10.0)
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#"}]))
    _connect(bc)
    h.set_time(15.0)
    _deliver(bc, "a/b", "hi", retain=False)
    entry = bc.monitors["m1"].topics["a/b"]
    assert entry["last_live_at"] == 15.0
    assert entry["last_message_at"] == 15.0
    assert entry["first_seen"] == 15.0


def test_retained_message_never_sets_live(h):
    # THE honesty contract: a RETAIN=1 replay is not proof of device liveness.
    h.set_time(10.0)
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#"}]))
    _connect(bc)
    h.set_time(20.0)
    _deliver(bc, "a/b", "stored", retain=True)
    entry = bc.monitors["m1"].topics["a/b"]
    assert entry["last_message_at"] == 20.0
    assert entry["last_live_at"] is None


def test_later_retained_does_not_reset_prior_live(h):
    h.set_time(10.0)
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#"}]))
    _connect(bc)
    h.set_time(12.0)
    _deliver(bc, "a/b", "live", retain=False)
    h.set_time(30.0)
    _deliver(bc, "a/b", "retained", retain=True)
    entry = bc.monitors["m1"].topics["a/b"]
    assert entry["last_message_at"] == 30.0
    assert entry["last_live_at"] == 12.0  # unchanged by the retained replay


def test_message_captures_payload_when_enabled(h):
    bc = m._BrokerClient(
        _broker(monitors=[{"id": "m1", "topic_filter": "a/#", "capture_payload": True}])
    )
    _connect(bc)
    _deliver(bc, "a/b", "PAYLOAD", retain=True)
    entry = bc.monitors["m1"].topics["a/b"]
    assert entry["payload"] == "PAYLOAD"
    assert entry["payload_retained"] is True


def test_message_omits_payload_when_disabled(h):
    bc = m._BrokerClient(
        _broker(monitors=[{"id": "m1", "topic_filter": "a/#", "capture_payload": False}])
    )
    _connect(bc)
    _deliver(bc, "a/b", "PAYLOAD")
    entry = bc.monitors["m1"].topics["a/b"]
    assert entry["payload"] is None
    assert entry["payload_retained"] is None


def test_non_matching_topic_is_ignored(h):
    bc = m._BrokerClient(
        _broker(monitors=[{"id": "m1", "topic_filter": "iot/+/status"}])
    )
    _connect(bc)
    _deliver(bc, "other/topic", "x")
    assert bc.monitors["m1"].topics == {}


def test_empty_filter_monitor_is_skipped(h):
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": None}]))
    _connect(bc)
    _deliver(bc, "anything", "x")
    assert bc.monitors["m1"].topics == {}


def test_wildcard_fans_out_to_multiple_topics(h):
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "s/#"}]))
    _connect(bc)
    _deliver(bc, "s/a", "1")
    _deliver(bc, "s/b/c", "2")
    assert set(bc.monitors["m1"].topics) == {"s/a", "s/b/c"}


def test_overlapping_monitors_both_receive(h):
    bc = m._BrokerClient(
        _broker(
            monitors=[
                {"id": "wild", "topic_filter": "a/#"},
                {"id": "exact", "topic_filter": "a/b"},
            ]
        )
    )
    _connect(bc)
    _deliver(bc, "a/b", "x")
    assert "a/b" in bc.monitors["wild"].topics
    assert "a/b" in bc.monitors["exact"].topics


# --- topic cap -------------------------------------------------------------


def test_cap_stops_discovery_and_flags(h):
    with patch.object(m, "MAX_TOPICS_PER_MONITOR", 2):
        bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "d/+"}]))
        _connect(bc)
        _deliver(bc, "d/1", "x")
        _deliver(bc, "d/2", "x")
        _deliver(bc, "d/3", "x")  # dropped
        mon = bc.monitors["m1"]
        assert set(mon.topics) == {"d/1", "d/2"}
        assert mon.capped is True


def test_capped_monitor_still_updates_known_topics(h):
    with patch.object(m, "MAX_TOPICS_PER_MONITOR", 1):
        h.set_time(1.0)
        bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "d/+"}]))
        _connect(bc)
        _deliver(bc, "d/1", "x")
        _deliver(bc, "d/2", "x")  # dropped -> capped
        h.set_time(5.0)
        _deliver(bc, "d/1", "x")  # existing topic keeps updating
        mon = bc.monitors["m1"]
        assert mon.capped is True
        assert mon.topics["d/1"]["last_message_at"] == 5.0


# --- update_monitors (in-place reconfigure) -------------------------------


def test_update_add_monitor_subscribes_new_filter(h):
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#"}]))
    _connect(bc)
    bc._client.subscribe.reset_mock()
    bc.update_monitors(
        [{"id": "m1", "topic_filter": "a/#"}, {"id": "m2", "topic_filter": "b/#"}]
    )
    bc._client.subscribe.assert_called_once_with("b/#", qos=0)
    assert "m2" in bc.monitors


def test_update_remove_monitor_unsubscribes(h):
    bc = m._BrokerClient(
        _broker(
            monitors=[
                {"id": "m1", "topic_filter": "a/#"},
                {"id": "m2", "topic_filter": "b/#"},
            ]
        )
    )
    _connect(bc)
    bc.update_monitors([{"id": "m1", "topic_filter": "a/#"}])
    bc._client.unsubscribe.assert_called_once_with("b/#")
    assert "m2" not in bc.monitors


def test_update_change_filter_resubscribes_and_resets_state(h):
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#"}]))
    _connect(bc)
    _deliver(bc, "a/x", "1")
    assert bc.monitors["m1"].topics
    bc.update_monitors([{"id": "m1", "topic_filter": "z/#"}])
    bc._client.unsubscribe.assert_called_once_with("a/#")
    bc._client.subscribe.assert_called_with("z/#", qos=0)
    # New filter -> fresh state, prior topics dropped.
    assert bc.monitors["m1"].topic_filter == "z/#"
    assert bc.monitors["m1"].topics == {}


def test_update_capture_toggle_is_no_wire_change(h):
    bc = m._BrokerClient(
        _broker(monitors=[{"id": "m1", "topic_filter": "a/#", "capture_payload": False}])
    )
    _connect(bc)
    bc._client.subscribe.reset_mock()
    bc.update_monitors(
        [{"id": "m1", "topic_filter": "a/#", "capture_payload": True}]
    )
    bc._client.subscribe.assert_not_called()
    bc._client.unsubscribe.assert_not_called()
    assert bc.monitors["m1"].capture_payload is True


def test_update_while_disconnected_skips_wire(h):
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#"}]))
    # never connected
    bc.update_monitors(
        [{"id": "m1", "topic_filter": "a/#"}, {"id": "m2", "topic_filter": "b/#"}]
    )
    bc._client.subscribe.assert_not_called()
    bc._client.unsubscribe.assert_not_called()
    assert set(bc.monitors) == {"m1", "m2"}
    assert bc.monitors["m2"].subscribed_at is None


def test_update_skips_malformed_monitors(h):
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#"}]))
    _connect(bc)
    bc.update_monitors(
        [
            {"id": "m1", "topic_filter": "a/#"},
            "garbage",
            {"missing": "id"},
        ]
    )
    assert list(bc.monitors) == ["m1"]


def test_update_new_monitor_while_connected_is_armed(h):
    h.set_time(50.0)
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#"}]))
    _connect(bc)
    h.set_time(70.0)
    bc.update_monitors(
        [{"id": "m1", "topic_filter": "a/#"}, {"id": "m2", "topic_filter": "b/#"}]
    )
    assert bc.monitors["m2"].subscribed_at == 70.0


# --- broker snapshot -------------------------------------------------------


def test_snapshot_shape_with_capture(h):
    h.set_time(0.0)
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#", "capture_payload": True}]))
    _connect(bc)
    h.set_time(5.0)
    _deliver(bc, "a/b", "v", retain=False)
    h.set_time(10.0)
    snap = bc.snapshot()
    assert snap["status"] == "connected"
    assert snap["connected_age_s"] == 10.0
    topic = snap["monitors"]["m1"]["topics"]["a/b"]
    assert topic["last_live_seen_age_s"] == 5.0
    assert topic["last_payload"] == "v"
    assert topic["last_payload_retained"] is False


def test_snapshot_omits_payload_keys_without_capture(h):
    bc = m._BrokerClient(_broker(monitors=[{"id": "m1", "topic_filter": "a/#", "capture_payload": False}]))
    _connect(bc)
    _deliver(bc, "a/b", "v")
    topic = bc.snapshot()["monitors"]["m1"]["topics"]["a/b"]
    assert "last_payload" not in topic
    assert "last_payload_retained" not in topic


# --- manager reconcile -----------------------------------------------------


def test_reconcile_creates_and_starts_broker(h):
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1")])
    assert "b1" in mgr._brokers
    mgr._brokers["b1"]._client.loop_start.assert_called_once()


def test_reconcile_unchanged_config_does_not_restart(h):
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1")])
    first = mgr._brokers["b1"]
    mgr.reconcile([_broker("b1")])
    assert mgr._brokers["b1"] is first  # same client, no churn
    first._client.disconnect.assert_not_called()


def test_reconcile_monitor_change_updates_in_place(h):
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1", monitors=[{"id": "m1", "topic_filter": "a/#"}])])
    bc = mgr._brokers["b1"]
    _connect(bc)
    mgr.reconcile(
        [
            _broker(
                "b1",
                monitors=[
                    {"id": "m1", "topic_filter": "a/#"},
                    {"id": "m2", "topic_filter": "b/#"},
                ],
            )
        ]
    )
    assert mgr._brokers["b1"] is bc  # not restarted
    assert "m2" in bc.monitors


def test_reconcile_connection_change_restarts(h):
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1", port=1883)])
    old = mgr._brokers["b1"]
    mgr.reconcile([_broker("b1", port=8883)])
    new = mgr._brokers["b1"]
    assert new is not old
    old._client.disconnect.assert_called_once()  # torn down
    new._client.loop_start.assert_called_once()


def test_reconcile_restart_rebuild_failure_leaves_broker_absent(h):
    # Honesty guard: on a connection-param change the old client is stopped
    # first, so if the replacement can't be built the broker must drop out of
    # the snapshot -- never linger reporting the stopped client's stale status.
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1", port=1883)])
    _connect(mgr._brokers["b1"])  # old client is "connected"
    old_client = mgr._brokers["b1"]._client

    def boom(cfg):
        raise RuntimeError("tls context boom on rebuild")

    with patch.object(m, "_BrokerClient", side_effect=boom):
        mgr.reconcile([_broker("b1", port=8883)])  # conn change -> restart
    old_client.disconnect.assert_called_once()  # old one was torn down
    assert "b1" not in mgr._brokers
    assert mgr.snapshot() is None


def test_reconcile_removes_dropped_broker(h):
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1"), _broker("b2")])
    b1_client = mgr._brokers["b1"]._client
    mgr.reconcile([_broker("b2")])
    assert set(mgr._brokers) == {"b2"}
    b1_client.disconnect.assert_called_once()
    b1_client.loop_stop.assert_called_once()


def test_reconcile_none_tears_everything_down(h):
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1")])
    client = mgr._brokers["b1"]._client
    mgr.reconcile(None)
    assert mgr._brokers == {}
    client.disconnect.assert_called_once()


def test_reconcile_isolates_broker_construction_failure(h):
    mgr = m.MQTTManager()
    real = m._BrokerClient

    def flaky(cfg):
        if cfg["broker_id"] == "bad":
            raise RuntimeError("tls context boom")
        return real(cfg)

    with patch.object(m, "_BrokerClient", side_effect=flaky):
        mgr.reconcile([_broker("ok"), _broker("bad")])
    # The unbuildable broker is skipped (retried next tick); the healthy one
    # still snapshots -- one bad broker never nukes the whole subsystem.
    assert set(mgr._brokers) == {"ok"}
    assert mgr.snapshot()["brokers"]["ok"]["status"] == "error"


def test_reconcile_skips_malformed_broker_entries(h):
    mgr = m.MQTTManager()
    mgr.reconcile(["not-a-dict", {"no_broker_id": True}, _broker("good")])
    assert set(mgr._brokers) == {"good"}


def test_reconcile_non_list_is_teardown(h):
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1")])
    mgr.reconcile({"broker_id": "oops"})  # dict, not a list -> teardown
    assert mgr._brokers == {}


# --- manager snapshot / shutdown ------------------------------------------


def test_manager_snapshot_none_when_empty(h):
    mgr = m.MQTTManager()
    assert mgr.snapshot() is None


def test_manager_snapshot_keys_by_broker_id(h):
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1"), _broker("b2")])
    snap = mgr.snapshot()
    assert set(snap["brokers"]) == {"b1", "b2"}


def test_manager_shutdown_stops_all(h):
    mgr = m.MQTTManager()
    mgr.reconcile([_broker("b1"), _broker("b2")])
    clients = [bc._client for bc in mgr._brokers.values()]
    mgr.shutdown()
    assert mgr._brokers == {}
    for c in clients:
        c.disconnect.assert_called_once()
        c.loop_stop.assert_called_once()


# --- module entry points (singleton) --------------------------------------


def test_get_manager_is_idempotent(h):
    first = m._get_manager()
    assert m._get_manager() is first


def test_mqtt_metrics_reconciles_and_snapshots(h):
    out = m.mqtt_metrics([_broker("b1")])
    assert set(out["brokers"]) == {"b1"}
    # The persistent manager kept the client alive across the call.
    assert "b1" in m._get_manager()._brokers


def test_mqtt_metrics_none_when_unconfigured(h):
    assert m.mqtt_metrics(None) is None
    assert m.mqtt_metrics([]) is None


def test_mqtt_metrics_teardown_on_removal(h):
    m.mqtt_metrics([_broker("b1")])
    client = m._get_manager()._brokers["b1"]._client
    # A later tick with the key gone tears the client down and omits the key.
    assert m.mqtt_metrics(None) is None
    client.disconnect.assert_called_once()


def test_shutdown_mqtt_resets_singleton(h):
    m.mqtt_metrics([_broker("b1")])
    m.shutdown_mqtt()
    assert m._manager is None


def test_shutdown_mqtt_noop_when_never_configured(h):
    # No manager was ever created; must not raise.
    m.shutdown_mqtt()
    assert m._manager is None


# --- cross-repo contract ---------------------------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "mqtt_contract_payload.json"
)


def _replay(mgr, scenario, harness):
    harness.set_time(0.0)
    mgr.reconcile(scenario["config"])
    brokers = list(mgr._brokers.values())
    for event in scenario["events"]:
        harness.set_time(event["at"])
        etype = event["type"]
        for bc in brokers:
            if etype == "connect":
                bc._on_connect(bc._client, None, None, _rc(event["reason"]), None)
            elif etype == "disconnect":
                bc._on_disconnect(bc._client, None, None, event["reason"], None)
            elif etype == "message":
                _deliver(bc, event["topic"], event["payload"], event.get("retain", False))
    harness.set_time(scenario["snapshot_at"])
    return mgr.snapshot()


def test_contract_fixture_round_trip(h):
    """SHARED FIXTURE (cross-repo): fixtures/mqtt_contract_payload.json.

    Each scenario's events are replayed against a real MQTTManager (paho mocked,
    clock deterministic) and manager.snapshot() at snapshot_at must equal the
    pinned payload. fivenines-server vendors this file byte-identical and posts
    each 'payload' under data['mqtt'] to assert its ingester. Change only in
    lockstep across both repos.
    """
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)

    for name, scenario in fixture["scenarios"].items():
        mgr = m.MQTTManager()
        max_topics = scenario.get("max_topics")
        if max_topics is not None:
            with patch.object(m, "MAX_TOPICS_PER_MONITOR", max_topics):
                out = _replay(mgr, scenario, h)
        else:
            out = _replay(mgr, scenario, h)
        assert out == scenario["payload"], "scenario '{}' drifted".format(name)


def test_contract_pins_retained_and_failure_semantics(h):
    """Guardrails on the two properties the whole feature exists to protect."""
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)
    scenarios = fixture["scenarios"]

    # Retained-only: fresh payload state, but NO live freshness.
    retained = scenarios["retained_only"]["payload"]["brokers"]["iot-hub"]
    topic = retained["monitors"]["room-temp"]["topics"]["home/kitchen/temperature"]
    assert topic["last_live_seen_age_s"] is None
    assert topic["last_payload"] == "21.5"
    assert topic["last_payload_retained"] is True

    # Auth failure -> auth_error (server's amber config_error), no fabricated topics.
    auth = scenarios["auth_failure"]["payload"]["brokers"]["secure-broker"]
    assert auth["status"] == "auth_error"
    assert auth["connected_age_s"] is None
    assert auth["monitors"]["commands"]["topics"] == {}

    # Unreachable -> error, distinguishable from healthy-empty by status.
    down = scenarios["broker_unreachable"]["payload"]["brokers"]["offline-broker"]
    assert down["status"] == "error"
    assert down["monitors"]["telemetry"]["topics"] == {}

    # Capped discovery raises the flag and truncates.
    capped = scenarios["capped_discovery"]["payload"]["brokers"]["storm"]
    assert capped["monitors"]["heartbeats"]["capped"] is True
    assert len(capped["monitors"]["heartbeats"]["topics"]) == 2


def test_fixture_min_version_matches_release():
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)
    assert fixture["agent_min_version"] == "1.12.0"
