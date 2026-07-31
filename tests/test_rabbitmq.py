"""Tests for the RabbitMQ management-API collector (server issue #499).

Only the HTTP transport is mocked: a FakeSession dispatches per-URL, feeding
status codes + JSON bodies back through the real _request classification,
node selection, ranked-union, and normalization. The contract round-trip drives
the shared fixture end-to-end, mirroring test_apache.py / test_php_fpm.py.
"""

import json
import os

import pytest
import requests

from fivenines_agent import rabbitmq


# --- transport test doubles ------------------------------------------------


class FakeResponse:
    """Minimal stand-in for a requests.Response: status_code + json()."""

    def __init__(self, status=200, json_body=None, json_error=None):
        self.status_code = status
        self._json = json_body
        self._json_error = json_error

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._json


class FakeSession:
    """A stand-in requests.Session whose .get dispatches through a handler.

    The handler is called with the URL and returns a FakeResponse (or raises a
    requests exception to model a network failure). Records every URL and
    whether close() was called.
    """

    def __init__(self, handler):
        self._handler = handler
        self.auth = None
        self.closed = False
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append(url)
        return self._handler(url)

    def close(self):
        self.closed = True


def _raise(exc):
    def _handler(_url):
        raise exc

    return _handler


def _ok_handler(url):
    """A trivially healthy broker: empty queue set, one unalarmed node."""
    if "/api/overview" in url:
        return FakeResponse(200, {"rabbitmq_version": "3.13.2", "node": "rabbit@node1"})
    if "/api/nodes" in url:
        return FakeResponse(200, [{"name": "rabbit@node1"}])
    if "/api/queues" in url:
        return FakeResponse(200, {"total_count": 0, "items": []})
    raise AssertionError(f"unexpected URL {url}")


def _boom(*_args, **_kwargs):
    raise RuntimeError("boom")


# --- _new_session ----------------------------------------------------------


def test_new_session_no_username_leaves_auth_unset():
    session = rabbitmq._new_session(None, None)
    assert session.auth is None
    session.close()


def test_new_session_sets_basic_auth():
    session = rabbitmq._new_session("fivenines", "secret")
    assert session.auth == ("fivenines", "secret")
    session.close()


def test_new_session_none_password_becomes_empty_string():
    # A username with no password still authenticates (empty password), rather
    # than silently dropping auth.
    session = rabbitmq._new_session("fivenines", None)
    assert session.auth == ("fivenines", "")
    session.close()


# --- _http_get error classification ----------------------------------------


def test_http_get_timeout():
    session = FakeSession(_raise(requests.exceptions.Timeout("read timed out")))
    with pytest.raises(rabbitmq._RabbitError) as exc:
        rabbitmq._http_get(session, "http://h/api/overview")
    assert exc.value.error_type == "timeout"
    assert "timed out" in exc.value.message


def test_http_get_connection_error():
    session = FakeSession(_raise(requests.exceptions.ConnectionError("Connection refused")))
    with pytest.raises(rabbitmq._RabbitError) as exc:
        rabbitmq._http_get(session, "http://h/api/overview")
    assert exc.value.error_type == "connection_refused"
    assert exc.value.message == "Connection refused"


def test_http_get_other_request_exception_is_http_error():
    session = FakeSession(_raise(requests.exceptions.TooManyRedirects("loop")))
    with pytest.raises(rabbitmq._RabbitError) as exc:
        rabbitmq._http_get(session, "http://h/api/overview")
    assert exc.value.error_type == "http_error"


def test_http_get_success_returns_response():
    resp = FakeResponse(200, {"ok": True})
    session = FakeSession(lambda url: resp)
    assert rabbitmq._http_get(session, "http://h/api/overview") is resp


# --- _check_status / _parse_json -------------------------------------------


@pytest.mark.parametrize("status", [401, 403])
def test_check_status_auth_failed(status):
    with pytest.raises(rabbitmq._RabbitError) as exc:
        rabbitmq._check_status(status)
    assert exc.value.error_type == "auth_failed"
    assert exc.value.message == f"HTTP {status}"


def test_check_status_non_200_is_http_error():
    with pytest.raises(rabbitmq._RabbitError) as exc:
        rabbitmq._check_status(503)
    assert exc.value.error_type == "http_error"
    assert exc.value.message == "HTTP 503"


def test_check_status_200_does_not_raise():
    assert rabbitmq._check_status(200) is None


def test_parse_json_valid():
    assert rabbitmq._parse_json(FakeResponse(200, {"a": 1})) == {"a": 1}


def test_parse_json_malformed_is_http_error():
    resp = FakeResponse(200, json_error=ValueError("no json"))
    with pytest.raises(rabbitmq._RabbitError) as exc:
        rabbitmq._parse_json(resp)
    assert exc.value.error_type == "http_error"
    assert exc.value.message == "invalid JSON response"


# --- _request / _request_optional ------------------------------------------


def test_request_success_returns_json():
    session = FakeSession(lambda url: FakeResponse(200, {"rabbitmq_version": "3.13.2"}))
    assert rabbitmq._request(session, "http://h/api/overview") == {"rabbitmq_version": "3.13.2"}


def test_request_non_200_raises():
    session = FakeSession(lambda url: FakeResponse(500))
    with pytest.raises(rabbitmq._RabbitError) as exc:
        rabbitmq._request(session, "http://h/api/overview")
    assert exc.value.error_type == "http_error"


def test_request_optional_404_returns_none():
    session = FakeSession(lambda url: FakeResponse(404))
    assert rabbitmq._request_optional(session, "http://h/api/queues/%2F/gone") is None


def test_request_optional_200_returns_json():
    session = FakeSession(lambda url: FakeResponse(200, {"name": "q"}))
    assert rabbitmq._request_optional(session, "http://h/api/queues/%2F/q") == {"name": "q"}


def test_request_optional_auth_failure_still_raises():
    session = FakeSession(lambda url: FakeResponse(401))
    with pytest.raises(rabbitmq._RabbitError) as exc:
        rabbitmq._request_optional(session, "http://h/api/queues/%2F/q")
    assert exc.value.error_type == "auth_failed"


def test_request_optional_non_200_raises_http_error():
    session = FakeSession(lambda url: FakeResponse(502))
    with pytest.raises(rabbitmq._RabbitError) as exc:
        rabbitmq._request_optional(session, "http://h/api/queues/%2F/q")
    assert exc.value.error_type == "http_error"


# --- _fetch_node -----------------------------------------------------------


def _node_session(nodes_json):
    return FakeSession(lambda url: FakeResponse(200, nodes_json))


def test_fetch_node_selects_matching_name():
    nodes = [
        {"name": "rabbit@other", "mem_alarm": True},
        {
            "name": "rabbit@local",
            "mem_alarm": False,
            "disk_free_alarm": True,
            "fd_used": 10,
            "fd_total": 100,
            "sockets_used": 5,
            "sockets_total": 50,
        },
    ]
    node = rabbitmq._fetch_node(_node_session(nodes), "http://h", "rabbit@local")
    assert node == {
        "mem_alarm": False,
        "disk_free_alarm": True,
        "fd_used": 10,
        "fd_total": 100,
        "sockets_used": 5,
        "sockets_total": 50,
    }


def test_fetch_node_falls_back_to_first_when_name_absent():
    nodes = [{"name": "rabbit@a", "mem_alarm": True}, {"name": "rabbit@b"}]
    node = rabbitmq._fetch_node(_node_session(nodes), "http://h", "rabbit@missing")
    assert node["mem_alarm"] is True  # first node


def test_fetch_node_no_overview_name_uses_first():
    nodes = [{"name": "rabbit@a", "disk_free_alarm": True}]
    node = rabbitmq._fetch_node(_node_session(nodes), "http://h", None)
    assert node["disk_free_alarm"] is True


def test_fetch_node_skips_non_dict_items():
    nodes = ["garbage", {"name": "rabbit@local", "mem_alarm": True}]
    node = rabbitmq._fetch_node(_node_session(nodes), "http://h", "rabbit@local")
    assert node["mem_alarm"] is True


def test_fetch_node_defaults_alarms_false_and_gauges_none():
    node = rabbitmq._fetch_node(_node_session([{"name": "rabbit@x"}]), "http://h", "rabbit@x")
    assert node == {
        "mem_alarm": False,
        "disk_free_alarm": False,
        "fd_used": None,
        "fd_total": None,
        "sockets_used": None,
        "sockets_total": None,
    }


def test_fetch_node_non_list_returns_none():
    node = rabbitmq._fetch_node(_node_session({"not": "a list"}), "http://h", "x")
    assert node is None


def test_fetch_node_empty_list_returns_none():
    assert rabbitmq._fetch_node(_node_session([]), "http://h", "x") is None


# --- _page_items / _total_count --------------------------------------------


def test_page_items_variants():
    assert rabbitmq._page_items({"items": [1, 2]}) == [1, 2]
    # Anything that is not a dict-with-list-items is an untrustworthy 200: it must
    # raise (-> unreachable), never coerce to [] and false-heal to "no queues".
    for bad in ({"items": "nope"}, {"no_items": 1}, [{"a": 1}], None):
        with pytest.raises(rabbitmq._RabbitError):
            rabbitmq._page_items(bad)


def test_total_count_variants():
    assert rabbitmq._total_count({"total_count": 184, "items": [1]}) == 184
    assert rabbitmq._total_count({"items": [1, 2]}) == 2  # missing metadata -> length
    # bool is an int subclass but not a real count -> fall back to the length.
    assert rabbitmq._total_count({"total_count": True, "items": [1]}) == 1


# --- _normalize_queue ------------------------------------------------------


_RAW_QUEUE = {
    "vhost": "/",
    "name": "notifications",
    "messages": 12000,
    "messages_unacknowledged": 400,
    "consumers": 0,
    "message_stats": {"publish": 981221, "deliver_get": 969221},
}


def test_normalize_queue_full():
    assert rabbitmq._normalize_queue(_RAW_QUEUE) == {
        "vhost": "/",
        "name": "notifications",
        "messages": 12000,
        "messages_unacked": 400,
        "consumers": 0,
        "publish_total": 981221,
        "deliver_total": 969221,
    }


def test_normalize_queue_no_message_stats_omits_counters():
    raw = {"vhost": "/", "name": "logs", "messages": 0, "messages_unacknowledged": 0, "consumers": 1}
    out = rabbitmq._normalize_queue(raw)
    assert "publish_total" not in out and "deliver_total" not in out
    assert out == {
        "vhost": "/",
        "name": "logs",
        "messages": 0,
        "messages_unacked": 0,
        "consumers": 1,
    }


def test_normalize_queue_partial_message_stats():
    # publish present, deliver_get absent -> only publish_total emitted.
    raw = {"vhost": "/", "name": "q", "message_stats": {"publish": 5}}
    out = rabbitmq._normalize_queue(raw)
    assert out["publish_total"] == 5
    assert "deliver_total" not in out
    # deliver_get present, publish absent -> only deliver_total emitted.
    raw = {"vhost": "/", "name": "q", "message_stats": {"deliver_get": 9}}
    out = rabbitmq._normalize_queue(raw)
    assert out["deliver_total"] == 9
    assert "publish_total" not in out


def test_normalize_queue_non_dict_message_stats_omitted():
    raw = {"vhost": "/", "name": "q", "message_stats": None}
    out = rabbitmq._normalize_queue(raw)
    assert "publish_total" not in out and "deliver_total" not in out


# --- _fetch_queues (union + vhost scoping) ---------------------------------


def test_fetch_queues_unions_and_dedups():
    big = {"vhost": "/", "name": "big", "messages": 100, "messages_unacknowledged": 1, "consumers": 2}
    stuck = {"vhost": "/", "name": "stuck", "messages": 3, "messages_unacknowledged": 3, "consumers": 0}

    def handler(url):
        if "sort=messages_unacknowledged" in url:
            return FakeResponse(200, {"total_count": 5, "items": [stuck, big]})
        return FakeResponse(200, {"total_count": 5, "items": [big]})

    queues, total = rabbitmq._fetch_queues(FakeSession(handler), "http://h", None, [])
    assert total == 5
    # by_messages first (big), then unacked adds the new one (stuck); big deduped.
    assert [q["name"] for q in queues] == ["big", "stuck"]


def test_fetch_queues_vhost_scoped_and_encoded():
    calls = []

    def handler(url):
        calls.append(url)
        return FakeResponse(200, {"total_count": 0, "items": []})

    queues, total = rabbitmq._fetch_queues(FakeSession(handler), "http://h", "my/vhost", [])
    assert queues == [] and total == 0
    assert calls and all("/api/queues/my%2Fvhost?" in url for url in calls)


def test_fetch_queues_default_path_when_vhost_none():
    calls = []

    def handler(url):
        calls.append(url)
        return FakeResponse(200, {"total_count": 0, "items": []})

    rabbitmq._fetch_queues(FakeSession(handler), "http://h", None, [])
    assert all("/api/queues?" in url for url in calls)


# --- _add_include_queues / _fetch_single_queue -----------------------------


def test_add_include_empty_makes_no_request():
    session = FakeSession(_boom)  # would raise if called
    merged = {}
    rabbitmq._add_include_queues(session, "http://h", None, [], merged)
    assert merged == {}
    assert session.calls == []


def test_add_include_skips_already_present():
    session = FakeSession(_boom)  # must not be called for a present queue
    merged = {("/", "watched"): {"vhost": "/", "name": "watched"}}
    rabbitmq._add_include_queues(session, "http://h", None, ["watched"], merged)
    assert session.calls == []


def test_add_include_fetches_missing_queue():
    raw = {"vhost": "/", "name": "below_cap", "messages": 2, "messages_unacknowledged": 2, "consumers": 0}
    session = FakeSession(lambda url: FakeResponse(200, raw))
    merged = {}
    rabbitmq._add_include_queues(session, "http://h", None, ["below_cap"], merged)
    assert ("/", "below_cap") in merged
    assert merged[("/", "below_cap")]["messages"] == 2
    # default lookup vhost is "/" -> %2F in the URL.
    assert "/api/queues/%2F/below_cap?" in session.calls[0]


def test_add_include_uses_configured_vhost():
    raw = {"vhost": "prod", "name": "q", "messages": 1, "messages_unacknowledged": 0, "consumers": 1}
    session = FakeSession(lambda url: FakeResponse(200, raw))
    rabbitmq._add_include_queues(session, "http://h", "prod", ["q"], {})
    assert "/api/queues/prod/q?" in session.calls[0]


def test_add_include_missing_queue_404_is_skipped():
    session = FakeSession(lambda url: FakeResponse(404))
    merged = {}
    rabbitmq._add_include_queues(session, "http://h", None, ["deleted"], merged)
    assert merged == {}  # 404 -> not added, not an error


def test_add_include_dedups_repeated_names():
    raw = {"vhost": "/", "name": "q", "messages": 1, "messages_unacknowledged": 0, "consumers": 1}
    session = FakeSession(lambda url: FakeResponse(200, raw))
    merged = {}
    rabbitmq._add_include_queues(session, "http://h", None, ["q", "q"], merged)
    assert len(session.calls) == 1  # fetched once despite the repeat


def test_add_include_transport_error_propagates(monkeypatch):
    # A transport failure on the include lookup must NOT be swallowed: it sinks
    # the whole tick to unreachable (unknown != recovered).
    session = FakeSession(_raise(requests.exceptions.ConnectionError("refused")))
    with pytest.raises(rabbitmq._RabbitError):
        rabbitmq._add_include_queues(session, "http://h", None, ["q"], {})


def test_fetch_single_queue_404_returns_none():
    # A genuine 404 -> None (queue deleted, safe to drop).
    session = FakeSession(lambda url: FakeResponse(404))
    assert rabbitmq._fetch_single_queue(session, "http://h", "/", "gone") is None


def test_fetch_single_queue_non_dict_200_raises(monkeypatch):
    # A 200 whose body is not a queue object is untrustworthy (proxy / error
    # page): it must RAISE (-> unreachable), never coerce to None ("deleted")
    # which would drop the watched queue and false-resolve its incident.
    monkeypatch.setattr(rabbitmq, "_request_optional", lambda s, u: ["unexpected"])
    with pytest.raises(rabbitmq._RabbitError):
        rabbitmq._fetch_single_queue(FakeSession(_boom), "http://h", "/", "q")


def test_fetch_single_queue_encodes_name():
    calls = []

    def handler(url):
        calls.append(url)
        return FakeResponse(200, {"vhost": "/", "name": "a/b"})

    rabbitmq._fetch_single_queue(FakeSession(handler), "http://h", "/", "a/b")
    assert "/api/queues/%2F/a%2Fb?" in calls[0]


# --- _unreachable ----------------------------------------------------------


def test_unreachable_truncates_message():
    out = rabbitmq._unreachable("timeout", "x" * 600)
    assert out["reachable"] is False
    assert out["error_type"] == "timeout"
    assert len(out["error_message"]) == rabbitmq._ERROR_MESSAGE_MAX


def test_unreachable_none_message_becomes_empty():
    assert rabbitmq._unreachable("http_error", None)["error_message"] == ""


# --- rabbitmq_metrics top level --------------------------------------------


def test_metrics_default_url_and_closes_session(monkeypatch):
    session = FakeSession(_ok_handler)
    monkeypatch.setattr(rabbitmq, "_new_session", lambda user, password: session)
    out = rabbitmq.rabbitmq_metrics()
    assert out["reachable"] is True
    assert out["queues"] == [] and out["queues_total"] == 0
    assert session.calls[0].startswith("http://127.0.0.1:15672/api/overview")
    assert session.closed  # finally always closes the session


def test_metrics_none_url_uses_default(monkeypatch):
    session = FakeSession(_ok_handler)
    monkeypatch.setattr(rabbitmq, "_new_session", lambda user, password: session)
    rabbitmq.rabbitmq_metrics(url=None, include_queues=None)
    assert session.calls[0].startswith("http://127.0.0.1:15672/api/overview")


def test_metrics_strips_trailing_slash(monkeypatch):
    session = FakeSession(_ok_handler)
    monkeypatch.setattr(rabbitmq, "_new_session", lambda user, password: session)
    rabbitmq.rabbitmq_metrics(url="http://broker:15672/")
    assert session.calls[0].startswith("http://broker:15672/api/overview")
    assert "15672//api" not in session.calls[0]


def test_metrics_rabbit_error_becomes_unreachable(monkeypatch):
    session = FakeSession(_raise(requests.exceptions.ConnectionError("Connection refused")))
    monkeypatch.setattr(rabbitmq, "_new_session", lambda user, password: session)
    out = rabbitmq.rabbitmq_metrics()
    assert out == {
        "reachable": False,
        "error_type": "connection_refused",
        "error_message": "Connection refused",
    }
    assert session.closed


def test_metrics_unexpected_exception_becomes_http_error(monkeypatch):
    session = FakeSession(_ok_handler)
    monkeypatch.setattr(rabbitmq, "_new_session", lambda user, password: session)
    monkeypatch.setattr(rabbitmq, "_fetch_node", _boom)  # a non-_RabbitError bug
    out = rabbitmq.rabbitmq_metrics()
    assert out == {"reachable": False, "error_type": "http_error", "error_message": "boom"}
    assert session.closed


# --- review hardening: node fallback, include correctness, sharp edge -------


def test_fetch_node_fallback_skips_non_dict_first():
    # No name match and a non-dict first element: the fallback must pick the
    # first *dict* node, never crash on ["garbage"][0].get(...) (which the outer
    # handler would mislabel as a fabricated http_error outage).
    nodes = ["garbage", {"name": "rabbit@local", "mem_alarm": True}]
    node = rabbitmq._fetch_node(_node_session(nodes), "http://h", None)
    assert node["mem_alarm"] is True


def test_fetch_node_all_non_dict_returns_none():
    assert rabbitmq._fetch_node(_node_session(["garbage", 42]), "http://h", None) is None


def test_include_names_variants():
    assert rabbitmq._include_names(None) == []
    assert rabbitmq._include_names([]) == []
    assert rabbitmq._include_names("orders") == ["orders"]  # scalar string guarded
    assert rabbitmq._include_names(["a", "", "b"]) == ["a", "b"]  # falsy filtered
    assert rabbitmq._include_names(("a", "b")) == ["a", "b"]  # tuple accepted
    assert rabbitmq._include_names(123) == []  # unexpected type ignored


def test_add_include_cross_vhost_name_collision_still_fetches():
    # A same-named queue in a DIFFERENT vhost is already in the ranked union.
    # The watched below-cap queue at the lookup vhost ("/") MUST still be fetched
    # by identity -- presence is keyed on (vhost, name), not the bare name.
    other = {"vhost": "openstack", "name": "celery", "messages": 9000, "messages_unacknowledged": 0, "consumers": 3}
    watched = {"vhost": "/", "name": "celery", "messages": 5, "messages_unacknowledged": 5, "consumers": 0}
    calls = []

    def handler(url):
        calls.append(url)
        return FakeResponse(200, watched)

    merged = {("openstack", "celery"): rabbitmq._normalize_queue(other)}
    rabbitmq._add_include_queues(FakeSession(handler), "http://h", None, ["celery"], merged)
    assert ("/", "celery") in merged  # fetched, not suppressed by the openstack twin
    assert len(calls) == 1
    assert "/api/queues/%2F/celery?" in calls[0]


def test_add_include_lookups_are_capped(monkeypatch):
    monkeypatch.setattr(rabbitmq, "_INCLUDE_QUEUES_CAP", 1)
    calls = []

    def handler(url):
        calls.append(url)
        name = url.rsplit("/", 1)[-1].split("?")[0]
        return FakeResponse(200, {"vhost": "/", "name": name, "messages": 1, "messages_unacknowledged": 0, "consumers": 1})

    merged = {}
    rabbitmq._add_include_queues(FakeSession(handler), "http://h", None, ["a", "b", "c"], merged)
    assert len(calls) == 1  # capped at the budget; b/c not looked up
    assert len(merged) == 1


def test_fetch_queues_surfaces_below_cap_include():
    # include_queues wired end-to-end through _fetch_queues: a below-cap watched
    # queue (absent from both ranked pages) is fetched by identity and appended.
    watched = {"vhost": "/", "name": "watched", "messages": 2, "messages_unacknowledged": 2, "consumers": 0}
    big = {"vhost": "/", "name": "big", "messages": 100, "messages_unacknowledged": 0, "consumers": 1}

    def handler(url):
        if "/api/queues/%2F/watched?" in url:
            return FakeResponse(200, watched)
        return FakeResponse(200, {"total_count": 184, "items": [big]})

    queues, total = rabbitmq._fetch_queues(FakeSession(handler), "http://h", None, ["watched"])
    assert [q["name"] for q in queues] == ["big", "watched"]
    assert total == 184  # broker total, not the shipped count


def test_fetch_queues_second_page_failure_propagates():
    # THE SHARP EDGE at the fetch layer: by_messages OK, by_unacked fails midway.
    # Must raise (never return the messages-only partial array).
    def handler(url):
        if "sort=messages_unacknowledged" in url:
            raise requests.exceptions.ConnectionError("refused")
        return FakeResponse(200, {"total_count": 5, "items": [
            {"vhost": "/", "name": "big", "messages": 100, "messages_unacknowledged": 1, "consumers": 2}]})

    with pytest.raises(rabbitmq._RabbitError):
        rabbitmq._fetch_queues(FakeSession(handler), "http://h", None, [])


def test_metrics_partial_queue_listing_is_unreachable(monkeypatch):
    # THE SHARP EDGE end-to-end: a partial queue listing sinks the whole tick to
    # the unreachable envelope with NO queues key -- never a truncated array that
    # would let the server prune the missing queues and false-resolve incidents.
    def handler(url):
        if "/api/overview" in url:
            return FakeResponse(200, {"rabbitmq_version": "3.13.2", "node": "rabbit@n1"})
        if "/api/nodes" in url:
            return FakeResponse(200, [{"name": "rabbit@n1"}])
        if "sort=messages_unacknowledged" in url:
            raise requests.exceptions.Timeout("read timed out")
        return FakeResponse(200, {"total_count": 5, "items": [
            {"vhost": "/", "name": "big", "messages": 100, "messages_unacknowledged": 1, "consumers": 2}]})

    session = FakeSession(handler)
    monkeypatch.setattr(rabbitmq, "_new_session", lambda user, password: session)
    out = rabbitmq.rabbitmq_metrics()
    assert out["reachable"] is False and "queues" not in out
    assert out["error_type"] == "timeout"


def test_metrics_ignores_unknown_config_keys(monkeypatch):
    # **_kwargs forward-compat: a future server-pushed config key must be ignored,
    # not raise TypeError and crash the collector every tick.
    session = FakeSession(_ok_handler)
    monkeypatch.setattr(rabbitmq, "_new_session", lambda user, password: session)
    out = rabbitmq.rabbitmq_metrics(future_flag=True)
    assert out["reachable"] is True


def test_normalize_queue_field_order_is_the_contract_order():
    # The wire/fixture field order is part of the byte-identical contract; dict
    # equality in the round-trip is order-insensitive, so pin order explicitly.
    assert list(rabbitmq._normalize_queue(_RAW_QUEUE).keys()) == [
        "vhost", "name", "messages", "messages_unacked", "consumers",
        "publish_total", "deliver_total",
    ]
    idle = rabbitmq._normalize_queue(
        {"vhost": "/", "name": "x", "messages": 0, "messages_unacknowledged": 0, "consumers": 1}
    )
    assert list(idle.keys()) == ["vhost", "name", "messages", "messages_unacked", "consumers"]


# --- adversarial hardening: false-heal, watchdog, never-None ---------------


def test_include_names_drops_non_strings():
    # A non-string element (an int, or the {vhost,name} dict a future contract
    # might send) is dropped -- never passed to quote() where it would crash into
    # a per-tick false outage.
    assert rabbitmq._include_names([123, {"vhost": "/", "name": "q"}, "keep"]) == ["keep"]


def test_add_include_stops_at_deadline():
    # A past wall-clock deadline stops the include loop before any lookup (a TIME
    # bound, not just the COUNT cap), so a long watch list against a slow broker
    # can't stall the collect tick past the systemd watchdog.
    calls = []

    def handler(url):
        calls.append(url)
        return FakeResponse(200, {"vhost": "/", "name": "x"})

    rabbitmq._add_include_queues(FakeSession(handler), "http://h", None, ["a", "b"], {}, deadline=0.0)
    assert calls == []  # deadline already passed -> zero lookups


def test_fetch_queues_wrong_shape_200_is_untrustworthy():
    # A reverse-proxy / gateway 200 with a non-paginated body must raise (->
    # unreachable), never yield queues:[] which the server reads as "all deleted".
    def handler(url):
        return FakeResponse(200, {"error": "unauthorized"})  # no list "items"

    with pytest.raises(rabbitmq._RabbitError):
        rabbitmq._fetch_queues(FakeSession(handler), "http://h", None, [])


def test_fetch_queues_non_dict_row_is_untrustworthy():
    def handler(url):
        return FakeResponse(200, {"total_count": 2, "items": [{"vhost": "/", "name": "ok"}, "garbage"]})

    with pytest.raises(rabbitmq._RabbitError):
        rabbitmq._fetch_queues(FakeSession(handler), "http://h", None, [])


def test_metrics_gateway_200_empty_body_is_unreachable(monkeypatch):
    # END-TO-END false-heal guard: a gateway answering 200 {} for every endpoint
    # must NOT become reachable:true + queues:[] (which prunes rows and
    # false-resolves every open backlog incident) -- it must be unreachable.
    session = FakeSession(lambda url: FakeResponse(200, {}))
    monkeypatch.setattr(rabbitmq, "_new_session", lambda user, password: session)
    out = rabbitmq.rabbitmq_metrics()
    assert out["reachable"] is False
    assert "queues" not in out


def test_metrics_session_creation_failure_is_envelope_not_none(monkeypatch):
    # A failure before/at session creation must degrade to the reachable:false
    # envelope (never escape as an exception the collector wrapper turns into
    # None), and the finally must tolerate session being None.
    def boom_session(user, password):
        raise RuntimeError("cannot create session")

    monkeypatch.setattr(rabbitmq, "_new_session", boom_session)
    out = rabbitmq.rabbitmq_metrics()
    assert out == {"reachable": False, "error_type": "http_error", "error_message": "cannot create session"}


# --- cross-repo contract (fivenines-server) --------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "rabbitmq_contract_payload.json"
)

# The exact top-level keys the server ingester reads on a reachable tick. A
# rename or drop must fail loudly here, not silently zero the server metrics.
_REACHABLE_KEYS = {"reachable", "version", "node", "queues_total", "queues"}
_UNREACHABLE_KEYS = {"reachable", "error_type", "error_message"}
_CONFIG_KEYS = {"url", "username", "password", "vhost", "include_queues"}


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


def _label_for(url):
    """Map a collector request URL to a fixture 'responses' key.

    Disambiguates the two ranked queue fetches on the SORT param (both carry
    'messages_unacknowledged' in their columns list, so the sort key is the only
    reliable discriminator).
    """
    if "/api/overview" in url:
        return "overview"
    if "/api/nodes" in url:
        return "nodes"
    if "sort=messages_unacknowledged" in url:
        return "queues_by_unacked"
    if "sort=messages" in url:
        return "queues_by_messages"
    return "single_queue"


_RAISE_EXCEPTIONS = {
    "connection_refused": requests.exceptions.ConnectionError,
    "timeout": requests.exceptions.Timeout,
}


def _fixture_handler(responses):
    def handler(url):
        label = _label_for(url)
        desc = responses.get(label)
        assert desc is not None, f"scenario has no response for {label} ({url})"
        if "error" in desc:
            raise _RAISE_EXCEPTIONS[desc["error"]](desc.get("message", ""))
        return FakeResponse(desc["status"], desc.get("json"))

    return handler


@pytest.mark.parametrize(
    "name",
    [
        "healthy",
        "node_mem_alarm",
        "unreachable",
        "auth_failure",
        "cap_overflow",
        "include_below_cap",
    ],
)
def test_contract_fixture_round_trip(name, monkeypatch):
    """SHARED FIXTURE (cross-repo contract): fixtures/rabbitmq_contract_payload.json.

    Asserted on both sides:
    - here: rabbitmq_metrics(**scenario["config"]["rabbitmq"]) must equal
      scenario["payload"]["rabbitmq"] with only the HTTP transport mocked (a fake
      session replays the scenario's per-endpoint responses through the real
      classification + normalization);
    - fivenines-server: spec/requests/api_collect_rabbitmq_spec.rb posts
      scenario["payload"]["rabbitmq"] under data["rabbitmq"] and asserts
      Ingesters::Agent handles the reachable / unreachable envelopes.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    fixture = _load_fixture()
    scenario = fixture["scenarios"][name]
    session = FakeSession(_fixture_handler(scenario["responses"]))
    monkeypatch.setattr(rabbitmq, "_new_session", lambda user, password: session)
    out = rabbitmq.rabbitmq_metrics(**scenario["config"]["rabbitmq"])
    assert out == scenario["payload"]["rabbitmq"]


def test_fixture_agent_min_version():
    assert _load_fixture()["agent_min_version"] == "1.14.2"


def test_fixture_config_is_documented_shape():
    for scenario in _load_fixture()["scenarios"].values():
        assert set(scenario["config"]["rabbitmq"]) == _CONFIG_KEYS


def test_fixture_reachable_and_unreachable_envelope_keys():
    scenarios = _load_fixture()["scenarios"]
    for name in ("healthy", "node_mem_alarm", "cap_overflow", "include_below_cap"):
        assert set(scenarios[name]["payload"]["rabbitmq"]) == _REACHABLE_KEYS
    for name in ("unreachable", "auth_failure"):
        payload = scenarios[name]["payload"]["rabbitmq"]
        assert set(payload) == _UNREACHABLE_KEYS
        assert "queues" not in payload  # the server keys ingestion off this


def test_fixture_cap_overflow_total_exceeds_shipped():
    cap = _load_fixture()["scenarios"]["cap_overflow"]["payload"]["rabbitmq"]
    assert cap["queues_total"] > len(cap["queues"])
