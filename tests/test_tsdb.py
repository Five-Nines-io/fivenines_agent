"""Tests for the TSDB (Prometheus / VictoriaMetrics) health collector (#672).

Only requests.get is mocked; each case feeds a canned /metrics body (and, for
the Prometheus flavor, an /api/v1/targets body) back through the real parse ->
payload pipeline. Mirrors test_apache.py's cross-repo fixture assertion, with
the postgresql.py reachability envelope: unreachable rides the payload, never
None.
"""

import json
import os
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import pytest
import requests

from fivenines_agent import tsdb
from fivenines_agent.tsdb import tsdb_metrics


def _resp(status=200, text="", json_data=None):
    """A stand-in requests.Response: status_code, text, and a json() method."""
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    if json_data is None:
        resp.json.side_effect = ValueError("no json")
    else:
        resp.json.return_value = json_data
    return resp


def _patch_get(mapping=None, side_effect=None):
    """Patch tsdb.requests.get with a path-routed fake.

    mapping: {path: _resp(...)} looked up by URL path. side_effect (a callable)
    takes precedence for full control (e.g. raising).
    """
    if side_effect is not None:
        return patch("fivenines_agent.tsdb.requests.get", side_effect=side_effect)

    def fake_get(url, **kwargs):
        path = urlsplit(url).path
        if path not in mapping:
            raise AssertionError(f"unexpected GET path: {path}")
        return mapping[path]

    return patch("fivenines_agent.tsdb.requests.get", side_effect=fake_get)


# --- transport wiring: headers / auth / verify -----------------------------


def test_custom_auth_header_and_verify_passed_through():
    captured = {}

    def fake_get(url, **kwargs):
        # Capture the /metrics call only; a prometheus body also triggers a
        # follow-up /api/v1/targets GET that would otherwise clobber it.
        if urlsplit(url).path == "/metrics":
            captured["url"] = url
            captured.update(kwargs)
        return _resp(200, "prometheus_tsdb_head_series 1\n", json_data={"data": {}})

    with patch("fivenines_agent.tsdb.requests.get", side_effect=fake_get):
        tsdb_metrics(
            url="https://tsdb.local:9090/",
            auth_header_name="X-Scope-OrgID",
            auth_header_value="tenant-a",
            verify_ssl=False,
        )

    # Trailing slash on the base URL is stripped before the path is appended.
    assert captured["url"] == "https://tsdb.local:9090/metrics"
    assert captured["headers"] == {"X-Scope-OrgID": "tenant-a"}
    assert captured["auth"] is None
    assert captured["verify"] is False
    assert captured["timeout"] == tsdb._TIMEOUT


def test_basic_auth_tuple_built_with_empty_password_default():
    captured = {}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return _resp(200, "vm_app_version{short_version=\"v1.0.0\"} 1\n")

    with patch("fivenines_agent.tsdb.requests.get", side_effect=fake_get):
        tsdb_metrics(url="http://x", basic_auth_username="monitor")

    # username set, password omitted -> ("monitor", "").
    assert captured["auth"] == ("monitor", "")


def test_partial_custom_header_is_ignored():
    captured = {}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return _resp(200, "prometheus_tsdb_head_series 1\n")

    with patch("fivenines_agent.tsdb.requests.get", side_effect=fake_get):
        # Only the name, no value -> the header is not sent.
        tsdb_metrics(url="http://x", auth_header_name="X-Only-Name")

    assert captured["headers"] == {}


# --- reachability envelope: connection-level failures ----------------------


def test_connection_error_is_connection_refused():
    def boom(url, **kwargs):
        raise requests.exceptions.ConnectionError("Connection refused")

    with _patch_get(side_effect=boom):
        out = tsdb_metrics(url="http://x")
    assert out == {
        "reachable": False,
        "error_type": "connection_refused",
        "error_message": "Connection refused",
    }


def test_timeout_maps_to_timeout():
    def boom(url, **kwargs):
        raise requests.exceptions.ReadTimeout("timed out")

    with _patch_get(side_effect=boom):
        out = tsdb_metrics(url="http://x")
    assert out["reachable"] is False
    assert out["error_type"] == "timeout"


def test_ssl_error_maps_to_tls_error():
    def boom(url, **kwargs):
        raise requests.exceptions.SSLError("certificate verify failed")

    with _patch_get(side_effect=boom):
        out = tsdb_metrics(url="https://x")
    assert out["error_type"] == "tls_error"
    assert out["reachable"] is False


def test_unexpected_transport_error_folds_to_connection_refused():
    # A non-Connection/Timeout/SSL requests error (e.g. a malformed URL) still
    # yields a reachable:false envelope -- never None, never a crash.
    def boom(url, **kwargs):
        raise requests.exceptions.MissingSchema("Invalid URL")

    with _patch_get(side_effect=boom):
        out = tsdb_metrics(url="not-a-url")
    assert out["error_type"] == "connection_refused"


def test_non_string_url_yields_envelope_never_none():
    # A pathological non-string url (malformed server config) must NOT raise out
    # of the collector (which the registry would turn into None) -- str() routes
    # it through requests' own URL validation into a reachable:false envelope.
    # requests raises MissingSchema synchronously (no network) for a schemeless
    # URL, so this is deterministic and offline.
    out = tsdb_metrics(url=9090)
    assert isinstance(out, dict)
    assert out["reachable"] is False
    assert out["error_type"] == "connection_refused"


def test_empty_error_message_falls_back_to_class_name():
    def boom(url, **kwargs):
        raise requests.exceptions.ConnectionError("")

    with _patch_get(side_effect=boom):
        out = tsdb_metrics(url="http://x")
    assert out["error_message"] == "ConnectionError"


def test_long_error_message_truncated_to_200():
    def boom(url, **kwargs):
        raise requests.exceptions.ConnectionError("x" * 500)

    with _patch_get(side_effect=boom):
        out = tsdb_metrics(url="http://x")
    assert len(out["error_message"]) == 200


def test_non_2xx_non_auth_is_http_error():
    with _patch_get({"/metrics": _resp(503, "Service Unavailable")}):
        out = tsdb_metrics(url="http://x")
    assert out == {
        "reachable": False,
        "error_type": "http_error",
        "error_message": "HTTP 503 on /metrics",
    }


def test_403_maps_to_auth_failed():
    with _patch_get({"/metrics": _resp(403, "Forbidden")}):
        out = tsdb_metrics(url="http://x")
    assert out["error_type"] == "auth_failed"
    assert out["error_message"] == "HTTP 403 on /metrics"


# --- the sharp edge: a 2xx is always reachable -----------------------------


def test_parse_bug_stays_reachable():
    # Force an unexpected exception AFTER the 2xx: reachable must stay true.
    with _patch_get({"/metrics": _resp(200, "prometheus_build_info{} 1\n")}):
        with patch(
            "fivenines_agent.tsdb._parse_exposition",
            side_effect=RuntimeError("boom"),
        ):
            out = tsdb_metrics(url="http://x")
    assert out == {"reachable": True, "flavor": None, "version": None}


def test_2xx_unrecognised_body_is_reachable_with_null_flavor():
    # A 2xx body with neither vm_ nor prometheus_ metrics: reachable, but no
    # fabricated flavor / version / metrics.
    body = "go_goroutines 5\nnode_cpu_seconds_total 3\n"
    with _patch_get({"/metrics": _resp(200, body)}):
        out = tsdb_metrics(url="http://x")
    assert out == {"reachable": True, "flavor": None, "version": None}


def test_targets_probe_failure_keeps_prometheus_reachable():
    body = "prometheus_tsdb_head_series 10\n"

    def fake_get(url, **kwargs):
        path = urlsplit(url).path
        if path == "/metrics":
            return _resp(200, body)
        raise requests.exceptions.ConnectionError("targets api down")

    with _patch_get(side_effect=fake_get):
        out = tsdb_metrics(url="http://x")
    assert out["reachable"] is True
    assert out["flavor"] == "prometheus"
    assert "targets_total" not in out and "targets_down" not in out
    assert out["head_series"] == 10


# --- flavor-specific extraction edges --------------------------------------


def test_vm_version_from_version_label_without_v_prefix():
    # No short_version; the 'version' label is used verbatim (no leading 'v').
    body = 'vm_app_version{version="1.99.0"} 1\n'
    with _patch_get({"/metrics": _resp(200, body)}):
        out = tsdb_metrics(url="http://x")
    assert out["flavor"] == "victoriametrics"
    assert out["version"] == "1.99.0"


def test_vm_missing_metrics_omit_their_keys():
    # Only the version metric present: every numeric VM key is omitted, and
    # active_series (its cache proxy absent) is omitted too.
    body = 'vm_app_version{short_version="v2.0.0"} 1\n'
    with _patch_get({"/metrics": _resp(200, body)}):
        out = tsdb_metrics(url="http://x")
    assert out == {"reachable": True, "flavor": "victoriametrics", "version": "2.0.0"}


def test_vm_active_series_requires_the_exact_label():
    # vm_cache_entries present but never with type="storage/hour_metric_ids" ->
    # active_series omitted (a filtered-sum with no match is not fabricated).
    body = (
        'vm_app_version{short_version="v1.0.0"} 1\n'
        'vm_cache_entries{type="storage/date_metric_ids"} 42\n'
    )
    with _patch_get({"/metrics": _resp(200, body)}):
        out = tsdb_metrics(url="http://x")
    assert "active_series" not in out


def test_prometheus_build_info_without_version_label_yields_null_version():
    body = "prometheus_build_info{branch=\"HEAD\"} 1\nprometheus_tsdb_head_series 3\n"
    with _patch_get({"/metrics": _resp(200, body)}):
        out = tsdb_metrics(url="http://x")
    assert out["flavor"] == "prometheus"
    assert out["version"] is None


def test_prometheus_no_build_info_yields_null_version():
    body = "prometheus_tsdb_head_series 3\n"
    with _patch_get({"/metrics": _resp(200, body)}):
        out = tsdb_metrics(url="http://x")
    assert out["version"] is None


# --- exposition parser units -----------------------------------------------


def test_parse_metric_line_variants():
    # comment, blank, lone token, unclosed brace -> all None
    assert tsdb._parse_metric_line("# HELP foo bar") is None
    assert tsdb._parse_metric_line("   ") is None
    assert tsdb._parse_metric_line("loneword") is None
    assert tsdb._parse_metric_line("weird{unclosed 5") is None
    # value-less metric (empty rest after labels) -> value None
    name, labels, value = tsdb._parse_metric_line('foo{a="b"}')
    assert (name, labels, value) == ("foo", {"a": "b"}, None)


def test_parse_value_edges():
    # trailing timestamp is ignored; scientific notation parses; NaN/Inf -> None
    assert tsdb._parse_value("42 1620000000000") == 42.0
    assert tsdb._parse_value("5.3687e+09") == 5.3687e09
    assert tsdb._parse_value("notanumber") is None
    assert tsdb._parse_value("NaN") is None
    assert tsdb._parse_value("+Inf") is None
    assert tsdb._parse_value("") is None


def test_sum_skips_none_and_absent_is_none():
    # A value-less metric line parses to None; _sum skips it (NaN/Inf are
    # already normalized to None by _parse_value before reaching here).
    samples = {
        "m": [({}, 1.0), ({}, None), ({}, 2.0)],
    }
    assert tsdb._sum(samples, "m") == 3.0
    assert tsdb._sum(samples, "missing") is None


def test_scientific_notation_body_parses_to_exact_int():
    # Prometheus emits large gauges in e-notation; the float sum narrows to int.
    body = "prometheus_tsdb_storage_blocks_bytes 5.36870912e+09\n"
    with _patch_get({"/metrics": _resp(200, body)}):
        out = tsdb_metrics(url="http://x")
    assert out["storage_bytes"] == 5368709120


# --- targets probe units ---------------------------------------------------


def test_fetch_targets_malformed_activetargets_is_none():
    get = MagicMock(return_value=_resp(200, json_data={"data": {"activeTargets": "nope"}}))
    assert tsdb._fetch_targets(get) is None


def test_fetch_targets_json_raises_is_none():
    get = MagicMock(return_value=_resp(200, text="not json"))  # json() raises
    assert tsdb._fetch_targets(get) is None


def test_fetch_targets_counts_non_up_health():
    active = [{"health": "up"}, {"health": "down"}, {"health": "unknown"}]
    get = MagicMock(return_value=_resp(200, json_data={"data": {"activeTargets": active}}))
    assert tsdb._fetch_targets(get) == (3, 2)


# --- cross-repo contract (fivenines-server) --------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "tsdb_contract_payload.json"
)


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


_FIXTURE = _load_fixture()
_EXC_MAP = {
    "connection_refused": requests.exceptions.ConnectionError,
    "timeout": requests.exceptions.Timeout,
    "tls_error": requests.exceptions.SSLError,
}


def _fake_get_for(scenario):
    responses = scenario.get("responses", {})
    raise_spec = scenario.get("raise")

    def fake_get(url, **kwargs):
        path = urlsplit(url).path
        if raise_spec and path == raise_spec["path"]:
            raise _EXC_MAP[raise_spec["type"]](raise_spec["message"])
        if path not in responses:
            raise AssertionError(f"scenario did not expect a GET to {path}")
        spec = responses[path]
        return _resp(spec["status"], spec.get("body", ""), spec.get("json"))

    return fake_get


@pytest.mark.parametrize("name", list(_FIXTURE["scenarios"].keys()))
def test_contract_fixture_round_trip(name):
    """SHARED FIXTURE (cross-repo contract): fixtures/tsdb_contract_payload.json.

    Asserted on both sides:
    - here: tsdb_metrics(**scenario["config"]) must equal scenario["payload"]
      with only requests.get mocked (each scenario's canned bodies fed back per
      URL path, a 'raise' entry making that path raise the named transport
      exception);
    - fivenines-server: spec/requests/api_collect_tsdb_spec.rb posts
      scenario["payload"] under data["tsdb"] and asserts Ingesters::Agent ingests
      the reachable true/false shapes.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    scenario = _FIXTURE["scenarios"][name]
    with patch(
        "fivenines_agent.tsdb.requests.get", side_effect=_fake_get_for(scenario)
    ):
        out = tsdb_metrics(**scenario["config"])
    assert out == scenario["payload"]


def test_fixture_agent_min_version():
    assert _FIXTURE["agent_min_version"] == "1.14.1"


def test_fixture_config_is_documented_shape():
    documented = {
        "url",
        "auth_header_name",
        "auth_header_value",
        "basic_auth_username",
        "basic_auth_password",
        "verify_ssl",
    }
    for scenario in _FIXTURE["scenarios"].values():
        assert set(scenario["config"]) == documented


def test_fixture_reachable_scenarios_never_null_and_have_flag():
    # Every scenario payload is a dict carrying an explicit reachable flag --
    # the envelope contract (never None on either verdict).
    for scenario in _FIXTURE["scenarios"].values():
        assert isinstance(scenario["payload"], dict)
        assert "reachable" in scenario["payload"]
