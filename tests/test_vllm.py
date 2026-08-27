"""Tests for the vLLM inference-serving health collector (server #887).

Only requests.get is mocked; each case feeds a canned /metrics body back through
the real parse -> group -> payload pipeline. Mirrors test_tsdb.py (the direct
sibling) including its cross-repo fixture assertion, with the same reachability
envelope: unreachable rides the payload, never None.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from fivenines_agent import inference_metrics, vllm
from fivenines_agent.vllm import vllm_metrics


def _resp(status=200, text="", chunks=None):
    """A stand-in streamed requests.Response.

    The collector reads the body via iter_content (bounded), never .text, so the
    fake yields the body as chunks. Pass *chunks* explicitly to control chunking
    (e.g. to exceed the byte cap mid-stream).
    """
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    body = chunks if chunks is not None else [text.encode()]
    resp.iter_content.return_value = iter(body)
    return resp


def _collect(body, status=200, **config):
    """Run the collector against one canned /metrics body."""
    with patch(
        "fivenines_agent.inference_metrics.requests.get",
        return_value=_resp(status, body),
    ):
        return vllm_metrics(**config)


def _only_model(body, **config):
    """Collect a single-model body and return that one models[] entry."""
    out = _collect(body, **config)
    assert out["reachable"] is True
    assert len(out["models"]) == 1
    return out["models"][0]


def _series(name, value, model="m", **labels):
    """One exposition line for *name*, labelled with model_name plus extras."""
    pairs = [f'model_name="{model}"'] + [f'{k}="{v}"' for k, v in labels.items()]
    return f"{name}{{{','.join(pairs)}}} {value}\n"


# --- transport wiring: url / headers / verify ------------------------------


def test_metrics_url_headers_and_verify_passed_through():
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _resp(200, "")

    with patch("fivenines_agent.inference_metrics.requests.get", side_effect=fake_get):
        vllm_metrics(
            metrics_url="https://vllm.local:8000/metrics",
            auth_header_name="Authorization",
            auth_header_value="Bearer k",
            verify_ssl=False,
        )

    # metrics_url is the FULL endpoint URL (unlike tsdb's base url): no path is
    # appended and no trailing slash is stripped.
    assert captured["url"] == "https://vllm.local:8000/metrics"
    assert captured["headers"]["Authorization"] == "Bearer k"
    assert captured["verify"] is False
    assert captured["timeout"] == inference_metrics._TIMEOUT


def test_default_metrics_url_is_the_local_api_server():
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        return _resp(200, "")

    with patch("fivenines_agent.inference_metrics.requests.get", side_effect=fake_get):
        vllm_metrics()

    assert captured["url"] == "http://127.0.0.1:8000/metrics"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"auth_header_name": "Authorization"},
        {"auth_header_value": "Bearer k"},
    ],
)
def test_partial_auth_header_is_ignored(kwargs):
    captured = {}

    def fake_get(url, **kw):
        captured.update(kw)
        return _resp(200, "")

    with patch("fivenines_agent.inference_metrics.requests.get", side_effect=fake_get):
        vllm_metrics(metrics_url="http://x/metrics", **kwargs)

    # Half a header pair is not a header (only the transport header remains).
    assert list(captured["headers"]) == ["Accept-Encoding"]


def test_unknown_config_keys_are_tolerated():
    # Forward compatibility: the backend pushing a key this agent version does
    # not know must not raise into a None payload.
    with patch(
        "fivenines_agent.inference_metrics.requests.get", return_value=_resp(200, "")
    ):
        out = vllm_metrics(metrics_url="http://x/metrics", future_key="whatever")
    assert out == {"reachable": True, "models": []}


# --- reachability envelope: connection-level failures ----------------------


def _raising(exc):
    def boom(url, **kwargs):
        raise exc

    return patch("fivenines_agent.inference_metrics.requests.get", side_effect=boom)


def test_connection_error_is_connection_refused():
    with _raising(requests.exceptions.ConnectionError("Connection refused")):
        out = vllm_metrics(metrics_url="http://x/metrics")
    assert out == {
        "reachable": False,
        "error_type": "connection_refused",
        "error_message": "Connection refused",
    }


def test_timeout_maps_to_timeout():
    with _raising(requests.exceptions.ReadTimeout("timed out")):
        out = vllm_metrics(metrics_url="http://x/metrics")
    assert out["reachable"] is False
    assert out["error_type"] == "timeout"


def test_ssl_error_maps_to_tls_error():
    # SSLError subclasses ConnectionError, so it must be classified first.
    with _raising(requests.exceptions.SSLError("certificate verify failed")):
        out = vllm_metrics(metrics_url="https://x/metrics")
    assert out["reachable"] is False
    assert out["error_type"] == "tls_error"


def test_unexpected_transport_error_folds_to_connection_refused():
    with _raising(requests.exceptions.MissingSchema("Invalid URL")):
        out = vllm_metrics(metrics_url="not-a-url")
    assert out["error_type"] == "connection_refused"


@pytest.mark.parametrize("bad_url", [8000, None])
def test_pathological_url_yields_envelope_never_none(bad_url):
    # A malformed server push (a non-string, or a missing url) must NOT raise
    # out of the collector -- the registry would turn that into None, which the
    # server reads as "collector disabled" rather than "vLLM is down". str()
    # coercion routes it through requests' own URL validation into the envelope.
    # requests raises MissingSchema synchronously, so this is offline.
    out = vllm_metrics(metrics_url=bad_url)
    assert isinstance(out, dict)
    assert out["reachable"] is False
    assert out["error_type"] == "connection_refused"


def test_empty_error_message_falls_back_to_class_name():
    with _raising(requests.exceptions.ConnectionError("")):
        out = vllm_metrics(metrics_url="http://x/metrics")
    assert out["error_message"] == "ConnectionError"


def test_long_error_message_truncated_to_200():
    with _raising(requests.exceptions.ConnectionError("x" * 500)):
        out = vllm_metrics(metrics_url="http://x/metrics")
    assert len(out["error_message"]) == 200


def test_non_2xx_non_auth_is_http_error():
    out = _collect("Service Unavailable", status=503, metrics_url="http://x/metrics")
    assert out == {
        "reachable": False,
        "error_type": "http_error",
        "error_message": "HTTP 503 on /metrics",
    }


@pytest.mark.parametrize("status", [401, 403])
def test_401_and_403_map_to_auth_failed(status):
    out = _collect("nope", status=status, metrics_url="http://x/metrics")
    assert out["error_type"] == "auth_failed"
    assert out["error_message"] == f"HTTP {status} on /metrics"


def test_204_is_reachable():
    # Any 2xx counts, not just 200.
    assert _collect("", status=204) == {"reachable": True, "models": []}


# --- sharp edge #1: a 2xx is always reachable ------------------------------


def test_parse_bug_stays_reachable():
    # Force an unexpected exception AFTER the 2xx: reachable must stay true and
    # degrade to an empty models list, never page "your vLLM is down".
    with patch(
        "fivenines_agent.inference_metrics.requests.get", return_value=_resp(200, "x")
    ):
        with patch(
            "fivenines_agent.inference_metrics._parse_exposition",
            side_effect=RuntimeError("boom"),
        ):
            out = vllm_metrics(metrics_url="http://x/metrics")
    assert out == {"reachable": True, "models": []}


def test_2xx_with_zero_vllm_metrics_is_reachable_with_empty_models():
    # --disable-log-stats, or an upstream rename the whitelist misses.
    body = 'python_info{major="3"} 1.0\nprocess_cpu_seconds_total 88213.44\n'
    assert _collect(body) == {"reachable": True, "models": []}


def test_series_without_model_name_are_dropped_not_renamed():
    # The contract keys every entry by model; an unattributable series is
    # dropped rather than given an invented name. Reachable stays true -- but
    # the drop is announced, never silent.
    body = (
        "vllm:num_requests_running 4.0\n"
        'vllm:kv_cache_usage_perc{engine="0"} 0.5\n'
        'vllm:num_requests_waiting{model_name=""} 9.0\n'
    )
    assert _collect(body) == {
        "reachable": True,
        "models": [],
        "read_warnings": ["unlabelled_series"],
    }


# --- the alias table (sharp edge #2) ---------------------------------------


def test_new_name_wins_during_a_deprecation_window():
    # Upstream exposes BOTH spellings while a metric is deprecated-but-visible.
    # First-present-wins on the newest name reads it once; summing both would
    # double-count (and for the fraction, exceed 1.0).
    body = (
        _series("vllm:kv_cache_usage_perc", "0.40")
        + _series("vllm:gpu_cache_usage_perc", "0.40")
        + _series("vllm:prefix_cache_queries_total", "100.0")
        + _series("vllm:gpu_prefix_cache_queries_total", "100.0")
    )
    model = _only_model(body)
    assert model["kv_cache_usage"] == 0.40
    assert model["prefix_cache_queries_total"] == 100


def test_legacy_only_names_fall_through_to_the_old_spelling():
    body = _series("vllm:gpu_cache_usage_perc", "0.61") + _series(
        "vllm:gpu_prefix_cache_hits_total", "7.0"
    )
    model = _only_model(body)
    assert model["kv_cache_usage"] == 0.61
    assert model["prefix_cache_hits_total"] == 7


def test_deprecated_hit_rate_gauge_is_not_a_prefix_cache_substitute():
    # The v1 gpu_prefix_cache_hit_rate GAUGE is explicitly NOT a stand-in for
    # the query/hit counters: with the counters absent, both keys are omitted.
    body = _series("vllm:gpu_prefix_cache_hit_rate", "0.82") + _series(
        "vllm:num_requests_running", "1.0"
    )
    model = _only_model(body)
    assert "prefix_cache_queries_total" not in model
    assert "prefix_cache_hits_total" not in model


def test_histogram_alias_pair_is_resolved_as_a_unit():
    # A deprecation window can expose the new histogram's _sum next to the old
    # one's _count. The pair must come from ONE base name (the newest present),
    # never be mixed across spellings.
    body = (
        _series("vllm:inter_token_latency_seconds_sum", "10.0")
        + _series("vllm:time_per_output_token_seconds_sum", "999.0")
        + _series("vllm:time_per_output_token_seconds_count", "888.0")
    )
    model = _only_model(body)
    assert model["itl_sum_seconds"] == 10.0
    # The old spelling's _count is NOT grafted onto the new spelling's _sum.
    assert "itl_count" not in model


def test_request_time_per_output_token_is_not_the_itl_alias():
    # A near-miss upstream name (a different, per-request histogram).
    body = (
        _series("vllm:request_time_per_output_token_seconds_sum", "77.7")
        + _series("vllm:request_time_per_output_token_seconds_count", "5.0")
        + _series("vllm:num_requests_running", "1.0")
    )
    model = _only_model(body)
    assert "itl_sum_seconds" not in model
    assert "itl_count" not in model


def test_histogram_half_present_emits_only_that_half():
    body = _series("vllm:time_to_first_token_seconds_count", "12.0")
    model = _only_model(body)
    assert model["ttft_count"] == 12
    assert "ttft_sum_seconds" not in model


# --- reduction rules: sum vs max across label dimensions -------------------


def test_counts_and_counters_sum_across_the_engine_label():
    body = (
        _series("vllm:num_requests_running", "2.0", engine="0")
        + _series("vllm:num_requests_running", "3.0", engine="1")
        + _series("vllm:request_success_total", "10.0", finished_reason="stop")
        + _series("vllm:request_success_total", "4.0", finished_reason="length")
    )
    model = _only_model(body)
    assert model["requests_running"] == 5
    assert model["request_success_total"] == 14


def test_kv_cache_usage_takes_the_max_not_the_sum():
    # THE FRACTION RULE: 0.6 + 0.7 across two data-parallel engines would ship
    # 1.3, which the server renders as 130%. The max is the saturating engine.
    body = _series("vllm:kv_cache_usage_perc", "0.6", engine="0") + _series(
        "vllm:kv_cache_usage_perc", "0.7", engine="1"
    )
    assert _only_model(body)["kv_cache_usage"] == 0.7


def test_reducers_are_pure_functions_over_their_series():
    assert inference_metrics.sum_values([1.0, 2.5]) == 3.5
    assert inference_metrics.max_value([0.2, 0.9, 0.4]) == 0.9


def test_models_are_sorted_by_name():
    body = (
        _series("vllm:num_requests_running", "1.0", model="zeta")
        + _series("vllm:num_requests_running", "2.0", model="Alpha")
        + _series("vllm:num_requests_running", "3.0", model="beta")
    )
    out = _collect(body)
    assert [m["name"] for m in out["models"]] == ["Alpha", "beta", "zeta"]


# --- omit-not-zero / never fabricate ---------------------------------------


def test_present_but_zero_ships_and_absent_is_omitted():
    body = _series("vllm:num_requests_waiting", "0.0")
    model = _only_model(body)
    assert model["requests_waiting"] == 0
    assert "requests_running" not in model
    assert model == {"name": "m", "requests_waiting": 0}


@pytest.mark.parametrize("value", ["NaN", "+Inf", "-Inf", "not-a-number"])
def test_non_finite_and_unparseable_values_omit_their_key(value):
    # A non-finite float reaching the payload would make json.dumps emit invalid
    # Infinity/NaN JSON and poison the whole tick's payload, not just this key.
    body = _series("vllm:kv_cache_usage_perc", value) + _series(
        "vllm:num_requests_running", "1.0"
    )
    model = _only_model(body)
    assert "kv_cache_usage" not in model
    assert json.dumps(model, allow_nan=False)


def test_bucket_series_are_never_read_as_the_sum_or_count():
    body = _series(
        "vllm:time_to_first_token_seconds_bucket", "500.0", le="0.1"
    ) + _series("vllm:time_to_first_token_seconds_bucket", "900.0", le="+Inf")
    assert _collect(body) == {"reachable": True, "models": []}


# --- the models cap --------------------------------------------------------


def test_models_cap_truncates_and_flags():
    body = "".join(
        _series("vllm:num_requests_running", "1.0", model=f"model-{i}")
        for i in range(inference_metrics._MAX_MODELS + 5)
    )
    out = _collect(body)
    assert len(out["models"]) == inference_metrics._MAX_MODELS
    # A truncation the server can SEE -- never a silently short list.
    assert out["read_warnings"] == ["models_capped"]
    # First-seen models win, so the cap is deterministic for a given body.
    assert out["models"][0]["name"] == "model-0"


def test_read_warnings_absent_on_a_normal_tick():
    assert "read_warnings" not in _collect(_series("vllm:num_requests_running", "1.0"))


# --- sharp edge #3: this endpoint is not one local vLLM --------------------


def test_foreign_label_dimension_is_flagged_not_silently_merged():
    # metrics_url pointed at a Prometheus scraping 3 vLLM nodes: every series
    # carries an "instance" label. Summing across it reports the FLEET's queue
    # depth as this host's -- plausible and wrong. We still ship what parsed,
    # but the server is told the read is not authoritative.
    body = _series(
        "vllm:num_requests_running", "4.0", instance="10.0.4.11:8000"
    ) + _series("vllm:num_requests_running", "7.0", instance="10.0.4.12:8000")
    out = _collect(body)
    assert out["read_warnings"] == ["foreign_labels"]
    assert out["models"][0]["requests_running"] == 11


@pytest.mark.parametrize("label", ["engine", "finished_reason"])
def test_documented_reducible_labels_are_not_foreign(label):
    # The two dimensions a single vLLM really does emit must NOT trip the flag.
    body = _series("vllm:request_success_total", "3.0", **{label: "x"}) + _series(
        "vllm:request_success_total", "4.0", **{label: "y"}
    )
    out = _collect(body)
    assert "read_warnings" not in out
    assert out["models"][0]["request_success_total"] == 7


def test_both_warnings_ride_together_sorted():
    body = "".join(
        _series("vllm:num_requests_running", "1.0", model=f"m-{i}", pod=f"p-{i}")
        for i in range(inference_metrics._MAX_MODELS + 2)
    )
    assert _collect(body)["read_warnings"] == ["foreign_labels", "models_capped"]


# --- bounded body read -----------------------------------------------------


def test_oversized_body_is_truncated_and_publishes_nothing():
    # Half an exposition parses cleanly into a SHORT models list; a server that
    # prunes what is missing would vanish every model past the cut. Ship none.
    big = b"x" * (inference_metrics._MAX_RESPONSE_BYTES + 1)
    with patch(
        "fivenines_agent.inference_metrics.requests.get",
        return_value=_resp(200, chunks=[big]),
    ):
        out = vllm_metrics(metrics_url="http://x/metrics")
    assert out == {
        "reachable": True,
        "models": [],
        "read_warnings": ["body_truncated"],
    }


def test_body_read_deadline_truncates():
    body = _series("vllm:num_requests_running", "1.0").encode()
    ticks = iter([0.0, 1e9, 1e9])  # start, then far past the deadline
    with patch(
        "fivenines_agent.inference_metrics.time.monotonic",
        side_effect=lambda: next(ticks),
    ):
        with patch(
            "fivenines_agent.inference_metrics.requests.get",
            return_value=_resp(200, chunks=[body, body]),
        ):
            out = vllm_metrics(metrics_url="http://x/metrics")
    assert out["read_warnings"] == ["body_truncated"]
    assert out["models"] == []


def test_empty_chunks_are_skipped_and_body_still_parses():
    # requests can yield keep-alive empty chunks; they must not end the read.
    body = _series("vllm:num_requests_running", "2.0").encode()
    with patch(
        "fivenines_agent.inference_metrics.requests.get",
        return_value=_resp(200, chunks=[b"", body, b""]),
    ):
        out = vllm_metrics(metrics_url="http://x/metrics")
    assert out["models"][0]["requests_running"] == 2


def test_transport_is_streamed_non_redirecting_and_uncompressed():
    captured = {}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return _resp(200, "")

    with patch("fivenines_agent.inference_metrics.requests.get", side_effect=fake_get):
        vllm_metrics(metrics_url="http://x/metrics")

    # stream: the body is bounded, not buffered whole.
    assert captured["stream"] is True
    # allow_redirects: a misconfigured endpoint must not bounce us at an
    # internal address (SSRF); identity encoding declines a decompression bomb.
    assert captured["allow_redirects"] is False
    assert captured["headers"]["Accept-Encoding"] == "identity"


def test_response_is_closed_even_when_the_body_read_raises():
    resp = _resp(200, "")
    resp.iter_content.side_effect = requests.exceptions.ConnectionError("reset")
    with patch("fivenines_agent.inference_metrics.requests.get", return_value=resp):
        out = vllm_metrics(metrics_url="http://x/metrics")
    # A mid-body reset is a transport failure -> the unreachable envelope...
    assert out["reachable"] is False
    assert out["error_type"] == "connection_refused"
    # ...and the connection is released regardless.
    resp.close.assert_called_once()


# --- negative values are corruption, not zero ------------------------------


@pytest.mark.parametrize(
    "name,key",
    [
        ("vllm:num_requests_waiting", "requests_waiting"),
        ("vllm:num_preemptions_total", "preemptions_total"),
        ("vllm:kv_cache_usage_perc", "kv_cache_usage"),
    ],
)
def test_negative_value_omits_its_key_never_truncates_to_zero(name, key):
    # int(-0.5) == 0 would turn corruption into a believable "idle" reading --
    # the wireguard lesson: a negative age is null, NEVER 0.
    body = _series(name, "-0.5") + _series("vllm:num_requests_running", "1.0")
    model = _only_model(body)
    assert key not in model


def test_negative_value_warns_rather_than_dropping_silently():
    # A silent drop still hands the server a believable snapshot -- and a model
    # whose every series is negative would vanish from models[] with nothing
    # saying why, rebuilding the vanish-prune this warning set exists to stop.
    out = _collect(_series("vllm:num_requests_running", "-1.0"))
    assert out["models"] == []
    assert out["read_warnings"] == ["invalid_values"]


@pytest.mark.parametrize(
    "name,key",
    [
        ("vllm:num_requests_running", "requests_running"),
        ("vllm:time_to_first_token_seconds_count", "ttft_count"),
    ],
)
def test_non_integral_value_for_an_integer_field_is_rejected_not_floored(name, key):
    # A queue of 0.9 is not a queue of 0. vLLM never emits a fractional count --
    # an averaging proxy in front of it does -- so reject and flag.
    out = _collect(_series(name, "0.9"))
    assert key not in (out["models"][0] if out["models"] else {})
    assert out["read_warnings"] == ["invalid_values"]


def test_fractional_value_is_fine_for_a_float_field():
    # The same guard must not touch the fields that are legitimately fractional.
    body = _series("vllm:kv_cache_usage_perc", "0.87") + _series(
        "vllm:time_to_first_token_seconds_sum", "1234.5"
    )
    out = _collect(body)
    assert out["models"][0]["kv_cache_usage"] == 0.87
    assert out["models"][0]["ttft_sum_seconds"] == 1234.5
    assert "read_warnings" not in out


@pytest.mark.parametrize("value", ["NaN", "+Inf", "-Inf"])
def test_non_finite_does_not_warn(value):
    # Prometheus uses NaN as a legitimate "no observations yet", so warning on
    # it would fire on every idle vLLM. Only negatives are corruption.
    body = _series("vllm:kv_cache_usage_perc", value) + _series(
        "vllm:num_requests_running", "1.0"
    )
    out = _collect(body)
    assert "read_warnings" not in out


def test_unlabelled_whitelisted_series_warns():
    # If upstream ever renames model_name, every host goes to models: [] at
    # once. The warning is what stops that reading as "no models exist".
    out = _collect("vllm:num_requests_running 4.0\n")
    assert out["models"] == []
    assert out["read_warnings"] == ["unlabelled_series"]


def test_unlabelled_NON_whitelisted_series_does_not_warn():
    # Ordinary label-less noise (and vLLM's own info gauges, which carry no
    # model_name) must stay silent -- they are not anomalies.
    body = (
        "go_goroutines 148\n"
        'vllm:cache_config_info{block_size="16"} 1.0\n'
        'vllm:lora_requests_info{max_lora="0"} 1.0\n'
    )
    out = _collect(body)
    assert out == {"reachable": True, "models": []}


def test_negative_series_does_not_shrink_a_sum():
    body = _series("vllm:num_requests_running", "5.0", engine="0") + _series(
        "vllm:num_requests_running", "-3.0", engine="1"
    )
    assert _only_model(body)["requests_running"] == 5


# --- exposition parser units -----------------------------------------------


def test_parse_metric_line_variants():
    # comment, blank, lone token, unclosed brace -> all None
    assert inference_metrics._parse_metric_line("# HELP foo bar") is None
    assert inference_metrics._parse_metric_line("   ") is None
    assert inference_metrics._parse_metric_line("loneword") is None
    assert inference_metrics._parse_metric_line("weird{unclosed 5") is None
    # value-less metric (empty rest after labels) -> value None
    assert inference_metrics._parse_metric_line('foo{a="b"}') == (
        "foo",
        {"a": "b"},
        None,
    )
    # unlabelled metric
    assert inference_metrics._parse_metric_line("foo 5") == ("foo", {}, 5.0)


def test_parse_value_edges():
    # trailing timestamp is ignored; scientific notation parses; NaN/Inf -> None
    assert inference_metrics._parse_value("42 1620000000000") == 42.0
    assert inference_metrics._parse_value("1.23456789e+08") == 123456789.0
    assert inference_metrics._parse_value("notanumber") is None
    assert inference_metrics._parse_value("NaN") is None
    assert inference_metrics._parse_value("+Inf") is None
    assert inference_metrics._parse_value("") is None


def test_parse_labels_honours_escaped_quotes():
    labels = inference_metrics._parse_labels(r'model_name="a\"b",engine="0"')
    assert labels["engine"] == "0"
    assert labels["model_name"] == r"a\"b"


def test_summed_returns_none_when_absent():
    assert inference_metrics._summed({"a": [1.0, 2.0]}, "a") == 3.0
    assert inference_metrics._summed({}, "a") is None


def test_whitelist_covers_every_declared_alias():
    # The scan-time whitelist is derived from the field tables; if a table gains
    # an alias the parser must retain it, or the key silently never appears.
    for _key, names, _reduce, _cast in vllm._GAUGE_FIELDS + vllm._COUNTER_FIELDS:
        for name in names:
            assert name in vllm._NAMES_OF_INTEREST
    for _prefix, bases in vllm._HISTOGRAM_FIELDS:
        for base in bases:
            assert base + "_sum" in vllm._NAMES_OF_INTEREST
            assert base + "_count" in vllm._NAMES_OF_INTEREST
    # Bucket series are deliberately NOT retained (they are the bulk of a vLLM
    # exposition and carry nothing the payload needs).
    assert "vllm:time_to_first_token_seconds_bucket" not in vllm._NAMES_OF_INTEREST


def test_v0_only_metrics_are_deliberately_not_collected():
    for name in ("vllm:num_requests_swapped", "vllm:cpu_cache_usage_perc"):
        assert name not in vllm._NAMES_OF_INTEREST


# --- cross-repo contract (fivenines-server) --------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "vllm_contract_payload.json"
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
    raise_spec = scenario.get("raise")
    response = scenario.get("response")

    def fake_get(url, **kwargs):
        if raise_spec:
            raise _EXC_MAP[raise_spec["type"]](raise_spec["message"])
        return _resp(response["status"], response.get("body", ""))

    return fake_get


@pytest.mark.parametrize("name", list(_FIXTURE["scenarios"].keys()))
def test_contract_fixture_round_trip(name):
    """SHARED FIXTURE (cross-repo contract): fixtures/vllm_contract_payload.json.

    Asserted on both sides:
    - here: vllm_metrics(**scenario["config"]) must equal scenario["payload"]
      with only requests.get mocked (the scenario's canned 'response' fed back
      as the single GET, or its 'raise' entry making that GET raise the named
      transport exception);
    - fivenines-server: spec/requests/api_collect_vllm_spec.rb posts
      scenario["payload"] under data["vllm"] and asserts Ingesters::Agent
      ingests the reachable true/false shapes.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    scenario = _FIXTURE["scenarios"][name]
    with patch(
        "fivenines_agent.inference_metrics.requests.get",
        side_effect=_fake_get_for(scenario),
    ):
        out = vllm_metrics(**scenario["config"])
    assert out == scenario["payload"]


def test_fixture_agent_min_version():
    # A FROZEN LITERAL, never read from pyproject: a later version bump must not
    # be able to break this assertion (or the server's copy of it).
    assert _FIXTURE["agent_min_version"] == "1.17.0"


def test_fixture_config_is_documented_shape():
    documented = {
        "metrics_url",
        "auth_header_name",
        "auth_header_value",
        "verify_ssl",
    }
    for scenario in _FIXTURE["scenarios"].values():
        assert set(scenario["config"]) == documented


def test_fixture_payloads_are_never_null_and_carry_the_flag():
    # Every scenario payload is a dict carrying an explicit reachable flag --
    # the envelope contract (never None on either verdict).
    for scenario in _FIXTURE["scenarios"].values():
        payload = scenario["payload"]
        assert isinstance(payload, dict)
        assert "reachable" in payload
        if payload["reachable"]:
            assert isinstance(payload["models"], list)
        else:
            assert payload["error_type"] in {
                "connection_refused",
                "timeout",
                "tls_error",
                "auth_failed",
                "http_error",
            }


def test_fixture_read_warnings_only_on_the_degraded_scenario():
    # read_warnings means "this tick is not a clean snapshot of one local vLLM".
    # Every healthy/error scenario must be free of it, or the server learns to
    # ignore a flag that is supposed to suppress pruning.
    warned = {
        name
        for name, sc in _FIXTURE["scenarios"].items()
        if sc["payload"].get("read_warnings")
    }
    assert warned == {"aggregating_endpoint"}
    known = {
        "foreign_labels",
        "models_capped",
        "body_truncated",
        "invalid_values",
        "unlabelled_series",
    }
    for name in warned:
        assert set(_FIXTURE["scenarios"][name]["payload"]["read_warnings"]) <= known


def test_fixture_legacy_names_produce_the_identical_payload():
    # The alias table's whole point: two metric-name generations, one payload.
    scenarios = _FIXTURE["scenarios"]
    assert (
        scenarios["healthy"]["payload"] == scenarios["healthy_legacy_names"]["payload"]
    )
    # ...and they really are different expositions.
    assert (
        scenarios["healthy"]["response"]["body"]
        != scenarios["healthy_legacy_names"]["response"]["body"]
    )


def test_fixture_counter_values_are_raw_integers_not_rates():
    # Counter discipline: the server rate()s these, so the agent must ship the
    # cumulative value verbatim. int-typed in the fixture, never a float rate.
    model = _FIXTURE["scenarios"]["healthy"]["payload"]["models"][0]
    for key in (
        "prompt_tokens_total",
        "generation_tokens_total",
        "request_success_total",
        "preemptions_total",
        "prefix_cache_queries_total",
        "prefix_cache_hits_total",
        "ttft_count",
        "itl_count",
        "e2e_latency_count",
    ):
        assert isinstance(model[key], int)
    # kv_cache_usage stays a 0-1 float fraction (the server converts to a pct).
    assert isinstance(model["kv_cache_usage"], float)
    assert 0.0 <= model["kv_cache_usage"] <= 1.0
