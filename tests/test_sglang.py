"""Tests for the SGLang inference-serving health collector (server #893).

Only requests.get is mocked; each case feeds a canned /metrics body back through
the real parse -> group -> payload pipeline. The transport, parser and envelope
are shared with the vLLM sibling (fivenines_agent/inference_metrics.py, exercised
in depth by test_vllm.py), so this file concentrates on what is SGLang's own: the
whitelist, the opt-in-metrics shape, and the per-rank fold rules -- plus enough
end-to-end envelope cases to prove this collector is really wired to the shared
machinery rather than a fork of it.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from fivenines_agent import inference_metrics, sglang, vllm
from fivenines_agent.sglang import sglang_metrics


def _resp(status=200, text="", chunks=None):
    """A stand-in streamed requests.Response.

    The collector reads the body via iter_content (bounded), never .text, so the
    fake yields the body as chunks.
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
        return sglang_metrics(**config)


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


def _ranks(name, values, model="m"):
    """The same scheduler gauge repeated once per tp_rank, TP-style."""
    return "".join(
        _series(name, value, model, engine_type="unified", tp_rank=str(i), pp_rank="0")
        for i, value in enumerate(values)
    )


# --- transport wiring ------------------------------------------------------


def test_default_metrics_url_is_the_local_sglang_api_server():
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        return _resp(200, "")

    with patch("fivenines_agent.inference_metrics.requests.get", side_effect=fake_get):
        sglang_metrics()

    # SGLang serves /metrics on its API server port, which defaults to 30000
    # (vLLM's is 8000) -- the one transport difference between the siblings.
    assert captured["url"] == "http://127.0.0.1:30000/metrics"


def test_metrics_url_headers_and_verify_passed_through():
    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _resp(200, "")

    with patch("fivenines_agent.inference_metrics.requests.get", side_effect=fake_get):
        sglang_metrics(
            metrics_url="https://sglang.local:30000/metrics",
            auth_header_name="Authorization",
            auth_header_value="Bearer k",
            verify_ssl=False,
        )

    # metrics_url is the FULL endpoint URL: no path is appended, no trailing
    # slash stripped.
    assert captured["url"] == "https://sglang.local:30000/metrics"
    assert captured["headers"]["Authorization"] == "Bearer k"
    assert captured["verify"] is False
    assert captured["timeout"] == inference_metrics._TIMEOUT


def test_unknown_config_keys_are_tolerated():
    # Forward compatibility: the backend pushing a key this agent version does
    # not know must not raise into a None payload.
    with patch(
        "fivenines_agent.inference_metrics.requests.get", return_value=_resp(200, "")
    ):
        out = sglang_metrics(metrics_url="http://x/metrics", future_key="whatever")
    assert out == {"reachable": True, "models": []}


# --- the reachability envelope ---------------------------------------------


def _raising(exc):
    def boom(url, **kwargs):
        raise exc

    return patch("fivenines_agent.inference_metrics.requests.get", side_effect=boom)


def test_connection_error_is_connection_refused():
    with _raising(requests.exceptions.ConnectionError("Connection refused")):
        out = sglang_metrics(metrics_url="http://x/metrics")
    assert out == {
        "reachable": False,
        "error_type": "connection_refused",
        "error_message": "Connection refused",
    }


@pytest.mark.parametrize(
    "exc,error_type",
    [
        (requests.exceptions.ReadTimeout("timed out"), "timeout"),
        (requests.exceptions.SSLError("certificate verify failed"), "tls_error"),
        (requests.exceptions.MissingSchema("Invalid URL"), "connection_refused"),
    ],
)
def test_transport_failures_map_to_the_error_vocabulary(exc, error_type):
    with _raising(exc):
        out = sglang_metrics(metrics_url="http://x/metrics")
    assert out["reachable"] is False
    assert out["error_type"] == error_type


@pytest.mark.parametrize(
    "status,error_type",
    [(401, "auth_failed"), (403, "auth_failed"), (503, "http_error")],
)
def test_non_2xx_statuses_map_to_the_error_vocabulary(status, error_type):
    out = _collect("nope", status=status, metrics_url="http://x/metrics")
    assert out["error_type"] == error_type
    assert out["error_message"] == f"HTTP {status} on /metrics"


@pytest.mark.parametrize("bad_url", [30000, None])
def test_pathological_url_yields_envelope_never_none(bad_url):
    # A malformed server push must NOT raise out of the collector: the registry
    # would turn that into None, which the server reads as "collector disabled"
    # rather than "SGLang is down". requests raises MissingSchema
    # synchronously, so this is offline.
    out = sglang_metrics(metrics_url=bad_url)
    assert isinstance(out, dict)
    assert out["reachable"] is False
    assert out["error_type"] == "connection_refused"


def test_parse_bug_stays_reachable():
    # Force an unexpected exception AFTER the 2xx: reachable must stay true and
    # degrade to an empty models list, never page "your SGLang is down".
    with patch(
        "fivenines_agent.inference_metrics.requests.get", return_value=_resp(200, "x")
    ):
        with patch(
            "fivenines_agent.inference_metrics._parse_exposition",
            side_effect=RuntimeError("boom"),
        ):
            out = sglang_metrics(metrics_url="http://x/metrics")
    assert out == {"reachable": True, "models": []}


# --- SGLang edge #1: metrics are opt-in ------------------------------------


def test_stock_launch_without_enable_metrics_is_reachable_with_empty_models():
    # THE EXPECTED FIRST-RUN STATE, not an edge case: SGLang publishes sglang:*
    # samples only under --enable-metrics, so a stock server answers 2xx with
    # nothing but the default prometheus_client collectors. Conflating that with
    # unreachable would page a customer whose server is serving traffic fine.
    body = (
        'python_info{implementation="CPython",major="3"} 1.0\n'
        "process_cpu_seconds_total 41276.91\n"
    )
    assert _collect(body) == {"reachable": True, "models": []}


# --- SGLang edge #2: per-rank gauges fold by MAX, counters by SUM ----------


@pytest.mark.parametrize(
    "name,key,values,expected",
    [
        ("sglang:num_running_reqs", "running_requests", ["6.0"] * 8, 6),
        ("sglang:num_queue_reqs", "queue_requests", ["22.0"] * 8, 22),
        (
            "sglang:token_usage",
            "token_usage",
            ["0.90", "0.90", "0.90", "0.93", "0.90", "0.90", "0.90", "0.90"],
            0.93,
        ),
        (
            "sglang:cache_hit_rate",
            "cache_hit_rate",
            ["0.42"] * 6 + ["0.45", "0.42"],
            0.45,
        ),
        ("sglang:gen_throughput", "gen_throughput", ["1843.5"] * 8, 1843.5),
    ],
)
def test_every_gauge_folds_by_max_across_tp_ranks(name, key, values, expected):
    # A TP=8 SGLang reports one scheduler EIGHT times: the ranks replicate the
    # reading rather than partitioning it, so max is the only fold that neither
    # multiplies the value by the TP degree nor breaks the 0-1 invariant.
    assert _only_model(_ranks(name, values))[key] == expected


def test_gen_throughput_is_not_multiplied_by_the_tp_degree():
    # The headline mistake this rule prevents, spelled out: summing 8 identical
    # per-rank tokens/s readings would report 14748.0 instead of 1843.5.
    model = _only_model(_ranks("sglang:gen_throughput", ["1843.5"] * 8))
    assert model["gen_throughput"] == 1843.5
    assert model["gen_throughput"] != 1843.5 * 8


def test_counters_and_histogram_halves_sum_across_a_label_dimension():
    # The other half of the fold contract: where a dimension really does
    # partition the work, the cumulative quantities add up.
    body = (
        _series("sglang:prompt_tokens_total", "1000.0", dp_rank="0")
        + _series("sglang:prompt_tokens_total", "2000.0", dp_rank="1")
        + _series("sglang:time_to_first_token_seconds_sum", "10.5", dp_rank="0")
        + _series("sglang:time_to_first_token_seconds_sum", "20.25", dp_rank="1")
        + _series("sglang:time_to_first_token_seconds_count", "100.0", dp_rank="0")
        + _series("sglang:time_to_first_token_seconds_count", "400.0", dp_rank="1")
    )
    model = _only_model(body)
    assert model["prompt_tokens_total"] == 3000
    assert model["ttft_sum_seconds"] == 30.75
    assert model["ttft_count"] == 500


def test_gauges_use_max_and_counters_use_sum_in_the_same_table():
    # The two reducers are declared per field, so one body must exercise both.
    gauges = {key: reduce_fn for key, _n, reduce_fn, _c in sglang._GAUGE_FIELDS}
    counters = {key: reduce_fn for key, _n, reduce_fn, _c in sglang._COUNTER_FIELDS}
    assert set(gauges.values()) == {inference_metrics.max_value}
    assert set(counters.values()) == {inference_metrics.sum_values}


@pytest.mark.parametrize("label", ["engine_type", "tp_rank", "pp_rank", "dp_rank"])
def test_documented_rank_labels_are_not_foreign(label):
    # The dimensions a single SGLang really does emit must NOT trip the flag, or
    # every TP host would report itself as an aggregating endpoint on every tick.
    body = _series("sglang:num_running_reqs", "3.0", **{label: "0"}) + _series(
        "sglang:num_running_reqs", "4.0", **{label: "1"}
    )
    out = _collect(body)
    assert "read_warnings" not in out
    assert out["models"][0]["running_requests"] == 4


def test_foreign_label_dimension_is_flagged_not_silently_merged():
    # metrics_url pointed at a Prometheus scraping 2 SGLang nodes: every series
    # carries an "instance" label, so the queue depth folded here may belong to
    # another host. We still ship what parsed, flagged as non-authoritative.
    body = _series(
        "sglang:num_queue_reqs", "0.0", instance="10.0.7.21:30000"
    ) + _series("sglang:num_queue_reqs", "480.0", instance="10.0.7.22:30000")
    out = _collect(body)
    assert out["read_warnings"] == ["foreign_labels"]
    assert out["models"][0]["queue_requests"] == 480


def test_models_are_sorted_by_name():
    body = _series("sglang:num_running_reqs", "1.0", model="zeta") + _series(
        "sglang:num_running_reqs", "2.0", model="Alpha"
    )
    assert [m["name"] for m in _collect(body)["models"]] == ["Alpha", "zeta"]


# --- the whitelist ---------------------------------------------------------


def test_whitelist_covers_every_declared_source_name():
    # The scan-time whitelist is derived from the field tables; if a table gains
    # a name the parser must retain it, or the key silently never appears.
    for _key, names, _reduce, _cast in sglang._GAUGE_FIELDS + sglang._COUNTER_FIELDS:
        for name in names:
            assert name in sglang._NAMES_OF_INTEREST
    for _prefix, bases in sglang._HISTOGRAM_FIELDS:
        for base in bases:
            assert base + "_sum" in sglang._NAMES_OF_INTEREST
            assert base + "_count" in sglang._NAMES_OF_INTEREST


@pytest.mark.parametrize(
    "name",
    [
        # token_usage already carries the ratio, so the raw token count is noise.
        "sglang:num_used_tokens",
        "sglang:cached_tokens_total",
        "sglang:num_requests_total",
        # Speculative decoding and the --enable-mfu-metrics counters are v2.
        "sglang:spec_accept_length",
        "sglang:num_spec_accepted_tokens_total",
        "sglang:func_latency_seconds_sum",
        # Bucket series are the bulk of the body and carry nothing we need.
        "sglang:time_to_first_token_seconds_bucket",
    ],
)
def test_metrics_deliberately_not_collected_are_absent_from_the_whitelist(name):
    assert name not in sglang._NAMES_OF_INTEREST


def test_itl_reads_the_name_sglang_kept_not_the_vllm_rename():
    # vLLM renamed time_per_output_token_seconds to inter_token_latency_seconds;
    # SGLang did not. Aliasing the vLLM spelling in would be a guess that a
    # future SGLang uses it for the SAME measurement, and first-present-wins
    # would then silently switch which histogram we report.
    assert "sglang:time_per_output_token_seconds_sum" in sglang._NAMES_OF_INTEREST
    assert "sglang:inter_token_latency_seconds_sum" not in sglang._NAMES_OF_INTEREST
    body = _series("sglang:time_per_output_token_seconds_sum", "8899.2") + _series(
        "sglang:time_per_output_token_seconds_count", "9000000.0"
    )
    model = _only_model(body)
    assert model["itl_sum_seconds"] == 8899.2
    assert model["itl_count"] == 9000000


def test_bucket_series_are_never_read_as_the_sum_or_count():
    body = _series(
        "sglang:e2e_request_latency_seconds_bucket", "500.0", le="10.0"
    ) + _series("sglang:e2e_request_latency_seconds_bucket", "900.0", le="+Inf")
    # Dropped by name before the label scan, so the "le" dimension a single
    # SGLang never folds cannot trip foreign_labels either.
    assert _collect(body) == {"reachable": True, "models": []}


# --- omit-not-zero, and corruption is not a reading ------------------------


def test_present_but_zero_ships_and_absent_is_omitted():
    model = _only_model(_series("sglang:num_queue_reqs", "0.0"))
    assert model == {"name": "m", "queue_requests": 0}


@pytest.mark.parametrize("value", ["NaN", "+Inf", "not-a-number"])
def test_non_finite_and_unparseable_values_omit_their_key(value):
    # A non-finite float reaching the payload would make json.dumps emit invalid
    # Infinity/NaN JSON and poison the whole tick, not just this key.
    body = _series("sglang:token_usage", value) + _series(
        "sglang:num_running_reqs", "1.0"
    )
    model = _only_model(body)
    assert "token_usage" not in model
    assert json.dumps(model, allow_nan=False)


def test_negative_value_omits_its_key_and_warns():
    # int(-0.5) == 0 would turn corruption into a believable "idle" reading.
    body = _series("sglang:gen_throughput", "-1.0") + _series(
        "sglang:num_running_reqs", "1.0"
    )
    out = _collect(body)
    assert "gen_throughput" not in out["models"][0]
    assert out["read_warnings"] == ["invalid_values"]


def test_non_integral_value_for_an_integer_field_is_rejected_not_floored():
    # A queue of 0.9 is not a queue of 0.
    out = _collect(_series("sglang:num_queue_reqs", "0.9"))
    assert "queue_requests" not in out["models"][0]
    assert out["read_warnings"] == ["invalid_values"]


def test_fractions_ship_verbatim_between_zero_and_one():
    body = _series("sglang:token_usage", "0.97") + _series(
        "sglang:cache_hit_rate", "0.08"
    )
    model = _only_model(body)
    # Verbatim 0-1: the server converts to a percentage, the agent never does.
    assert model["token_usage"] == 0.97
    assert model["cache_hit_rate"] == 0.08


def test_read_warnings_absent_on_a_normal_tick():
    assert "read_warnings" not in _collect(_series("sglang:num_running_reqs", "1.0"))


# --- shared implementation, not a fork -------------------------------------


def test_the_two_collectors_share_one_implementation():
    # The acceptance criterion for #135: sglang.py and vllm.py are two
    # whitelists over one module, so a fix to the transport, the parser, the
    # envelope or the warning vocabulary lands on both at once.
    assert sglang.collect is vllm.collect is inference_metrics.collect
    assert isinstance(sglang._SPEC, inference_metrics.ExpositionSpec)
    assert isinstance(vllm._SPEC, inference_metrics.ExpositionSpec)
    # The specs differ only in vocabulary -- and the model label is the same.
    assert sglang._SPEC.model_label == vllm._SPEC.model_label == "model_name"
    assert sglang._SPEC.reducible_labels != vllm._SPEC.reducible_labels
    assert not sglang._SPEC.names_of_interest & vllm._SPEC.names_of_interest


# --- cross-repo contract (fivenines-server) --------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "sglang_contract_payload.json"
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
    """SHARED FIXTURE (cross-repo contract): fixtures/sglang_contract_payload.json.

    Asserted on both sides:
    - here: sglang_metrics(**scenario["config"]) must equal scenario["payload"]
      with only requests.get mocked (the scenario's canned 'response' fed back
      as the single GET, or its 'raise' entry making that GET raise the named
      transport exception);
    - fivenines-server: spec/requests/api_collect_sglang_spec.rb posts
      scenario["payload"] under data["sglang"] and asserts Ingesters::Agent
      ingests the reachable true/false shapes.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    scenario = _FIXTURE["scenarios"][name]
    with patch(
        "fivenines_agent.inference_metrics.requests.get",
        side_effect=_fake_get_for(scenario),
    ):
        out = sglang_metrics(**scenario["config"])
    assert out == scenario["payload"]


def test_fixture_agent_min_version():
    # A FROZEN LITERAL, never read from pyproject: a later version bump must not
    # be able to break this assertion (or the server's copy of it).
    assert _FIXTURE["agent_min_version"] == "1.17.1"


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
            assert payload["error_type"] in inference_metrics.ERROR_TYPES


def test_fixture_read_warnings_only_on_the_degraded_scenario():
    # read_warnings means "this tick is not a clean snapshot of one local
    # SGLang". Every healthy/error scenario must be free of it, or the server
    # learns to ignore a flag that is supposed to suppress pruning.
    warned = {
        name
        for name, sc in _FIXTURE["scenarios"].items()
        if sc["payload"].get("read_warnings")
    }
    assert warned == {"aggregating_endpoint"}
    for name in warned:
        warnings = _FIXTURE["scenarios"][name]["payload"]["read_warnings"]
        assert set(warnings) <= inference_metrics.WARNING_VOCABULARY


def test_fixture_metrics_not_enabled_is_reachable_with_no_models():
    # The stock-launch state the server renders its --enable-metrics hint from
    # must stay distinguishable from an outage in the fixture itself.
    payload = _FIXTURE["scenarios"]["metrics_not_enabled"]["payload"]
    assert payload == {"reachable": True, "models": []}


def test_fixture_tp_fold_keeps_one_row_and_does_not_multiply_the_gauges():
    # The fold rules, pinned where the server can read them: eight per-rank
    # series collapse to ONE model row, and the gauges are peaks, not sums.
    single = _FIXTURE["scenarios"]["healthy"]["payload"]["models"][0]
    folded = _FIXTURE["scenarios"]["healthy_tp_multirank"]["payload"]["models"]
    assert len(folded) == 1
    folded = folded[0]
    assert folded["gen_throughput"] == single["gen_throughput"]
    assert folded["running_requests"] == single["running_requests"]
    # The eight rank series really are in the body (an 8x sum would be visible).
    body = _FIXTURE["scenarios"]["healthy_tp_multirank"]["response"]["body"]
    assert body.count("sglang:gen_throughput{") == 8
    # ...and the peaked fractions come from a middle rank, not the first or last.
    assert folded["token_usage"] > single["token_usage"]
    assert folded["cache_hit_rate"] > single["cache_hit_rate"]


def test_fixture_counter_values_are_raw_integers_not_rates():
    # Counter discipline: the server rate()s these, so the agent must ship the
    # cumulative value verbatim. int-typed in the fixture, never a float rate.
    model = _FIXTURE["scenarios"]["healthy"]["payload"]["models"][0]
    for key in (
        "prompt_tokens_total",
        "generation_tokens_total",
        "ttft_count",
        "itl_count",
        "e2e_latency_count",
    ):
        assert isinstance(model[key], int)
    # ...while the gauges SGLang computes itself stay floats the server must not
    # rate(), and the fractions stay inside 0-1.
    for key in ("token_usage", "cache_hit_rate", "gen_throughput"):
        assert isinstance(model[key], float)
    assert 0.0 <= model["token_usage"] <= 1.0
    assert 0.0 <= model["cache_hit_rate"] <= 1.0
