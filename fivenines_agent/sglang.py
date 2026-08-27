"""SGLang inference-serving health collector (server #893).

The sibling of ``vllm.py`` and the same alert: the NVIDIA GPU metrics we already
ship say "8 GPUs, all green" while the SGLang process that owns those GPUs has
crashed, wedged its scheduler queue, or filled its KV cache. This collector polls
the SGLang server's native Prometheus endpoint (the same HTTP port as its API
server, default 30000) and ships one health object under ``data["sglang"]``. The
server turns it into an ``sglang_status`` axis, queue / token-usage saturation
thresholds, and a tokens-per-second + latency series.

This module is ONLY the SGLang whitelist. The transport, the exposition parser,
the reduction, the never-``None`` reachability envelope and the ``read_warnings``
vocabulary all live in ``inference_metrics.py``, shared verbatim with
``vllm.py`` -- read that module's docstring for the contract and its sharp
edges.

SGLANG-SPECIFIC EDGE #1 -- metrics are OPT-IN. Unlike vLLM, which exposes its
metrics by default, SGLang only publishes ``sglang:*`` samples when it was
launched with ``--enable-metrics``. A stock SGLang answers ``/metrics`` with a
2xx carrying the default prometheus_client collectors and nothing else, so
``reachable: true`` with ``models: []`` is the EXPECTED first-run state here, not
an edge case: it is what the server renders the "add --enable-metrics to your
launch command" hint from. It must never be conflated with unreachable.

SGLANG-SPECIFIC EDGE #2 -- the gauges are REPLICATED per rank, not partitioned.
SGLang stamps ``tp_rank`` / ``pp_rank`` (and ``dp_rank``) alongside
``model_name``, and the motivating fleet runs TP=8, so multi-rank series are the
NORMAL exposition there rather than an oddity. Those ranks are one scheduler
reporting itself N times, so every gauge takes the MAX: summing
``gen_throughput`` across 8 tp_ranks would report 8x the real tokens/s, and
summing ``token_usage`` would ship 8.0 for a cache that is merely full. Counters
and histogram ``_sum``/``_count`` still SUM -- see ``_GAUGE_FIELDS`` below. (This
is where the two whitelists genuinely differ: vLLM's ``engine`` dimension is data
parallelism, where the counts really do add up.)
"""

from fivenines_agent.debug import debug
from fivenines_agent.inference_metrics import (
    ExpositionSpec,
    collect,
    max_value,
    sum_values,
)

# The label SGLang stamps on every serving metric. It is the grouping key: one
# models[] entry per distinct value.
_MODEL_LABEL = "model_name"

# The other label dimensions a single SGLang puts on a whitelisted metric.
# "engine_type" tags the scheduler flavour; the rank labels appear once the
# server is launched so that every scheduler (not just rank 0) reports. Folding
# these away is the documented reduction; any OTHER label key is the tell that
# this endpoint is not one local SGLang (sharp edge #3 in inference_metrics.py).
# "dp_rank" is in the set for the same reason as the other two: a data-parallel
# SGLang emits it as a matter of course, and treating it as foreign would flag a
# perfectly ordinary deployment as an aggregating endpoint on every tick.
_REDUCIBLE_LABELS = frozenset({"engine_type", "tp_rank", "pp_rank", "dp_rank"})

# Gauges: (payload key, source names newest-first, reducer, cast). ALL take the
# MAX, which is the difference from the vLLM table: these are scheduler-level
# readings that each rank repeats, so summing multiplies them by the TP degree
# (and, for the 0-1 fractions, ships a number the server renders as >100%).
# Where the deployment is single-rank -- the common one-GPU case -- max is
# identity and the value ships verbatim either way.
_GAUGE_FIELDS = (
    ("running_requests", ("sglang:num_running_reqs",), max_value, int),
    ("queue_requests", ("sglang:num_queue_reqs",), max_value, int),
    # 0-1 ratio, shipped verbatim; the server converts to a percentage.
    ("token_usage", ("sglang:token_usage",), max_value, float),
    # 0-1 proportion, shipped verbatim. A GAUGE SGLang computes itself -- the
    # server must not rate() it (the Caddy num_requests mistake).
    ("cache_hit_rate", ("sglang:cache_hit_rate",), max_value, float),
    # Tokens/s, INSTANTANEOUS. Also a gauge SGLang computes itself: it is not a
    # counter, so it is never diffed here nor rate()d server-side.
    ("gen_throughput", ("sglang:gen_throughput",), max_value, float),
)

# Cumulative counters. prometheus_client exposes a Counter with the "_total"
# suffix appended, so these are the names as they appear on the wire regardless
# of how SGLang declared them. All shipped RAW -- never diffed agent-side.
_COUNTER_FIELDS = (
    ("prompt_tokens_total", ("sglang:prompt_tokens_total",), sum_values, int),
    ("generation_tokens_total", ("sglang:generation_tokens_total",), sum_values, int),
)

# Histograms, read as their cumulative _sum / _count pair only (never buckets):
# (payload key prefix, base names newest-first). The payload keys are
# "<prefix>_sum_seconds" and "<prefix>_count".
_HISTOGRAM_FIELDS = (
    ("ttft", ("sglang:time_to_first_token_seconds",)),
    # SGLang kept the name vLLM renamed to inter_token_latency_seconds. There is
    # deliberately no alias here: adding the vLLM spelling would mean guessing
    # that a future SGLang release uses it for the SAME measurement, and
    # first-present-wins would then silently switch which histogram we report.
    ("itl", ("sglang:time_per_output_token_seconds",)),
    ("e2e_latency", ("sglang:e2e_request_latency_seconds",)),
)

# Deliberately NOT collected in v1: the --enable-mfu-metrics FLOPs/bytes
# counters, the speculative-decoding gauges, sglang:func_latency_seconds, and
# sglang:num_used_tokens (token_usage already carries the ratio the saturation
# threshold is about).
_SPEC = ExpositionSpec(
    product="SGLang",
    model_label=_MODEL_LABEL,
    reducible_labels=_REDUCIBLE_LABELS,
    gauges=_GAUGE_FIELDS,
    counters=_COUNTER_FIELDS,
    histograms=_HISTOGRAM_FIELDS,
)

# Retained scan-time whitelist, derived from the tables above.
_NAMES_OF_INTEREST = _SPEC.names_of_interest


@debug("sglang_metrics")
def sglang_metrics(
    metrics_url="http://127.0.0.1:30000/metrics",
    auth_header_name=None,
    auth_header_value=None,
    verify_ssl=True,
    **_kwargs,
):
    """Poll an SGLang server's /metrics endpoint and return its health object.

    Args:
        metrics_url: full URL of the SGLang Prometheus endpoint (its API server
            port, ``/metrics``).
        auth_header_name / auth_header_value: an optional custom auth header
            (both must be set to take effect). Covers ``--api-key`` deployments
            (``Authorization: Bearer <key>``) and any front proxy.
        verify_ssl: verify the server certificate for ``https`` URLs.
        **_kwargs: forward-compatible with the backend pushing config keys the
            agent does not yet know.

    Returns:
        dict: the reachability envelope from ``inference_metrics.collect``.
        Never ``None``: unreachable is the signal and must ride the payload.
    """
    return collect(
        _SPEC,
        metrics_url,
        auth_header_name=auth_header_name,
        auth_header_value=auth_header_value,
        verify_ssl=verify_ssl,
    )
