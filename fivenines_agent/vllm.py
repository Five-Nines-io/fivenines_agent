"""vLLM inference-serving health collector (server #887).

A customer running vLLM has two monitoring layers that can disagree: the NVIDIA
GPU metrics we already ship say "8 GPUs, all green", while the serving process
that owns those GPUs has OOM-crashed, wedged its scheduler queue, or filled its
KV cache. This collector polls the vLLM OpenAI-compatible server's native
Prometheus endpoint (exposed by default on the API server port, 8000 -- no
exporter, no customer-side setup) and ships one health object under
``data["vllm"]``. The server turns it into a ``vllm_status`` axis, queue /
KV-cache saturation thresholds, and tokens-per-second + latency series.

This module is ONLY the vLLM whitelist. The transport, the exposition parser,
the reduction, the never-``None`` reachability envelope and the ``read_warnings``
vocabulary all live in ``inference_metrics.py``, shared verbatim with the SGLang
sibling (``sglang.py``, server #893) -- read that module's docstring for the
contract and its sharp edges.

The vLLM-specific edge is VERSION DRIFT: metric names moved between the v0 and
v1 engines AND inside v1 (upstream PR #18354 dropped the ``gpu_`` prefix from
metrics that are not GPU-specific), so the field tables below fold aliases onto
one canonical payload key, first-present-wins with the NEWEST name first. That
ordering matters during an upstream deprecation window, when both spellings are
exposed at once: we read the new one and ignore the old rather than
double-counting.
"""

from fivenines_agent.debug import debug
from fivenines_agent.inference_metrics import (
    ExpositionSpec,
    collect,
    max_value,
    sum_values,
)

# The label vLLM stamps on every serving metric. It is the grouping key: one
# models[] entry per distinct value.
_MODEL_LABEL = "model_name"

# The ONLY other label dimensions a single vLLM puts on a whitelisted metric:
# "engine" (one series per data-parallel engine) and "finished_reason" (on
# request_success). Folding these away is the documented reduction; any OTHER
# label key is the tell that this endpoint is not one local vLLM (sharp edge #3
# in inference_metrics.py).
_REDUCIBLE_LABELS = frozenset({"engine", "finished_reason"})

# Gauges: (payload key, source names newest-first, reducer, cast).
_GAUGE_FIELDS = (
    # vLLM's "engine" dimension is data parallelism: each engine owns its own
    # scheduler and its own slice of the requests, so the counts really do add
    # up (contrast SGLang, whose tp_rank series REPLICATE one scheduler).
    ("requests_running", ("vllm:num_requests_running",), sum_values, int),
    ("requests_waiting", ("vllm:num_requests_waiting",), sum_values, int),
    (
        "kv_cache_usage",
        # Renamed from the gpu_-prefixed spelling upstream (PR #18354); the old
        # name is still what a pinned older deployment exposes.
        ("vllm:kv_cache_usage_perc", "vllm:gpu_cache_usage_perc"),
        max_value,
        float,
    ),
)

# Cumulative counters. prometheus_client exposes a Counter with the "_total"
# suffix appended, so these are the names as they appear on the wire regardless
# of how vLLM declared them. All shipped RAW -- never diffed agent-side.
_COUNTER_FIELDS = (
    ("prompt_tokens_total", ("vllm:prompt_tokens_total",), sum_values, int),
    ("generation_tokens_total", ("vllm:generation_tokens_total",), sum_values, int),
    # Summed across the finished_reason label dimension.
    ("request_success_total", ("vllm:request_success_total",), sum_values, int),
    ("preemptions_total", ("vllm:num_preemptions_total",), sum_values, int),
    (
        "prefix_cache_queries_total",
        ("vllm:prefix_cache_queries_total", "vllm:gpu_prefix_cache_queries_total"),
        sum_values,
        int,
    ),
    (
        "prefix_cache_hits_total",
        ("vllm:prefix_cache_hits_total", "vllm:gpu_prefix_cache_hits_total"),
        sum_values,
        int,
    ),
)

# Histograms, read as their cumulative _sum / _count pair only (never buckets):
# (payload key prefix, base names newest-first). The payload keys are
# "<prefix>_sum_seconds" and "<prefix>_count". The deprecated v1
# gpu_prefix_cache_hit_rate GAUGE is deliberately absent everywhere: a rate gauge
# is not a substitute for the query/hit counters, so when the counters are gone
# the keys are simply omitted.
_HISTOGRAM_FIELDS = (
    ("ttft", ("vllm:time_to_first_token_seconds",)),
    (
        "itl",
        # inter_token_latency_seconds is the current name;
        # time_per_output_token_seconds is what it was called before. NOT to be
        # confused with request_time_per_output_token_seconds, a different
        # (per-request mean) histogram that is not an alias of either.
        ("vllm:inter_token_latency_seconds", "vllm:time_per_output_token_seconds"),
    ),
    ("e2e_latency", ("vllm:e2e_request_latency_seconds",)),
)

_SPEC = ExpositionSpec(
    product="vLLM",
    model_label=_MODEL_LABEL,
    reducible_labels=_REDUCIBLE_LABELS,
    gauges=_GAUGE_FIELDS,
    counters=_COUNTER_FIELDS,
    histograms=_HISTOGRAM_FIELDS,
)

# Retained scan-time whitelist, derived from the tables above.
_NAMES_OF_INTEREST = _SPEC.names_of_interest


@debug("vllm_metrics")
def vllm_metrics(
    metrics_url="http://127.0.0.1:8000/metrics",
    auth_header_name=None,
    auth_header_value=None,
    verify_ssl=True,
    **_kwargs,
):
    """Poll a vLLM server's /metrics endpoint and return its health object.

    Args:
        metrics_url: full URL of the vLLM Prometheus endpoint (the API server
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
