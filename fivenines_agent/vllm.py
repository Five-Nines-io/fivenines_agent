"""vLLM inference-serving health collector (server #887).

A customer running vLLM has two monitoring layers that can disagree: the NVIDIA
GPU metrics we already ship say "8 GPUs, all green", while the serving process
that owns those GPUs has OOM-crashed, wedged its scheduler queue, or filled its
KV cache. This collector polls the vLLM OpenAI-compatible server's native
Prometheus endpoint (exposed by default on the API server port, 8000 -- no
exporter, no customer-side setup) and ships one health object under
``data["vllm"]``. The server turns it into a ``vllm_status`` axis, queue /
KV-cache saturation thresholds, and tokens-per-second + latency series.

Pattern: ``tsdb.py`` is the direct sibling -- same local HTTP fetch, same
Prometheus text-exposition parsing, same envelope semantics. This collector is
essentially "the tsdb fetch with a ``vllm:*`` whitelist and per-model grouping".
Config-driven with no OS gate and no capability probe (the nginx / apache /
php_fpm / tsdb posture), because it is pure HTTP and works on every platform.

Reachability contract (the ``tsdb.py`` posture, NOT the php_fpm null one): here
UNREACHABLE IS THE SIGNAL, so it must ride the payload as
``{"reachable": false, ...}`` and MUST NEVER collapse to ``None`` (which the
server would read as "collector disabled / no data" rather than "vLLM is down").

SHARP EDGE #1 -- reachable means "vLLM answered ``/metrics``", nothing else. A
2xx yields ``reachable: true`` EVEN IF the exposition carries zero ``vllm:*``
metrics (``--disable-log-stats``, or a future name drift the whitelist misses):
we ship ``models: []`` and stay reachable. Only a connection-level failure on
``/metrics`` itself -- refused / timeout / TLS / auth / non-2xx -- produces
``reachable: false``. An agent-side parse bug must never page a customer with
"your vLLM is down", so once a 2xx is in hand nothing below can flip the verdict.

SHARP EDGE #2 -- version drift. Metric names moved between the v0 and v1 engines
AND inside v1 (upstream PR #18354 dropped the ``gpu_`` prefix from metrics that
are not GPU-specific), so the whitelist folds aliases onto one canonical payload
key, first-present-wins with the NEWEST name first. That ordering matters during
an upstream deprecation window, when both spellings are exposed at once: we read
the new one and ignore the old rather than double-counting.

Counter discipline (the #97 lesson): every ``*_total`` field and every histogram
``_sum`` / ``_count`` is a RAW cumulative counter shipped as-is -- the server
``rate()``s them; we never diff or reset them agent-side. A name absent from the
exposition OMITS its payload key (the server treats a missing key as no-data) --
we never fabricate a ``0``.

SHARP EDGE #3 -- a plausible lie is worse than no data. The endpoint is only
supposed to be one local vLLM, but ``metrics_url`` is operator-supplied and
nothing stops it landing on a Prometheus, a federation, or a scrape proxy that
answers 2xx with a superset. Reducing across THAT would sum three nodes' queue
depth into this host's row. Rather than guess which series is local, an
optional ``read_warnings`` list rides the payload naming why this tick is not a
clean snapshot (``foreign_labels`` / ``models_capped`` / ``body_truncated`` /
``invalid_values`` / ``unlabelled_series``). The server's rule for every one of
them is the same: do not treat ``models[]`` as authoritative, and above all do
not vanish-prune the rows missing from it. On a normal tick the key is absent.
"""

import math
import re
import time

import requests

from fivenines_agent.debug import debug, log

# Shared transport timeout (seconds), matching tsdb.py / caddy.py / apache.py. A
# wedged vLLM must never hang the whole collect tick.
_TIMEOUT = 5

# Streamed-read bounds, the haproxy._http_show_stat precedent. A real vLLM
# exposition is ~100 KB even with every histogram bucket, so 8 MB is ~80x
# headroom; the cap exists because a metrics_url aimed at the wrong thing (a
# Prometheus /federate, a log endpoint) would otherwise pull an unbounded body
# into a long-lived daemon's memory before any whitelist could shrink it.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_RECV_CHUNK_BYTES = 64 * 1024

# The label vLLM stamps on every serving metric. It is the grouping key: one
# models[] entry per distinct value.
_MODEL_LABEL = "model_name"

# The ONLY other label dimensions a single vLLM puts on a whitelisted metric:
# "engine" (one series per data-parallel engine) and "finished_reason" (on
# request_success). Folding these away is the documented reduction.
#
# Any OTHER label key is the tell that this endpoint is not one local vLLM --
# a Prometheus, a federation, or a scrape proxy stamps "instance" / "job" /
# "pod". Reducing across THAT dimension would sum three nodes' queue depth into
# this host's row and report the fleet's hottest KV cache as ours: a plausible
# lie, which is the one outcome this collector must never produce. We cannot
# know which series is the local one, so we still ship what we parsed but flag
# the read (a _WARN_* reason) so the server never reads it as authoritative.
_REDUCIBLE_LABELS = frozenset({"engine", "finished_reason"})

# Defensive bound on the number of distinct model_name groups. One vLLM serves
# one model, so this is ~50x headroom; it only exists so a metrics_url pointed at
# an aggregating proxy or a federated Prometheus cannot turn one tick into
# thousands of rows.
_MAX_MODELS = 50

# The vocabulary of the optional "read_warnings" payload key. Each value means
# "this tick is NOT a clean, complete snapshot of one local vLLM", so the server
# must not treat models[] as authoritative -- above all it must not vanish-prune
# the model rows that are missing from it. ONE key carrying an enum-like list
# rather than a boolean per cause: the server's rule is identical for all of
# them, and a new cause then costs no new contract surface.
_WARN_FOREIGN_LABELS = "foreign_labels"
_WARN_MODELS_CAPPED = "models_capped"
_WARN_BODY_TRUNCATED = "body_truncated"
_WARN_INVALID_VALUES = "invalid_values"
_WARN_UNLABELLED_SERIES = "unlabelled_series"

# Prometheus label matcher: name="value" pairs, honouring backslash escapes in
# the value so a stray quote does not truncate the scan.
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')


def _sum_values(values):
    """Total a metric across its remaining label dimensions.

    The right reduction for counts and cumulative counters: requests running
    across every data-parallel engine of a model, successes across every
    finished_reason.
    """
    return float(sum(values))


def _max_value(values):
    """Peak across the remaining label dimensions.

    The right reduction for a 0-1 saturation FRACTION: summing the KV-cache
    usage of 8 data-parallel engines at 0.5 each would ship 4.0, which the
    server renders as 400%. The max is the most-saturated engine -- the number
    the saturation threshold is actually about -- and it keeps the 0-1 range
    invariant the contract promises. With the common single-engine deployment
    max is identity, so the fraction still ships verbatim.
    """
    return float(max(values))


# Gauges: (payload key, source names newest-first, reducer, cast).
_GAUGE_FIELDS = (
    ("requests_running", ("vllm:num_requests_running",), _sum_values, int),
    ("requests_waiting", ("vllm:num_requests_waiting",), _sum_values, int),
    (
        "kv_cache_usage",
        # Renamed from the gpu_-prefixed spelling upstream (PR #18354); the old
        # name is still what a pinned older deployment exposes.
        ("vllm:kv_cache_usage_perc", "vllm:gpu_cache_usage_perc"),
        _max_value,
        float,
    ),
)

# Cumulative counters. prometheus_client exposes a Counter with the "_total"
# suffix appended, so these are the names as they appear on the wire regardless
# of how vLLM declared them. All shipped RAW -- never diffed agent-side.
_COUNTER_FIELDS = (
    ("prompt_tokens_total", ("vllm:prompt_tokens_total",), _sum_values, int),
    ("generation_tokens_total", ("vllm:generation_tokens_total",), _sum_values, int),
    # Summed across the finished_reason label dimension.
    ("request_success_total", ("vllm:request_success_total",), _sum_values, int),
    ("preemptions_total", ("vllm:num_preemptions_total",), _sum_values, int),
    (
        "prefix_cache_queries_total",
        ("vllm:prefix_cache_queries_total", "vllm:gpu_prefix_cache_queries_total"),
        _sum_values,
        int,
    ),
    (
        "prefix_cache_hits_total",
        ("vllm:prefix_cache_hits_total", "vllm:gpu_prefix_cache_hits_total"),
        _sum_values,
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

# Only these exact sample names are retained while scanning the exposition;
# everything else is discarded, so a multi-hundred-KB /metrics body never builds
# a giant dict. Histograms contribute their _sum / _count names (their _bucket
# series, by far the bulk of a vLLM exposition, are skipped).
_NAMES_OF_INTEREST = frozenset(
    [name for _key, names, _reduce, _cast in _GAUGE_FIELDS for name in names]
    + [name for _key, names, _reduce, _cast in _COUNTER_FIELDS for name in names]
    + [
        base + suffix
        for _prefix, bases in _HISTOGRAM_FIELDS
        for base in bases
        for suffix in ("_sum", "_count")
    ]
)


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
        dict: ``{"reachable": True, "models": [...]}`` on a 2xx; ``{"reachable":
        False, "error_type": ..., "error_message": ...}`` on any
        connection-level failure. Never ``None``: unreachable is the signal and
        must ride the payload.
    """
    # Request setup and the GET share one try: a connection-level failure here
    # (and ONLY here) is what "unreachable" means. The setup lives inside it too
    # so that even a pathological config -- a non-string url from a malformed
    # server push, say -- yields a reachable:false envelope rather than raising
    # into a None (which the server would misread as "collector disabled").
    # str() coercion routes a bad url through requests' own URL validation into
    # that same envelope.
    try:
        headers = {"Accept-Encoding": "identity"}
        if auth_header_name and auth_header_value:
            headers[auth_header_name] = auth_header_value
        # Streamed, not buffered: see _read_body. Redirects are refused so a
        # misconfigured or compromised endpoint cannot bounce the fetch to an
        # internal address (SSRF), and identity encoding declines a
        # decompression bomb -- both the haproxy._http_show_stat posture.
        response = requests.get(
            str(metrics_url or ""),
            headers=headers,
            timeout=_TIMEOUT,
            verify=verify_ssl,
            stream=True,
            allow_redirects=False,
        )
    except Exception as e:
        return _unreachable(e)

    # Split from the GET purely so `response` is guaranteed bound here: the
    # connection must be released on every path below, and a `finally` that has
    # to ask whether the response exists carries an arc nothing can reach.
    try:
        if response.status_code in (401, 403):
            return {
                "reachable": False,
                "error_type": "auth_failed",
                "error_message": f"HTTP {response.status_code} on /metrics",
            }
        if not 200 <= response.status_code < 300:
            return {
                "reachable": False,
                "error_type": "http_error",
                "error_message": f"HTTP {response.status_code} on /metrics",
            }
        # A mid-body reset is still a connection-level failure, so it lands in
        # the unreachable envelope rather than an empty-but-reachable payload.
        text, truncated = _read_body(response)
    except Exception as e:
        return _unreachable(e)
    finally:
        response.close()

    # A 2xx is in hand: vLLM answered, so reachable is now locked True no matter
    # what parsing does below (sharp edge #1). A parse bug degrades to an empty
    # models list, it never pages the customer.
    #
    # A truncated body is the one case where we hold a 2xx but must NOT present
    # models[] as a snapshot: half an exposition parses cleanly into a SHORT
    # list, and a server that prunes what is missing would vanish every model
    # past the cut. Ship nothing and say why.
    try:
        if truncated:
            return {
                "reachable": True,
                "models": [],
                "read_warnings": [_WARN_BODY_TRUNCATED],
            }
        return _build_payload(text)
    except Exception as e:
        log(f"vLLM parse error (staying reachable): {e}", "error")
        return {"reachable": True, "models": []}


def _read_body(response):
    """Stream the response body under a byte cap and a wall-clock deadline.

    Returns ``(text, truncated)``. ``truncated`` is True when either bound was
    hit, and the caller then refuses to publish a partial parse. The deadline is
    best-effort in the same way haproxy's is: ``requests`` exposes only a scalar
    inactivity timeout, so connect + response headers happen before the loop and
    each chunk read still gets the full ``_TIMEOUT``.
    """
    deadline = time.monotonic() + _TIMEOUT
    chunks = bytearray()
    for chunk in response.iter_content(chunk_size=_RECV_CHUNK_BYTES):
        if time.monotonic() > deadline:
            log(f"vLLM /metrics read exceeded the {_TIMEOUT}s deadline", "error")
            return "", True
        if not chunk:
            continue
        chunks += chunk
        if len(chunks) > _MAX_RESPONSE_BYTES:
            log(
                f"vLLM /metrics body exceeded {_MAX_RESPONSE_BYTES} bytes -- "
                "is metrics_url pointed at a vLLM server?",
                "error",
            )
            return "", True
    return chunks.decode("utf-8", "replace"), False


def _unreachable(exc):
    """Build the reachable:false envelope for a connection-level failure."""
    message = str(exc).strip()
    return {
        "reachable": False,
        "error_type": _classify_error(exc),
        "error_message": message[:200] if message else exc.__class__.__name__,
    }


def _classify_error(exc):
    """Map a transport exception to the contract's error_type vocabulary.

    SSLError must be tested before Timeout/ConnectionError because it subclasses
    ConnectionError; ConnectTimeout subclasses both ConnectionError and Timeout,
    so Timeout is tested before the ConnectionError catch-all. Every remaining
    transport error (refused, DNS failure, reset, or an unexpected requests
    error) folds into ``connection_refused`` -- the enum has no finer bucket and
    the server maps it to "unreachable" regardless.
    """
    if isinstance(exc, requests.exceptions.SSLError):
        return "tls_error"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    return "connection_refused"


def _build_payload(text):
    """Parse a 2xx /metrics body into the reachable health payload."""
    grouped, warnings = _parse_exposition(text)
    payload = {
        "reachable": True,
        "models": [
            _model_entry(name, samples, warnings)
            for name, samples in sorted(grouped.items())
        ],
    }
    if warnings:
        payload["read_warnings"] = sorted(warnings)
    return payload


# --- text exposition parsing ----------------------------------------------


def _parse_exposition(text):
    """Scan a Prometheus text-exposition body into per-model sample values.

    Returns ``(grouped, warnings)`` where ``grouped`` maps each ``model_name`` to
    ``{sample_name: [value, ...]}`` -- one list entry per remaining label series,
    for the field reducer to fold -- and ``warnings`` is the set of
    ``_WARN_*`` reasons this read is not a clean single-vLLM snapshot
    (_MAX_MODELS reached, first-seen models winning; or a foreign label
    dimension seen).

    Series carrying no ``model_name`` label are dropped: the contract keys every
    entry by model and we will not invent a name for an unattributable series.
    A body where that leaves nothing still ships reachable with ``models: []``.
    """
    grouped = {}
    warnings = set()
    foreign = set()
    for line in text.splitlines():
        parsed = _parse_metric_line(line)
        if parsed is None:
            continue
        name, labels, value = parsed
        if value is None or name not in _NAMES_OF_INTEREST:
            continue
        # Every quantity in this payload -- a queue count, a cumulative counter,
        # a seconds sum, a 0-1 fraction -- is non-negative by definition, so a
        # negative sample means the body is lying. Drop it here rather than let
        # int() truncate it toward a believable 0 (the wireguard lesson: a
        # negative age is null, NEVER 0) or let it quietly shrink a sum -- and
        # WARN (_WARN_INVALID_VALUES, shared with the non-integral rejection in
        # _put), because a silent drop would still hand the server a believable
        # snapshot -- and a model whose every series is negative would vanish
        # from models[] with nothing saying why. NaN / +Inf are deliberately NOT
        # warned: Prometheus uses NaN as a legitimate "no observations yet", so
        # flagging it would fire on every idle server.
        if value < 0:
            warnings.add(_WARN_INVALID_VALUES)
            continue
        model = labels.get(_MODEL_LABEL)
        if not model:
            # A whitelisted vllm:* metric with no model_name is an anomaly, not
            # noise: either something stripped the label or upstream renamed it.
            # We still refuse to invent a name, but dropping it SILENTLY would
            # rebuild the exact vanish-prune this warning set exists to prevent
            # -- an upstream rename of model_name would otherwise blind every
            # host at once with an innocent-looking empty models list.
            warnings.add(_WARN_UNLABELLED_SERIES)
            continue
        foreign.update(set(labels) - _REDUCIBLE_LABELS - {_MODEL_LABEL})
        samples = grouped.get(model)
        if samples is None:
            if len(grouped) >= _MAX_MODELS:
                warnings.add(_WARN_MODELS_CAPPED)
                continue
            samples = grouped[model] = {}
        samples.setdefault(name, []).append(value)
    if foreign:
        log(
            "vLLM exposition carries labels a single vLLM does not emit "
            f"({', '.join(sorted(foreign))}) -- is metrics_url pointed at a "
            "Prometheus or a scrape proxy rather than the vLLM API server?",
            "error",
        )
        warnings.add(_WARN_FOREIGN_LABELS)
    return grouped, warnings


def _parse_metric_line(line):
    """Parse one exposition line into ``(name, labels, value)`` or ``None``.

    ``value`` is a float, or ``None`` for NaN / +Inf / -Inf (which the caller
    skips -- a non-finite value must never reach the payload, where json.dumps
    would emit invalid Infinity/NaN JSON and poison the whole tick).
    ``# HELP`` / ``# TYPE`` comments, blanks and unparseable lines return None.
    """
    line = line.strip()
    if not line or line[0] == "#":
        return None
    brace = line.find("{")
    if brace != -1:
        name = line[:brace]
        close = line.find("}", brace)
        if close == -1:
            return None
        labels = _parse_labels(line[brace + 1 : close])
        rest = line[close + 1 :]
    else:
        parts = line.split()
        if len(parts) < 2:
            return None
        name = parts[0]
        rest = parts[1]
        labels = {}
    return name, labels, _parse_value(rest)


def _parse_labels(label_str):
    """Extract the ``name="value"`` label pairs from inside the braces."""
    return {m.group(1): m.group(2) for m in _LABEL_RE.finditer(label_str)}


def _parse_value(rest):
    """Read the numeric sample value, ignoring any trailing timestamp."""
    rest = rest.strip()
    if not rest:
        return None
    token = rest.split()[0]
    try:
        value = float(token)
    except ValueError:
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return value


# --- per-model payload assembly --------------------------------------------


def _model_entry(name, samples, warnings):
    """Build one models[] entry from a model's whitelisted sample values."""
    entry = {"name": name}
    for key, source_names, reduce_fn, cast in _GAUGE_FIELDS + _COUNTER_FIELDS:
        value = _reduce_first_present(samples, source_names, reduce_fn)
        _put(entry, key, value, cast, warnings)
    for prefix, base_names in _HISTOGRAM_FIELDS:
        _put_histogram(entry, samples, prefix, base_names, warnings)
    return entry


def _reduce_first_present(samples, source_names, reduce_fn):
    """Fold the first present alias's series, or None when none is present.

    First-present-wins over the newest-first alias tuple: during an upstream
    deprecation window both spellings are exposed at once, so reading only the
    newest avoids double-counting the same quantity.
    """
    for source_name in source_names:
        values = samples.get(source_name)
        if values:
            return reduce_fn(values)
    return None


def _put_histogram(entry, samples, prefix, base_names, warnings):
    """Emit ``<prefix>_sum_seconds`` / ``<prefix>_count`` for a histogram.

    The alias is resolved ONCE for the pair -- the first base name contributing
    either half wins -- so a deprecation window can never mix the new metric's
    ``_sum`` with the old one's ``_count``. Whichever half is missing simply
    omits its key.
    """
    for base in base_names:
        total = _summed(samples, base + "_sum")
        count = _summed(samples, base + "_count")
        if total is None and count is None:
            continue
        _put(entry, prefix + "_sum_seconds", total, float, warnings)
        _put(entry, prefix + "_count", count, int, warnings)
        return


def _summed(samples, name):
    """Total one sample name across its label series, or None when absent."""
    values = samples.get(name)
    if not values:
        return None
    return _sum_values(values)


def _put(entry, key, value, cast, warnings):
    """Set ``entry[key]`` to ``cast(value)`` unless value is None.

    Omit-not-zero: a metric absent from the exposition leaves its key out, which
    the server reads as no-data. A present-but-zero metric ships its 0.

    An integer field given a non-integral value is REJECTED, not floored: a
    request queue of 0.9 is not a queue of 0, and silently flooring it would
    ship the same believable lie the negative check exists to stop. vLLM never
    emits a fractional count -- an averaging proxy in front of it does -- so the
    value is dropped and the read is flagged.
    """
    if value is None:
        return
    if cast is int and float(value) != int(value):
        warnings.add(_WARN_INVALID_VALUES)
        return
    entry[key] = cast(value)
