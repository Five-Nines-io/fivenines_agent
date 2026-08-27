"""Shared fetch + Prometheus-exposition machinery for the inference collectors.

Two collectors sit on this module -- ``vllm.py`` (server #887) and ``sglang.py``
(server #893) -- and they are the same collector twice: GET one local inference
server's native Prometheus ``/metrics``, keep a handful of sample names out of a
body that is mostly histogram buckets, fold the remaining label dimensions onto
one entry per served model, and ship a reachability envelope. Only the metric
NAMES differ between the two, so only the names are forked: each collector
contributes an ``ExpositionSpec`` (its field tables plus the label dimensions
its engine really emits) and a thin wrapper for the config splat. Everything
below -- the transport, the parser, the reduction, the envelope, the warning
vocabulary -- is shared, so a fix to one engine's blind spot fixes both.

Pattern: ``tsdb.py`` is the ancestor -- same local HTTP fetch, same text
exposition, same envelope semantics. Config-driven with no OS gate and no
capability probe (the nginx / apache / php_fpm / tsdb posture), because it is
pure HTTP and works on every platform.

Reachability contract (the ``tsdb.py`` posture, NOT the php_fpm null one): here
UNREACHABLE IS THE SIGNAL, so it must ride the payload as
``{"reachable": false, ...}`` and MUST NEVER collapse to ``None`` (which the
server would read as "collector disabled / no data" rather than "the inference
server is down").

SHARP EDGE #1 -- reachable means "the server answered ``/metrics``", nothing
else. A 2xx yields ``reachable: true`` EVEN IF the exposition carries zero
whitelisted samples: we ship ``models: []`` and stay reachable. That is an edge
case for vLLM (``--disable-log-stats``) and the EXPECTED first-run state for
SGLang (whose metrics only exist with ``--enable-metrics``), and it is also what
an upstream rename the whitelist misses degrades to. Only a connection-level
failure on ``/metrics`` itself -- refused / timeout / TLS / auth / non-2xx --
produces ``reachable: false``. An agent-side parse bug must never page a
customer with "your inference server is down", so once a 2xx is in hand nothing
below can flip the verdict.

SHARP EDGE #2 -- version drift. Metric names move upstream, so every field
carries a tuple of source names, first-present-wins with the NEWEST name first.
That ordering matters during a deprecation window, when both spellings are
exposed at once: we read the new one and ignore the old rather than
double-counting the same quantity.

Counter discipline (the #97 lesson): every ``*_total`` field and every histogram
``_sum`` / ``_count`` is a RAW cumulative counter shipped as-is -- the server
``rate()``s them; we never diff or reset them agent-side. A name absent from the
exposition OMITS its payload key (the server treats a missing key as no-data) --
we never fabricate a ``0``.

SHARP EDGE #3 -- a plausible lie is worse than no data. The endpoint is only
supposed to be one local engine, but ``metrics_url`` is operator-supplied and
nothing stops it landing on a Prometheus, a federation, or a scrape proxy that
answers 2xx with a superset. Reducing across THAT would sum three nodes' queue
depth into this host's row. Rather than guess which series is local, an optional
``read_warnings`` list rides the payload naming why this tick is not a clean
snapshot (``foreign_labels`` / ``models_capped`` / ``body_truncated`` /
``invalid_values`` / ``unlabelled_series``). The server's rule for every one of
them is the same: do not treat ``models[]`` as authoritative, and above all do
not vanish-prune the rows missing from it. On a normal tick the key is absent.
"""

import math
import re
import time

import requests

from fivenines_agent.debug import log

# Shared transport timeout (seconds), matching tsdb.py / caddy.py / apache.py. A
# wedged inference server must never hang the whole collect tick.
_TIMEOUT = 5

# Streamed-read bounds, the haproxy._http_show_stat precedent. A real vLLM or
# SGLang exposition is ~100 KB even with every histogram bucket, so 8 MB is ~80x
# headroom; the cap exists because a metrics_url aimed at the wrong thing (a
# Prometheus /federate, a log endpoint) would otherwise pull an unbounded body
# into a long-lived daemon's memory before any whitelist could shrink it.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_RECV_CHUNK_BYTES = 64 * 1024

# Defensive bound on the number of distinct model groups. One inference server
# serves one model, so this is ~50x headroom; it only exists so a metrics_url
# pointed at an aggregating proxy or a federated Prometheus cannot turn one tick
# into thousands of rows.
_MAX_MODELS = 50

# The vocabulary of the optional "read_warnings" payload key. Each value means
# "this tick is NOT a clean, complete snapshot of one local inference server", so
# the server must not treat models[] as authoritative -- above all it must not
# vanish-prune the model rows that are missing from it. ONE key carrying an
# enum-like list rather than a boolean per cause: the server's rule is identical
# for all of them, and a new cause then costs no new contract surface.
_WARN_FOREIGN_LABELS = "foreign_labels"
_WARN_MODELS_CAPPED = "models_capped"
_WARN_BODY_TRUNCATED = "body_truncated"
_WARN_INVALID_VALUES = "invalid_values"
_WARN_UNLABELLED_SERIES = "unlabelled_series"

# The closed set both collectors' contract fixtures assert against.
WARNING_VOCABULARY = frozenset(
    {
        _WARN_FOREIGN_LABELS,
        _WARN_MODELS_CAPPED,
        _WARN_BODY_TRUNCATED,
        _WARN_INVALID_VALUES,
        _WARN_UNLABELLED_SERIES,
    }
)

# The closed set of error_type values the reachable:false envelope can carry.
ERROR_TYPES = frozenset(
    {"connection_refused", "timeout", "tls_error", "auth_failed", "http_error"}
)

# Prometheus label matcher: name="value" pairs, honouring backslash escapes in
# the value so a stray quote does not truncate the scan.
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')


def sum_values(values):
    """Total a metric across its remaining label dimensions.

    The right reduction for cumulative counters and histogram totals: tokens
    generated across every engine, requests finished across every
    finished_reason, seconds observed across every tensor-parallel rank.
    """
    return float(sum(values))


def max_value(values):
    """Peak across the remaining label dimensions.

    The right reduction for a 0-1 saturation FRACTION -- summing the KV-cache
    usage of 8 engines at 0.5 each would ship 4.0, which the server renders as
    400% -- and for any gauge an engine REPLICATES rather than partitions:
    SGLang stamps the same scheduler-level queue depth and throughput on every
    tp_rank series, so summing would multiply them by the TP degree. The max is
    the most-saturated / highest-reading rank, it can never double-count, and it
    keeps the 0-1 range invariant the contract promises for fractions. Where the
    dimension is absent (the common single-rank, single-engine deployment) max
    is identity, so the value still ships verbatim.
    """
    return float(max(values))


class ExpositionSpec:
    """One inference engine's whitelist: everything vllm.py and sglang.py differ by.

    Args:
        product: display name used in the operator-facing log lines.
        model_label: the exposition label whose value keys each models[] entry.
        reducible_labels: the OTHER label dimensions this engine legitimately
            emits on a whitelisted metric. Folding these away is the documented
            reduction; any label OUTSIDE this set (and the model label) is the
            tell that the endpoint is not one local engine -- a Prometheus, a
            federation or a scrape proxy stamps "instance" / "job" / "pod" --
            and trips _WARN_FOREIGN_LABELS.
        gauges / counters: ``(payload key, source names newest-first, reducer,
            cast)`` tuples.
        histograms: ``(payload key prefix, base names newest-first)`` tuples,
            read as their cumulative ``_sum`` / ``_count`` pair only.
    """

    def __init__(
        self,
        product,
        model_label,
        reducible_labels,
        gauges,
        counters,
        histograms,
    ):
        self.product = product
        self.model_label = model_label
        self.reducible_labels = frozenset(reducible_labels)
        self.gauges = tuple(gauges)
        self.counters = tuple(counters)
        self.histograms = tuple(histograms)
        # Only these exact sample names are retained while scanning the
        # exposition; everything else is discarded, so a multi-hundred-KB
        # /metrics body never builds a giant dict. Histograms contribute their
        # _sum / _count names only (their _bucket series, by far the bulk of
        # such a body, are skipped).
        self.names_of_interest = frozenset(
            [
                name
                for _key, names, _reduce, _cast in self.gauges + self.counters
                for name in names
            ]
            + [
                base + suffix
                for _prefix, bases in self.histograms
                for base in bases
                for suffix in ("_sum", "_count")
            ]
        )


def collect(
    spec,
    metrics_url,
    auth_header_name=None,
    auth_header_value=None,
    verify_ssl=True,
):
    """Poll one inference server's /metrics endpoint and return its health object.

    Args:
        spec: the engine's ExpositionSpec (its whitelist and label dimensions).
        metrics_url: full URL of the engine's Prometheus endpoint (its API
            server port, ``/metrics``).
        auth_header_name / auth_header_value: an optional custom auth header
            (both must be set to take effect). Covers api-key deployments
            (``Authorization: Bearer <key>``) and any front proxy.
        verify_ssl: verify the server certificate for ``https`` URLs.

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
        text, truncated = _read_body(spec, response)
    except Exception as e:
        return _unreachable(e)
    finally:
        response.close()

    # A 2xx is in hand: the engine answered, so reachable is now locked True no
    # matter what parsing does below (sharp edge #1). A parse bug degrades to an
    # empty models list, it never pages the customer.
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
        return _build_payload(spec, text)
    except Exception as e:
        log(f"{spec.product} parse error (staying reachable): {e}", "error")
        return {"reachable": True, "models": []}


def _read_body(spec, response):
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
            log(
                f"{spec.product} /metrics read exceeded the {_TIMEOUT}s deadline",
                "error",
            )
            return "", True
        if not chunk:
            continue
        chunks += chunk
        if len(chunks) > _MAX_RESPONSE_BYTES:
            log(
                f"{spec.product} /metrics body exceeded {_MAX_RESPONSE_BYTES} "
                f"bytes -- is metrics_url pointed at a {spec.product} server?",
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


def _build_payload(spec, text):
    """Parse a 2xx /metrics body into the reachable health payload."""
    grouped, warnings = _parse_exposition(spec, text)
    payload = {
        "reachable": True,
        "models": [
            _model_entry(spec, name, samples, warnings)
            for name, samples in sorted(grouped.items())
        ],
    }
    if warnings:
        payload["read_warnings"] = sorted(warnings)
    return payload


# --- text exposition parsing ----------------------------------------------


def _parse_exposition(spec, text):
    """Scan a Prometheus text-exposition body into per-model sample values.

    Returns ``(grouped, warnings)`` where ``grouped`` maps each model label value
    to ``{sample_name: [value, ...]}`` -- one list entry per remaining label
    series, for the field reducer to fold -- and ``warnings`` is the set of
    ``_WARN_*`` reasons this read is not a clean single-engine snapshot
    (_MAX_MODELS reached, first-seen models winning; or a foreign label
    dimension seen).

    Series carrying no model label are dropped: the contract keys every entry by
    model and we will not invent a name for an unattributable series. A body
    where that leaves nothing still ships reachable with ``models: []``.
    """
    grouped = {}
    warnings = set()
    foreign = set()
    for line in text.splitlines():
        parsed = _parse_metric_line(line)
        if parsed is None:
            continue
        name, labels, value = parsed
        if value is None or name not in spec.names_of_interest:
            continue
        # Every quantity in this payload -- a queue count, a cumulative counter,
        # a seconds sum, a 0-1 fraction, a tokens/s rate -- is non-negative by
        # definition, so a negative sample means the body is lying. Drop it here
        # rather than let int() truncate it toward a believable 0 (the wireguard
        # lesson: a negative age is null, NEVER 0) or let it quietly shrink a
        # sum -- and WARN (_WARN_INVALID_VALUES, shared with the non-integral
        # rejection in _put), because a silent drop would still hand the server
        # a believable snapshot -- and a model whose every series is negative
        # would vanish from models[] with nothing saying why. NaN / +Inf are
        # deliberately NOT warned: Prometheus uses NaN as a legitimate "no
        # observations yet", so flagging it would fire on every idle server.
        if value < 0:
            warnings.add(_WARN_INVALID_VALUES)
            continue
        model = labels.get(spec.model_label)
        if not model:
            # A whitelisted sample with no model label is an anomaly, not noise:
            # either something stripped the label or upstream renamed it. We
            # still refuse to invent a name, but dropping it SILENTLY would
            # rebuild the exact vanish-prune this warning set exists to prevent
            # -- an upstream rename of the model label would otherwise blind
            # every host at once with an innocent-looking empty models list.
            warnings.add(_WARN_UNLABELLED_SERIES)
            continue
        foreign.update(set(labels) - spec.reducible_labels - {spec.model_label})
        samples = grouped.get(model)
        if samples is None:
            if len(grouped) >= _MAX_MODELS:
                warnings.add(_WARN_MODELS_CAPPED)
                continue
            samples = grouped[model] = {}
        samples.setdefault(name, []).append(value)
    if foreign:
        log(
            f"{spec.product} exposition carries labels a single {spec.product} "
            f"does not emit ({', '.join(sorted(foreign))}) -- is metrics_url "
            f"pointed at a Prometheus or a scrape proxy rather than the "
            f"{spec.product} API server?",
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


def _model_entry(spec, name, samples, warnings):
    """Build one models[] entry from a model's whitelisted sample values."""
    entry = {"name": name}
    for key, source_names, reduce_fn, cast in spec.gauges + spec.counters:
        value = _reduce_first_present(samples, source_names, reduce_fn)
        _put(entry, key, value, cast, warnings)
    for prefix, base_names in spec.histograms:
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
    """Total one sample name across its label series, or None when absent.

    Histogram halves are cumulative counters on every engine, so they SUM across
    the remaining dimensions regardless of how that engine's gauges reduce.
    """
    values = samples.get(name)
    if not values:
        return None
    return sum_values(values)


def _put(entry, key, value, cast, warnings):
    """Set ``entry[key]`` to ``cast(value)`` unless value is None.

    Omit-not-zero: a metric absent from the exposition leaves its key out, which
    the server reads as no-data. A present-but-zero metric ships its 0.

    An integer field given a non-integral value is REJECTED, not floored: a
    request queue of 0.9 is not a queue of 0, and silently flooring it would
    ship the same believable lie the negative check exists to stop. Neither
    engine emits a fractional count -- an averaging proxy in front of it does --
    so the value is dropped and the read is flagged.
    """
    if value is None:
        return
    if cast is int and float(value) != int(value):
        warnings.add(_WARN_INVALID_VALUES)
        return
    entry[key] = cast(value)
