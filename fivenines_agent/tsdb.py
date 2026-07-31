"""TSDB (Prometheus / VictoriaMetrics) server-health collector (server #672).

"Who watches the watcher": a customer's Prometheus or VictoriaMetrics server is
the thing scraping every OTHER target, so when it dies the whole observability
stack goes dark silently -- no target reports the outage because the collector
of outages is the collector that is down. This collector polls that TSDB and
ships one health object under ``data["tsdb"]``; the server turns it into a
``tsdb_status`` axis, a ``prometheus_targets_down`` trigger, and VictoriaMetrics
series.

Pattern: ``caddy.py`` (a local HTTP admin/scrape endpoint) crossed with
``postgresql.py`` (a reachability envelope). It is config-driven with no OS gate
and no capability probe -- the nginx / apache / php_fpm posture -- because it is
pure HTTP and works on every platform.

Reachability contract (the ``postgresql.py`` posture, NOT the php_fpm null one):
here UNREACHABLE IS THE SIGNAL, so it must ride the payload as
``{"reachable": false, ...}`` and MUST NEVER collapse to ``None`` (which the
server would read as "collector disabled / no data" rather than "the TSDB is
down"). A healthy tick is ``{"reachable": true, "flavor": ..., ...}``.

THE SHARP EDGE -- reachability means "the TSDB answered ``/metrics``", nothing
more. A 2xx on ``/metrics`` with a body we can feed to the parser yields
``reachable: true`` EVEN IF every whitelisted metric is missing, the flavor is
unrecognisable, or the follow-up ``/api/v1/targets`` call fails (an agent-mode
Prometheus, a locked-down API). Only a connection-level failure on ``/metrics``
itself -- refused / timeout / TLS / auth / non-2xx -- produces
``reachable: false``. An agent-side parse bug must never page a customer with
"your Prometheus is down", so once a 2xx is in hand nothing below can flip the
verdict.

Counter discipline (the #97 lesson): every ``*_total`` field is a RAW cumulative
counter shipped as-is -- the server ``rate()``s them; we never diff or reset
them agent-side. Whitelisted names are summed across their label series; a name
absent from the exposition OMITS its payload key (the server treats a missing
key as no-data) -- we never fabricate a ``0``.
"""

import math
import re

import requests

from fivenines_agent.debug import debug, log

# Shared transport timeout (seconds), matching caddy.py / apache.py. A wedged
# TSDB must never hang the whole collect tick.
_TIMEOUT = 5

# The exact source metric names we read out of the text exposition, by flavor.
# Pinned byte-for-byte against the contract fixture -- a rename upstream shows up
# as a silently-omitted payload key, so these are the single source of truth for
# both the parser and the fixture. Every "*_total" is a raw cumulative counter.
#
# Prometheus self-metrics:
_PROM_HEAD_SERIES = "prometheus_tsdb_head_series"
_PROM_STORAGE_BYTES = "prometheus_tsdb_storage_blocks_bytes"
_PROM_RULE_FAILURES = "prometheus_rule_evaluation_failures_total"
_PROM_NOTIF_DROPPED = "prometheus_notifications_dropped_total"
_PROM_WAL_CORRUPTIONS = "prometheus_tsdb_wal_corruptions_total"
_PROM_BUILD_INFO = "prometheus_build_info"
# VictoriaMetrics self-metrics:
_VM_FREE_DISK = "vm_free_disk_space_bytes"
_VM_DATA_SIZE = "vm_data_size_bytes"
_VM_SLOW_INSERTS = "vm_slow_row_inserts_total"
_VM_ROWS_IGNORED = "vm_rows_ignored_total"
_VM_NEW_SERIES = "vm_new_timeseries_created_total"
_VM_CACHE_ENTRIES = "vm_cache_entries"
_VM_APP_VERSION = "vm_app_version"

# The documented VictoriaMetrics proxy for "active series": the count of hourly
# metric ids held in the storage cache. It is a single label series of the
# multi-series vm_cache_entries gauge, so it needs a label filter, not a sum.
_VM_ACTIVE_SERIES_TYPE = "storage/hour_metric_ids"

# Only these names are retained while scanning the exposition (everything else is
# counted for flavor detection then discarded), so a multi-hundred-KB /metrics
# body never builds a giant dict.
_NAMES_OF_INTEREST = frozenset(
    {
        _PROM_HEAD_SERIES,
        _PROM_STORAGE_BYTES,
        _PROM_RULE_FAILURES,
        _PROM_NOTIF_DROPPED,
        _PROM_WAL_CORRUPTIONS,
        _PROM_BUILD_INFO,
        _VM_FREE_DISK,
        _VM_DATA_SIZE,
        _VM_SLOW_INSERTS,
        _VM_ROWS_IGNORED,
        _VM_NEW_SERIES,
        _VM_CACHE_ENTRIES,
        _VM_APP_VERSION,
    }
)

# Prometheus label matcher: name="value" pairs, honouring backslash escapes in
# the value so a stray quote does not truncate the scan. We only ever read the
# version / short_version / type labels, none of which carry escapes in practice.
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"')


@debug("tsdb_metrics")
def tsdb_metrics(
    url="http://127.0.0.1:9090",
    auth_header_name=None,
    auth_header_value=None,
    basic_auth_username=None,
    basic_auth_password=None,
    verify_ssl=True,
    **_kwargs,
):
    """Poll a Prometheus / VictoriaMetrics server and return its health object.

    Args:
        url: base URL of the TSDB (e.g. ``http://127.0.0.1:9090``).
        auth_header_name / auth_header_value: an optional custom auth header
            (both must be set to take effect). Mirrors the node_exporter pull
            config so the server reuses one settings shape.
        basic_auth_username / basic_auth_password: optional HTTP Basic auth.
        verify_ssl: verify the server certificate for ``https`` URLs.
        **_kwargs: forward-compatible with the backend pushing config keys the
            agent does not yet know.

    Returns:
        dict: ``{"reachable": True, "flavor": ..., "version": ..., <metrics>}``
        on a 2xx ``/metrics``; ``{"reachable": False, "error_type": ...,
        "error_message": ...}`` on any connection-level failure. Never ``None``:
        unreachable is the signal and must ride the payload.
    """
    # Request setup and the /metrics probe share one try: a connection-level
    # failure here (and ONLY here) is what "unreachable" means. The setup lives
    # inside it too so that even a pathological config -- a non-string url from a
    # malformed server push, say -- yields a reachable:false envelope rather than
    # raising into a None (which the server would misread as "collector
    # disabled"). str() coercion routes a bad url through requests' own URL
    # validation into that same envelope.
    try:
        base = str(url or "").rstrip("/")
        headers = {}
        if auth_header_name and auth_header_value:
            headers[auth_header_name] = auth_header_value
        auth = None
        if basic_auth_username:
            auth = (basic_auth_username, basic_auth_password or "")

        def get(path):
            return requests.get(
                base + path,
                headers=headers,
                auth=auth,
                timeout=_TIMEOUT,
                verify=verify_ssl,
            )

        response = get("/metrics")
    except Exception as e:
        return _unreachable(e)

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

    # A 2xx is in hand: the TSDB answered, so reachable is now locked True no
    # matter what parsing or the targets probe do below (the sharp edge). A
    # parse bug degrades to a bare reachable payload, it never pages the customer.
    try:
        return _build_payload(response.text, get)
    except Exception as e:
        log(f"TSDB parse error (staying reachable): {e}", "error")
        return {"reachable": True, "flavor": None, "version": None}


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


def _build_payload(text, get):
    """Parse a 2xx /metrics body into the reachable health payload."""
    samples, has_vm, has_prometheus = _parse_exposition(text)
    if has_vm:
        flavor = "victoriametrics"
    elif has_prometheus:
        flavor = "prometheus"
    else:
        # A 2xx body with neither namespace: still reachable (the sharp edge),
        # but we surface no fabricated flavor or metrics.
        flavor = None

    payload = {
        "reachable": True,
        "flavor": flavor,
        "version": _extract_version(samples, flavor),
    }

    if flavor == "victoriametrics":
        payload.update(_victoriametrics_metrics(samples))
    elif flavor == "prometheus":
        payload.update(_prometheus_metrics(samples))
        # Scrape-target health is a separate API call; a failure OMITS the keys
        # and leaves reachable True (locked-down / agent-mode Prometheus).
        targets = _fetch_targets(get)
        if targets is not None:
            payload["targets_total"], payload["targets_down"] = targets

    return payload


# --- text exposition parsing ----------------------------------------------


def _parse_exposition(text):
    """Scan a Prometheus text-exposition body.

    Returns ``(samples, has_vm, has_prometheus)`` where ``samples`` maps each
    name-of-interest to its list of ``(labels, value)`` series (so a caller can
    sum across labels or filter by one), and the two flags record whether any
    ``vm_*`` / ``prometheus_*`` metric was seen (the flavor sniff).
    """
    samples = {}
    has_vm = False
    has_prometheus = False
    for line in text.splitlines():
        parsed = _parse_metric_line(line)
        if parsed is None:
            continue
        name, labels, value = parsed
        if name.startswith("vm_"):
            has_vm = True
        elif name.startswith("prometheus_"):
            has_prometheus = True
        if name in _NAMES_OF_INTEREST:
            samples.setdefault(name, []).append((labels, value))
    return samples, has_vm, has_prometheus


def _parse_metric_line(line):
    """Parse one exposition line into ``(name, labels, value)`` or ``None``.

    ``value`` is a float, or ``None`` for NaN / +Inf / -Inf (which a sum skips).
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


# --- flavor-specific payload builders --------------------------------------


def _prometheus_metrics(samples):
    """Whitelisted Prometheus self-metrics; absent names omit their keys."""
    out = {}
    _put_int(out, "head_series", _sum(samples, _PROM_HEAD_SERIES))
    _put_int(out, "storage_bytes", _sum(samples, _PROM_STORAGE_BYTES))
    _put_int(out, "rule_eval_failures_total", _sum(samples, _PROM_RULE_FAILURES))
    _put_int(out, "notifications_dropped_total", _sum(samples, _PROM_NOTIF_DROPPED))
    _put_int(out, "wal_corruptions_total", _sum(samples, _PROM_WAL_CORRUPTIONS))
    return out


def _victoriametrics_metrics(samples):
    """Whitelisted VictoriaMetrics self-metrics; absent names omit their keys.

    No ``targets_*`` / rule keys: a single-node VM scrapes nothing.
    ``free_disk_space_bytes`` is the critical one -- VM rejects inserts once it
    drops below its threshold.
    """
    out = {}
    _put_int(out, "free_disk_space_bytes", _sum(samples, _VM_FREE_DISK))
    _put_int(out, "data_size_bytes", _sum(samples, _VM_DATA_SIZE))
    _put_int(out, "slow_inserts_total", _sum(samples, _VM_SLOW_INSERTS))
    _put_int(out, "rows_ignored_total", _sum(samples, _VM_ROWS_IGNORED))
    _put_int(out, "new_series_created_total", _sum(samples, _VM_NEW_SERIES))
    _put_int(
        out,
        "active_series",
        _filtered_sum(samples, _VM_CACHE_ENTRIES, "type", _VM_ACTIVE_SERIES_TYPE),
    )
    return out


def _extract_version(samples, flavor):
    """Read the server version from the flavor's build-info metric labels.

    Prometheus exposes ``prometheus_build_info{version="2.53.1"}``;
    VictoriaMetrics exposes ``vm_app_version{short_version="v1.102.0"}`` (a
    leading ``v`` is stripped so both flavors report bare semver). These labels
    ride the same ``/metrics`` scrape we already have, so no extra round-trip to
    ``/api/v1/status/buildinfo`` is needed. Returns None when unavailable.
    """
    if flavor == "prometheus":
        labels = _first_labels(samples, _PROM_BUILD_INFO)
        if labels:
            version = labels.get("version")
            if version:
                return version
    elif flavor == "victoriametrics":
        labels = _first_labels(samples, _VM_APP_VERSION)
        if labels:
            version = labels.get("short_version") or labels.get("version")
            if version:
                return version[1:] if version.startswith("v") else version
    return None


def _sum(samples, name):
    """Sum a metric across its label series, or None when absent from the body.

    Present-with-value-0 returns 0.0 (the key is emitted); genuinely absent
    returns None (the key is omitted). NaN / Inf series are skipped.
    """
    entries = samples.get(name)
    if not entries:
        return None
    total = 0.0
    for _labels, value in entries:
        if value is not None:
            total += value
    return total


def _filtered_sum(samples, name, label, expected):
    """Sum only the series of ``name`` whose ``label`` equals ``expected``.

    Returns None when the metric or the matching label series is absent, so the
    payload key is omitted rather than fabricated.
    """
    entries = samples.get(name)
    if not entries:
        return None
    matched = [
        value
        for labels, value in entries
        if value is not None and labels.get(label) == expected
    ]
    if not matched:
        return None
    return float(sum(matched))


def _first_labels(samples, name):
    """Return the label dict of the first series of ``name``, or None."""
    entries = samples.get(name)
    if entries:
        return entries[0][0]
    return None


def _put_int(out, key, value):
    """Set ``out[key]`` to ``int(value)`` unless value is None (omit-not-zero).

    Every whitelisted field is an integral quantity (a series count, a byte
    total, a cumulative counter), so the float sum is narrowed to int here.
    """
    if value is not None:
        out[key] = int(value)


# --- Prometheus scrape-target health ---------------------------------------


def _fetch_targets(get):
    """Return ``(targets_total, targets_down)`` from /api/v1/targets, or None.

    ANY failure (network, non-2xx, malformed JSON) returns None so the caller
    omits both keys while staying reachable -- a locked-down or agent-mode
    Prometheus that 403s the targets API must never read as "the TSDB is down".
    ``targets_down`` counts active targets whose health is anything but "up"
    (down / unknown).
    """
    try:
        response = get("/api/v1/targets")
        if not 200 <= response.status_code < 300:
            return None
        active = response.json().get("data", {}).get("activeTargets")
        if not isinstance(active, list):
            return None
        total = len(active)
        down = sum(1 for target in active if target.get("health") != "up")
        return total, down
    except Exception as e:
        log(f"TSDB targets probe failed (staying reachable): {e}", "debug")
        return None
