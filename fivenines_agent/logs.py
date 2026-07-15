"""Incident log capture (Brique A): retroactive journald slice -> enriched digest.

The LogUploader thread calls build_capture_bundle(job) per capture command. It
runs a bounded `journalctl` slice (WITH a subprocess timeout - a wedged journalctl
would otherwise hang the worker - and get_clean_env() to avoid the PyInstaller
LD_LIBRARY_PATH conflicts), then turns it into an LLM-oriented enriched digest:
per-severity counts plus, per error fingerprint, a redacted representative excerpt.

V1 posture is "digest": raw lines never leave the box, only redacted excerpts.
Raw opt-in is a follow-up. Redaction is best-effort (it will miss novel secret
formats); the digest default is the mitigation.

    journalctl -u <unit> --since @<epoch> -o json   (timeout, clean env)
          |  entries [{priority, message}]
          v
    build_digest: counts by severity + group by fingerprint(masked) + redact excerpt
          |
          v
    bundle {capture_id (ack), unit, posture, truncated, redaction, digest, raw=None}
"""

import hashlib
import json
import re
import subprocess
import time

from fivenines_agent.debug import log
from fivenines_agent.subprocess_utils import get_clean_env

_CAPTURE_TIMEOUT = 30  # seconds; matches packages.py (timeout-the-data-path)
_DEFAULT_LINES = 1000
_MAX_FINGERPRINTS = 50
_MAX_EXCERPT = 500
REDACTION_VERSION = 1

_SEVERITY_RANK = {"info": 0, "warn": 1, "error": 2}

# Best-effort secret/PII redaction. Order matters: structured secrets before the
# generic key=value rule. Documented as best-effort - it WILL miss novel formats.
_REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "[REDACTED_JWT]",
    ),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"), "Bearer [REDACTED]"),
    # password inside a connection string user:pass@host
    (re.compile(r"(\w+://[^:@\s/]+:)[^@\s/]+(@)"), r"\1[REDACTED]\2"),
    # generic secret assignment: key=value / key: value
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|"
            r"access[_-]?key|authorization)\b\s*[=:]\s*\"?'?[^\s\"']+"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
        "[REDACTED_EMAIL]",
    ),
]

# Fingerprint masking: collapse volatile tokens so the same error template hashes
# to one fingerprint regardless of ids/numbers. Order: structured before numbers.
_MASKS = [
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<UUID>",
    ),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    # IPv6: >=3 colon-separated hex groups (a HH:MM:SS time has only 2 colons,
    # so it is not matched here; its digits collapse via the \d+ rule below).
    (re.compile(r"(?:[0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F]{0,4}"), "<IP>"),
    (re.compile(r"0x[0-9a-fA-F]+"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HEX>"),
    # base64 / opaque token: >=20 base64 chars containing at least one digit.
    # The digit lookahead skips long plain-letter identifiers (class names,
    # method paths) so distinct errors are not over-collapsed into one fp.
    (re.compile(r"(?=[A-Za-z0-9+/]*\d)[A-Za-z0-9+/]{20,}={0,2}"), "<B64>"),
    # Any digit run, even when glued to a unit (30s, 5ms), so the same error
    # template collapses to one fingerprint regardless of the number.
    (re.compile(r"\d+"), "<N>"),
]


def redact(text):
    """Best-effort secret/PII redaction on a single log line."""
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def fingerprint(message):
    """Stable fingerprint of an error template (volatile tokens masked, then hashed)."""
    masked = message
    for pattern, repl in _MASKS:
        masked = pattern.sub(repl, masked)
    return hashlib.sha256(masked.encode("utf-8")).hexdigest()[:12]


def severity_from_priority(priority):
    """Map a journald PRIORITY (0-7, may be a string) to error/warn/info."""
    try:
        p = int(priority)
    except (TypeError, ValueError):
        return "info"
    if p <= 3:
        return "error"
    if p == 4:
        return "warn"
    return "info"


def build_digest(entries):
    """Turn journal entries into the enriched digest. Returns (digest, truncated)."""
    counts = {"error": 0, "warn": 0, "info": 0}
    groups = {}
    order = []
    for e in entries:
        sev = severity_from_priority(e.get("priority"))
        counts[sev] += 1
        message = e.get("message") or ""
        fp = fingerprint(message)
        group = groups.get(fp)
        if group is None:
            groups[fp] = {"count": 1, "severity": sev, "message": message}
            order.append(fp)
        else:
            group["count"] += 1
            if _SEVERITY_RANK[sev] > _SEVERITY_RANK[group["severity"]]:
                group["severity"] = sev
    ranked = sorted(order, key=lambda fp: groups[fp]["count"], reverse=True)
    truncated = len(ranked) > _MAX_FINGERPRINTS
    fingerprints = [
        {
            "fp": fp,
            "count": groups[fp]["count"],
            "severity": groups[fp]["severity"],
            "excerpt": redact(groups[fp]["message"])[:_MAX_EXCERPT],
        }
        for fp in ranked[:_MAX_FINGERPRINTS]
    ]
    return {"counts": counts, "fingerprints": fingerprints}, truncated


def _since_arg(since):
    """journalctl --since value: epoch seconds become @<epoch>, else passed through."""
    if isinstance(since, bool):
        return None
    if isinstance(since, (int, float)):
        return f"@{int(since)}"
    if isinstance(since, str) and since:
        return since
    return None


def _capture_entries(unit, since, lines, timeout=_CAPTURE_TIMEOUT):
    """Run a bounded journalctl slice. Returns a list of entries on success
    (possibly empty), or None on failure (timeout / non-zero exit / error)."""
    cmd = ["journalctl", "-u", str(unit), "-o", "json", "-n", str(int(lines))]
    since_arg = _since_arg(since)
    if since_arg is not None:
        cmd += ["--since", since_arg]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=get_clean_env()
        )
    except subprocess.TimeoutExpired:
        log(f"journalctl capture timed out for {unit!r}", "error")
        return None
    except Exception as e:
        log(f"journalctl capture failed for {unit!r}: {e}", "error")
        return None
    if result.returncode != 0:
        log(f"journalctl capture rc={result.returncode}: {result.stderr}", "error")
        return None
    entries = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        message = obj.get("MESSAGE")
        if isinstance(message, list):
            # journald emits non-UTF8 payloads as byte arrays; decode them
            # (same handling as the systemd collector's journal tail) rather
            # than dropping the entry.
            try:
                message = bytes(message).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                continue
        if not isinstance(message, str) or not message:
            continue
        entries.append({"priority": obj.get("PRIORITY"), "message": message})
    return entries


def build_capture_bundle(job, _entries_fn=_capture_entries):
    """Build the /logs bundle for one capture job, or None to skip.

    Returns None only on capture FAILURE (timeout/error), so the backend re-issues
    after expiry. An empty journal window still returns a bundle (with an empty
    digest) so the capture_id ack closes the loop.
    """
    unit = job.get("unit")
    entries = _entries_fn(unit, job.get("since"), job.get("lines") or _DEFAULT_LINES)
    if entries is None:
        log(f"build_capture_bundle: capture failed for {unit!r}, no bundle", "error")
        return None
    digest, truncated = build_digest(entries)
    return {
        "capture_id": job.get("capture_id"),
        "unit": unit,
        "since": job.get("since"),
        "posture": "digest",
        "truncated": truncated,
        "redaction": {
            "version": REDACTION_VERSION,
            "applied": True,
            "best_effort": True,
        },
        "digest": digest,
        "raw": None,
    }


# --- Brique C: continuous per-tick log signals (error/warn rate + fingerprints) ---

_SIGNAL_LINES = 5000  # upper bound of journal entries scanned per unit per tick
_SIGNAL_TIMEOUT = 5  # signals scan a small window; short timeout avoids the
# watchdog risk of N units x 30s on the collection loop at a low incident interval.
_TOP_FINGERPRINTS = 20


def _signals_for_unit(entries):
    """error/warn rate + top redacted fingerprints for one unit's window."""
    counts = {"error": 0, "warn": 0}
    groups = {}
    order = []
    for e in entries:
        sev = severity_from_priority(e.get("priority"))
        if sev not in counts:
            continue  # signals track error/warn only; info is dropped for size
        counts[sev] += 1
        message = e.get("message") or ""
        fp = fingerprint(message)
        group = groups.get(fp)
        if group is None:
            groups[fp] = {"count": 1, "severity": sev, "message": message}
            order.append(fp)
        else:
            group["count"] += 1
            if _SEVERITY_RANK[sev] > _SEVERITY_RANK[group["severity"]]:
                group["severity"] = sev
    ranked = sorted(order, key=lambda fp: groups[fp]["count"], reverse=True)
    return {
        "error_rate": counts["error"],
        "warn_rate": counts["warn"],
        "fingerprints": [
            {
                "fp": fp,
                "count": groups[fp]["count"],
                "severity": groups[fp]["severity"],
                "sample": redact(groups[fp]["message"])[:_MAX_EXCERPT],
            }
            for fp in ranked[:_TOP_FINGERPRINTS]
        ],
    }


def collect_log_signals(
    units=None,
    signal_interval_s=None,
    enabled=True,
    _entries_fn=_capture_entries,
    _now=time.time,
    **kwargs,
):
    """Brique C: per-tick, per-unit error/warn rates + top fingerprints.

    Stateless on purpose: it reports the fingerprints + counts for the last
    window; the backend derives new-vs-recurring from its own cross-tick history
    (the agent stays dumb). Each unit is isolated so one bad unit never blanks the
    others (registry-collector-needs-per-item-isolation).
    """
    window = signal_interval_s
    if isinstance(window, bool) or not isinstance(window, (int, float)) or window <= 0:
        window = 60
    if not enabled:
        return {"window_s": window, "units": {}}
    since = int(_now()) - int(window)
    result = {"window_s": window, "units": {}}
    for unit in units or []:
        try:
            entries = _entries_fn(unit, since, _SIGNAL_LINES, _SIGNAL_TIMEOUT)
            if entries is None:
                continue  # capture failed for this unit; skip, others still run
            result["units"][unit] = _signals_for_unit(entries)
        except Exception as e:
            log(f"log signals failed for {unit!r}: {e}", "error")
    return result
