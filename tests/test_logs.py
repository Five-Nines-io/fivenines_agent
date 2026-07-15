"""Tests for Brique A: incident journald capture -> enriched digest.

Pure helpers (redact, fingerprint, severity, build_digest) are tested directly;
_capture_entries mocks subprocess.run; build_capture_bundle injects the entries
seam. No real journald is touched.
"""

import json
from unittest.mock import MagicMock, patch

from fivenines_agent import logs
from fivenines_agent.logs import (
    build_capture_bundle,
    build_digest,
    fingerprint,
    redact,
    severity_from_priority,
)

# --- redact (best-effort secret/PII) ---


def test_redact_jwt():
    out = redact("auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-DEF_123")
    assert "eyJ" not in out and "[REDACTED_JWT]" in out


def test_redact_bearer_token():
    out = redact("Authorization: Bearer sk-aBc123XyZ.tok_456")
    assert "sk-aBc123XyZ" not in out and "[REDACTED]" in out


def test_redact_connection_string_password():
    out = redact("dsn=postgres://app:s3cr3tPass@db.host:5432/main")
    assert "s3cr3tPass" not in out and "[REDACTED]" in out


def test_redact_generic_secret_assignment():
    assert "hunter2" not in redact("password: hunter2")
    assert "tok_abc" not in redact("api_key=tok_abc")


def test_redact_email():
    out = redact("user alice.smith@example.com failed")
    assert "alice.smith@example.com" not in out and "[REDACTED_EMAIL]" in out


def test_redact_aws_key_and_private_key():
    assert "AKIA" not in redact("key AKIAIOSFODNN7EXAMPLE here")
    out = redact("-----BEGIN RSA PRIVATE KEY-----")
    assert "[REDACTED_PRIVATE_KEY]" in out and "BEGIN" not in out


def test_redact_leaves_plain_text_untouched():
    assert redact("connection refused on socket") == "connection refused on socket"


# --- fingerprint ---


def test_fingerprint_same_template_different_numbers_collapses():
    assert fingerprint("timeout after 30s on conn 5") == fingerprint(
        "timeout after 900s on conn 42"
    )


def test_fingerprint_masks_uuid_and_ip():
    a = fingerprint("user 550e8400-e29b-41d4-a716-446655440000 from 10.0.0.1")
    b = fingerprint("user 550e8400-e29b-41d4-a716-446655449999 from 192.168.1.9")
    assert a == b


def test_fingerprint_masks_ipv6():
    a = fingerprint("peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 closed")
    b = fingerprint("peer fe80:0000:0000:0000:0202:b3ff:fe1e:8329 closed")
    assert a == b


def test_fingerprint_masks_base64_token():
    a = fingerprint("auth token c3VwZXJzZWNyZXQ1MjM0NXZhbHVl rejected")
    b = fingerprint("auth token aGVsbG93b3JsZDk5OTl0b2tlbnh5 rejected")
    assert a == b


def test_fingerprint_keeps_plain_letter_identifiers_distinct():
    # No digit -> not masked as base64, so distinct long identifiers stay distinct
    # (guards against over-collapsing different errors into one fingerprint).
    a = fingerprint("NullPointerException in OrderServiceHandlerFactory")
    b = fingerprint("NullPointerException in PaymentGatewayDispatcher")
    assert a != b


def test_fingerprint_collapses_timestamps_via_digits():
    a = fingerprint("request at 12:34:56 failed")
    b = fingerprint("request at 01:02:03 failed")
    assert a == b


def test_fingerprint_different_template_differs():
    assert fingerprint("disk full") != fingerprint("connection refused")


def test_fingerprint_is_deterministic_short_hash():
    fp = fingerprint("oom killed pid 1234")
    assert fp == fingerprint("oom killed pid 9999")
    assert len(fp) == 12


# --- severity_from_priority ---


def test_severity_mapping():
    assert severity_from_priority("0") == "error"
    assert severity_from_priority(3) == "error"
    assert severity_from_priority("4") == "warn"
    assert severity_from_priority("6") == "info"
    assert severity_from_priority(None) == "info"
    assert severity_from_priority("not-a-number") == "info"


# --- build_digest ---


def test_build_digest_counts_and_groups():
    entries = [
        {"priority": "3", "message": "timeout after 1s"},
        {"priority": "3", "message": "timeout after 9s"},  # same fp as above
        {"priority": "4", "message": "cache miss"},
        {"priority": "6", "message": "started ok"},
    ]
    digest, truncated = build_digest(entries)
    assert truncated is False
    assert digest["counts"] == {"error": 2, "warn": 1, "info": 1}
    timeout_fp = [f for f in digest["fingerprints"] if f["count"] == 2][0]
    assert timeout_fp["severity"] == "error"
    assert timeout_fp["count"] == 2


def test_build_digest_excerpt_is_redacted():
    entries = [{"priority": "3", "message": "login token=sk_live_999 rejected"}]
    digest, _ = build_digest(entries)
    assert "sk_live_999" not in digest["fingerprints"][0]["excerpt"]


def test_build_digest_severity_escalates_within_group():
    # Same template seen first as warn (4) then error (3) -> group labelled error.
    entries = [
        {"priority": "4", "message": "db slow on shard 1"},
        {"priority": "3", "message": "db slow on shard 2"},
    ]
    digest, _ = build_digest(entries)
    assert digest["fingerprints"][0]["severity"] == "error"
    assert digest["fingerprints"][0]["count"] == 2


def test_build_digest_truncates_above_cap():
    entries = [
        {"priority": "3", "message": f"distinct error {chr(65 + i)}"} for i in range(60)
    ]
    digest, truncated = build_digest(entries)
    assert truncated is True
    assert len(digest["fingerprints"]) == logs._MAX_FINGERPRINTS


def test_build_digest_empty():
    digest, truncated = build_digest([])
    assert truncated is False
    assert digest == {"counts": {"error": 0, "warn": 0, "info": 0}, "fingerprints": []}


# --- _capture_entries (subprocess seam) ---


def _result(returncode=0, stdout="", stderr=""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


def test_capture_entries_parses_json_skips_garbage():
    stdout = "\n".join(
        [
            json.dumps({"PRIORITY": "3", "MESSAGE": "boom"}),
            "",  # blank
            "not json",  # bad
            json.dumps(["array", "not", "dict"]),  # non-dict
            # binary MESSAGE (byte array): decoded, not dropped (mirrors the
            # systemd collector's journal-tail handling)
            json.dumps({"PRIORITY": "6", "MESSAGE": [104, 105]}),
            json.dumps({"PRIORITY": "6", "MESSAGE": [999999]}),  # undecodable
            json.dumps({"PRIORITY": "6", "MESSAGE": ""}),  # empty: skipped
            json.dumps({"PRIORITY": "4", "MESSAGE": "warn here"}),
        ]
    )
    with patch.object(
        logs.subprocess, "run", return_value=_result(stdout=stdout)
    ) as run:
        entries = logs._capture_entries("nginx.service", 1000, 500)
    assert entries == [
        {"priority": "3", "message": "boom"},
        {"priority": "6", "message": "hi"},
        {"priority": "4", "message": "warn here"},
    ]
    # timeout + clean env are passed (the two learnings).
    _, kwargs = run.call_args
    assert kwargs["timeout"] == logs._CAPTURE_TIMEOUT
    assert "env" in kwargs


def test_capture_entries_since_epoch_becomes_at_arg():
    with patch.object(logs.subprocess, "run", return_value=_result(stdout="")) as run:
        logs._capture_entries("u", 1700000000, 100)
    cmd = run.call_args[0][0]
    assert "--since" in cmd and "@1700000000" in cmd


def test_capture_entries_since_string_passthrough_and_bool_ignored():
    with patch.object(logs.subprocess, "run", return_value=_result(stdout="")) as run:
        logs._capture_entries("u", "2 hours ago", 100)
    assert "2 hours ago" in run.call_args[0][0]
    with patch.object(logs.subprocess, "run", return_value=_result(stdout="")) as run:
        logs._capture_entries("u", True, 100)
    assert "--since" not in run.call_args[0][0]


def test_capture_entries_timeout_returns_none():
    import subprocess as _sp

    with patch.object(
        logs.subprocess, "run", side_effect=_sp.TimeoutExpired("journalctl", 30)
    ):
        assert logs._capture_entries("u", None, 100) is None


def test_capture_entries_nonzero_exit_returns_none():
    with patch.object(
        logs.subprocess, "run", return_value=_result(returncode=1, stderr="nope")
    ):
        assert logs._capture_entries("u", None, 100) is None


def test_capture_entries_generic_exception_returns_none():
    with patch.object(logs.subprocess, "run", side_effect=OSError("boom")):
        assert logs._capture_entries("u", None, 100) is None


# --- build_capture_bundle ---


def test_bundle_none_when_capture_fails():
    assert (
        build_capture_bundle(
            {"capture_id": "x", "unit": "u"}, _entries_fn=lambda *a: None
        )
        is None
    )


def test_bundle_empty_window_still_acks():
    bundle = build_capture_bundle(
        {"capture_id": "cap-1", "unit": "nginx.service", "since": 1000},
        _entries_fn=lambda *a: [],
    )
    assert bundle["capture_id"] == "cap-1"
    assert bundle["posture"] == "digest"
    assert bundle["raw"] is None
    assert bundle["truncated"] is False
    assert bundle["digest"]["counts"] == {"error": 0, "warn": 0, "info": 0}
    assert bundle["redaction"] == {"version": 1, "applied": True, "best_effort": True}


def test_bundle_with_entries_builds_digest():
    entries = [{"priority": "3", "message": "kernel panic"}]
    bundle = build_capture_bundle(
        {"capture_id": "cap-2", "unit": "u"}, _entries_fn=lambda *a: entries
    )
    assert bundle["digest"]["counts"]["error"] == 1
    assert bundle["digest"]["fingerprints"][0]["severity"] == "error"
    assert bundle["truncated"] is False
