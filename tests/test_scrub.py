"""Tests for the shared wire/log sanitation helpers (proxmox + pbs)."""

from unittest.mock import patch

from fivenines_agent import scrub


def test_scrub_str():
    assert scrub.scrub_str(None) is None
    assert scrub.scrub_str("a\x00b") == "ab"
    assert scrub.scrub_str(42) == "42"
    assert "\ud800" not in scrub.scrub_str("x\ud800y")
    assert len(scrub.scrub_str("z" * 10_000)) == scrub.FIELD_MAX_LEN
    assert scrub.scrub_str("abc", max_len=2) == "ab"


def test_scrub_message_bounds_before_redacting():
    with patch.object(scrub, "redact", side_effect=lambda text: text) as redact:
        out = scrub.scrub_message("m" * 100_000)
    assert len(redact.call_args[0][0]) == scrub.ERROR_PRE_REDACT_MAX_LEN
    assert len(out) == scrub.ERROR_MAX_LEN
    assert scrub.scrub_message("secret=AKIAIOSFODNN7EXAMPLE") == "secret=[REDACTED]"


def test_log_safe():
    assert scrub.log_safe("a\nb\r\tc") == "a b  c"
    assert scrub.log_safe(RuntimeError("boom\x85x")) == "boom x"
    assert len(scrub.log_safe("a b " * 2000)) == scrub.ERROR_MAX_LEN
    # ASCII only, so print() cannot raise on a stdout of any encoding: a lone
    # surrogate (a JSON "\\udc80" escape) breaks UTF-8, and a Windows service's
    # stdout is the ANSI code page, which has no U+FFFD or CJK text.
    line = scrub.log_safe("\ud800 \ufffd \u5b58 \xe9")
    assert line == "\\ud800 \\ufffd \\u5b58 \\xe9"
    line.encode("ascii")
    assert len(scrub.log_safe("\u5b58" * 2000)) == scrub.ERROR_MAX_LEN


def test_as_int_and_as_bool():
    assert scrub.as_int(True) is None and scrub.as_int(None) is None
    assert scrub.as_int("12") == 12 and scrub.as_int(1.9) == 1
    assert scrub.as_int("x") is None and scrub.as_int(float("inf")) is None
    assert scrub.as_bool("0") is False and scrub.as_bool(" ") is False
    assert scrub.as_bool("1") is True and scrub.as_bool(True) is True
    assert scrub.as_bool(0) is False and scrub.as_bool(None) is False


def test_log_safe_collapses_del():
    """DEL (0x7f) is a control character too: systemd counts 0x7f-0x9f as
    unprintable, so a journal line holding one is stored as binary and shown
    by journalctl as "[N blob data]" -- the line is lost to the operator."""
    assert scrub.log_safe("a\x7fb") == "a b"


def test_log_safe_collapses_every_control_character():
    for c in list(range(0x20)) + list(range(0x7F, 0xA0)):
        assert scrub.log_safe("a" + chr(c) + "b") == "a b", hex(c)


def test_caps_are_pinned():
    # Literals: ERROR_PRE_REDACT_MAX_LEN bounds the input of redact(), whose
    # regexes are a CPU sink on hostile text; the wire caps bound the payload.
    assert (scrub.FIELD_MAX_LEN, scrub.ERROR_MAX_LEN) == (500, 500)
    assert scrub.ERROR_PRE_REDACT_MAX_LEN == 2000
