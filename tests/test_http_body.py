"""Tests for the shared bounded streamed-body reader."""

import time
from unittest.mock import MagicMock

import pytest

from fivenines_agent.http_body import BodyOverBudget, read_capped_body


def _resp(chunks):
    resp = MagicMock()
    resp.iter_content = lambda chunk_size=65536: iter(chunks)
    return resp


def test_reads_body_and_closes():
    resp = _resp([b"hello ", b"", b"world"])  # empty keep-alive chunk skipped
    assert read_capped_body(resp, 1024, 5) == b"hello world"
    resp.close.assert_called_once()


def test_byte_cap_raises_and_closes():
    resp = _resp([b"x" * 100])
    with pytest.raises(BodyOverBudget):
        read_capped_body(resp, 64, 5)
    resp.close.assert_called_once()


def test_wall_clock_deadline_raises(monkeypatch):
    """requests' timeout is per-socket-op; a trickling endpoint never trips
    it, so the reader enforces its own wall-clock deadline."""
    clock = iter([0.0, 100.0])  # deadline computation, then first chunk check
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))
    resp = _resp([b"a", b"b"])
    with pytest.raises(BodyOverBudget):
        read_capped_body(resp, 1024, 5)
    resp.close.assert_called_once()


def test_transport_error_propagates_but_still_closes():
    def broken(chunk_size=65536):
        yield b"partial"
        raise OSError("connection reset")

    resp = MagicMock()
    resp.iter_content = broken
    with pytest.raises(OSError):
        read_capped_body(resp, 1024, 5)
    resp.close.assert_called_once()


def test_over_budget_is_a_value_error():
    """Callers map ValueError (tsdb) or any Exception (rabbitmq/php_fpm) onto
    their module contracts; BodyOverBudget must stay a ValueError subclass."""
    assert issubclass(BodyOverBudget, ValueError)
