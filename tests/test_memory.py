"""Tests for the memory and swap collectors.

Both ship psutil's namedtuple as a plain dict, every field kept under
psutil's own name.
"""

from typing import NamedTuple

import psutil

from fivenines_agent.memory import memory, swap


class svmem(NamedTuple):
    total: int
    available: int
    percent: float
    used: int
    free: int
    buffers: int
    cached: int


class sswap(NamedTuple):
    total: int
    used: int
    free: int
    percent: float
    sin: int
    sout: int


def test_memory_converts_virtual_memory_to_a_dict(monkeypatch):
    reading = svmem(
        total=8_000,
        available=6_000,
        percent=25.0,
        used=1_500,
        free=4_000,
        buffers=100,
        cached=400,
    )
    monkeypatch.setattr(psutil, "virtual_memory", lambda: reading)
    result = memory()
    assert result == {
        "total": 8_000,
        "available": 6_000,
        "percent": 25.0,
        "used": 1_500,
        "free": 4_000,
        "buffers": 100,
        "cached": 400,
    }
    assert type(result) is dict


def test_swap_converts_swap_memory_to_a_dict(monkeypatch):
    reading = sswap(total=2_048, used=512, free=1_536, percent=25.0, sin=7, sout=3)
    monkeypatch.setattr(psutil, "swap_memory", lambda: reading)
    result = swap()
    assert result == {
        "total": 2_048,
        "used": 512,
        "free": 1_536,
        "percent": 25.0,
        "sin": 7,
        "sout": 3,
    }
    assert type(result) is dict


def test_swap_with_no_swap_configured(monkeypatch):
    """A host without swap reports zeros, still as a full dict."""
    reading = sswap(total=0, used=0, free=0, percent=0.0, sin=0, sout=0)
    monkeypatch.setattr(psutil, "swap_memory", lambda: reading)
    assert swap() == {
        "total": 0,
        "used": 0,
        "free": 0,
        "percent": 0.0,
        "sin": 0,
        "sout": 0,
    }


def test_memory_and_swap_against_the_real_host():
    """Unmocked: the fields every psutil platform provides are present."""
    mem = memory()
    assert {"total", "available", "percent", "used", "free"} <= mem.keys()
    assert mem["total"] > 0
    sw = swap()
    assert {"total", "used", "free", "percent"} <= sw.keys()
    assert sw["total"] >= 0
