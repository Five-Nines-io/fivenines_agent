"""Tests for the temperatures collector.

psutil only provides sensors_temperatures() on Linux and FreeBSD; on Windows
and macOS the attribute does not exist at all, and the collector must report
an empty map rather than raise.
"""

from typing import NamedTuple, Optional

import psutil

from fivenines_agent.temperatures import temperatures


class shwtemp(NamedTuple):
    label: str
    current: float
    high: Optional[float]
    critical: Optional[float]


def test_temperatures_without_psutil_support_is_empty(monkeypatch):
    monkeypatch.delattr(psutil, "sensors_temperatures", raising=False)
    assert temperatures() == {}


def test_temperatures_returns_the_psutil_reading_verbatim(monkeypatch):
    reading = {
        "coretemp": [
            shwtemp(label="Package id 0", current=48.0, high=80.0, critical=100.0),
            shwtemp(label="Core 0", current=45.0, high=80.0, critical=100.0),
        ],
        "nvme": [shwtemp(label="Composite", current=37.85, high=None, critical=None)],
    }
    monkeypatch.setattr(psutil, "sensors_temperatures", lambda: reading, raising=False)
    assert temperatures() is reading


def test_temperatures_with_no_sensors_is_empty(monkeypatch):
    monkeypatch.setattr(psutil, "sensors_temperatures", lambda: {}, raising=False)
    assert temperatures() == {}
