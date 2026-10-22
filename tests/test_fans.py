"""Tests for the fans collector.

psutil only provides sensors_fans() on Linux (and only when the kernel
exposes hwmon fan inputs); on Windows and macOS the attribute does not exist
at all, and the collector must report an empty map rather than raise.
"""

from typing import NamedTuple

import psutil

from fivenines_agent.fans import fans


class sfan(NamedTuple):
    label: str
    current: int


def test_fans_without_psutil_support_is_empty(monkeypatch):
    monkeypatch.delattr(psutil, "sensors_fans", raising=False)
    assert fans() == {}


def test_fans_returns_the_psutil_reading_verbatim(monkeypatch):
    reading = {
        "dell_smm": [sfan(label="CPU Fan", current=3120), sfan(label="", current=0)],
        "thinkpad": [sfan(label="", current=2400)],
    }
    monkeypatch.setattr(psutil, "sensors_fans", lambda: reading, raising=False)
    assert fans() is reading
