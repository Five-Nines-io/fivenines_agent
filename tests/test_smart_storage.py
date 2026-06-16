from unittest.mock import patch

import pytest

from fivenines_agent import cache as cache_mod
from fivenines_agent import smart_storage


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    """Deterministic clock + clean module cache for each test."""
    c = _FakeClock()
    monkeypatch.setattr(cache_mod, "time", c)
    smart_storage._cache._entries.clear()
    yield c
    smart_storage._cache._entries.clear()


# --- smart_storage_health -------------------------------------------------


def test_health_unavailable_returns_empty(clock):
    with patch.multiple(smart_storage, smartctl_available=lambda: False):
        assert smart_storage.smart_storage_health() == []


def test_health_no_devices_returns_empty(clock):
    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        list_storage_devices=lambda: [],
    ):
        assert smart_storage.smart_storage_health() == []


def test_health_happy_filters_none(clock):
    def fake_info(dev):
        return None if dev == "/dev/sdb" else {"device": "sda"}

    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        list_storage_devices=lambda: ["/dev/sda", "/dev/sdb"],
        get_storage_info=fake_info,
    ):
        assert smart_storage.smart_storage_health() == [{"device": "sda"}]


def test_health_cache_hit_within_ttl(clock):
    calls = []

    def fake_info(dev):
        calls.append(dev)
        return {"device": dev.split("/")[-1]}

    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        list_storage_devices=lambda: ["/dev/sda"],
        get_storage_info=fake_info,
    ):
        first = smart_storage.smart_storage_health()
        clock.t += 30  # inside 60s TTL
        second = smart_storage.smart_storage_health()

    assert first == second == [{"device": "sda"}]
    assert calls == ["/dev/sda"]  # computed exactly once


def test_health_recomputes_after_ttl(clock):
    calls = []

    def fake_info(dev):
        calls.append(dev)
        return {"device": dev.split("/")[-1]}

    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        list_storage_devices=lambda: ["/dev/sda"],
        get_storage_info=fake_info,
    ):
        smart_storage.smart_storage_health()
        clock.t += 60  # TTL elapsed
        smart_storage.smart_storage_health()

    assert calls == ["/dev/sda", "/dev/sda"]  # recomputed


# --- smart_storage_identification -----------------------------------------


def test_identification_unavailable_returns_empty(clock):
    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: False,
        nvme_cli_available=lambda: False,
    ):
        assert smart_storage.smart_storage_identification() == []


def test_identification_no_devices_returns_empty(clock):
    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        nvme_cli_available=lambda: False,
        get_smartctl_version=lambda: "7.0",
        list_storage_devices=lambda: [],
    ):
        assert smart_storage.smart_storage_identification() == []


def test_identification_happy_adds_tool_versions(clock):
    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        nvme_cli_available=lambda: True,
        get_smartctl_version=lambda: "7.0",
        get_nvme_cli_version=lambda: "1.0",
        list_storage_devices=lambda: ["/dev/sda"],
        get_storage_identification=lambda dev: {"device": "sda"},
    ):
        result = smart_storage.smart_storage_identification()

    assert result == [
        {"device": "sda", "smartctl_version": "7.0", "nvme_cli_version": "1.0"}
    ]


def test_identification_cache_hit_within_ttl(clock):
    calls = []

    def fake_id(dev):
        calls.append(dev)
        return {"device": dev.split("/")[-1]}

    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        nvme_cli_available=lambda: False,
        get_smartctl_version=lambda: "7.0",
        get_nvme_cli_version=lambda: None,
        list_storage_devices=lambda: ["/dev/sda"],
        get_storage_identification=fake_id,
    ):
        smart_storage.smart_storage_identification()
        clock.t += 300  # inside 600s TTL
        smart_storage.smart_storage_identification()

    assert calls == ["/dev/sda"]  # computed once
