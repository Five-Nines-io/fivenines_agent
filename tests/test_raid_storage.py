from unittest.mock import patch

import pytest

from fivenines_agent import cache as cache_mod
from fivenines_agent import raid_storage


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = _FakeClock()
    monkeypatch.setattr(cache_mod, "time", c)
    raid_storage._cache._entries.clear()
    yield c
    raid_storage._cache._entries.clear()


def test_health_unavailable_returns_empty(clock):
    with patch.multiple(raid_storage, mdadm_available=lambda: False):
        assert raid_storage.raid_storage_health() == []


def test_health_no_devices_returns_empty(clock):
    with patch.multiple(
        raid_storage,
        mdadm_available=lambda: True,
        get_mdadm_version=lambda: "4.1",
        list_raid_devices=lambda: [],
    ):
        assert raid_storage.raid_storage_health() == []


def test_health_happy_filters_none_and_adds_version(clock):
    def fake_info(dev):
        return None if dev == "/dev/md1" else {"device": "md0"}

    with patch.multiple(
        raid_storage,
        mdadm_available=lambda: True,
        get_mdadm_version=lambda: "4.1",
        list_raid_devices=lambda: ["/dev/md0", "/dev/md1"],
        get_raid_info=fake_info,
    ):
        result = raid_storage.raid_storage_health()

    assert result == [{"device": "md0", "mdadm_version": "4.1"}]


def test_health_cache_hit_within_ttl(clock):
    calls = []

    def fake_info(dev):
        calls.append(dev)
        return {"device": dev.split("/")[-1]}

    with patch.multiple(
        raid_storage,
        mdadm_available=lambda: True,
        get_mdadm_version=lambda: "4.1",
        list_raid_devices=lambda: ["/dev/md0"],
        get_raid_info=fake_info,
    ):
        first = raid_storage.raid_storage_health()
        clock.t += 30  # inside 60s TTL
        second = raid_storage.raid_storage_health()

    assert first == second == [{"device": "md0", "mdadm_version": "4.1"}]
    assert calls == ["/dev/md0"]  # computed once


def test_health_recomputes_after_ttl(clock):
    calls = []

    def fake_info(dev):
        calls.append(dev)
        return {"device": dev.split("/")[-1]}

    with patch.multiple(
        raid_storage,
        mdadm_available=lambda: True,
        get_mdadm_version=lambda: "4.1",
        list_raid_devices=lambda: ["/dev/md0"],
        get_raid_info=fake_info,
    ):
        raid_storage.raid_storage_health()
        clock.t += 60  # TTL elapsed
        raid_storage.raid_storage_health()

    assert calls == ["/dev/md0", "/dev/md0"]  # recomputed
