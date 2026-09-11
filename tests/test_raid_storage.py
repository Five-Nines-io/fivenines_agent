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
    # mdadm unusable surfaces as no devices parsed from /proc/mdstat (or a
    # failed read); there is no separate availability spawn anymore.
    with patch.multiple(raid_storage, list_raid_devices=lambda: []):
        assert raid_storage.raid_storage_health() == []


def test_health_no_devices_returns_empty(clock):
    with patch.multiple(
        raid_storage,
        get_mdadm_version=lambda: "4.1",
        list_raid_devices=lambda: [],
    ):
        assert raid_storage.raid_storage_health() == []


def test_health_happy_filters_none_and_adds_version(clock):
    def fake_info(dev):
        return None if dev == "/dev/md1" else {"device": "md0"}

    with patch.multiple(
        raid_storage,
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
        get_mdadm_version=lambda: "4.1",
        list_raid_devices=lambda: ["/dev/md0"],
        get_raid_info=fake_info,
    ):
        raid_storage.raid_storage_health()
        clock.t += 60  # TTL elapsed
        raid_storage.raid_storage_health()

    assert calls == ["/dev/md0", "/dev/md0"]  # recomputed


def test_get_mdadm_version_cached_after_first_success(monkeypatch):
    """The version fetch is one sudo spawn; it only changes on upgrade, so the
    first successful read is cached for the process lifetime."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)

        class P:
            stdout = "mdadm - v4.2 - 2021-12-30\nextra\n"

        return P()

    monkeypatch.setattr(raid_storage.subprocess, "run", fake_run)
    assert raid_storage.get_mdadm_version() == "mdadm - v4.2 - 2021-12-30"
    assert raid_storage.get_mdadm_version() == "mdadm - v4.2 - 2021-12-30"
    assert len(calls) == 1
    # sudo -n (non-interactive) and a timeout: a wedged sudo/mdadm must not
    # stall the collection loop.
    assert calls[0][:3] == ["sudo", "-n", "mdadm"]


def test_get_mdadm_version_failure_not_cached(monkeypatch):
    def boom(cmd, **kwargs):
        raise OSError("no sudo")

    monkeypatch.setattr(raid_storage.subprocess, "run", boom)
    assert raid_storage.get_mdadm_version() is None

    def ok(cmd, **kwargs):
        class P:
            stdout = "mdadm - v4.2\n"

        return P()

    monkeypatch.setattr(raid_storage.subprocess, "run", ok)
    assert raid_storage.get_mdadm_version() == "mdadm - v4.2"  # retried


def test_get_raid_info_passes_timeout(monkeypatch):
    """mdadm --detail is bounded: unbounded, a dying member disk could park the
    whole collection loop in uninterruptible I/O past the systemd watchdog."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["timeout"] = kwargs.get("timeout")

        class P:
            stdout = "/dev/md0:\n        Raid Level : raid1\n"

        return P()

    monkeypatch.setattr(raid_storage.subprocess, "run", fake_run)
    info = raid_storage.get_raid_info("/dev/md0")
    assert info["raid_level"] == "raid1"
    assert captured["timeout"] == raid_storage._DATA_SUBPROCESS_TIMEOUT
    assert captured["cmd"][:3] == ["sudo", "-n", "mdadm"]


def test_get_raid_info_timeout_propagates(monkeypatch):
    """A timed-out mdadm --detail must FAIL the collection (propagate), not be
    swallowed into None: filtering the wedged array out of an otherwise-healthy
    list would report the dying array as removed exactly when it matters."""
    def boom(cmd, **kwargs):
        raise raid_storage.subprocess.TimeoutExpired(cmd=cmd, timeout=30)

    monkeypatch.setattr(raid_storage.subprocess, "run", boom)
    with pytest.raises(raid_storage.subprocess.TimeoutExpired):
        raid_storage.get_raid_info("/dev/md0")
