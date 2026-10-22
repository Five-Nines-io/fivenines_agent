import datetime
import subprocess
import time
from unittest.mock import MagicMock, mock_open, patch

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


# --- realistic mdadm / mdstat output ---------------------------------------

MDSTAT = (
    "Personalities : [raid1] [raid6] [raid5] [raid4] [linear] [multipath]"
    " [raid0] [raid10]\n"
    "md127 : active raid5 sdd1[3] sdc1[1] sdb1[0]\n"
    "      1953260544 blocks super 1.2 level 5, 512k chunk, algorithm 2"
    " [3/3] [UUU]\n"
    "      bitmap: 0/8 pages [0KB], 65536KB chunk\n"
    "\n"
    "md0 : active raid1 sdb2[2] sda2[0]\n"
    "      976630464 blocks super 1.2 [2/1] [U_]\n"
    "      [====>................]  recovery = 21.4% (209715200/976630464)"
    " finish=63.2min speed=202216K/sec\n"
    "\n"
    "unused devices: <none>\n"
)

# `mdadm --detail /dev/md0` for a RAID1 rebuilding onto a replacement disk,
# with the slot it replaces still listed as "removed".
DETAIL_RAID1_REBUILDING = """\
/dev/md0:
           Version : 1.2
     Creation Time : Mon Jan  8 09:15:42 2024
        Raid Level : raid1
        Array Size : 976630464 (931.39 GiB 1000.07 GB)
     Used Dev Size : 976630464 (931.39 GiB 1000.07 GB)
      Raid Devices : 2
     Total Devices : 2
       Persistence : Superblock is persistent

     Intent Bitmap : Internal

       Update Time : Tue Feb 13 08:15:30 2024
             State : clean, degraded, recovering
    Active Devices : 1
   Working Devices : 2
    Failed Devices : 0
     Spare Devices : 1

Consistency Policy : bitmap

    Rebuild Status : 21% complete

              Name : host1:0  (local to host host1)
              UUID : 3b5c9f2e:1a2b3c4d:5e6f7a8b:9c0d1e2f
            Events : 48211

    Number   Major   Minor   RaidDevice State
       0       8        2        0      active sync   /dev/sda2
       2       8       18        1      spare rebuilding   /dev/sdb2
       -       0        0        2      removed
"""


def _completed(stdout):
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = stdout
    return proc


# --- list_raid_devices ------------------------------------------------------


def test_list_raid_devices_reads_array_names_from_mdstat(monkeypatch):
    """Every `mdN :` line is an array; the Personalities header, member
    detail lines and the `unused devices` footer are not."""
    fake_open = mock_open(read_data=MDSTAT)
    monkeypatch.setattr(raid_storage, "open", fake_open, raising=False)

    assert raid_storage.list_raid_devices() == ["/dev/md127", "/dev/md0"]
    fake_open.assert_called_once_with("/proc/mdstat", "r")


def test_list_raid_devices_empty_and_logged_when_mdstat_unreadable(monkeypatch):
    """No /proc/mdstat (md module not loaded) reads as zero arrays, with an
    error line, instead of raising out of the collector."""
    missing = FileNotFoundError(2, "No such file or directory", "/proc/mdstat")
    monkeypatch.setattr(
        raid_storage, "open", MagicMock(side_effect=missing), raising=False
    )
    log = MagicMock()
    monkeypatch.setattr(raid_storage, "log", log)

    assert raid_storage.list_raid_devices() == []
    log.assert_called_once()
    message, level = log.call_args.args
    assert level == "error"
    assert "/proc/mdstat" in message


# --- value parsers ----------------------------------------------------------


def test_parse_size_with_units_takes_the_leading_number():
    parse = raid_storage._parse_size_with_units
    assert parse("976630464 (931.39 GiB 1000.07 GB)") == 976630464
    assert parse("512K") == 512
    assert parse("") is None
    assert parse(None) is None
    assert parse("unknown") is None


def test_parse_timestamp_reads_mdadm_format():
    """mdadm prints asctime-style time (day padded with a space); anything
    else is unparseable."""
    expected = int(datetime.datetime(2024, 1, 8, 9, 15, 42).timestamp())
    assert raid_storage._parse_timestamp("Mon Jan  8 09:15:42 2024") == expected
    assert raid_storage._parse_timestamp("") is None
    assert raid_storage._parse_timestamp(None) is None
    assert raid_storage._parse_timestamp("2024-01-08T09:15:42") is None


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="needs time.tzset (POSIX)")
def test_parse_timestamp_reads_the_host_zone_not_utc(monkeypatch):
    """mdadm writes LOCAL time. CI hosts run in UTC, where local and UTC
    agree, so the zone is pinned to one that differs: 09:15:42 EST is
    14:15:42 UTC. EST5 is a POSIX zone string, so no tzdata is needed (an
    unknown zone name silently falls back to UTC)."""
    try:
        with monkeypatch.context() as m:
            m.setenv("TZ", "EST5")
            time.tzset()
            ts = raid_storage._parse_timestamp("Mon Jan  8 09:15:42 2024")
            assert ts == 1704723342
    finally:
        time.tzset()


# --- get_raid_info ----------------------------------------------------------


def test_get_raid_info_parses_rebuilding_raid1(monkeypatch):
    run = MagicMock(return_value=_completed(DETAIL_RAID1_REBUILDING))
    monkeypatch.setattr(raid_storage, "run_privileged", run)

    info = raid_storage.get_raid_info("/dev/md0")

    assert run.call_args.args[0] == ["sudo", "-n", "mdadm", "--detail", "/dev/md0"]
    assert info["device"] == "md0"
    assert info["version"] == "1.2"
    assert info["raid_level"] == "raid1"
    assert info["state"] == ["clean", "degraded", "recovering"]
    assert info["active_devices"] == 1
    assert info["total_devices"] == 2
    assert info["working_devices"] == 2
    assert info["failed_devices"] == 0
    assert info["spare_devices"] == 1
    assert info["creation_time"] == "Mon Jan  8 09:15:42 2024"
    assert info["creation_time_epoch"] == int(
        datetime.datetime(2024, 1, 8, 9, 15, 42).timestamp()
    )
    assert info["update_time"] == "Tue Feb 13 08:15:30 2024"
    assert info["update_time_epoch"] == int(
        datetime.datetime(2024, 2, 13, 8, 15, 30).timestamp()
    )
    assert info["array_size"] == "976630464 (931.39 GiB 1000.07 GB)"
    assert info["array_size_num"] == 976630464
    assert info["used_dev_size_num"] == 976630464
    assert info["persistence"] == "Superblock is persistent"
    assert info["consistency_policy"] == "bitmap"
    assert info["rebuild_status"] == "21% complete"
    assert info["rebuild_status_percent"] == 21
    assert info["resync_status"] is None
    assert info["check_status"] is None
    assert info["name"] == "host1:0  (local to host host1)"
    assert info["uuid"] == "3b5c9f2e:1a2b3c4d:5e6f7a8b:9c0d1e2f"
    assert info["events"] == "48211"
    assert info["events_num"] == 48211
    # The header row is not a device; the "-" removed slot carries no device
    # (the array-level counts above already say it is degraded).
    assert info["component_devices"] == [
        {
            "number": 0,
            "major": 8,
            "minor": 2,
            "raid_device": 0,
            "state": ["active", "sync"],
            "device": "/dev/sda2",
        },
        {
            "number": 2,
            "major": 8,
            "minor": 18,
            "raid_device": 1,
            "state": ["spare", "rebuilding"],
            "device": "/dev/sdb2",
        },
    ]


def test_get_raid_info_parses_raid5_resync_and_check_fields(monkeypatch):
    """Chunk size, each sync-action status line into its own field, and a
    faulty member whose RaidDevice column is "-"."""
    detail = """\
/dev/md127:
           Version : 1.2
        Raid Level : raid5
        Array Size : 1953260544 (1862.77 GiB 2000.14 GB)
             State : active, resyncing
        Chunk Size : 512K
     Resync Status : 37% complete
      Check Status : 5% complete
            Events : 0.9047

    Number   Major   Minor   RaidDevice State
       0       8       17        0      active sync   /dev/sdb1
       3       8       49        -      faulty   /dev/sdd1
"""
    monkeypatch.setattr(
        raid_storage, "run_privileged", MagicMock(return_value=_completed(detail))
    )

    info = raid_storage.get_raid_info("/dev/md127")

    assert info["device"] == "md127"
    assert info["state"] == ["active", "resyncing"]
    assert info["chunk_size"] == "512K"
    assert info["chunk_size_num"] == 512
    assert info["resync_status_percent"] == 37
    assert info["check_status"] == "5% complete"
    assert info["check_status_percent"] == 5
    # A non-integer event count (0.90-era "major.minor") keeps the string only.
    assert info["events"] == "0.9047"
    assert info["events_num"] is None
    assert info["component_devices"][1] == {
        "number": 3,
        "major": 8,
        "minor": 49,
        "raid_device": None,
        "state": ["faulty"],
        "device": "/dev/sdd1",
    }


def test_get_raid_info_status_without_percent_leaves_percent_unset(monkeypatch):
    detail = (
        "/dev/md1:\n"
        "     Resync Status : DELAYED\n"
        "      Check Status : PENDING\n"
        "    Rebuild Status : DELAYED\n"
    )
    monkeypatch.setattr(
        raid_storage, "run_privileged", MagicMock(return_value=_completed(detail))
    )

    info = raid_storage.get_raid_info("/dev/md1")

    assert info["resync_status"] == "DELAYED"
    assert info["check_status"] == "PENDING"
    assert info["rebuild_status"] == "DELAYED"
    assert info["resync_status_percent"] is None
    assert info["check_status_percent"] is None
    assert info["rebuild_status_percent"] is None
    # No device table in the output -> the default empty list.
    assert info["component_devices"] == []


def test_get_raid_info_legacy_and_container_fields(monkeypatch):
    """The less common Preferred Minor (0.90 metadata) and Physical Disks
    fields, and a device table header without the State column (containers).
    Short table rows are tolerated: four columns give a row with no device,
    fewer are not a row."""
    detail = """\
/dev/md126:
           Version : 0.90
   Preferred Minor : 126
    Physical Disks : 2

    Number   Major   Minor   RaidDevice

       0       8        0        0
       1       8
"""
    monkeypatch.setattr(
        raid_storage, "run_privileged", MagicMock(return_value=_completed(detail))
    )

    info = raid_storage.get_raid_info("/dev/md126")

    assert info["version"] == "0.90"
    assert info["preferred_minor"] == 126
    assert info["physical_disks"] == 2
    assert info["component_devices"] == [
        {
            "number": 0,
            "major": 8,
            "minor": 0,
            "raid_device": 0,
            "state": [],
            "device": None,
        }
    ]


def test_get_raid_info_none_and_logged_when_mdadm_fails(monkeypatch):
    """A non-zero mdadm exit (check=True) drops that one array with an error
    line; only a TIMEOUT fails the whole collection."""
    failed = subprocess.CalledProcessError(
        1, ["sudo", "-n", "mdadm", "--detail", "/dev/md9"]
    )
    monkeypatch.setattr(raid_storage, "run_privileged", MagicMock(side_effect=failed))
    log = MagicMock()
    monkeypatch.setattr(raid_storage, "log", log)

    assert raid_storage.get_raid_info("/dev/md9") is None
    message, level = log.call_args.args
    assert level == "error"
    assert "/dev/md9" in message


def test_get_raid_info_none_when_a_count_is_not_an_integer(monkeypatch):
    """An unparseable count fails that array's read (None) rather than
    shipping a half-parsed record."""
    detail = "/dev/md0:\n    Active Devices : two\n"
    monkeypatch.setattr(
        raid_storage, "run_privileged", MagicMock(return_value=_completed(detail))
    )
    monkeypatch.setattr(raid_storage, "log", MagicMock())

    assert raid_storage.get_raid_info("/dev/md0") is None


# --- raid_storage_health end to end ----------------------------------------


def test_health_end_to_end_from_mdstat_and_mdadm(clock, monkeypatch):
    """mdstat lists two arrays; mdadm answers the version once and --detail
    per array; an array whose --detail fails is dropped, the other ships
    with the mdadm version stamped on it."""
    monkeypatch.setattr(
        raid_storage, "open", mock_open(read_data=MDSTAT), raising=False
    )
    monkeypatch.setattr(raid_storage, "log", MagicMock())
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd == ["sudo", "-n", "mdadm", "--version"]:
            return _completed("mdadm - v4.2 - 2021-12-30\n")
        if cmd[-1] == "/dev/md0":
            return _completed(DETAIL_RAID1_REBUILDING)
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(raid_storage, "run_privileged", fake_run)

    result = raid_storage.raid_storage_health()

    assert len(result) == 1
    assert result[0]["device"] == "md0"
    assert result[0]["mdadm_version"] == "mdadm - v4.2 - 2021-12-30"
    assert result[0]["rebuild_status_percent"] == 21
    assert calls == [
        ["sudo", "-n", "mdadm", "--version"],
        ["sudo", "-n", "mdadm", "--detail", "/dev/md127"],
        ["sudo", "-n", "mdadm", "--detail", "/dev/md0"],
    ]
