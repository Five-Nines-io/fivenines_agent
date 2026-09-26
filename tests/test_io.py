"""Tests for io.py - per-disk counters and the block device topology (#155)."""

import json
import os
import shutil
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from fivenines_agent import io as io_mod
from fivenines_agent.collectors import collect_metrics
from fivenines_agent.io import (
    _io_name,
    _partitions,
    _whole_device,
    io,
    io_topology,
)

# Entries every real /sys/block/<disk>/ carries besides its partitions. Built
# into every fake disk so the partition scan has to skip them.
_DISK_NOISE_DIRS = ("holders", "power", "queue", "trace")
_DISK_NOISE_FILES = ("dev", "size", "stat", "uevent")


def _build_sys_block(root, model):
    """Materialize a {name: {device, slaves, partitions}} model as sysfs does.

    Real layout: /sys/block/<name> is a symlink into /sys/devices/..., the
    device directory holds slaves/ (symlinks to the devices beneath), a `device`
    symlink for hardware-backed disks, and one subdirectory per partition with
    a `partition` attribute. slaves=None models an unreadable slaves/.
    """
    devices = root / "devices"
    block = root / "block"
    devices.mkdir()
    block.mkdir()
    for name, spec in model.items():
        disk = devices / name
        disk.mkdir()
        for sub in _DISK_NOISE_DIRS:
            (disk / sub).mkdir()
        for attr in _DISK_NOISE_FILES:
            (disk / attr).write_text("0\n")
        if spec["slaves"] is not None:
            (disk / "slaves").mkdir()
            for slave in spec["slaves"]:
                os.symlink(f"../../{slave}", disk / "slaves" / slave)
        if spec["device"]:
            (devices / f"hw-{name}").mkdir()
            os.symlink(f"../hw-{name}", disk / "device")
        for part in spec.get("partitions", []):
            (disk / part).mkdir()
            (disk / part / "partition").write_text("1\n")
            (disk / part / "holders").mkdir()
        os.symlink(f"../devices/{name}", block / name)
    return block


@pytest.fixture
def linux():
    with patch("fivenines_agent.io.os_family", return_value="linux"):
        yield


def _topology_of(tmp_path, model):
    block = _build_sys_block(tmp_path, model)
    with patch("fivenines_agent.io.SYS_BLOCK", str(block)):
        return io_topology()


# --- io() -----------------------------------------------------------------


def test_io_reports_one_row_per_disk_verbatim():
    counters = {
        "sda": SimpleNamespace(_asdict=lambda: {"read_bytes": 1, "write_bytes": 2}),
        "sda1": SimpleNamespace(_asdict=lambda: {"read_bytes": 3, "write_bytes": 4}),
    }
    with patch(
        "fivenines_agent.io.psutil.disk_io_counters", return_value=counters
    ) as m:
        assert io() == [
            {"sda": {"read_bytes": 1, "write_bytes": 2}},
            {"sda1": {"read_bytes": 3, "write_bytes": 4}},
        ]
    m.assert_called_once_with(perdisk=True)


# --- io_topology(): shapes ------------------------------------------------


def test_whole_disk_partition_and_stacked_layer(tmp_path, linux):
    out = _topology_of(
        tmp_path,
        {
            "sda": {"device": True, "slaves": [], "partitions": ["sda1", "sda2"]},
            "dm-0": {"device": False, "slaves": ["sda2"]},
        },
    )
    assert out == {
        "dm-0": {"slaves": ["sda2"], "virtual": True},
        "sda": {"slaves": [], "virtual": False},
        "sda1": {"partition_of": "sda"},
        "sda2": {"partition_of": "sda"},
    }


def test_partition_is_decided_by_structure_not_by_name(tmp_path, linux):
    """xvda1 at the top of /sys/block is a whole disk (a Xen PV guest with no
    xvda); nvme0n1, which ends in a digit, is one too."""
    out = _topology_of(
        tmp_path,
        {
            "xvda1": {"device": True, "slaves": []},
            "nvme0n1": {"device": True, "slaves": [], "partitions": ["nvme0n1p1"]},
        },
    )
    assert out == {
        "nvme0n1": {"slaves": [], "virtual": False},
        "nvme0n1p1": {"partition_of": "nvme0n1"},
        "xvda1": {"slaves": [], "virtual": False},
    }


def test_virtual_leaf_is_not_reported_as_hardware(tmp_path, linux):
    """A zvol or loop device has no slaves either; only the device link tells
    it apart from a real disk."""
    out = _topology_of(
        tmp_path,
        {
            "zd0": {"device": False, "slaves": []},
            "sda": {"device": True, "slaves": []},
        },
    )
    assert out["zd0"] == {"slaves": [], "virtual": True}
    assert out["sda"] == {"slaves": [], "virtual": False}


def test_unreadable_slaves_leaves_the_device_out(tmp_path, linux):
    """[] is a claim (nothing beneath); an unread directory must not make it."""
    out = _topology_of(
        tmp_path,
        {
            "dm-0": {"device": False, "slaves": None},
            "sda": {"device": True, "slaves": []},
        },
    )
    assert "dm-0" not in out
    assert out["sda"] == {"slaves": [], "virtual": False}


def test_unreadable_whole_device_still_reports_its_partitions(tmp_path, linux):
    """Each fact is reported only from its own successful read: a disk whose
    slaves/ failed is unknown, its partitions are still partitions."""
    out = _topology_of(
        tmp_path,
        {"sda": {"device": True, "slaves": None, "partitions": ["sda1"]}},
    )
    assert out == {"sda1": {"partition_of": "sda"}}


def test_slashed_names_are_reported_as_io_spells_them(tmp_path, linux):
    """/proc/diskstats (so `io`) says cciss/c0d0; sysfs says cciss!c0d0."""
    out = _topology_of(
        tmp_path,
        {
            "cciss!c0d0": {
                "device": True,
                "slaves": [],
                "partitions": ["cciss!c0d0p1"],
            },
            "dm-0": {"device": False, "slaves": ["cciss!c0d0p1"]},
        },
    )
    assert out == {
        "cciss/c0d0": {"slaves": [], "virtual": False},
        "cciss/c0d0p1": {"partition_of": "cciss/c0d0"},
        "dm-0": {"slaves": ["cciss/c0d0p1"], "virtual": True},
    }


def test_empty_sys_block_is_an_empty_map(tmp_path, linux):
    assert _topology_of(tmp_path, {}) == {}


def test_unlistable_sys_block_is_none(tmp_path, linux):
    with patch("fivenines_agent.io.SYS_BLOCK", str(tmp_path / "missing")):
        assert io_topology() is None


@pytest.mark.parametrize("family", ["windows", "darwin", "freebsd"])
def test_non_linux_is_none_without_touching_the_filesystem(family):
    with patch("fivenines_agent.io.os_family", return_value=family), patch(
        "fivenines_agent.io.os.listdir"
    ) as listdir:
        assert io_topology() is None
    listdir.assert_not_called()


# --- helpers --------------------------------------------------------------


def test_io_name_maps_sysfs_bang_back_to_slash():
    assert _io_name("cciss!c0d0p1") == "cciss/c0d0p1"
    assert _io_name("sda1") == "sda1"


def test_whole_device_sorts_slaves(tmp_path):
    """listdir order is the filesystem's; the payload's must not be."""
    block = _build_sys_block(tmp_path, {"md0": {"device": False, "slaves": []}})
    with patch("fivenines_agent.io.os.listdir", return_value=["sdb1", "sda1"]):
        assert _whole_device(str(block / "md0")) == {
            "slaves": ["sda1", "sdb1"],
            "virtual": True,
        }


def test_whole_device_counts_a_dangling_device_link_as_hardware(tmp_path):
    """The link's presence is the signal (lstat), not whether it resolves."""
    block = _build_sys_block(tmp_path, {"sda": {"device": False, "slaves": []}})
    os.symlink("../nowhere", block / "sda" / "device")
    assert _whole_device(str(block / "sda")) == {"slaves": [], "virtual": False}


def test_whole_device_vanishing_mid_read_is_unknown_not_virtual(tmp_path):
    """A disk hot-removed between the slaves/ read and the device lstat also
    answers ENOENT; calling it virtual would drop its already-collected `io`
    row from the server's total."""
    block = _build_sys_block(tmp_path, {"sdz": {"device": True, "slaves": []}})
    device_link = str(block / "sdz" / "device")
    real_lstat = os.lstat

    def unplug_on_device_lstat(path, *args, **kwargs):
        if path == device_link:
            shutil.rmtree(tmp_path / "devices" / "sdz")
            os.unlink(block / "sdz")
        return real_lstat(path, *args, **kwargs)

    with patch("fivenines_agent.io.os.lstat", side_effect=unplug_on_device_lstat):
        assert _whole_device(str(block / "sdz")) is None


def test_whole_device_unknown_when_device_link_cannot_be_checked(tmp_path):
    """Only ENOENT means virtual; any other failure is unknown, never a claim."""
    block = _build_sys_block(tmp_path, {"sda": {"device": True, "slaves": []}})
    with patch("fivenines_agent.io.os.lstat", side_effect=PermissionError):
        assert _whole_device(str(block / "sda")) is None


def test_partitions_skips_non_partition_entries(tmp_path):
    """A prefixed entry is only a candidate: it must be a real directory
    carrying a `partition` file."""
    block = _build_sys_block(
        tmp_path, {"sda": {"device": True, "slaves": [], "partitions": ["sda1"]}}
    )
    disk = block / "sda"
    (disk / "sda9").mkdir()  # directory, no partition attribute
    (disk / "sda8").write_text("1\n")  # a file, not a directory
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "partition").write_text("1\n")
    os.symlink(tmp_path / "elsewhere", disk / "sda7")  # a symlinked directory
    assert _partitions(str(disk), "sda") == ["sda1"]


def test_partitions_checks_only_prefixed_candidates(tmp_path):
    """The name prefix spares a stat per queue/, holders/, power/... entry."""
    block = _build_sys_block(
        tmp_path,
        {"sda": {"device": True, "slaves": [], "partitions": ["sda1", "sda2"]}},
    )
    real_isfile = os.path.isfile
    with patch("fivenines_agent.io.os.path.isfile", side_effect=real_isfile) as isfile:
        assert _partitions(str(block / "sda"), "sda") == ["sda1", "sda2"]
    checked = sorted(
        os.path.basename(os.path.dirname(c.args[0])) for c in isfile.call_args_list
    )
    assert checked == ["sda1", "sda2"]


def test_partitions_empty_when_disk_directory_unreadable(tmp_path):
    assert _partitions(str(tmp_path / "gone"), "gone") == []


# --- registry dispatch ----------------------------------------------------


def test_registered_under_its_own_top_level_flag(tmp_path, linux):
    """config["io_topology"] is a plain boolean, never splatted as kwargs.

    A dict value must still collect: splatting it would raise TypeError, which
    the dispatcher turns into None -- so the assertion is on a real, non-empty
    topology and on a telemetry entry with no errors, never on None.
    """
    block = _build_sys_block(
        tmp_path, {"sda": {"device": True, "slaves": [], "partitions": ["sda1"]}}
    )
    data, telemetry = {}, {}
    with patch("fivenines_agent.io.SYS_BLOCK", str(block)):
        collect_metrics({"io_topology": {"unexpected": 1}}, data, telemetry)
    assert data == {
        "io_topology": {
            "sda": {"slaves": [], "virtual": False},
            "sda1": {"partition_of": "sda"},
        }
    }
    assert "errors" not in telemetry["io_topology"]


def test_registry_reports_none_off_linux():
    with patch.object(io_mod, "os_family", return_value="darwin"):
        data = {}
        collect_metrics({"io_topology": True}, data)
    assert data == {"io_topology": None}


def test_not_collected_when_flag_absent():
    data = {}
    with patch("fivenines_agent.io.os.listdir") as listdir:
        collect_metrics({}, data)
    assert "io_topology" not in data
    listdir.assert_not_called()


# --- cross-repo contract (fivenines-server, agent issue #155) -------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "io_topology_contract_payload.json"
)


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


@pytest.mark.parametrize("name", sorted(_load_fixture()["scenarios"]))
def test_contract_fixture_round_trip(name, tmp_path, linux):
    """SHARED FIXTURE (cross-repo contract): fixtures/io_topology_contract_payload.json.

    Asserted on both sides:
    - here: each scenario's 'sysfs' is built as a real /sys/block tree and
      io_topology() must equal scenario['payload']['io_topology'];
    - fivenines-server: its collect spec posts payload['io_topology'] under
      data['io_topology'] and asserts the I/O totals count each write once.

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    scenario = _load_fixture()["scenarios"][name]
    if scenario["sysfs"] is None:
        with patch("fivenines_agent.io.SYS_BLOCK", str(tmp_path / "missing")):
            out = io_topology()
    else:
        out = _topology_of(tmp_path, scenario["sysfs"])
    assert out == scenario["payload"]["io_topology"]


def test_contract_entries_have_exactly_one_shape():
    """Every entry is a whole device or a partition, never a mix."""
    whole = {"slaves", "virtual"}
    part = {"partition_of"}
    for scenario in _load_fixture()["scenarios"].values():
        for entry in (scenario["payload"]["io_topology"] or {}).values():
            assert set(entry) in (whole, part), entry


def test_fixture_agent_min_version():
    assert _load_fixture()["agent_min_version"] == "1.20.0"
