"""Tests for io.py - per-disk counters and the block device topology (#155)."""

import json
import os
import shutil
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from fivenines_agent import io as io_mod
from fivenines_agent.collectors import collect_metrics
from fivenines_agent.io import (
    _diskstats_names,
    _IoNames,
    _partitions,
    _read_attr,
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
    a `partition` attribute. slaves=None models an unreadable slaves/,
    `multipath` lists an NVMe native-multipath head's path links, and `hidden`
    marks a hidden disk (every disk gets the attribute, as since 4.15). Link
    targets use native separators: Windows CI runs this suite, and a
    '/'-separated relative link does not resolve there.
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
        (disk / "hidden").write_text("1\n" if spec.get("hidden") else "0\n")
        if spec["slaves"] is not None:
            (disk / "slaves").mkdir()
            for slave in spec["slaves"]:
                os.symlink(
                    os.path.join(os.pardir, os.pardir, slave), disk / "slaves" / slave
                )
        if spec.get("multipath"):
            (disk / "multipath").mkdir()
            for path in spec["multipath"]:
                os.symlink(
                    os.path.join(os.pardir, os.pardir, path), disk / "multipath" / path
                )
        if spec["device"]:
            (devices / f"hw-{name}").mkdir()
            os.symlink(os.path.join(os.pardir, f"hw-{name}"), disk / "device")
        for part in spec.get("partitions", []):
            (disk / part).mkdir()
            (disk / part / "partition").write_text("1\n")
            (disk / part / "holders").mkdir()
        os.symlink(os.path.join(os.pardir, "devices", name), block / name)
    return block


@pytest.fixture(autouse=True)
def _no_stalled_worker():
    io_mod._stalled_worker = None
    yield
    io_mod._stalled_worker = None


@pytest.fixture
def linux():
    with patch("fivenines_agent.io.os_family", return_value="linux"):
        yield


def _topology_of(tmp_path, model, diskstats=None):
    """io_topology() over a built /sys/block; `diskstats` lists the names
    /proc/diskstats holds (None: a path that does not exist)."""
    block = _build_sys_block(tmp_path, model)
    proc = tmp_path / "diskstats"
    if diskstats is not None:
        proc.write_text(_diskstats_text(diskstats))
    with patch("fivenines_agent.io.SYS_BLOCK", str(block)), patch(
        "fivenines_agent.io.PROC_DISKSTATS", str(proc)
    ):
        return io_topology()


def _diskstats_text(names):
    """Real /proc/diskstats lines (20 fields since 5.5) for the given names."""
    return "".join(
        f"   8       {i} {name} 1 2 3 4 5 6 7 8 0 9 10 0 0 0 0 0 0\n"
        for i, name in enumerate(names)
    )


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
        diskstats=["cciss/c0d0", "cciss/c0d0p1", "dm-0"],
    )
    assert out == {
        "cciss/c0d0": {"slaves": [], "virtual": False},
        "cciss/c0d0p1": {"partition_of": "cciss/c0d0"},
        "dm-0": {"slaves": ["cciss/c0d0p1"], "virtual": True},
    }


def test_literal_bang_in_a_named_md_array_is_kept(tmp_path, linux):
    """md takes any `md_*` name verbatim, so a '!' in sysfs can be literal:
    mapping it to '/' unconditionally would key md_data! as md_data/."""
    out = _topology_of(
        tmp_path,
        {
            "md_data!": {"device": False, "slaves": ["sda1", "sdb1"]},
            "sda": {"device": True, "slaves": [], "partitions": ["sda1"]},
            "sdb": {"device": True, "slaves": [], "partitions": ["sdb1"]},
        },
        diskstats=["sda", "sda1", "sdb", "sdb1", "md_data!"],
    )
    assert out["md_data!"] == {"slaves": ["sda1", "sdb1"], "virtual": True}
    assert "md_data/" not in out


def test_unplaceable_names_are_left_out_never_guessed(tmp_path, linux):
    """A '!' name that no /proc/diskstats name escapes to is unknown: the
    device, its partitions and any layer listing it as a slave are left out
    (a partial slaves list would be a false claim); neighbours are kept."""
    out = _topology_of(
        tmp_path,
        {
            "odd!disk": {"device": True, "slaves": [], "partitions": ["odd!disk1"]},
            "dm-0": {"device": False, "slaves": ["odd!disk1"]},
            "sda": {"device": True, "slaves": []},
        },
        diskstats=["sda", "dm-0"],
    )
    assert out == {"sda": {"slaves": [], "virtual": False}}


def test_unplaceable_partition_of_a_placeable_disk_is_left_out(tmp_path, linux):
    """/proc/diskstats skips a zero-size partition, so a '!' partition can be
    unplaceable while its disk is not: it is left out, never keyed as None."""
    out = _topology_of(
        tmp_path,
        {"cciss!c0d0": {"device": True, "slaves": [], "partitions": ["cciss!c0d0p1"]}},
        diskstats=["cciss/c0d0"],
    )
    assert out == {"cciss/c0d0": {"slaves": [], "virtual": False}}


def test_bang_names_are_left_out_when_diskstats_is_unreadable(tmp_path, linux):
    out = _topology_of(
        tmp_path,
        {
            "cciss!c0d0": {"device": True, "slaves": []},
            "sda": {"device": True, "slaves": []},
        },
    )
    assert out == {"sda": {"slaves": [], "virtual": False}}


def test_undecodable_diskstats_byte_is_escaped_like_psutil(tmp_path, linux):
    """psutil reads /proc/diskstats with surrogateescape, so an `io` row whose
    name is not valid UTF-8 still has a key; decoding the same way keeps the
    '!' lookup working and keys that name exactly as `io` does. (0x81 is
    invalid UTF-8 and unmapped in cp1252, so this holds on the Windows CI.)"""
    block = _build_sys_block(
        tmp_path,
        {
            "cciss!c0d0": {"device": True, "slaves": []},
            "md_\udc81!": {"device": False, "slaves": ["sda"]},
            "sda": {"device": True, "slaves": []},
        },
    )
    proc = tmp_path / "diskstats"
    proc.write_bytes(
        _diskstats_text(["sda", "cciss/c0d0"]).encode() + b"   9 0 md_\x81! 1 2\n"
    )
    with patch("fivenines_agent.io.SYS_BLOCK", str(block)), patch(
        "fivenines_agent.io.PROC_DISKSTATS", str(proc)
    ):
        assert io_topology() == {
            "cciss/c0d0": {"slaves": [], "virtual": False},
            "md_\udc81!": {"slaves": ["sda"], "virtual": True},
            "sda": {"slaves": [], "virtual": False},
        }


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="psutil's Linux diskstats parser"
)
def test_topology_keys_match_psutil_for_the_same_diskstats(tmp_path, linux):
    """The load-bearing contract, checked against psutil itself rather than a
    hand-written expectation: fed one /proc/diskstats, io_topology keys every
    device exactly as psutil keys the `io` rows -- a '/', a literal '!' and a
    byte that is not valid UTF-8 included."""
    import psutil

    block = _build_sys_block(
        tmp_path,
        {
            "cciss!c0d0": {"device": True, "slaves": []},
            "md_\udc81!": {"device": False, "slaves": ["sda"]},
            "sda": {"device": True, "slaves": []},
        },
    )
    (tmp_path / "diskstats").write_bytes(
        _diskstats_text(["sda", "cciss/c0d0"]).encode()
        + b"   9 0 md_\x81! 1 2 3 4 5 6 7 8 0 9 10 0 0 0 0 0 0\n"
    )
    with patch("fivenines_agent.io.SYS_BLOCK", str(block)), patch(
        "fivenines_agent.io.PROC_DISKSTATS", str(tmp_path / "diskstats")
    ), patch.object(psutil, "PROCFS_PATH", str(tmp_path)):
        topology = io_topology()
        io_rows = psutil.disk_io_counters(perdisk=True, nowrap=False)
    assert set(topology) == set(io_rows) == {"sda", "cciss/c0d0", "md_\udc81!"}


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


# --- the wall-clock bound ------------------------------------------------


def test_blocked_sysfs_read_is_abandoned_then_single_flight(linux):
    """A kernfs stall must not hold the watchdog-bounded loop: the tick gets
    None at the deadline, later ticks do not pile up workers behind the stuck
    one, and collection resumes once it returns."""
    release = threading.Event()
    calls = []

    def blocked_read():
        calls.append(1)
        # Bounded, so a missing join timeout FAILS the test instead of hanging it.
        release.wait(5)
        return {"sda": {"slaves": [], "virtual": False}}

    with patch.object(io_mod, "TOPOLOGY_READ_TIMEOUT", 0.05), patch.object(
        io_mod, "_read_topology", side_effect=blocked_read
    ):
        start = time.monotonic()
        assert io_topology() is None
        assert time.monotonic() - start < 1

        assert io_topology() is None
        assert len(calls) == 1

        release.set()
        io_mod._stalled_worker.join(5)
        # The resume leg is a success path: give it a real deadline, so it
        # never depends on a fresh thread being scheduled within 50ms.
        with patch.object(io_mod, "TOPOLOGY_READ_TIMEOUT", 5):
            assert io_topology() == {"sda": {"slaves": [], "virtual": False}}
        assert len(calls) == 2


def test_stall_reaches_telemetry_once_and_never_holds_exit(linux):
    """The first stalled tick logs at error on the CALLER's thread, where the
    dispatcher captures a collector's errors for telemetry; ticks that find
    the same read still blocked log at debug, so one stall is one telemetry
    error, not one per tick. The abandoned worker is a daemon, so a read that
    never returns cannot hold the agent's shutdown either."""
    release = threading.Event()

    def blocked_read():
        release.wait(5)
        return {}

    with patch.object(io_mod, "TOPOLOGY_READ_TIMEOUT", 0.05), patch.object(
        io_mod, "_read_topology", side_effect=blocked_read
    ):
        try:
            data, first, second = {}, {}, {}
            collect_metrics({"io_topology": True}, data, first)
            assert data == {"io_topology": None}
            assert len(first["io_topology"]["errors"]) == 1
            assert "sysfs read blocked" in first["io_topology"]["errors"][0]
            assert io_mod._stalled_worker.daemon

            collect_metrics({"io_topology": True}, data, second)
            assert data == {"io_topology": None}
            assert "errors" not in second["io_topology"]
        finally:
            release.set()
            if io_mod._stalled_worker is not None:
                io_mod._stalled_worker.join(5)


def test_walk_errors_surface_on_the_callers_thread(linux):
    """The dispatcher's telemetry records a collector error only if it is
    raised where the dispatcher can see it."""
    with patch.object(io_mod, "_read_topology", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError, match="boom"):
            io_topology()


# --- helpers --------------------------------------------------------------


def test_io_names_resolve_bang_both_ways():
    known = {"cciss/c0d0p1", "md_x!", "md_a/b!"}
    with patch("fivenines_agent.io._diskstats_names", return_value=known):
        io_name = _IoNames()
        assert io_name("cciss!c0d0p1") == "cciss/c0d0p1"
        assert io_name("md_x!") == "md_x!"
        # A '/' and a literal '!' in one name: sysfs shows both as '!'.
        assert io_name("md_a!b!") == "md_a/b!"
        assert io_name("gone!") is None


def test_io_names_refuse_a_name_two_diskstats_names_escape_to():
    with patch("fivenines_agent.io._diskstats_names", return_value={"a/b", "a!b"}):
        assert _IoNames()("a!b") is None


def test_io_names_read_diskstats_only_for_a_bang_and_only_once():
    """The common path (no '!') never opens /proc/diskstats."""
    with patch("fivenines_agent.io._diskstats_names", return_value={"a/b"}) as names:
        io_name = _IoNames()
        assert io_name("sda1") == "sda1"
        assert io_name("nvme0n1p1") == "nvme0n1p1"
        names.assert_not_called()
        assert io_name("a!b") == "a/b"
        assert io_name("a!b") == "a/b"
        names.assert_called_once_with()


def test_diskstats_names_parses_the_name_column(tmp_path):
    proc = tmp_path / "diskstats"
    proc.write_text(_diskstats_text(["sda", "cciss/c0d0"]) + "\n  8 0\n")
    with patch("fivenines_agent.io.PROC_DISKSTATS", str(proc)):
        assert _diskstats_names() == {"sda", "cciss/c0d0"}


def test_diskstats_names_decode_with_the_filesystem_encoding(tmp_path):
    """The encoding psutil (and os.listdir) use, not the locale's."""
    proc = tmp_path / "diskstats"
    proc.write_bytes(b"   9 0 md_\xe9 1 2\n")
    with patch("fivenines_agent.io.PROC_DISKSTATS", str(proc)), patch(
        "fivenines_agent.io.sys.getfilesystemencoding", return_value="latin-1"
    ):
        assert _diskstats_names() == {"md_\xe9"}


def test_diskstats_names_empty_when_unreadable(tmp_path):
    with patch("fivenines_agent.io.PROC_DISKSTATS", str(tmp_path / "missing")):
        assert _diskstats_names() == set()


def test_nvme_multipath_head_is_a_layer_over_its_paths(tmp_path, linux):
    """The head links its hidden path disks from multipath/, not slaves/; both
    carry the same I/O in /proc/diskstats, so the head must read as a layer."""
    out = _topology_of(
        tmp_path,
        {
            "nvme0n1": {
                "device": True,
                "slaves": [],
                "multipath": ["nvme0c1n1", "nvme0c0n1"],
                "partitions": ["nvme0n1p1"],
            },
            "nvme0c0n1": {"device": True, "slaves": []},
            "nvme0c1n1": {"device": True, "slaves": []},
        },
    )
    assert out == {
        "nvme0c0n1": {"slaves": [], "virtual": False},
        "nvme0c1n1": {"slaves": [], "virtual": False},
        "nvme0n1": {"slaves": ["nvme0c0n1", "nvme0c1n1"], "virtual": False},
        "nvme0n1p1": {"partition_of": "nvme0n1"},
    }


def test_nvme_head_before_6_15_is_derived_from_its_path_names(tmp_path, linux):
    """No multipath/ links before Linux 6.15: the kernel names a hidden path
    nvme{S}c{C}n{H} after its head nvme{S}n{H}, so the head is derived. An NVMe
    with no head (nvme0n1, no hidden paths) stays a plain leaf."""
    out = _topology_of(
        tmp_path,
        {
            "nvme1n1": {"device": True, "slaves": []},
            "nvme1c0n1": {"device": True, "slaves": [], "hidden": True},
            "nvme1c1n1": {"device": True, "slaves": [], "hidden": True},
            "nvme0n1": {"device": True, "slaves": []},
        },
    )
    assert out["nvme1n1"] == {"slaves": ["nvme1c0n1", "nvme1c1n1"], "virtual": False}
    assert out["nvme1c0n1"] == {"slaves": [], "virtual": False}
    assert out["nvme0n1"] == {"slaves": [], "virtual": False}


def test_derivation_keeps_multi_digit_instances_and_namespaces_apart(tmp_path, linux):
    """Ten-plus subsystems and controllers, and several namespaces per
    subsystem (NVMe-oF arrays), are the usual native-multipath hosts: each
    path goes to its own subsystem's own namespace head, and nowhere else."""
    out = _topology_of(
        tmp_path,
        {
            "nvme1n1": {"device": True, "slaves": []},
            "nvme10n1": {"device": True, "slaves": []},
            "nvme10n2": {"device": True, "slaves": []},
            "nvme10c12n1": {"device": True, "slaves": [], "hidden": True},
            "nvme10c3n1": {"device": True, "slaves": [], "hidden": True},
            "nvme10c12n2": {"device": True, "slaves": [], "hidden": True},
            "nvme10n12": {"device": True, "slaves": []},
            "nvme10c3n12": {"device": True, "slaves": [], "hidden": True},
        },
    )
    assert out["nvme10n1"]["slaves"] == ["nvme10c12n1", "nvme10c3n1"]
    assert out["nvme10n2"]["slaves"] == ["nvme10c12n2"]
    assert out["nvme10n12"]["slaves"] == ["nvme10c3n12"]
    assert out["nvme1n1"]["slaves"] == []


def test_hidden_paths_found_both_ways_are_listed_once(tmp_path, linux):
    """On 6.15+ multipath/ and the name derivation find the same paths."""
    out = _topology_of(
        tmp_path,
        {
            "nvme0n1": {"device": True, "slaves": [], "multipath": ["nvme0c0n1"]},
            "nvme0c0n1": {"device": True, "slaves": [], "hidden": True},
        },
    )
    assert out["nvme0n1"]["slaves"] == ["nvme0c0n1"]


def test_a_path_missing_its_multipath_link_is_still_attached_in_order(tmp_path, linux):
    """A path whose multipath/ link was not created (the race 08937bcd4cfe
    fixes upstream) is still found by name, and slaves stays sorted."""
    out = _topology_of(
        tmp_path,
        {
            "nvme0n1": {"device": True, "slaves": [], "multipath": ["nvme0c1n1"]},
            "nvme0c0n1": {"device": True, "slaves": [], "hidden": True},
            "nvme0c1n1": {"device": True, "slaves": [], "hidden": True},
        },
    )
    assert out["nvme0n1"]["slaves"] == ["nvme0c0n1", "nvme0c1n1"]


def test_a_path_whose_own_entry_is_unreadable_is_still_listed(tmp_path, linux):
    """The head's list is a fact about the head, as multipath/ would give it;
    the path itself is left out as unknown."""
    out = _topology_of(
        tmp_path,
        {
            "nvme0n1": {"device": True, "slaves": []},
            "nvme0c0n1": {"device": True, "slaves": None, "hidden": True},
        },
    )
    assert out == {"nvme0n1": {"slaves": ["nvme0c0n1"], "virtual": False}}


@pytest.mark.parametrize(
    "model",
    [
        # The derived head does not exist (not live yet under ANA).
        {
            "nvme0n1": {"device": True, "slaves": []},
            "nvme1c0n1": {"device": True, "slaves": [], "hidden": True},
        },
        # The derived head's own entry is unreadable: it is left out, never
        # given a list, and nothing else inherits its path.
        {
            "nvme0n1": {"device": True, "slaves": None},
            "nvme0c0n1": {"device": True, "slaves": [], "hidden": True},
            "nvme9n1": {"device": True, "slaves": []},
        },
        # Path-shaped name, but the disk is not hidden.
        {
            "nvme0n1": {"device": True, "slaves": []},
            "nvme0c0n1": {"device": True, "slaves": []},
        },
    ],
)
def test_a_path_without_its_head_attaches_nothing(model, tmp_path, linux):
    """Nothing is claimed: every whole device that is reported stays a leaf."""
    out = _topology_of(tmp_path, model)
    assert all(entry.get("slaves") == [] for entry in out.values())


def test_a_path_whose_hidden_attribute_cannot_be_read_leaves_its_head_out(
    tmp_path, linux
):
    block = _build_sys_block(
        tmp_path,
        {
            "nvme0n1": {"device": True, "slaves": []},
            "nvme0c0n1": {"device": True, "slaves": [], "hidden": True},
        },
    )
    os.unlink(tmp_path / "devices" / "nvme0c0n1" / "hidden")
    with patch("fivenines_agent.io.SYS_BLOCK", str(block)):
        out = io_topology()
    # The head's list cannot be established: unknown, never [] beside a path.
    assert out == {"nvme0c0n1": {"slaves": [], "virtual": False}}


def test_two_unreadable_paths_leave_their_head_out_once(tmp_path, linux):
    """The head is dropped by the first path; the second must not fail on it,
    nor may a path whose derived head was never reported."""
    block = _build_sys_block(
        tmp_path,
        {
            "nvme0n1": {"device": True, "slaves": []},
            "nvme0c0n1": {"device": True, "slaves": [], "hidden": True},
            "nvme0c1n1": {"device": True, "slaves": [], "hidden": True},
            "nvme1c0n1": {"device": True, "slaves": [], "hidden": True},
        },
    )
    for path in ("nvme0c0n1", "nvme0c1n1", "nvme1c0n1"):
        os.unlink(tmp_path / "devices" / path / "hidden")
    with patch("fivenines_agent.io.SYS_BLOCK", str(block)):
        out = io_topology()
    leaf = {"slaves": [], "virtual": False}
    assert out == {"nvme0c0n1": leaf, "nvme0c1n1": leaf, "nvme1c0n1": leaf}


def test_a_path_hot_removed_mid_walk_does_not_unseat_its_head(tmp_path, linux):
    """ENOENT on `hidden` because the path is gone is not an unknown head: the
    head's multipath/ links were read before, and the path is no longer one."""
    block = _build_sys_block(
        tmp_path,
        {
            "nvme0n1": {
                "device": True,
                "slaves": [],
                "multipath": ["nvme0c0n1", "nvme0c1n1"],
            },
            "nvme0c0n1": {"device": True, "slaves": [], "hidden": True},
            "nvme0c1n1": {"device": True, "slaves": [], "hidden": True},
        },
    )
    real_read_attr = _read_attr

    def unplug_then_read(path, attr):
        if path.endswith("nvme0c1n1") and attr == "hidden":
            shutil.rmtree(tmp_path / "devices" / "nvme0c1n1")
            os.unlink(block / "nvme0c1n1")
        return real_read_attr(path, attr)

    with patch("fivenines_agent.io.SYS_BLOCK", str(block)), patch(
        "fivenines_agent.io._read_attr", side_effect=unplug_then_read
    ):
        out = io_topology()
    assert out["nvme0n1"] == {
        "slaves": ["nvme0c0n1", "nvme0c1n1"],
        "virtual": False,
    }


def test_a_derived_head_that_is_a_partition_is_left_alone(tmp_path, linux):
    """Only root could arrange it (a disk nvme0n partitioned into nvme0n1),
    but it must not null the map with a KeyError."""
    out = _topology_of(
        tmp_path,
        {
            "nvme0n": {"device": True, "slaves": [], "partitions": ["nvme0n1"]},
            "nvme0c0n1": {"device": True, "slaves": [], "hidden": True},
        },
    )
    assert out["nvme0n1"] == {"partition_of": "nvme0n"}
    assert out["nvme0c0n1"] == {"slaves": [], "virtual": False}


def test_hidden_is_read_only_for_path_shaped_names(tmp_path, linux):
    """The fallback costs nothing on a host without NVMe multipath."""
    real_read_attr = _read_attr
    with patch(
        "fivenines_agent.io._read_attr", side_effect=real_read_attr
    ) as read_attr:
        _topology_of(
            tmp_path,
            {
                "sda": {"device": True, "slaves": []},
                "nvme0n1": {"device": True, "slaves": []},
                "nvme0c0n1": {"device": True, "slaves": [], "hidden": True},
            },
        )
    assert [os.path.basename(c.args[0]) for c in read_attr.call_args_list] == [
        "nvme0c0n1"
    ]


def test_read_attr_is_none_when_unreadable(tmp_path):
    assert _read_attr(str(tmp_path), "hidden") is None
    (tmp_path / "hidden").write_text("  1  \n")
    assert _read_attr(str(tmp_path), "hidden") == "1"


def test_unreadable_multipath_dir_leaves_the_head_out(tmp_path):
    """Only ENOENT means "not a head"; a multipath/ that cannot be read would
    make the list partial, and a partial list is a false claim."""
    block = _build_sys_block(tmp_path, {"nvme0n1": {"device": True, "slaves": []}})
    real_listdir = os.listdir

    def denied(path):
        if path.endswith("multipath"):
            raise PermissionError(path)
        return real_listdir(path)

    with patch("fivenines_agent.io.os.listdir", side_effect=denied):
        assert _whole_device(str(block / "nvme0n1"), _IoNames()) is None


def test_whole_device_sorts_slaves(tmp_path):
    """listdir order is the filesystem's; the payload's must not be."""
    block = _build_sys_block(tmp_path, {"md0": {"device": False, "slaves": []}})

    def listdir(path):
        if path.endswith("multipath"):
            raise FileNotFoundError(path)
        return ["sdb1", "sda1"]

    with patch("fivenines_agent.io.os.listdir", side_effect=listdir):
        assert _whole_device(str(block / "md0"), _IoNames()) == {
            "slaves": ["sda1", "sdb1"],
            "virtual": True,
        }


def test_whole_device_counts_a_dangling_device_link_as_hardware(tmp_path):
    """The link's presence is the signal (lstat), not whether it resolves."""
    block = _build_sys_block(tmp_path, {"sda": {"device": False, "slaves": []}})
    os.symlink(os.path.join(os.pardir, "nowhere"), block / "sda" / "device")
    assert _whole_device(str(block / "sda"), _IoNames()) == {
        "slaves": [],
        "virtual": False,
    }


def test_whole_device_vanishing_mid_read_is_unknown_not_virtual(tmp_path):
    """A disk hot-removed between the slaves/ read and the device lstat also
    answers ENOENT; calling it virtual would drop its already-collected `io`
    row from the server's total."""
    block = _build_sys_block(tmp_path, {"sdz": {"device": True, "slaves": []}})
    device_link = str(block / "sdz" / "device")
    real_lstat = os.lstat

    def unplug_on_device_lstat(path, *args, **kwargs):
        if path == device_link:
            # The device directory goes; /sys/block/sdz is left dangling
            # (portable: Windows cannot os.unlink a directory symlink).
            shutil.rmtree(tmp_path / "devices" / "sdz")
        return real_lstat(path, *args, **kwargs)

    with patch("fivenines_agent.io.os.lstat", side_effect=unplug_on_device_lstat):
        assert _whole_device(str(block / "sdz"), _IoNames()) is None


def test_whole_device_unknown_when_device_link_cannot_be_checked(tmp_path):
    """Only ENOENT means virtual; any other failure is unknown, never a claim.

    Only the `device` link fails: slaves/ must stay visible, or the hot-removal
    fallback (lexists on slaves/) would return None for the wrong reason and a
    code path treating every lstat error as ENOENT would pass unnoticed."""
    block = _build_sys_block(tmp_path, {"sda": {"device": True, "slaves": []}})
    device_link = str(block / "sda" / "device")
    real_lstat = os.lstat

    def denied(path, *args, **kwargs):
        if path == device_link:
            raise PermissionError(path)
        return real_lstat(path, *args, **kwargs)

    with patch("fivenines_agent.io.os.lstat", side_effect=denied):
        assert _whole_device(str(block / "sda"), _IoNames()) is None


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
      data['io_topology'] and asserts the I/O totals per counting_contract.

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
