"""Tests for the partitions collectors.

The collectors filter out pseudo / overlay filesystems on Linux and
read-only optical media (CDFS, UDF, ISO9660) on Windows. Empty CD/DVD
drives on Windows report as 100%-full partitions and would otherwise
trigger misleading disk-full alerts on the dashboard.
"""

from collections import namedtuple
from unittest.mock import patch

from fivenines_agent.partitions import (
    IGNORED_FS,
    _should_ignore,
    partitions_metadata,
    partitions_usage,
)


Partition = namedtuple("Partition", ["device", "mountpoint", "fstype", "opts"])
Usage = namedtuple("Usage", ["total", "used", "free", "percent"])


def test_should_ignore_pseudo_fs():
    """Linux pseudo / overlay filesystems are filtered out."""
    for fstype in ("squashfs", "overlay", "tmpfs", "devtmpfs", "nullfs"):
        assert _should_ignore(fstype, "rw") is True


def test_should_ignore_cdrom_fstypes():
    """Windows optical-media fstypes (CDFS/UDF/ISO9660) are filtered out."""
    for fstype in ("CDFS", "UDF", "ISO9660", "udf", "cdfs"):
        assert _should_ignore(fstype, "ro,readonly,cdrom") is True


def test_should_ignore_cdrom_opts():
    """opts='cdrom' triggers the filter even for unknown fstypes."""
    # On Windows the opts string carries 'cdrom' for optical drives even
    # when fstype is something unusual.
    assert _should_ignore("Unknown", "ro,cdrom") is True


def test_should_keep_real_fs():
    """Real filesystems (ext4, NTFS, ZFS, ...) pass the filter."""
    for fstype, opts in [
        ("ext4", "rw,relatime"),
        ("NTFS", "rw,fixed"),
        ("zfs", "rw,xattr"),
        ("xfs", "rw"),
    ]:
        assert _should_ignore(fstype, opts) is False


def test_partitions_metadata_filters_cdrom():
    """A Windows-style listing with a real disk + CD-ROM keeps only the disk."""
    fake = [
        Partition(device="C:\\", mountpoint="C:\\", fstype="NTFS", opts="rw,fixed"),
        Partition(device="D:\\", mountpoint="D:\\", fstype="UDF", opts="ro,readonly,cdrom"),
    ]
    with patch("fivenines_agent.partitions.psutil.disk_partitions", return_value=fake):
        result = partitions_metadata()
    assert len(result) == 1
    assert result[0]["device"] == "C:\\"


def test_partitions_usage_filters_cdrom():
    """partitions_usage skips the same set of filesystems as partitions_metadata."""
    fake = [
        Partition(device="C:\\", mountpoint="C:\\", fstype="NTFS", opts="rw,fixed"),
        Partition(device="D:\\", mountpoint="D:\\", fstype="UDF", opts="ro,readonly,cdrom"),
    ]
    with patch("fivenines_agent.partitions.psutil.disk_partitions", return_value=fake), \
         patch("fivenines_agent.partitions.psutil.disk_usage") as mock_usage:
        mock_usage.return_value = Usage(total=100, used=50, free=50, percent=50.0)
        result = partitions_usage()
    assert "C:\\" in result
    assert "D:\\" not in result
    # disk_usage was called once (for C:\\) and not at all for the CD-ROM.
    mock_usage.assert_called_once_with("C:\\")


def test_ignored_fs_includes_optical_media():
    """Regression guard: the IGNORED_FS list still has the optical entries."""
    for fstype in ("cdfs", "udf", "iso9660"):
        assert fstype in IGNORED_FS
