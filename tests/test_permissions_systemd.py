"""Tests for the systemd and cgroup capabilities in PermissionProbe."""

import io
import subprocess
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from fivenines_agent.permissions import PermissionProbe, print_capabilities_banner


def _make_probe():
    """Create a probe instance without invoking _probe_all in __init__."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    return probe


# --- _can_probe_systemd ---


@patch.object(PermissionProbe, "_probe_all")
def test_can_probe_systemd_happy(mock_probe):
    probe = _make_probe()
    fake = MagicMock(returncode=0)
    with patch("fivenines_agent.permissions.os.path.isdir", return_value=True):
        with patch(
            "fivenines_agent.permissions.shutil.which",
            return_value="/usr/bin/systemctl",
        ):
            with patch("fivenines_agent.permissions.subprocess.run", return_value=fake):
                assert probe._can_probe_systemd() is True


@patch.object(PermissionProbe, "_probe_all")
def test_can_probe_systemd_no_run_systemd_directory(mock_probe):
    """Alpine OpenRC, BusyBox containers: /run/systemd/system absent."""
    probe = _make_probe()
    with patch("fivenines_agent.permissions.os.path.isdir", return_value=False):
        assert probe._can_probe_systemd() is False


@patch.object(PermissionProbe, "_probe_all")
def test_can_probe_systemd_no_systemctl_binary(mock_probe):
    probe = _make_probe()
    with patch("fivenines_agent.permissions.os.path.isdir", return_value=True):
        with patch("fivenines_agent.permissions.shutil.which", return_value=None):
            assert probe._can_probe_systemd() is False


@patch.object(PermissionProbe, "_probe_all")
def test_can_probe_systemd_timeout(mock_probe):
    probe = _make_probe()
    with patch("fivenines_agent.permissions.os.path.isdir", return_value=True):
        with patch(
            "fivenines_agent.permissions.shutil.which",
            return_value="/usr/bin/systemctl",
        ):
            with patch(
                "fivenines_agent.permissions.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="systemctl", timeout=5),
            ):
                assert probe._can_probe_systemd() is False


@patch.object(PermissionProbe, "_probe_all")
def test_can_probe_systemd_oserror(mock_probe):
    probe = _make_probe()
    with patch("fivenines_agent.permissions.os.path.isdir", return_value=True):
        with patch(
            "fivenines_agent.permissions.shutil.which",
            return_value="/usr/bin/systemctl",
        ):
            with patch(
                "fivenines_agent.permissions.subprocess.run",
                side_effect=OSError("no exec"),
            ):
                assert probe._can_probe_systemd() is False


@patch.object(PermissionProbe, "_probe_all")
def test_can_probe_systemd_non_zero_exit(mock_probe):
    probe = _make_probe()
    fake = MagicMock(returncode=1)
    with patch("fivenines_agent.permissions.os.path.isdir", return_value=True):
        with patch(
            "fivenines_agent.permissions.shutil.which",
            return_value="/usr/bin/systemctl",
        ):
            with patch("fivenines_agent.permissions.subprocess.run", return_value=fake):
                assert probe._can_probe_systemd() is False


# --- _detect_cgroup_hierarchy ---


@patch.object(PermissionProbe, "_probe_all")
def test_detect_cgroup_hierarchy_v2(mock_probe):
    probe = _make_probe()
    with patch(
        "fivenines_agent.permissions.os.path.exists",
        side_effect=lambda p: p == "/sys/fs/cgroup/cgroup.controllers",
    ):
        assert probe._detect_cgroup_hierarchy() == "v2"


@patch.object(PermissionProbe, "_probe_all")
def test_detect_cgroup_hierarchy_v1(mock_probe):
    probe = _make_probe()
    with patch("fivenines_agent.permissions.os.path.exists", return_value=False):
        with patch(
            "fivenines_agent.permissions.os.path.isdir",
            side_effect=lambda p: p == "/sys/fs/cgroup/memory",
        ):
            assert probe._detect_cgroup_hierarchy() == "v1"


@patch.object(PermissionProbe, "_probe_all")
def test_detect_cgroup_hierarchy_none(mock_probe):
    probe = _make_probe()
    with patch("fivenines_agent.permissions.os.path.exists", return_value=False):
        with patch("fivenines_agent.permissions.os.path.isdir", return_value=False):
            assert probe._detect_cgroup_hierarchy() is None


# --- Banner placement ---


def _print_banner_with_capabilities(caps):
    """Helper to capture banner output for a given capabilities dict."""

    class FakeProbe:
        def get_all(self):
            return caps

        def get_unavailable(self):
            return [k for k, v in caps.items() if not v]

    buf = io.StringIO()
    with patch("fivenines_agent.permissions.get_permissions", return_value=FakeProbe()):
        with redirect_stdout(buf):
            print_capabilities_banner()
    return buf.getvalue()


def _full_caps(systemd=False, cgroup=False):
    """Return a complete capabilities dict for banner rendering."""
    return {
        "cpu": True,
        "memory": True,
        "load_average": True,
        "io": True,
        "network": True,
        "partitions": True,
        "file_handles": True,
        "ports": True,
        "processes": True,
        "temperatures": False,
        "fans": False,
        "nvidia_gpu": False,
        "smart_storage": False,
        "raid_storage": False,
        "zfs": False,
        "docker": False,
        "qemu": False,
        "proxmox": False,
        "fail2ban": False,
        "packages": False,
        "snmp": False,
        "systemd": systemd,
        "cgroup": cgroup,
    }


def test_banner_systemd_in_services_section_when_available():
    output = _print_banner_with_capabilities(_full_caps(systemd=True))
    # systemd row should be in the Services section, not Hardware
    services_idx = output.index("Services:")
    systemd_idx = output.index("Systemd")
    assert systemd_idx > services_idx
    assert "[+] Systemd" in output


def test_banner_systemd_unavailable_hint():
    output = _print_banner_with_capabilities(_full_caps(systemd=False))
    assert "[-] Systemd (requires: systemd init system)" in output


def test_banner_cgroup_v2_renders_with_version_in_name():
    output = _print_banner_with_capabilities(_full_caps(cgroup="v2"))
    assert "[+] Cgroup v2" in output


def test_banner_cgroup_v1_renders_with_version_in_name():
    output = _print_banner_with_capabilities(_full_caps(cgroup="v1"))
    assert "[+] Cgroup v1" in output


def test_banner_cgroup_unavailable_hint():
    output = _print_banner_with_capabilities(_full_caps(cgroup=False))
    assert "[-] Cgroup (no /sys/fs/cgroup hierarchy found)" in output


def test_banner_cgroup_in_hardware_section():
    """cgroup is a kernel surface, listed under Hardware Sensors."""
    output = _print_banner_with_capabilities(_full_caps(cgroup="v2"))
    hardware_idx = output.index("Hardware Sensors:")
    services_idx = output.index("Services:")
    cgroup_idx = output.index("Cgroup")
    assert hardware_idx < cgroup_idx < services_idx
