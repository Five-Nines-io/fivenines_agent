"""Tests for the packages capability in PermissionProbe."""

from unittest.mock import patch

from fivenines_agent.permissions import PermissionProbe


@patch.object(PermissionProbe, "_probe_all")
def test_can_list_packages_dpkg(mock_probe):
    """dpkg-query available should return True."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    with patch("fivenines_agent.permissions.shutil.which") as mock_which:
        mock_which.side_effect = lambda cmd: (
            "/usr/bin/dpkg-query" if cmd == "dpkg-query" else None
        )
        assert probe._can_list_packages() is True


@patch.object(PermissionProbe, "_probe_all")
def test_can_list_packages_rpm(mock_probe):
    """rpm available should return True."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    with patch("fivenines_agent.permissions.shutil.which") as mock_which:
        mock_which.side_effect = lambda cmd: "/usr/bin/rpm" if cmd == "rpm" else None
        assert probe._can_list_packages() is True


@patch.object(PermissionProbe, "_probe_all")
def test_can_list_packages_apk(mock_probe):
    """apk available should return True."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    with patch("fivenines_agent.permissions.shutil.which") as mock_which:
        mock_which.side_effect = lambda cmd: "/sbin/apk" if cmd == "apk" else None
        assert probe._can_list_packages() is True


@patch.object(PermissionProbe, "_probe_all")
def test_can_list_packages_pacman(mock_probe):
    """pacman available should return True."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    with patch("fivenines_agent.permissions.shutil.which") as mock_which:
        mock_which.side_effect = lambda cmd: (
            "/usr/bin/pacman" if cmd == "pacman" else None
        )
        assert probe._can_list_packages() is True


@patch.object(PermissionProbe, "_probe_all")
def test_can_list_packages_none(mock_probe):
    """No package manager should return False."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    with patch("fivenines_agent.permissions.shutil.which", return_value=None):
        assert probe._can_list_packages() is False
