"""Tests for Agent.packages_sync()."""

import sys
from unittest.mock import MagicMock, patch


# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())


from fivenines_agent.agent import Agent  # noqa: E402

PACKAGES_CONFIG = {"scan": True, "last_scan_at": None, "last_package_hash": None}


def make_agent():
    """Create an Agent-like object with packages_sync attached."""
    agent = Agent.__new__(Agent)
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer = MagicMock()
    return agent


# --- packages_sync ---


@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_no_packages_key(mock_hash, mock_distro, mock_pkgs):
    agent = make_agent()
    agent.config = {"enabled": True}

    agent.packages_sync()

    mock_distro.assert_not_called()
    mock_pkgs.assert_not_called()


@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_packages_none(mock_hash, mock_distro, mock_pkgs):
    agent = make_agent()
    agent.config = {"enabled": True, "packages": None}

    agent.packages_sync()

    mock_distro.assert_not_called()


@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_scan_false(mock_hash, mock_distro, mock_pkgs):
    agent = make_agent()
    agent.config = {"enabled": True, "packages": {"scan": False}}

    agent.packages_sync()

    mock_distro.assert_not_called()


@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_no_packages_found(mock_hash, mock_distro, mock_pkgs):
    agent = make_agent()
    agent.config = {"enabled": True, "packages": PACKAGES_CONFIG}
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = []

    agent.packages_sync()

    mock_distro.assert_called_once()
    mock_pkgs.assert_called_once()
    mock_hash.assert_not_called()
    agent.synchronizer.send_packages.assert_not_called()


@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_hash_matches_server(mock_hash, mock_distro, mock_pkgs):
    agent = make_agent()
    agent.config = {
        "enabled": True,
        "packages": {"scan": True, "last_package_hash": "abc123"},
    }
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "abc123"

    agent.packages_sync()

    agent.synchronizer.send_packages.assert_not_called()


@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_sends_on_hash_change(mock_hash, mock_distro, mock_pkgs, mock_dry):
    agent = make_agent()
    agent.config = {
        "enabled": True,
        "packages": {"scan": True, "last_package_hash": "old_hash"},
    }
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"
    agent.synchronizer.send_packages.return_value = {"status": "queued"}

    agent.packages_sync()

    agent.synchronizer.send_packages.assert_called_once_with(
        {
            "distro": "debian:12",
            "packages_hash": "new_hash",
            "packages": [{"name": "openssl", "version": "3.0"}],
        }
    )


@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_sends_when_server_hash_is_none(mock_hash, mock_distro, mock_pkgs, mock_dry):
    """First scan ever: server has no hash yet."""
    agent = make_agent()
    agent.config = {"enabled": True, "packages": PACKAGES_CONFIG}
    mock_distro.return_value = "ubuntu:22.04"
    mock_pkgs.return_value = [{"name": "bash", "version": "5.0"}]
    mock_hash.return_value = "hash1"
    agent.synchronizer.send_packages.return_value = {"status": "queued"}

    agent.packages_sync()

    agent.synchronizer.send_packages.assert_called_once()


@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_failure_logs_error(mock_hash, mock_distro, mock_pkgs, mock_dry):
    agent = make_agent()
    agent.config = {"enabled": True, "packages": PACKAGES_CONFIG}
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"
    agent.synchronizer.send_packages.return_value = None

    agent.packages_sync()

    agent.synchronizer.send_packages.assert_called_once()


@patch("fivenines_agent.agent.dry_run", return_value=True)
@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_dry_run_skips_send(mock_hash, mock_distro, mock_pkgs, mock_dry):
    agent = make_agent()
    agent.config = {"enabled": True, "packages": PACKAGES_CONFIG}
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"

    agent.packages_sync()

    agent.synchronizer.send_packages.assert_not_called()
