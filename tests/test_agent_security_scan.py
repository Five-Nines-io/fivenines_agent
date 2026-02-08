"""Tests for packages_sync() standalone function."""

from unittest.mock import MagicMock, patch

from fivenines_agent.packages import packages_sync


PACKAGES_CONFIG = {"scan": True, "last_scan_at": None, "last_package_hash": None}


# --- packages_sync ---


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_no_packages_key(mock_hash, mock_distro, mock_pkgs):
    config = {"enabled": True}
    send_fn = MagicMock()

    packages_sync(config, send_fn)

    mock_distro.assert_not_called()
    mock_pkgs.assert_not_called()


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_packages_none(mock_hash, mock_distro, mock_pkgs):
    config = {"enabled": True, "packages": None}
    send_fn = MagicMock()

    packages_sync(config, send_fn)

    mock_distro.assert_not_called()


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_scan_false(mock_hash, mock_distro, mock_pkgs):
    config = {"enabled": True, "packages": {"scan": False}}
    send_fn = MagicMock()

    packages_sync(config, send_fn)

    mock_distro.assert_not_called()


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_no_packages_found(mock_hash, mock_distro, mock_pkgs):
    config = {"enabled": True, "packages": PACKAGES_CONFIG}
    send_fn = MagicMock()
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = []

    packages_sync(config, send_fn)

    mock_distro.assert_called_once()
    mock_pkgs.assert_called_once()
    mock_hash.assert_not_called()
    send_fn.assert_not_called()


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_hash_matches_server(mock_hash, mock_distro, mock_pkgs):
    config = {
        "enabled": True,
        "packages": {"scan": True, "last_package_hash": "abc123"},
    }
    send_fn = MagicMock()
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "abc123"

    packages_sync(config, send_fn)

    send_fn.assert_not_called()


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_sends_on_hash_change(mock_hash, mock_distro, mock_pkgs, mock_dry):
    config = {
        "enabled": True,
        "packages": {"scan": True, "last_package_hash": "old_hash"},
    }
    send_fn = MagicMock(return_value={"status": "queued"})
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"

    packages_sync(config, send_fn)

    send_fn.assert_called_once_with(
        {
            "distro": "debian:12",
            "packages_hash": "new_hash",
            "packages": [{"name": "openssl", "version": "3.0"}],
        }
    )


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_sends_when_server_hash_is_none(mock_hash, mock_distro, mock_pkgs, mock_dry):
    """First scan ever: server has no hash yet."""
    config = {"enabled": True, "packages": PACKAGES_CONFIG}
    send_fn = MagicMock(return_value={"status": "queued"})
    mock_distro.return_value = "ubuntu:22.04"
    mock_pkgs.return_value = [{"name": "bash", "version": "5.0"}]
    mock_hash.return_value = "hash1"

    packages_sync(config, send_fn)

    send_fn.assert_called_once()


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_failure_logs_error(mock_hash, mock_distro, mock_pkgs, mock_dry):
    config = {"enabled": True, "packages": PACKAGES_CONFIG}
    send_fn = MagicMock(return_value=None)
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"

    packages_sync(config, send_fn)

    send_fn.assert_called_once()


@patch("fivenines_agent.packages.dry_run", return_value=True)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_dry_run_skips_send(mock_hash, mock_distro, mock_pkgs, mock_dry):
    config = {"enabled": True, "packages": PACKAGES_CONFIG}
    send_fn = MagicMock()
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"

    packages_sync(config, send_fn)

    send_fn.assert_not_called()
