"""Tests for Agent._maybe_run_security_scan()."""

import sys
from unittest.mock import MagicMock, patch


# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())


from fivenines_agent.agent import Agent  # noqa: E402


def make_agent():
    """Create an Agent-like object with _maybe_run_security_scan attached."""
    # Create a minimal agent-like object without running __init__
    agent = Agent.__new__(Agent)
    agent._last_packages_hash = ""
    agent.config = {"enabled": True, "interval": 60}
    agent.synchronizer = MagicMock()
    return agent


# --- _maybe_run_security_scan ---


@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_security_scan_not_configured(mock_hash, mock_distro, mock_pkgs):
    agent = make_agent()
    agent.config = {"enabled": True}  # no security_scan key

    agent._maybe_run_security_scan()

    mock_distro.assert_not_called()
    mock_pkgs.assert_not_called()


@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_security_scan_disabled(mock_hash, mock_distro, mock_pkgs):
    agent = make_agent()
    agent.config = {"enabled": True, "security_scan": None}

    agent._maybe_run_security_scan()

    mock_distro.assert_not_called()


@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_security_scan_no_packages(mock_hash, mock_distro, mock_pkgs):
    agent = make_agent()
    agent.config = {"enabled": True, "security_scan": {}}
    mock_distro.return_value = "debian"
    mock_pkgs.return_value = []

    agent._maybe_run_security_scan()

    mock_distro.assert_called_once()
    mock_pkgs.assert_called_once()
    mock_hash.assert_not_called()
    agent.synchronizer.send_security_scan.assert_not_called()


@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_security_scan_hash_unchanged(mock_hash, mock_distro, mock_pkgs):
    agent = make_agent()
    agent.config = {"enabled": True, "security_scan": {}}
    agent._last_packages_hash = "abc123"
    mock_distro.return_value = "debian"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "abc123"

    agent._maybe_run_security_scan()

    agent.synchronizer.send_security_scan.assert_not_called()


@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_security_scan_sends_on_hash_change(
    mock_hash, mock_distro, mock_pkgs, mock_dry
):
    agent = make_agent()
    agent.config = {"enabled": True, "security_scan": {}}
    agent._last_packages_hash = "old_hash"
    mock_distro.return_value = "debian"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"
    agent.synchronizer.send_security_scan.return_value = {"status": "queued"}

    agent._maybe_run_security_scan()

    agent.synchronizer.send_security_scan.assert_called_once_with(
        {
            "distro": "debian",
            "packages_hash": "new_hash",
            "packages": [{"name": "openssl", "version": "3.0"}],
        }
    )
    assert agent._last_packages_hash == "new_hash"


@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_security_scan_failure_keeps_old_hash(
    mock_hash, mock_distro, mock_pkgs, mock_dry
):
    agent = make_agent()
    agent.config = {"enabled": True, "security_scan": {}}
    mock_distro.return_value = "debian"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"
    agent.synchronizer.send_security_scan.return_value = None  # failure

    agent._maybe_run_security_scan()

    assert agent._last_packages_hash == ""  # unchanged


@patch("fivenines_agent.agent.dry_run", return_value=True)
@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_security_scan_dry_run_skips_send(
    mock_hash, mock_distro, mock_pkgs, mock_dry
):
    agent = make_agent()
    agent.config = {"enabled": True, "security_scan": {}}
    mock_distro.return_value = "debian"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"

    agent._maybe_run_security_scan()

    agent.synchronizer.send_security_scan.assert_not_called()


@patch("fivenines_agent.agent.dry_run", return_value=False)
@patch("fivenines_agent.agent.get_installed_packages")
@patch("fivenines_agent.agent.get_distro")
@patch("fivenines_agent.agent.get_packages_hash")
def test_security_scan_first_run(mock_hash, mock_distro, mock_pkgs, mock_dry):
    """First run sends scan when packages are found."""
    agent = make_agent()
    agent.config = {"enabled": True, "security_scan": {}}
    mock_distro.return_value = "ubuntu"
    mock_pkgs.return_value = [{"name": "bash", "version": "5.0"}]
    mock_hash.return_value = "hash1"
    agent.synchronizer.send_security_scan.return_value = {"status": "queued"}

    agent._maybe_run_security_scan()

    agent.synchronizer.send_security_scan.assert_called_once()
    assert agent._last_packages_hash == "hash1"
