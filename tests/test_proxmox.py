"""Tests for fivenines_agent.proxmox module."""

from unittest.mock import patch

from fivenines_agent.proxmox import proxmox_metrics


def test_proxmox_metrics_no_proxmoxer():
    """proxmox_metrics returns None when proxmoxer is not installed."""
    with patch("fivenines_agent.proxmox.ProxmoxAPI", None):
        result = proxmox_metrics()
        assert result is None
