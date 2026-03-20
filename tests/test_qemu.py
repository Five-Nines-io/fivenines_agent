"""Tests for fivenines_agent.qemu module."""

from unittest.mock import MagicMock, patch

from fivenines_agent.qemu import qemu_metrics


def test_qemu_metrics_no_libvirt():
    """qemu_metrics returns [] when libvirt is not installed."""
    with patch("fivenines_agent.qemu.libvirt", None):
        result = qemu_metrics()
        assert result == []
