"""Tests for the GPU capability in PermissionProbe."""

import sys
from unittest.mock import MagicMock, patch

from fivenines_agent.permissions import PermissionProbe


@patch.object(PermissionProbe, "_probe_all")
def test_can_access_gpu_found(mock_probe):
    """GPU found (count > 0) returns True."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}

    mock_nvml = MagicMock()
    mock_nvml.nvmlDeviceGetCount.return_value = 2

    with patch.dict(sys.modules, {"pynvml": mock_nvml}):
        assert probe._can_access_gpu() is True

    mock_nvml.nvmlInit.assert_called_once()
    mock_nvml.nvmlShutdown.assert_called_once()


@patch.object(PermissionProbe, "_probe_all")
def test_can_access_gpu_zero_devices(mock_probe):
    """Zero GPUs returns False."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}

    mock_nvml = MagicMock()
    mock_nvml.nvmlDeviceGetCount.return_value = 0

    with patch.dict(sys.modules, {"pynvml": mock_nvml}):
        assert probe._can_access_gpu() is False

    mock_nvml.nvmlShutdown.assert_called_once()


@patch.object(PermissionProbe, "_probe_all")
def test_can_access_gpu_init_fails(mock_probe):
    """nvmlInit failure returns False."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}

    mock_nvml = MagicMock()
    mock_nvml.nvmlInit.side_effect = Exception("driver not loaded")

    with patch.dict(sys.modules, {"pynvml": mock_nvml}):
        assert probe._can_access_gpu() is False


@patch.object(PermissionProbe, "_probe_all")
def test_can_access_gpu_no_pynvml(mock_probe):
    """pynvml not installed returns False."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}

    # Ensure pynvml is not available
    saved = sys.modules.pop("pynvml", None)
    try:
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "pynvml":
                raise ImportError("No module named 'pynvml'")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=fake_import):
            assert probe._can_access_gpu() is False
    finally:
        if saved is not None:
            sys.modules["pynvml"] = saved


@patch.object(PermissionProbe, "_probe_all")
def test_can_access_gpu_shutdown_called_on_exception(mock_probe):
    """nvmlShutdown is called even when nvmlDeviceGetCount raises."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}

    mock_nvml = MagicMock()
    mock_nvml.nvmlDeviceGetCount.side_effect = Exception("unexpected")

    with patch.dict(sys.modules, {"pynvml": mock_nvml}):
        assert probe._can_access_gpu() is False

    mock_nvml.nvmlShutdown.assert_called_once()
