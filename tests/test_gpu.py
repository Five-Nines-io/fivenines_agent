"""Tests for the NVIDIA GPU metrics collector."""

import importlib
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


# Mock libvirt before any fivenines_agent imports
sys.modules.setdefault("libvirt", MagicMock())


class TestGpuWithNvml:
    """Tests with a mocked pynvml module available."""

    def setup_method(self):
        self.mock_nvml = MagicMock()
        self.mock_nvml.NVML_TEMPERATURE_GPU = 0
        self.mock_nvml.NVML_CLOCK_SM = 0
        self.mock_nvml.NVML_CLOCK_MEM = 1
        sys.modules["pynvml"] = self.mock_nvml

        # Force re-import so HAS_NVML picks up the mock
        if "fivenines_agent.gpu" in sys.modules:
            del sys.modules["fivenines_agent.gpu"]

    def teardown_method(self):
        sys.modules.pop("pynvml", None)
        sys.modules.pop("fivenines_agent.gpu", None)

    def _import_gpu(self):
        import fivenines_agent.gpu as gpu_mod

        return gpu_mod

    def test_nvml_init_failure_returns_none(self):
        """When nvmlInit raises, gpu_metrics returns None."""
        self.mock_nvml.nvmlInit.side_effect = Exception("driver not loaded")
        gpu_mod = self._import_gpu()
        assert gpu_mod.gpu_metrics() is None

    def test_single_gpu_all_metrics(self):
        """Collect all metrics from a single GPU."""
        nvml = self.mock_nvml
        nvml.nvmlDeviceGetCount.return_value = 1

        handle = MagicMock()
        nvml.nvmlDeviceGetHandleByIndex.return_value = handle
        nvml.nvmlDeviceGetName.return_value = "NVIDIA RTX 4090"
        nvml.nvmlDeviceGetTemperature.return_value = 65
        nvml.nvmlDeviceGetFanSpeed.return_value = 45
        nvml.nvmlDeviceGetPowerUsage.return_value = 250000
        nvml.nvmlDeviceGetPowerManagementLimit.return_value = 450000
        nvml.nvmlDeviceGetUtilizationRates.return_value = SimpleNamespace(
            gpu=85, memory=60
        )
        nvml.nvmlDeviceGetMemoryInfo.return_value = SimpleNamespace(
            used=8000000000, total=24000000000, free=16000000000
        )
        nvml.nvmlDeviceGetClockInfo.side_effect = lambda h, t: (
            2100 if t == 0 else 1200
        )

        compute_proc = SimpleNamespace(pid=1234, usedGpuMemory=500000000)
        graphics_proc = SimpleNamespace(pid=5678, usedGpuMemory=200000000)
        nvml.nvmlDeviceGetComputeRunningProcesses.return_value = [compute_proc]
        nvml.nvmlDeviceGetGraphicsRunningProcesses.return_value = [graphics_proc]
        gpu_mod = self._import_gpu()
        result = gpu_mod.gpu_metrics()

        assert result is not None
        assert len(result) == 1
        gpu = result[0]
        assert gpu["index"] == 0
        assert gpu["name"] == "NVIDIA RTX 4090"
        assert gpu["temperature"] == 65
        assert gpu["fan_speed"] == 45
        assert gpu["power_draw"] == 250000
        assert gpu["power_limit"] == 450000
        assert gpu["utilization_gpu"] == 85
        assert gpu["utilization_memory"] == 60
        assert gpu["memory_used"] == 8000000000
        assert gpu["memory_total"] == 24000000000
        assert gpu["memory_free"] == 16000000000
        assert gpu["clock_sm"] == 2100
        assert gpu["clock_mem"] == 1200
        assert len(gpu["processes"]) == 2
        assert gpu["processes"][0] == {"pid": 1234, "memory_used": 500000000}
        assert gpu["processes"][1] == {"pid": 5678, "memory_used": 200000000}

        nvml.nvmlShutdown.assert_called_once()

    def test_multi_gpu(self):
        """Collect metrics from multiple GPUs."""
        nvml = self.mock_nvml
        nvml.nvmlDeviceGetCount.return_value = 2

        handle = MagicMock()
        nvml.nvmlDeviceGetHandleByIndex.return_value = handle
        nvml.nvmlDeviceGetName.return_value = "NVIDIA RTX 4090"
        nvml.nvmlDeviceGetTemperature.return_value = 50
        nvml.nvmlDeviceGetFanSpeed.return_value = 30
        nvml.nvmlDeviceGetPowerUsage.return_value = 100000
        nvml.nvmlDeviceGetPowerManagementLimit.return_value = 450000
        nvml.nvmlDeviceGetUtilizationRates.return_value = SimpleNamespace(
            gpu=10, memory=5
        )
        nvml.nvmlDeviceGetMemoryInfo.return_value = SimpleNamespace(
            used=1000, total=24000, free=23000
        )
        nvml.nvmlDeviceGetClockInfo.return_value = 1500
        nvml.nvmlDeviceGetComputeRunningProcesses.return_value = []
        nvml.nvmlDeviceGetGraphicsRunningProcesses.return_value = []

        gpu_mod = self._import_gpu()
        result = gpu_mod.gpu_metrics()

        assert len(result) == 2
        assert result[0]["index"] == 0
        assert result[1]["index"] == 1

    def test_safe_helper_returns_none_on_error(self):
        """When all NVML getters raise, values are None."""
        nvml = self.mock_nvml
        nvml.nvmlDeviceGetCount.return_value = 1

        handle = MagicMock()
        nvml.nvmlDeviceGetHandleByIndex.return_value = handle
        nvml.nvmlDeviceGetName.side_effect = Exception("fail")
        nvml.nvmlDeviceGetTemperature.side_effect = Exception("fail")
        nvml.nvmlDeviceGetFanSpeed.side_effect = Exception("fail")
        nvml.nvmlDeviceGetPowerUsage.side_effect = Exception("fail")
        nvml.nvmlDeviceGetPowerManagementLimit.side_effect = Exception("fail")
        nvml.nvmlDeviceGetUtilizationRates.side_effect = Exception("fail")
        nvml.nvmlDeviceGetMemoryInfo.side_effect = Exception("fail")
        nvml.nvmlDeviceGetClockInfo.side_effect = Exception("fail")
        nvml.nvmlDeviceGetComputeRunningProcesses.side_effect = Exception("fail")
        nvml.nvmlDeviceGetGraphicsRunningProcesses.side_effect = Exception("fail")

        gpu_mod = self._import_gpu()
        result = gpu_mod.gpu_metrics()

        assert len(result) == 1
        gpu = result[0]
        assert gpu["name"] is None
        assert gpu["temperature"] is None
        assert gpu["fan_speed"] is None
        assert gpu["power_draw"] is None
        assert gpu["power_limit"] is None
        assert gpu["utilization_gpu"] is None
        assert gpu["utilization_memory"] is None
        assert gpu["memory_used"] is None
        assert gpu["memory_total"] is None
        assert gpu["memory_free"] is None
        assert gpu["clock_sm"] is None
        assert gpu["clock_mem"] is None
        assert gpu["processes"] == []

    def test_handle_by_index_failure_skips_gpu(self):
        """When nvmlDeviceGetHandleByIndex raises, that GPU is skipped."""
        nvml = self.mock_nvml
        nvml.nvmlDeviceGetCount.return_value = 1
        nvml.nvmlDeviceGetHandleByIndex.side_effect = Exception("bad index")

        gpu_mod = self._import_gpu()
        result = gpu_mod.gpu_metrics()

        assert result == []

    def test_nvml_shutdown_called_on_exception(self):
        """nvmlShutdown is called even when nvmlDeviceGetCount raises."""
        nvml = self.mock_nvml
        nvml.nvmlDeviceGetCount.side_effect = Exception("unexpected")

        gpu_mod = self._import_gpu()
        result = gpu_mod.gpu_metrics()

        assert result is None
        nvml.nvmlShutdown.assert_called_once()

    def test_name_bytes_decoded(self):
        """GPU name returned as bytes is decoded to str."""
        nvml = self.mock_nvml
        nvml.nvmlDeviceGetCount.return_value = 1

        handle = MagicMock()
        nvml.nvmlDeviceGetHandleByIndex.return_value = handle
        nvml.nvmlDeviceGetName.return_value = b"NVIDIA RTX 4090"
        nvml.nvmlDeviceGetTemperature.return_value = 50
        nvml.nvmlDeviceGetFanSpeed.return_value = 30
        nvml.nvmlDeviceGetPowerUsage.return_value = 100000
        nvml.nvmlDeviceGetPowerManagementLimit.return_value = 300000
        nvml.nvmlDeviceGetUtilizationRates.return_value = SimpleNamespace(
            gpu=10, memory=5
        )
        nvml.nvmlDeviceGetMemoryInfo.return_value = SimpleNamespace(
            used=1000, total=24000, free=23000
        )
        nvml.nvmlDeviceGetClockInfo.return_value = 1500
        nvml.nvmlDeviceGetComputeRunningProcesses.return_value = []
        nvml.nvmlDeviceGetGraphicsRunningProcesses.return_value = []

        gpu_mod = self._import_gpu()
        result = gpu_mod.gpu_metrics()

        assert result[0]["name"] == "NVIDIA RTX 4090"
        assert isinstance(result[0]["name"], str)

    def test_process_list_both_compute_and_graphics(self):
        """Both compute and graphics processes are collected."""
        nvml = self.mock_nvml
        nvml.nvmlDeviceGetCount.return_value = 1

        handle = MagicMock()
        nvml.nvmlDeviceGetHandleByIndex.return_value = handle
        nvml.nvmlDeviceGetName.return_value = "GPU"
        nvml.nvmlDeviceGetTemperature.return_value = 50
        nvml.nvmlDeviceGetFanSpeed.return_value = 30
        nvml.nvmlDeviceGetPowerUsage.return_value = 100000
        nvml.nvmlDeviceGetPowerManagementLimit.return_value = 300000
        nvml.nvmlDeviceGetUtilizationRates.return_value = SimpleNamespace(
            gpu=10, memory=5
        )
        nvml.nvmlDeviceGetMemoryInfo.return_value = SimpleNamespace(
            used=1000, total=24000, free=23000
        )
        nvml.nvmlDeviceGetClockInfo.return_value = 1500

        compute = [
            SimpleNamespace(pid=100, usedGpuMemory=1000),
            SimpleNamespace(pid=200, usedGpuMemory=2000),
        ]
        graphics = [SimpleNamespace(pid=300, usedGpuMemory=3000)]
        nvml.nvmlDeviceGetComputeRunningProcesses.return_value = compute
        nvml.nvmlDeviceGetGraphicsRunningProcesses.return_value = graphics
        gpu_mod = self._import_gpu()
        result = gpu_mod.gpu_metrics()

        procs = result[0]["processes"]
        assert len(procs) == 3
        assert procs[0]["pid"] == 100
        assert procs[1]["pid"] == 200
        assert procs[2]["pid"] == 300

    def test_process_getter_fails_gracefully(self):
        """When one process getter fails, the other still collects."""
        nvml = self.mock_nvml
        nvml.nvmlDeviceGetCount.return_value = 1

        handle = MagicMock()
        nvml.nvmlDeviceGetHandleByIndex.return_value = handle
        nvml.nvmlDeviceGetName.return_value = "GPU"
        nvml.nvmlDeviceGetTemperature.return_value = 50
        nvml.nvmlDeviceGetFanSpeed.return_value = 30
        nvml.nvmlDeviceGetPowerUsage.return_value = 100000
        nvml.nvmlDeviceGetPowerManagementLimit.return_value = 300000
        nvml.nvmlDeviceGetUtilizationRates.return_value = SimpleNamespace(
            gpu=10, memory=5
        )
        nvml.nvmlDeviceGetMemoryInfo.return_value = SimpleNamespace(
            used=1000, total=24000, free=23000
        )
        nvml.nvmlDeviceGetClockInfo.return_value = 1500
        nvml.nvmlDeviceGetComputeRunningProcesses.side_effect = Exception("fail")
        nvml.nvmlDeviceGetGraphicsRunningProcesses.return_value = [
            SimpleNamespace(pid=999, usedGpuMemory=500)
        ]
        gpu_mod = self._import_gpu()
        result = gpu_mod.gpu_metrics()

        procs = result[0]["processes"]
        assert len(procs) == 1
        assert procs[0]["pid"] == 999


class TestGpuWithoutNvml:
    """Tests when pynvml is not installed."""

    def setup_method(self):
        # Remove pynvml from sys.modules to simulate it not being installed
        self._saved_pynvml = sys.modules.pop("pynvml", None)
        sys.modules.pop("fivenines_agent.gpu", None)

    def teardown_method(self):
        if self._saved_pynvml is not None:
            sys.modules["pynvml"] = self._saved_pynvml
        sys.modules.pop("fivenines_agent.gpu", None)

    def test_no_pynvml_returns_none(self):
        """Without pynvml installed, gpu_metrics returns None."""
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "pynvml":
                raise ImportError("No module named 'pynvml'")
            return real_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=fake_import):
            gpu_mod = importlib.import_module("fivenines_agent.gpu")

        assert gpu_mod.HAS_NVML is False
        assert gpu_mod.gpu_metrics() is None
