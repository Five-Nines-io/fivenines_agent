"""Tests for cpu.py - cross-OS cpu_model branches."""

from types import SimpleNamespace
from unittest.mock import mock_open, patch

from fivenines_agent.cpu import cpu_count, cpu_data, cpu_model, cpu_usage


def test_cpu_data_returns_per_core_dicts():
    fake_times = [SimpleNamespace(_asdict=lambda: {"user": 1.0, "system": 2.0})]
    with patch("fivenines_agent.cpu.psutil.cpu_times_percent", return_value=fake_times), \
         patch("fivenines_agent.cpu.psutil.cpu_percent", return_value=[42.0]):
        result = cpu_data()
    assert result == [{"percentage": 42.0, "user": 1.0, "system": 2.0}]


def test_cpu_usage_returns_psutil_value():
    sentinel = object()
    with patch("fivenines_agent.cpu.psutil.cpu_times", return_value=sentinel):
        assert cpu_usage() is sentinel


def test_cpu_count_returns_os_value():
    with patch("fivenines_agent.cpu.os.cpu_count", return_value=8):
        assert cpu_count() == 8


# --- cpu_model OS branches ---


def test_cpu_model_linux_parses_proc_cpuinfo():
    cpuinfo = (
        "processor\t: 0\n"
        "vendor_id\t: GenuineIntel\n"
        "model name\t: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz\n"
        "stepping\t: 9\n"
    )
    with patch("fivenines_agent.cpu.os_family", return_value="linux"), \
         patch("builtins.open", mock_open(read_data=cpuinfo)):
        assert cpu_model() == "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz"


def test_cpu_model_linux_no_match_returns_dash():
    cpuinfo = "processor\t: 0\nvendor_id\t: AMD\n"
    with patch("fivenines_agent.cpu.os_family", return_value="linux"), \
         patch("builtins.open", mock_open(read_data=cpuinfo)):
        assert cpu_model() == "-"


def test_cpu_model_linux_missing_cpuinfo_returns_dash():
    def fake_open(*args, **kwargs):
        raise FileNotFoundError
    with patch("fivenines_agent.cpu.os_family", return_value="linux"), \
         patch("builtins.open", fake_open):
        assert cpu_model() == "-"


def test_cpu_model_darwin_reads_sysctl():
    fake_popen = mock_open(read_data="Apple M2 Pro\n")
    with patch("fivenines_agent.cpu.os_family", return_value="darwin"), \
         patch("fivenines_agent.cpu.os.popen", fake_popen):
        assert cpu_model() == "Apple M2 Pro"


def test_cpu_model_windows_uses_platform_processor():
    with patch("fivenines_agent.cpu.os_family", return_value="windows"), \
         patch("platform.processor", return_value="Intel64 Family 6 Model 158 Stepping 9"):
        assert cpu_model() == "Intel64 Family 6 Model 158 Stepping 9"


def test_cpu_model_windows_empty_processor_returns_dash():
    with patch("fivenines_agent.cpu.os_family", return_value="windows"), \
         patch("platform.processor", return_value=""):
        assert cpu_model() == "-"


def test_cpu_model_unknown_os_returns_dash():
    with patch("fivenines_agent.cpu.os_family", return_value="freebsd"):
        assert cpu_model() == "-"
