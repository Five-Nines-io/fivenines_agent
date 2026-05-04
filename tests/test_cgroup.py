"""Tests for fivenines_agent.cgroup module."""

from unittest.mock import MagicMock, mock_open, patch

import pytest

from fivenines_agent.cgroup import (
    detect_hierarchy,
    read_cpu_usec,
    read_inception_id,
    read_memory_current,
    read_oom_kill_count,
    read_unit_resources,
    reset_cache,
    unit_path,
)


@pytest.fixture(autouse=True)
def _clear_cgroup_cache():
    reset_cache()
    yield
    reset_cache()


# --- detect_hierarchy ---


def test_detect_hierarchy_v2():
    def fake_exists(path):
        return path == "/sys/fs/cgroup/cgroup.controllers"

    with patch("fivenines_agent.cgroup.os.path.exists", side_effect=fake_exists):
        assert detect_hierarchy() == "v2"


def test_detect_hierarchy_v1():
    def fake_isdir(path):
        return path == "/sys/fs/cgroup/memory"

    with patch("fivenines_agent.cgroup.os.path.exists", return_value=False):
        with patch("fivenines_agent.cgroup.os.path.isdir", side_effect=fake_isdir):
            assert detect_hierarchy() == "v1"


def test_detect_hierarchy_none():
    with patch("fivenines_agent.cgroup.os.path.exists", return_value=False):
        with patch("fivenines_agent.cgroup.os.path.isdir", return_value=False):
            assert detect_hierarchy() is None


def test_detect_hierarchy_caches_result():
    """Second call returns cached value without re-probing the filesystem."""
    with patch(
        "fivenines_agent.cgroup.os.path.exists", return_value=True
    ) as mock_exists:
        first = detect_hierarchy()
        second = detect_hierarchy()
    assert first == "v2"
    assert second == "v2"
    # exists() called once during the first probe; cache returns on second call
    assert mock_exists.call_count == 1


# --- unit_path ---


def test_unit_path_v2_default_slice():
    assert unit_path("nginx.service", "v2") == (
        "/sys/fs/cgroup/system.slice/nginx.service"
    )


def test_unit_path_v1_requires_controller():
    with pytest.raises(ValueError, match="controller is required"):
        unit_path("nginx.service", "v1")


def test_unit_path_v1_with_controller():
    assert unit_path("nginx.service", "v1", controller="memory") == (
        "/sys/fs/cgroup/memory/system.slice/nginx.service"
    )


def test_unit_path_unknown_hierarchy():
    with pytest.raises(ValueError, match="unsupported hierarchy"):
        unit_path("nginx.service", "v3")


def test_unit_path_rejects_path_traversal():
    """Defense in depth: unit names with '/' must not build cgroup paths."""
    with pytest.raises(ValueError, match="invalid unit name"):
        unit_path("../../etc/passwd", "v2")


def test_unit_path_rejects_null_byte():
    with pytest.raises(ValueError, match="invalid unit name"):
        unit_path("nginx\x00.service", "v2")


def test_unit_path_accepts_systemd_special_chars():
    """systemd unit names with @ and : characters are valid."""
    p = unit_path("getty@tty1.service", "v2")
    assert p.endswith("getty@tty1.service")


# --- read_memory_current ---


def test_read_memory_current_v2_happy():
    with patch("builtins.open", mock_open(read_data="123456789\n")):
        assert read_memory_current("nginx.service", "v2") == 123456789


def test_read_memory_current_v1_happy():
    with patch("builtins.open", mock_open(read_data="987654321\n")):
        assert read_memory_current("nginx.service", "v1") == 987654321


def test_read_memory_current_max_returns_none():
    """memory.current can return literal 'max' on unbounded units."""
    with patch("builtins.open", mock_open(read_data="max\n")):
        assert read_memory_current("nginx.service", "v2") is None


def test_read_memory_current_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError):
        assert read_memory_current("nginx.service", "v2") is None


def test_read_memory_current_permission_denied_silent():
    """EACCES is the expected capability gap; must NOT log."""
    with patch("builtins.open", side_effect=PermissionError):
        with patch("fivenines_agent.cgroup.log") as mock_log:
            result = read_memory_current("nginx.service", "v2")
        assert result is None
        mock_log.assert_not_called()


def test_read_memory_current_oserror_logs_at_debug():
    """Other OS errors log at debug level (not error)."""
    with patch("builtins.open", side_effect=OSError("disk full")):
        with patch("fivenines_agent.cgroup.log") as mock_log:
            result = read_memory_current("nginx.service", "v2")
        assert result is None
        mock_log.assert_called_once()
        assert mock_log.call_args[0][1] == "debug"


def test_read_memory_current_invalid_value():
    """Non-integer text returns None."""
    with patch("builtins.open", mock_open(read_data="not-a-number")):
        assert read_memory_current("nginx.service", "v2") is None


def test_read_memory_current_unsupported_hierarchy():
    assert read_memory_current("nginx.service", None) is None


# --- read_cpu_usec ---


CPU_STAT_V2 = """\
usage_usec 5000000
user_usec 4500000
system_usec 500000
nr_periods 0
nr_throttled 0
throttled_usec 0
"""


def test_read_cpu_usec_v2_happy():
    with patch("builtins.open", mock_open(read_data=CPU_STAT_V2)):
        assert read_cpu_usec("nginx.service", "v2") == 5000000


def test_read_cpu_usec_v2_missing_key():
    with patch("builtins.open", mock_open(read_data="user_usec 100\n")):
        assert read_cpu_usec("nginx.service", "v2") is None


def test_read_cpu_usec_v2_unparseable():
    with patch("builtins.open", mock_open(read_data="usage_usec garbage\n")):
        assert read_cpu_usec("nginx.service", "v2") is None


def test_read_cpu_usec_v1_converts_ns_to_usec():
    """v1 cpuacct.usage is nanoseconds; we want microseconds."""
    with patch("builtins.open", mock_open(read_data="5000000000\n")):
        # 5_000_000_000 ns -> 5_000_000 us
        assert read_cpu_usec("nginx.service", "v1") == 5000000


def test_read_cpu_usec_v1_missing_file():
    with patch("builtins.open", side_effect=FileNotFoundError):
        assert read_cpu_usec("nginx.service", "v1") is None


def test_read_cpu_usec_v1_invalid():
    with patch("builtins.open", mock_open(read_data="garbage\n")):
        assert read_cpu_usec("nginx.service", "v1") is None


def test_read_cpu_usec_unsupported_hierarchy():
    assert read_cpu_usec("nginx.service", None) is None


# --- read_oom_kill_count ---


MEMORY_EVENTS_V2 = """\
low 0
high 0
max 0
oom 2
oom_kill 3
"""


def test_read_oom_kill_count_v2_happy():
    with patch("builtins.open", mock_open(read_data=MEMORY_EVENTS_V2)):
        assert read_oom_kill_count("nginx.service", "v2") == 3


def test_read_oom_kill_count_v1_returns_none():
    """v1 has no memory.events equivalent; collector ships null."""
    assert read_oom_kill_count("nginx.service", "v1") is None


def test_read_oom_kill_count_none_hierarchy():
    assert read_oom_kill_count("nginx.service", None) is None


def test_read_oom_kill_count_missing_key():
    with patch("builtins.open", mock_open(read_data="low 0\nhigh 0\n")):
        assert read_oom_kill_count("nginx.service", "v2") is None


def test_read_oom_kill_count_file_missing():
    with patch("builtins.open", side_effect=FileNotFoundError):
        assert read_oom_kill_count("nginx.service", "v2") is None


# --- read_inception_id ---


def test_read_inception_id_v2_happy():
    fake_stat = MagicMock(st_ino=42)
    with patch("fivenines_agent.cgroup.os.stat", return_value=fake_stat) as mock_stat:
        result = read_inception_id("nginx.service", "v2")
    assert result == 42
    mock_stat.assert_called_once_with("/sys/fs/cgroup/system.slice/nginx.service")


def test_read_inception_id_v1_uses_memory_controller():
    fake_stat = MagicMock(st_ino=99)
    with patch("fivenines_agent.cgroup.os.stat", return_value=fake_stat) as mock_stat:
        result = read_inception_id("nginx.service", "v1")
    assert result == 99
    mock_stat.assert_called_once_with(
        "/sys/fs/cgroup/memory/system.slice/nginx.service"
    )


def test_read_inception_id_no_hierarchy():
    assert read_inception_id("nginx.service", None) is None


def test_read_inception_id_file_not_found():
    with patch("fivenines_agent.cgroup.os.stat", side_effect=FileNotFoundError):
        assert read_inception_id("nginx.service", "v2") is None


def test_read_inception_id_permission_denied_silent():
    with patch("fivenines_agent.cgroup.os.stat", side_effect=PermissionError):
        with patch("fivenines_agent.cgroup.log") as mock_log:
            assert read_inception_id("nginx.service", "v2") is None
        mock_log.assert_not_called()


def test_read_inception_id_oserror_logs_debug():
    with patch("fivenines_agent.cgroup.os.stat", side_effect=OSError("err")):
        with patch("fivenines_agent.cgroup.log") as mock_log:
            assert read_inception_id("nginx.service", "v2") is None
        mock_log.assert_called_once()
        assert mock_log.call_args[0][1] == "debug"


# --- read_unit_resources ---


def test_read_unit_resources_v2_aggregates_all_metrics():
    """One call returns all four metrics for v2."""
    fake_stat = MagicMock(st_ino=7)

    def fake_open(path, *_args, **_kwargs):
        if path.endswith("memory.current"):
            return mock_open(read_data="1024\n").return_value
        if path.endswith("cpu.stat"):
            return mock_open(read_data=CPU_STAT_V2).return_value
        if path.endswith("memory.events"):
            return mock_open(read_data=MEMORY_EVENTS_V2).return_value
        raise FileNotFoundError

    with patch("builtins.open", side_effect=fake_open):
        with patch("fivenines_agent.cgroup.os.stat", return_value=fake_stat):
            result = read_unit_resources("nginx.service", "v2")
    assert result == {
        "memory_current": 1024,
        "cpu_usec": 5000000,
        "oom_kill_count": 3,
        "inception_id": 7,
    }


def test_read_unit_resources_v1_no_oom():
    """v1 fills memory + cpu but oom_kill_count stays null."""
    fake_stat = MagicMock(st_ino=8)

    def fake_open(path, *_args, **_kwargs):
        if path.endswith("memory.usage_in_bytes"):
            return mock_open(read_data="2048\n").return_value
        if path.endswith("cpuacct.usage"):
            return mock_open(read_data="3000000000\n").return_value
        raise FileNotFoundError

    with patch("builtins.open", side_effect=fake_open):
        with patch("fivenines_agent.cgroup.os.stat", return_value=fake_stat):
            result = read_unit_resources("nginx.service", "v1")
    assert result == {
        "memory_current": 2048,
        "cpu_usec": 3000000,
        "oom_kill_count": None,
        "inception_id": 8,
    }


def test_read_unit_resources_no_hierarchy_returns_empty():
    assert read_unit_resources("nginx.service", None) == {}


def test_read_unit_resources_unsupported_hierarchy_returns_empty():
    assert read_unit_resources("nginx.service", "v9") == {}
