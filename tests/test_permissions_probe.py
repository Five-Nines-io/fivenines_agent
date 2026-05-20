"""Tests for PermissionProbe initial-probe and flip logging."""

from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest

from fivenines_agent.permissions import CAPABILITY_HINTS, PermissionProbe


@pytest.fixture(autouse=True)
def _default_to_linux_probe():
    """Existing tests exercise the Linux capability probe; force
    is_windows=False by default so they run identically on Windows CI.
    Windows-specific tests explicitly override via @patch (decorator wins)."""
    with patch("fivenines_agent.permissions.is_windows", return_value=False):
        yield

_PROBE_METHODS = (
    "_can_read",
    "_can_access_hwmon",
    "_can_access_gpu",
    "_can_run_sudo",
    "_can_run_zfs",
    "_can_access_docker",
    "_can_access_libvirt",
    "_can_access_proxmox",
    "_can_list_packages",
    "_has_snmpget",
    "_can_query_psutil_sensors",
    "_can_query_wmi_storage",
    "_can_read_uninstall_registry",
)

_ALL_TRUE_CAPS = {
    "cpu": True,
    "memory": True,
    "load_average": True,
    "io": True,
    "network": True,
    "partitions": True,
    "file_handles": True,
    "ports": True,
    "processes": True,
    "temperatures": True,
    "fans": True,
    "nvidia_gpu": True,
    "smart_storage": True,
    "raid_storage": True,
    "fail2ban": True,
    "zfs": True,
    "docker": True,
    "qemu": True,
    "proxmox": True,
    "packages": True,
    "snmp": True,
}


def _patched_probe(returns, exclude=()):
    """Stack patches for every probe method with the given return value.

    Pass *exclude* to skip patching specific methods so the caller can patch
    them separately (e.g. with a side_effect).
    """
    stack = ExitStack()
    for name in _PROBE_METHODS:
        if name in exclude:
            continue
        rv = (
            returns.get(name, returns.get("default"))
            if isinstance(returns, dict)
            else returns
        )
        stack.enter_context(patch.object(PermissionProbe, name, return_value=rv))
    return stack


def _new_probe_with(caps):
    """Build a PermissionProbe instance bypassing __init__, with capabilities set."""
    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = caps
    probe._capability_reasons = {}
    probe._current_reason = None
    probe._last_probe_time = 0
    return probe


def test_initial_probe_logs_unavailable_capabilities_with_hint():
    """First probe (old_capabilities empty) emits info per unavailable cap with a hint."""
    returns = {"default": False, "_can_read": True}
    with _patched_probe(returns), patch("fivenines_agent.permissions.log") as mock_log:
        PermissionProbe()

    info_msgs = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "info"]
    assert any("nvidia_gpu" in m and "NVIDIA driver" in m for m in info_msgs)
    assert any("docker" in m and "docker group" in m for m in info_msgs)
    # Available capabilities (cpu via _can_read True) must not produce an unavailable log.
    assert not any("'cpu' unavailable" in m for m in info_msgs)


def test_flip_to_unavailable_includes_hint():
    """Flipping a capability false adds the hint to the existing flip log."""
    probe = _new_probe_with(dict(_ALL_TRUE_CAPS))

    returns = {"default": True, "_can_access_gpu": False}
    with _patched_probe(returns), patch("fivenines_agent.permissions.log") as mock_log:
        probe._probe_all()

    info_msgs = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "info"]
    flip_msg = [m for m in info_msgs if "nvidia_gpu" in m and "now UNAVAILABLE" in m]
    assert len(flip_msg) == 1
    assert "requires NVIDIA driver" in flip_msg[0]


def test_flip_to_available_logs_without_hint():
    """Flipping a capability to available logs the transition (no hint needed)."""
    probe = _new_probe_with({**_ALL_TRUE_CAPS, "docker": False})

    returns = {"default": True}
    with _patched_probe(returns), patch("fivenines_agent.permissions.log") as mock_log:
        probe._probe_all()

    info_msgs = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "info"]
    avail_msg = [m for m in info_msgs if "docker" in m and "now AVAILABLE" in m]
    assert len(avail_msg) == 1
    # The available transition does not append a hint.
    assert "requires" not in avail_msg[0]


def test_capability_hints_keys_are_known_capabilities():
    """Every hint key must correspond to a capability in some OS probe."""
    with _patched_probe({"default": True}):
        probe = PermissionProbe()
        linux_keys = set(probe._build_linux_capabilities().keys())
        with patch("fivenines_agent.permissions.is_windows", return_value=True):
            windows_keys = set(probe._build_windows_capabilities().keys())
    all_keys = linux_keys | windows_keys

    for hint_key in CAPABILITY_HINTS:
        assert (
            hint_key in all_keys
        ), f"hint {hint_key!r} has no matching capability"


# --- Reason capture ---


def test_probe_captures_failure_reason():
    """Probe wrapper records the probe method's set_reason on False return."""
    probe = _new_probe_with({})

    def fake_probe(self):
        self._set_reason("specific failure")
        return False

    with patch.object(
        PermissionProbe, "_can_access_gpu", autospec=True, side_effect=fake_probe
    ):
        result = probe._probe("nvidia_gpu", probe._can_access_gpu)

    assert result is False
    assert probe._capability_reasons["nvidia_gpu"] == "specific failure"


def test_probe_clears_reason_when_capability_recovers():
    """A previously-unavailable capability that returns True clears its reason."""
    probe = _new_probe_with({})
    probe._capability_reasons["nvidia_gpu"] = "stale reason"

    with patch.object(
        PermissionProbe, "_can_access_gpu", autospec=True, return_value=True
    ):
        result = probe._probe("nvidia_gpu", probe._can_access_gpu)

    assert result is True
    assert "nvidia_gpu" not in probe._capability_reasons


def test_probe_no_reason_set_does_not_record():
    """If a probe returns False without calling _set_reason, no reason is recorded."""
    probe = _new_probe_with({})

    with patch.object(
        PermissionProbe, "_can_access_gpu", autospec=True, return_value=False
    ):
        result = probe._probe("nvidia_gpu", probe._can_access_gpu)

    assert result is False
    assert "nvidia_gpu" not in probe._capability_reasons


def test_get_reasons_returns_copy():
    """get_reasons returns a snapshot the caller can safely mutate."""
    probe = _new_probe_with({})
    probe._capability_reasons["nvidia_gpu"] = (
        "nvmlInit failed: NVML Shared Library Not Found"
    )

    snapshot = probe.get_reasons()
    snapshot["nvidia_gpu"] = "tampered"

    assert (
        probe._capability_reasons["nvidia_gpu"]
        == "nvmlInit failed: NVML Shared Library Not Found"
    )


def test_initial_probe_log_includes_reason():
    """Initial probe info log appends the captured reason inline."""

    def gpu_unavailable_with_reason(self):
        self._set_reason("nvmlInit failed: NVML Shared Library Not Found")
        return False

    returns = {"default": True}
    with _patched_probe(returns, exclude=["_can_access_gpu"]), patch.object(
        PermissionProbe,
        "_can_access_gpu",
        autospec=True,
        side_effect=gpu_unavailable_with_reason,
    ), patch("fivenines_agent.permissions.log") as mock_log:
        PermissionProbe()

    info_msgs = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "info"]
    gpu_msg = next(m for m in info_msgs if "nvidia_gpu" in m and "unavailable" in m)
    assert "requires NVIDIA driver" in gpu_msg
    assert "(nvmlInit failed: NVML Shared Library Not Found)" in gpu_msg


def test_flip_to_unavailable_log_includes_reason():
    """Flip-to-unavailable info log appends the captured reason inline."""
    probe = _new_probe_with(dict(_ALL_TRUE_CAPS))

    def gpu_unavailable_with_reason(self):
        self._set_reason("nvmlInit failed: driver removed")
        return False

    returns = {"default": True}
    with _patched_probe(returns, exclude=["_can_access_gpu"]), patch.object(
        PermissionProbe,
        "_can_access_gpu",
        autospec=True,
        side_effect=gpu_unavailable_with_reason,
    ), patch("fivenines_agent.permissions.log") as mock_log:
        probe._probe_all()

    info_msgs = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "info"]
    flip_msg = next(
        m for m in info_msgs if "nvidia_gpu" in m and "now UNAVAILABLE" in m
    )
    assert "requires NVIDIA driver" in flip_msg
    assert "(nvmlInit failed: driver removed)" in flip_msg


def test_unavailable_log_without_reason_omits_parens():
    """When no reason was captured, the log line ends after the hint."""
    returns = {"default": False, "_can_read": True}
    with _patched_probe(returns), patch("fivenines_agent.permissions.log") as mock_log:
        PermissionProbe()

    info_msgs = [c.args[0] for c in mock_log.call_args_list if c.args[1] == "info"]
    docker_msg = next(m for m in info_msgs if "docker" in m and "unavailable" in m)
    # Patched probe returns False without calling _set_reason -> no parens.
    assert docker_msg.endswith("docker group")


# ----- T2: Windows-tailored capability set, banner, and probe methods -----


@patch("fivenines_agent.permissions.is_windows", return_value=True)
def test_build_windows_capabilities_has_windows_shape(mock_iw):
    """Windows probe omits Linux-only keys and includes Windows-native keys."""
    with _patched_probe({"default": True}):
        probe = PermissionProbe()

    # Linux-only keys are absent (D13 - the payload is Windows-shaped).
    for absent in ("raid_storage", "zfs", "fail2ban", "proxmox", "qemu",
                   "smart_storage", "packages", "snmp", "docker"):
        assert absent not in probe.capabilities, \
            f"Linux-only key {absent!r} leaked into Windows capability set"

    # Windows-native entries are present.
    assert "disk_health" in probe.capabilities
    assert "software_inventory" in probe.capabilities

    # Core metrics are unconditionally True on Windows (psutil works).
    for core in ("cpu", "memory", "load_average", "io", "network",
                 "partitions", "file_handles", "ports", "processes"):
        assert probe.capabilities[core] is True


def test_can_query_psutil_sensors_returns_true_when_data():
    probe = _new_probe_with({})
    with patch("fivenines_agent.permissions.psutil") as fake_psutil:
        fake_psutil.sensors_temperatures = MagicMock(
            return_value={"coretemp": [object()]}
        )
        assert probe._can_query_psutil_sensors("temperatures") is True


def test_can_query_psutil_sensors_returns_false_when_empty():
    probe = _new_probe_with({})
    with patch("fivenines_agent.permissions.psutil") as fake_psutil:
        fake_psutil.sensors_temperatures = MagicMock(return_value={})
        assert probe._can_query_psutil_sensors("temperatures") is False


def test_can_query_psutil_sensors_attribute_missing():
    """Windows psutil typically lacks sensors_fans; probe handles AttributeError."""
    probe = _new_probe_with({})
    fake_psutil = MagicMock(spec=[])  # no attributes at all
    with patch("fivenines_agent.permissions.psutil", fake_psutil):
        assert probe._can_query_psutil_sensors("fans") is False


def test_can_query_psutil_sensors_raises_oserror():
    probe = _new_probe_with({})
    with patch("fivenines_agent.permissions.psutil") as fake_psutil:
        fake_psutil.sensors_temperatures = MagicMock(side_effect=OSError("boom"))
        assert probe._can_query_psutil_sensors("temperatures") is False


def test_can_query_wmi_storage_present():
    probe = _new_probe_with({})
    with patch.dict("sys.modules", {"wmi": MagicMock()}):
        assert probe._can_query_wmi_storage() is True


def test_can_query_wmi_storage_absent():
    """wmi package not installed -> probe is False with a reason."""
    probe = _new_probe_with({})
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "wmi":
            raise ImportError("not installed")
        return real_import(name, *args, **kwargs)

    with patch.object(builtins, "__import__", fake_import):
        assert probe._can_query_wmi_storage() is False
    assert "wmi package not installed" in probe._capability_reasons.get(
        "_current", probe._current_reason or ""
    )


def test_can_read_uninstall_registry_success():
    probe = _new_probe_with({})
    fake_winreg = MagicMock()
    fake_winreg.HKEY_LOCAL_MACHINE = "HKLM"
    fake_winreg.OpenKey.return_value = "key-handle"
    with patch.dict("sys.modules", {"winreg": fake_winreg}):
        assert probe._can_read_uninstall_registry() is True
    fake_winreg.OpenKey.assert_called_once()
    fake_winreg.CloseKey.assert_called_once_with("key-handle")


def test_can_read_uninstall_registry_missing_winreg():
    """winreg unimportable on non-Windows -> probe False."""
    probe = _new_probe_with({})
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "winreg":
            raise ImportError("not on this OS")
        return real_import(name, *args, **kwargs)

    with patch.object(builtins, "__import__", fake_import):
        assert probe._can_read_uninstall_registry() is False


def test_can_read_uninstall_registry_openkey_oserror():
    probe = _new_probe_with({})
    fake_winreg = MagicMock()
    fake_winreg.HKEY_LOCAL_MACHINE = "HKLM"
    fake_winreg.OpenKey.side_effect = OSError("access denied")
    with patch.dict("sys.modules", {"winreg": fake_winreg}):
        assert probe._can_read_uninstall_registry() is False


def test_banner_uses_windows_groups(capsys):
    """On Windows, the banner shows Windows groupings (no Services/Security/Networking)."""
    import fivenines_agent.permissions as perm
    original_probe = perm._probe
    perm._probe = None  # force fresh singleton inside the Windows mock
    try:
        with patch("fivenines_agent.permissions.is_windows", return_value=True), \
             _patched_probe({"default": True}):
            perm.print_capabilities_banner()
    finally:
        perm._probe = original_probe
    out = capsys.readouterr().out
    assert "Inventory" in out  # Windows-only banner section
    assert "Disk Health" in out  # Windows-only capability
    assert "Services" not in out  # Linux services section absent
    assert "Fail2Ban" not in out  # Linux-only capability absent
