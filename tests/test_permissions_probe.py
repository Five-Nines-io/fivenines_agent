"""Tests for PermissionProbe initial-probe and flip logging."""

from contextlib import ExitStack
from unittest.mock import patch

from fivenines_agent.permissions import CAPABILITY_HINTS, PermissionProbe

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
    "_can_run_quota",
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
    "quota": True,
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
    """Every hint key must correspond to a capability produced by _probe_all."""
    with _patched_probe({"default": True}):
        probe = PermissionProbe()

    for hint_key in CAPABILITY_HINTS:
        assert (
            hint_key in probe.capabilities
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
