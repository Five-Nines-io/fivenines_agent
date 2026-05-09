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


def _patched_probe(returns):
    """Stack patches for every probe method with the given return value (or per-method mapping)."""
    stack = ExitStack()
    for name in _PROBE_METHODS:
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
