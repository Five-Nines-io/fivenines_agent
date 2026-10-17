"""Tests for the PermissionProbe's local probes and accessors.

Covers the probes that read the local host directly -- file readability
(core metrics), sudo -n failure paths, hwmon sensors, zpool, Proxmox node
detection and the net-snmp CLI -- plus the get()/get_available() accessors.
Every filesystem and subprocess touch is mocked, so the tests run identically
on Windows CI. Constructed via __new__ so only the probe under test runs, not
the full _probe_all.
"""

import os
import subprocess
from unittest.mock import MagicMock, patch

from fivenines_agent import permissions
from fivenines_agent.permissions import PermissionProbe

HWMON = "/sys/class/hwmon"


def _probe(capabilities=None):
    p = PermissionProbe.__new__(PermissionProbe)
    p.capabilities = dict(capabilities or {})
    p._capability_reasons = {}
    p._current_reason = None
    return p


def _completed(returncode=0, stdout=b"", stderr=b""):
    result = MagicMock(returncode=returncode)
    result.stdout = stdout
    result.stderr = stderr
    return result


def _debug_lines(mock_log):
    return [c.args[0] for c in mock_log.call_args_list if c.args[1] == "debug"]


# --- _can_read (every core-metric capability) ---


def test_can_read_missing_path_is_false_with_reason():
    p = _probe()
    with patch.object(permissions.os.path, "exists", return_value=False), patch.object(
        permissions.os, "access"
    ) as access:
        assert p._can_read("/proc/stat") is False
    assert p._current_reason == "/proc/stat does not exist"
    # A missing path is never handed to os.access.
    access.assert_not_called()


def test_can_read_readable_path_is_true_without_reason():
    p = _probe()
    with patch.object(permissions.os.path, "exists", return_value=True), patch.object(
        permissions.os, "access", return_value=True
    ) as access:
        assert p._can_read("/proc/meminfo") is True
    access.assert_called_once_with("/proc/meminfo", os.R_OK)
    assert p._current_reason is None


def test_can_read_unreadable_path_is_false_with_reason():
    p = _probe()
    with patch.object(permissions.os.path, "exists", return_value=True), patch.object(
        permissions.os, "access", return_value=False
    ):
        assert p._can_read("/proc/net/tcp") is False
    assert p._current_reason == "/proc/net/tcp is not readable"


def test_can_read_exception_is_false_with_reason():
    """A probe that raises must not take _probe_all down with it: the
    capability reads False and the exception becomes the reason."""
    p = _probe()
    with patch.object(permissions.os.path, "exists", return_value=True), patch.object(
        permissions.os, "access", side_effect=PermissionError("denied")
    ), patch("fivenines_agent.permissions.log") as mock_log:
        assert p._can_read("/proc/loadavg") is False
    assert p._current_reason == "/proc/loadavg: PermissionError: denied"
    assert any("exception: PermissionError" in m for m in _debug_lines(mock_log))


def test_can_read_reason_reaches_capability_reasons():
    """End to end through _probe: the reason lands under the capability."""
    p = _probe()
    with patch.object(permissions.os.path, "exists", return_value=False):
        assert p._probe("cpu", p._can_read, "/proc/stat") is False
    assert p._capability_reasons == {"cpu": "/proc/stat does not exist"}


# --- _can_run_sudo failure paths ---


def test_can_run_sudo_command_missing_never_runs_sudo():
    p = _probe()
    with patch.object(permissions.shutil, "which", return_value=None), patch(
        "fivenines_agent.permissions.run_privileged"
    ) as run_privileged:
        assert p._can_run_sudo("smartctl", "--version") is False
    run_privileged.assert_not_called()
    assert p._current_reason == "smartctl not found in PATH"


def test_can_run_sudo_timeout_is_false_with_reason():
    """A sudo -n that times out (a wedged sudoers backend) reads UNAVAILABLE,
    and the reason names the deadline that was actually applied."""
    p = _probe()
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["timeout"] = kwargs["timeout"]
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    with patch.object(
        permissions.shutil, "which", return_value="/sbin/mdadm"
    ), patch.object(permissions.subprocess, "run", fake_run), patch(
        "fivenines_agent.permissions.log"
    ):
        assert p._can_run_sudo("mdadm", "--version", timeout=7) is False
    assert seen == {"cmd": ["sudo", "-n", "mdadm", "--version"], "timeout": 7}
    assert p._current_reason == "sudo -n mdadm timed out after 7s"


def test_can_run_sudo_default_timeout_in_reason():
    p = _probe()
    with patch.object(
        permissions.shutil, "which", return_value="/usr/bin/fail2ban-client"
    ), patch(
        "fivenines_agent.permissions.run_privileged",
        side_effect=subprocess.TimeoutExpired(["sudo"], 5),
    ) as run_privileged:
        assert p._can_run_sudo("fail2ban-client", "status") is False
    assert run_privileged.call_args.kwargs["timeout"] == permissions.SUDO_PROBE_TIMEOUT
    assert p._current_reason == (
        f"sudo -n fail2ban-client timed out after " f"{permissions.SUDO_PROBE_TIMEOUT}s"
    )


def test_can_run_sudo_unexpected_exception_is_false_with_reason():
    """e.g. the EPERM a non-root parent gets when it tries to kill a sudo
    child: it must become a reason, not escape the probe."""
    p = _probe()
    with patch.object(
        permissions.shutil, "which", return_value="/usr/bin/fail2ban-client"
    ), patch.object(
        permissions.subprocess,
        "run",
        side_effect=PermissionError("Operation not permitted"),
    ), patch(
        "fivenines_agent.permissions.log"
    ) as mock_log:
        assert p._can_run_sudo("fail2ban-client", "status") is False
    assert p._current_reason == (
        "sudo -n fail2ban-client: PermissionError: Operation not permitted"
    )
    assert any("exception: PermissionError" in m for m in _debug_lines(mock_log))


# --- _can_access_hwmon (temperatures, fans) ---


def _fake_hwmon(tree, readable, errors=()):
    """Patches for a fake /sys/class/hwmon.

    *tree* maps a directory path to its listing, *readable* is the set of
    paths os.access reports readable, *errors* maps a directory to the
    exception its listing raises. Paths are built with os.path.join, as the
    probe builds them, so the fake matches on every OS.
    """
    errors = dict(errors)

    def listdir(path):
        if path in errors:
            raise errors[path]
        return list(tree[path])

    accessed = []

    def access(path, mode):
        accessed.append((path, mode))
        return path in readable

    exists = patch.object(
        permissions.os.path, "exists", side_effect=lambda path: path == HWMON
    )
    return (
        exists,
        patch.object(permissions.os, "listdir", side_effect=listdir),
        patch.object(permissions.os, "access", side_effect=access),
        accessed,
    )


def _run_hwmon(tree, readable, errors=()):
    exists, listdir, access, accessed = _fake_hwmon(tree, readable, errors)
    p = _probe()
    with exists, listdir, access, patch("fivenines_agent.permissions.log") as mock_log:
        result = p._can_access_hwmon()
    return p, result, accessed, mock_log


def test_hwmon_missing_root_is_false_with_reason():
    p = _probe()
    with patch.object(permissions.os.path, "exists", return_value=False), patch.object(
        permissions.os, "listdir"
    ) as listdir:
        assert p._can_access_hwmon() is False
    listdir.assert_not_called()
    assert p._current_reason == f"{HWMON} does not exist"


def test_hwmon_readable_temp_input_is_true():
    """Only temp*_input files count; one unreadable device (its listing
    raises) does not hide a readable sensor on the next one."""
    hwmon0 = os.path.join(HWMON, "hwmon0")
    hwmon1 = os.path.join(HWMON, "hwmon1")
    good = os.path.join(hwmon1, "temp2_input")
    tree = {
        HWMON: ["hwmon0", "hwmon1"],
        hwmon1: ["name", "fan1_input", "temp1_label", "temp1_input", "temp2_input"],
    }
    p, result, accessed, mock_log = _run_hwmon(
        tree,
        readable={good},
        errors={hwmon0: PermissionError("denied")},
    )

    assert result is True
    assert p._current_reason is None
    # name / fan1_input / temp1_label are never checked; the probe stops at
    # the first readable sensor.
    assert accessed == [
        (os.path.join(hwmon1, "temp1_input"), os.R_OK),
        (good, os.R_OK),
    ]
    lines = _debug_lines(mock_log)
    assert any("error reading hwmon0: PermissionError" in m for m in lines)
    assert any("AVAILABLE (found readable sensor)" in m for m in lines)


def test_hwmon_no_readable_sensor_is_false_with_reason():
    hwmon0 = os.path.join(HWMON, "hwmon0")
    hwmon1 = os.path.join(HWMON, "hwmon1")
    tree = {
        HWMON: ["hwmon0", "hwmon1"],
        hwmon0: ["temp1_input"],
        # A device with fans only offers no temperature input at all.
        hwmon1: ["fan1_input", "name"],
    }
    p, result, accessed, _ = _run_hwmon(tree, readable=set())

    assert result is False
    assert accessed == [(os.path.join(hwmon0, "temp1_input"), os.R_OK)]
    assert p._current_reason == f"no readable sensors under {HWMON}"


def test_hwmon_empty_root_is_false_with_reason():
    p, result, accessed, _ = _run_hwmon({HWMON: []}, readable=set())
    assert result is False
    assert accessed == []
    assert p._current_reason == f"no readable sensors under {HWMON}"


def test_hwmon_unlistable_root_is_false_with_reason():
    p, result, _, mock_log = _run_hwmon(
        {}, readable=set(), errors={HWMON: OSError("I/O error")}
    )
    assert result is False
    assert p._current_reason == f"{HWMON}: OSError: I/O error"
    assert any("exception: OSError" in m for m in _debug_lines(mock_log))


# --- _can_run_zfs ---


def _run_zfs(**run_kwargs):
    p = _probe()
    with patch.object(
        permissions.shutil, "which", return_value="/usr/sbin/zpool"
    ), patch.object(permissions.subprocess, "run", **run_kwargs) as run, patch(
        "fivenines_agent.permissions.log"
    ) as mock_log:
        result = p._can_run_zfs()
    return p, result, run, mock_log


def test_zfs_missing_zpool_never_spawns():
    p = _probe()
    with patch.object(permissions.shutil, "which", return_value=None), patch.object(
        permissions.subprocess, "run"
    ) as run:
        assert p._can_run_zfs() is False
    run.assert_not_called()
    assert p._current_reason == "zpool not found in PATH"


def test_zfs_returncode_zero_is_true():
    p, result, run, mock_log = _run_zfs(
        return_value=_completed(0, stdout=b"tank\t1.81T\t...\n")
    )
    assert result is True
    assert p._current_reason is None
    args, kwargs = run.call_args
    assert args[0] == ["zpool", "list", "-H"]
    assert kwargs["timeout"] == 5
    assert kwargs["capture_output"] is True
    assert kwargs["env"]["LC_ALL"] == "C"
    lines = _debug_lines(mock_log)
    assert any("stdout: tank" in m for m in lines)
    assert any("AVAILABLE (returncode 0)" in m for m in lines)


def test_zfs_no_pools_is_still_available():
    """ZFS that works but has no pools is a usable capability, not a failure."""
    p, result, _, mock_log = _run_zfs(
        return_value=_completed(1, stderr=b"No pools available\n")
    )
    assert result is True
    assert p._current_reason is None
    lines = _debug_lines(mock_log)
    assert any("stderr: No pools available" in m for m in lines)
    assert any("no pools but ZFS works" in m for m in lines)


def test_zfs_failure_reason_is_first_stderr_line():
    p, result, _, _ = _run_zfs(
        return_value=_completed(
            1,
            stderr=(
                b"Permission denied the ZFS utilities must be run as root.\n"
                b"second line\n"
            ),
        )
    )
    assert result is False
    assert p._current_reason == (
        "zpool list: Permission denied the ZFS utilities must be run as root."
    )


def test_zfs_failure_without_stderr_reports_returncode():
    p, result, _, _ = _run_zfs(return_value=_completed(2))
    assert result is False
    assert p._current_reason == "zpool list: returncode 2"


def test_zfs_timeout_is_false_with_reason():
    p, result, _, _ = _run_zfs(
        side_effect=subprocess.TimeoutExpired(["zpool", "list", "-H"], 5)
    )
    assert result is False
    assert p._current_reason == "zpool list timed out after 5s"


def test_zfs_unexpected_exception_is_false_with_reason():
    p, result, _, mock_log = _run_zfs(
        side_effect=FileNotFoundError("No such file or directory: 'zpool'")
    )
    assert result is False
    assert p._current_reason == (
        "zpool list: FileNotFoundError: No such file or directory: 'zpool'"
    )
    assert any("exception: FileNotFoundError" in m for m in _debug_lines(mock_log))


# --- _can_access_proxmox ---


def test_proxmox_etc_pve_directory_is_true():
    p = _probe()
    with patch.object(
        permissions.os.path, "exists", side_effect=lambda path: path == "/etc/pve"
    ), patch.object(
        permissions.os.path, "isdir", side_effect=lambda path: path == "/etc/pve"
    ), patch.object(
        permissions.shutil, "which"
    ) as which:
        assert p._can_access_proxmox() is True
    which.assert_not_called()
    assert p._current_reason is None


def test_proxmox_etc_pve_not_a_directory_falls_back_to_pvesh():
    p = _probe()
    with patch.object(permissions.os.path, "exists", return_value=True), patch.object(
        permissions.os.path, "isdir", return_value=False
    ), patch.object(
        permissions.shutil, "which", return_value="/usr/bin/pvesh"
    ) as which:
        assert p._can_access_proxmox() is True
    which.assert_called_once_with("pvesh")
    assert p._current_reason is None


def test_proxmox_neither_signal_is_false_with_reason():
    p = _probe()
    with patch.object(permissions.os.path, "exists", return_value=False), patch.object(
        permissions.shutil, "which", return_value=None
    ):
        assert p._can_access_proxmox() is False
    assert p._current_reason == "/etc/pve missing and pvesh not in PATH"


# --- _has_snmpget ---


def test_snmpget_found_is_true():
    p = _probe()
    with patch.object(
        permissions.shutil, "which", return_value="/usr/bin/snmpget"
    ) as which, patch("fivenines_agent.permissions.log") as mock_log:
        assert p._has_snmpget() is True
    which.assert_called_once_with("snmpget")
    assert p._current_reason is None
    assert "_has_snmpget: found" in _debug_lines(mock_log)


def test_snmpget_missing_is_false_with_reason():
    p = _probe()
    with patch.object(permissions.shutil, "which", return_value=None), patch(
        "fivenines_agent.permissions.log"
    ) as mock_log:
        assert p._has_snmpget() is False
    assert p._current_reason == "snmpget not found in PATH"
    assert "_has_snmpget: not found" in _debug_lines(mock_log)


# --- accessors ---


def test_get_returns_stored_value_or_default():
    p = _probe({"docker": True, "zfs": False, "cgroup": "v2"})
    assert p.get("docker") is True
    assert p.get("zfs") is False
    # cgroup is tri-state: the hierarchy string itself is returned.
    assert p.get("cgroup") == "v2"
    # Unknown capability: False unless the caller supplies a default.
    assert p.get("not_probed") is False
    assert p.get("not_probed", None) is None
    # A stored False wins over the default.
    assert p.get("zfs", True) is False


def test_get_available_lists_truthy_capabilities_only():
    p = _probe(
        {
            "cpu": True,
            "zfs": False,
            "cgroup": "v1",
            "systemd": None,
            "docker": True,
        }
    )
    assert p.get_available() == ["cpu", "cgroup", "docker"]
    assert p.get_unavailable() == ["zfs", "systemd"]
