"""Tests for the Windows disk-health collector.

The collector shells out to PowerShell with a hard timeout (D11). These tests
cover the parsing/normalization, the reliability-counter merge, and every
failure path (timeout, non-zero exit, PowerShell missing, malformed JSON,
non-Windows host)."""

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from fivenines_agent.disk_health_windows import (
    WMI_TIMEOUT_SECONDS,
    _run_powershell,
    disk_health_windows,
)


def _completed(stdout="", stderr="", returncode=0):
    return SimpleNamespace(
        stdout=stdout.encode("utf-8"),
        stderr=stderr.encode("utf-8"),
        returncode=returncode,
    )


# --- _run_powershell ---


def test_run_powershell_parses_dict_to_list():
    """ConvertTo-Json returns a dict for a single row; the helper normalizes to a list."""
    one_row = json.dumps({"FriendlyName": "SSD", "HealthStatus": 0})
    with patch("fivenines_agent.disk_health_windows.subprocess.run",
               return_value=_completed(stdout=one_row)):
        result = _run_powershell("dummy")
    assert result == [{"FriendlyName": "SSD", "HealthStatus": 0}]


def test_run_powershell_passes_list_through():
    payload = json.dumps([{"FriendlyName": "SSD"}, {"FriendlyName": "HDD"}])
    with patch("fivenines_agent.disk_health_windows.subprocess.run",
               return_value=_completed(stdout=payload)):
        result = _run_powershell("dummy")
    assert len(result) == 2


def test_run_powershell_empty_output_returns_empty_list():
    with patch("fivenines_agent.disk_health_windows.subprocess.run",
               return_value=_completed(stdout="")):
        assert _run_powershell("dummy") == []


def test_run_powershell_timeout_returns_none():
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="powershell", timeout=WMI_TIMEOUT_SECONDS)
    with patch("fivenines_agent.disk_health_windows.subprocess.run", side_effect=raise_timeout):
        assert _run_powershell("dummy") is None


def test_run_powershell_missing_powershell_returns_none():
    with patch("fivenines_agent.disk_health_windows.subprocess.run",
               side_effect=FileNotFoundError("powershell not found")):
        assert _run_powershell("dummy") is None


def test_run_powershell_nonzero_exit_returns_none():
    with patch("fivenines_agent.disk_health_windows.subprocess.run",
               return_value=_completed(stderr="oops", returncode=1)):
        assert _run_powershell("dummy") is None


def test_run_powershell_invalid_json_returns_none():
    with patch("fivenines_agent.disk_health_windows.subprocess.run",
               return_value=_completed(stdout="{not json")):
        assert _run_powershell("dummy") is None


def test_run_powershell_unexpected_json_shape_returns_none():
    """A JSON number or string is not a valid disk-list payload."""
    with patch("fivenines_agent.disk_health_windows.subprocess.run",
               return_value=_completed(stdout="42")):
        assert _run_powershell("dummy") is None


# --- disk_health_windows ---


def test_disk_health_windows_returns_none_on_non_windows():
    with patch("fivenines_agent.disk_health_windows.is_windows", return_value=False):
        assert disk_health_windows() is None


def test_disk_health_windows_returns_none_on_physical_query_failure():
    """If the primary MSFT_PhysicalDisk query fails, return None."""
    with patch("fivenines_agent.disk_health_windows.is_windows", return_value=True), \
         patch("fivenines_agent.disk_health_windows._run_powershell", return_value=None):
        assert disk_health_windows() is None


def test_disk_health_windows_returns_disks_without_reliability_when_counters_fail():
    """If reliability query fails, disks still come back without the merge."""
    disks_payload = [{"FriendlyName": "SSD", "ObjectId": "obj-1", "SerialNumber": "SN1"}]
    calls = {"n": 0}

    def fake_run(query):
        calls["n"] += 1
        if calls["n"] == 1:
            return disks_payload
        return None  # reliability query fails

    with patch("fivenines_agent.disk_health_windows.is_windows", return_value=True), \
         patch("fivenines_agent.disk_health_windows._run_powershell", side_effect=fake_run):
        result = disk_health_windows()
    assert result == disks_payload
    assert "reliability" not in result[0]


def test_disk_health_windows_merges_reliability_by_object_id():
    disks_payload = [{"FriendlyName": "SSD", "ObjectId": "obj-1", "SerialNumber": "SN1"}]
    counters_payload = [
        {"DeviceId": "obj-1", "Temperature": 45, "PowerOnHours": 1234, "Wear": 5}
    ]

    def fake_run(query):
        return disks_payload if "MSFT_PhysicalDisk" in query else counters_payload

    with patch("fivenines_agent.disk_health_windows.is_windows", return_value=True), \
         patch("fivenines_agent.disk_health_windows._run_powershell", side_effect=fake_run):
        result = disk_health_windows()
    assert result[0]["reliability"]["Temperature"] == 45
    assert result[0]["reliability"]["PowerOnHours"] == 1234


def test_disk_health_windows_merges_reliability_by_serial_number_fallback():
    """When ObjectId doesn't match, SerialNumber is the secondary join key."""
    disks_payload = [{"FriendlyName": "HDD", "ObjectId": "obj-x", "SerialNumber": "SN42"}]
    counters_payload = [{"DeviceId": "SN42", "Temperature": 30}]

    def fake_run(query):
        return disks_payload if "MSFT_PhysicalDisk" in query else counters_payload

    with patch("fivenines_agent.disk_health_windows.is_windows", return_value=True), \
         patch("fivenines_agent.disk_health_windows._run_powershell", side_effect=fake_run):
        result = disk_health_windows()
    assert result[0]["reliability"]["Temperature"] == 30


def test_disk_health_windows_ignores_non_dict_disk_entries():
    """Defensive: a malformed disk entry doesn't crash the merge loop."""
    disks_payload = ["not-a-dict", {"FriendlyName": "SSD", "ObjectId": "obj-1"}]
    counters_payload = [{"DeviceId": "obj-1", "Temperature": 40}]

    def fake_run(query):
        return disks_payload if "MSFT_PhysicalDisk" in query else counters_payload

    with patch("fivenines_agent.disk_health_windows.is_windows", return_value=True), \
         patch("fivenines_agent.disk_health_windows._run_powershell", side_effect=fake_run):
        result = disk_health_windows()
    assert len(result) == 2
    assert result[1]["reliability"]["Temperature"] == 40


def test_disk_health_windows_handles_no_counter_match():
    """A disk with no matching reliability entry stays bare, no error."""
    disks_payload = [{"FriendlyName": "SSD", "ObjectId": "obj-1", "SerialNumber": "SN1"}]
    counters_payload = [{"DeviceId": "obj-other", "Temperature": 50}]

    def fake_run(query):
        return disks_payload if "MSFT_PhysicalDisk" in query else counters_payload

    with patch("fivenines_agent.disk_health_windows.is_windows", return_value=True), \
         patch("fivenines_agent.disk_health_windows._run_powershell", side_effect=fake_run):
        result = disk_health_windows()
    assert "reliability" not in result[0]
