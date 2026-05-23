"""Windows disk-health collector via WMI MSFT_PhysicalDisk + reliability counters.

Subprocess-isolated PowerShell ``Get-CimInstance`` with a hard timeout (D11):
a wedged WMI service can't stall the collection tick, and the agent doesn't
need to pull pywin32 into this collector to make WMI calls. Reliability
counters (``MSFT_StorageReliabilityCounter``) are merged into each physical
disk record so the backend sees temperature, power-on hours, error counts,
and wear in one structure.
"""

import json
import subprocess

from fivenines_agent.debug import debug, log
from fivenines_agent.env import is_windows
from fivenines_agent.subprocess_utils import get_clean_env

# Hard timeout matching the existing smartctl/mdadm subprocess pattern.
WMI_TIMEOUT_SECONDS = 5

_PHYSICAL_DISK_QUERY = (
    "Get-CimInstance -Namespace root/Microsoft/Windows/Storage "
    "-ClassName MSFT_PhysicalDisk | "
    "Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, "
    "Size, SerialNumber, BusType, SpindleSpeed, ObjectId | "
    "ConvertTo-Json -Compress -Depth 3"
)

_RELIABILITY_QUERY = (
    "Get-CimInstance -Namespace root/Microsoft/Windows/Storage "
    "-ClassName MSFT_StorageReliabilityCounter | "
    "Select-Object DeviceId, Temperature, TemperatureMax, PowerOnHours, "
    "ReadErrorsTotal, ReadErrorsCorrected, ReadErrorsUncorrected, "
    "WriteErrorsTotal, WriteErrorsCorrected, WriteErrorsUncorrected, Wear | "
    "ConvertTo-Json -Compress -Depth 3"
)


def _run_powershell(query):
    """Run a PowerShell command with a hard timeout; return parsed JSON or None.

    Returns the parsed JSON (always a list; PowerShell collapses single rows to
    a dict which is normalized here). Returns None on timeout, non-zero exit,
    PowerShell-not-found, or unparseable output.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", query],
            capture_output=True,
            timeout=WMI_TIMEOUT_SECONDS,
            env=get_clean_env(),
        )
    except subprocess.TimeoutExpired:
        log(f"disk_health_windows: PowerShell timed out after {WMI_TIMEOUT_SECONDS}s", "debug")
        return None
    except (FileNotFoundError, OSError) as e:
        log(f"disk_health_windows: PowerShell not found: {e}", "debug")
        return None

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="ignore").strip()
        log(f"disk_health_windows: PowerShell exit {result.returncode}: {stderr[:200]}", "debug")
        return None

    stdout = result.stdout.decode("utf-8", errors="ignore").strip()
    if not stdout:
        return []
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as e:
        log(f"disk_health_windows: JSON parse failed: {e}", "debug")
        return None

    # ConvertTo-Json returns a single object if the result is one row, a list
    # otherwise. Normalize to always be a list of dicts.
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list):
        return parsed
    log(f"disk_health_windows: unexpected JSON shape: {type(parsed).__name__}", "debug")
    return None


@debug('disk_health_windows')
def disk_health_windows():
    """Collect Windows disk health + reliability counters.

    Returns None on non-Windows hosts and on a hard WMI failure. On success,
    returns a list of dicts (one per physical disk) with MSFT_PhysicalDisk
    fields, augmented by a ``reliability`` sub-dict from
    MSFT_StorageReliabilityCounter when matched by DeviceId/ObjectId.
    """
    if not is_windows():
        return None

    disks = _run_powershell(_PHYSICAL_DISK_QUERY)
    if disks is None:
        return None

    counters = _run_powershell(_RELIABILITY_QUERY) or []
    counter_by_id = {
        c.get("DeviceId"): c for c in counters if isinstance(c, dict) and c.get("DeviceId") is not None
    }

    for disk in disks:
        if not isinstance(disk, dict):
            continue
        # Try matching reliability counters by ObjectId, then SerialNumber.
        # The exact join key varies by Windows version; both are accepted.
        for key in (disk.get("ObjectId"), disk.get("SerialNumber")):
            if key and key in counter_by_id:
                disk["reliability"] = counter_by_id[key]
                break

    return disks
