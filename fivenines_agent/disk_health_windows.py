"""Windows disk-health collector via WMI MSFT_PhysicalDisk + reliability counters.

Subprocess-isolated PowerShell ``Get-CimInstance`` with a hard timeout (D11):
a wedged WMI service can't stall the collection tick, and the agent doesn't
need to pull pywin32 into this collector to make WMI calls. Reliability
counters (``MSFT_StorageReliabilityCounter``) are merged into each physical
disk record so the backend sees temperature, power-on hours, error counts,
and wear in one structure.

Each disk also carries ``DiskNumber``, the N of the ``PhysicalDriveN`` key its
``io`` row is reported under (psutil's ``disk_io_counters(perdisk=True)``), so
the server can tell which ``io`` row an attached VHD/VHDX disk (``BusType``
15, File Backed Virtual) is. The number is ``MSFT_Disk.Number``, read in the
same PowerShell process as ``MSFT_PhysicalDisk`` so the 5s bound still covers
both. ``MSFT_Disk.Location`` is never read: for a profile container it is a
file path holding a user name.
"""

import json
import subprocess

from fivenines_agent.debug import debug, log
from fivenines_agent.env import is_windows
from fivenines_agent.subprocess_utils import get_clean_env

# Hard timeout matching the existing smartctl/mdadm subprocess pattern.
WMI_TIMEOUT_SECONDS = 5

# One process, two classes. MSFT_PhysicalDisk failing is the collector failing
# (Stop turns it into a non-zero exit). MSFT_Disk must never cost the rows:
# it is skipped when MSFT_PhysicalDisk has already used MSFT_DISK_SKIP_AFTER_MS
# of the script (a cold or busy Storage provider), it is asked for its two
# properties only with a 1s operation timeout, and its failure is caught; each
# case leaves Disk null, so every DiskNumber reads unknown and the rows still
# go out. DeviceId and UniqueId are read for the join and dropped before the
# rows are sent; MSFT_Disk.Location is never requested. Both lists are built
# with @() so a single row stays a list, but the parser accepts the collapsed
# form too.
MSFT_DISK_SKIP_AFTER_MS = 2500

_PHYSICAL_DISK_QUERY = (
    "$ErrorActionPreference = 'Stop'; "
    "$sw = [Diagnostics.Stopwatch]::StartNew(); "
    "$ns = 'root/Microsoft/Windows/Storage'; "
    "$physical = @(Get-CimInstance -Namespace $ns -ClassName MSFT_PhysicalDisk | "
    "Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, "
    "Size, SerialNumber, BusType, SpindleSpeed, ObjectId, DeviceId, UniqueId); "
    "$disks = $null; "
    f"if ($sw.ElapsedMilliseconds -lt {MSFT_DISK_SKIP_AFTER_MS}) {{ "
    "try { $disks = @(Get-CimInstance -Namespace $ns -ClassName MSFT_Disk "
    "-Property Number, UniqueId -OperationTimeoutSec 1 | "
    "Select-Object Number, UniqueId) } catch { $disks = $null } }; "
    "@{ PhysicalDisk = $physical; Disk = $disks } | "
    "ConvertTo-Json -Compress -Depth 4"
)

# Read for the join only, never sent.
_JOIN_KEYS = ("DeviceId", "UniqueId")

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

    Returns the parsed JSON as is ([] for an empty output). Returns None on
    timeout, non-zero exit, PowerShell-not-found, or unparseable output.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", query],
            capture_output=True,
            timeout=WMI_TIMEOUT_SECONDS,
            env=get_clean_env(),
        )
    except subprocess.TimeoutExpired:
        log(
            f"disk_health_windows: PowerShell timed out after {WMI_TIMEOUT_SECONDS}s",
            "debug",
        )
        return None
    except (FileNotFoundError, OSError) as e:
        log(f"disk_health_windows: PowerShell not found: {e}", "debug")
        return None

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="ignore").strip()
        log(
            f"disk_health_windows: PowerShell exit {result.returncode}: {stderr[:200]}",
            "debug",
        )
        return None

    stdout = result.stdout.decode("utf-8", errors="ignore").strip()
    if not stdout:
        return []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        log(f"disk_health_windows: JSON parse failed: {e}", "debug")
        return None


def _rows(value):
    """A list of rows from ConvertTo-Json output, or None if not row-shaped.

    ConvertTo-Json returns a single object if the result is one row, a list
    otherwise. Normalize to always be a list.
    """
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return value
    return None


def _confirmed_numbers(disk_rows):
    """Index MSFT_Disk rows by Number spelled as a DeviceId ("3"), keeping
    only the rows that can confirm a match: an integer Number held by exactly
    one row, with a non-empty UniqueId. Value: (Number, UniqueId)."""
    seen = {}
    for row in disk_rows:
        if not isinstance(row, dict):
            continue
        number = row.get("Number")
        if type(number) is not int or number < 0:
            continue
        seen.setdefault(number, []).append(row.get("UniqueId"))
    return {
        str(number): (number, ids[0])
        for number, ids in seen.items()
        if len(ids) == 1 and isinstance(ids[0], str) and ids[0]
    }


def _disk_number(disk, confirmed):
    """The PhysicalDriveN index of a MSFT_PhysicalDisk row, or None.

    MSFT_PhysicalDisk.DeviceId is the disk number for a disk the OS exposes
    (the Storage module's own Get-PhysicalDisk | Get-Disk binds DeviceId to
    Number), but it is not documented as such, so the number is reported only
    when the MSFT_Disk row with that Number carries the same UniqueId. A
    Storage Spaces pool member has no MSFT_Disk row: None.
    """
    device_id = disk.get("DeviceId")
    if not isinstance(device_id, str) or device_id not in confirmed:
        return None
    number, unique_id = confirmed[device_id]
    return number if disk.get("UniqueId") == unique_id else None


@debug("disk_health_windows")
def disk_health_windows():
    """Collect Windows disk health + reliability counters.

    Returns None on non-Windows hosts and on a hard WMI failure. On success,
    returns a list of dicts (one per physical disk) with MSFT_PhysicalDisk
    fields plus ``DiskNumber`` (int, or None when it cannot be confirmed),
    augmented by a ``reliability`` sub-dict from
    MSFT_StorageReliabilityCounter when matched by DeviceId/ObjectId.
    """
    if not is_windows():
        return None

    result = _run_powershell(_PHYSICAL_DISK_QUERY)
    if not isinstance(result, dict):
        if result is not None:
            log("disk_health_windows: unexpected JSON shape", "debug")
        return None
    disks = _rows(result.get("PhysicalDisk"))
    if disks is None:
        log("disk_health_windows: unexpected PhysicalDisk shape", "debug")
        return None
    confirmed = _confirmed_numbers(_rows(result.get("Disk")) or [])

    counters = _rows(_run_powershell(_RELIABILITY_QUERY)) or []
    counter_by_id = {
        c.get("DeviceId"): c
        for c in counters
        if isinstance(c, dict) and c.get("DeviceId") is not None
    }

    for disk in disks:
        if not isinstance(disk, dict):
            continue
        disk["DiskNumber"] = _disk_number(disk, confirmed)
        for key in _JOIN_KEYS:
            disk.pop(key, None)
        # Try matching reliability counters by ObjectId, then SerialNumber.
        # The exact join key varies by Windows version; both are accepted.
        for key in (disk.get("ObjectId"), disk.get("SerialNumber")):
            if key and key in counter_by_id:
                disk["reliability"] = counter_by_id[key]
                break

    return disks
