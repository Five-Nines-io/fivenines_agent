"""Check disk_health_windows() against the real host (Windows CI only).

Run from the repository root with the disk images the workflow attached:

    python ci/windows-disk-number-check.py <number> [<number> ...]

Each <number> is a disk number Get-DiskImage reported for an attached VHD or
VHDX. The collector's output must carry, for each, a row with BusType 15 (an
integer) and DiskNumber equal to it, and psutil's per-disk I/O must have a
PhysicalDrive<number> row for it: the join the server relies on. Every disk
must be numbered (the runner has no Storage Spaces pool), and every row must
carry exactly the keys agents sent before DiskNumber existed, plus DiskNumber.
"""

import json
import sys

import psutil

from fivenines_agent.disk_health_windows import disk_health_windows

FILE_BACKED_VIRTUAL = 15
KEYS = {
    "FriendlyName",
    "MediaType",
    "HealthStatus",
    "OperationalStatus",
    "Size",
    "SerialNumber",
    "BusType",
    "SpindleSpeed",
    "ObjectId",
    "DiskNumber",
}


def main(expected):
    rows = None
    # The Storage WMI provider's first query after boot can take seconds: the
    # collector's 5s bound may cut it, so give it three ticks.
    for _ in range(3):
        rows = disk_health_windows()
        if rows is not None:
            break
    if rows is None:
        sys.exit("disk_health_windows() returned None three times")
    io_keys = set(psutil.disk_io_counters(perdisk=True))
    for row in rows:
        shown = {
            k: row.get(k) for k in ("FriendlyName", "BusType", "DiskNumber", "Size")
        }
        print(json.dumps(shown, sort_keys=True))
    print("psutil:", sorted(io_keys))

    failures = []
    for row in rows:
        keys = set(row) - {"reliability"}
        if keys != KEYS:
            failures.append(f"row keys {sorted(keys)} != {sorted(KEYS)}")
        if type(row["BusType"]) is not int:
            failures.append(
                f"BusType is {type(row['BusType']).__name__}: {row['BusType']!r}"
            )
        number = row["DiskNumber"]
        if type(number) is not int:
            # No Storage Spaces pool on the runner: every disk is confirmed.
            failures.append(f"DiskNumber is {number!r} for {row['FriendlyName']}")
        elif f"PhysicalDrive{number}" not in io_keys and number <= 32:
            # psutil probes PhysicalDrive0 to PhysicalDrive32 only.
            failures.append(f"DiskNumber {number} has no PhysicalDrive{number} io row")
    numbers = [row["DiskNumber"] for row in rows]
    if len(numbers) != len(set(numbers)):
        failures.append(f"a DiskNumber is reported twice: {numbers}")
    for n in expected:
        match = [r for r in rows if r["DiskNumber"] == n]
        if len(match) != 1 or match[0]["BusType"] != FILE_BACKED_VIRTUAL:
            failures.append(
                f"attached image disk {n}: expected one BusType 15 row, got {match}"
            )
    if failures:
        sys.exit("\n".join(failures))
    print(
        f"OK: {len(rows)} disks, images {expected} reported as BusType 15 with their numbers"
    )


if __name__ == "__main__":
    main([int(a) for a in sys.argv[1:]])
