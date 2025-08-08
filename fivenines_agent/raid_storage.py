import subprocess
import time
import re

from fivenines_agent.env import debug_mode
from fivenines_agent.debug import debug

_raid_cache = {
    "timestamp": 0,
    "data": []
}

def mdadm_available() -> bool:
    """Check if mdadm is available on the system."""
    try:
        subprocess.run(["sudo", "mdadm", "--version", ""], check=True)
        return True
    except Exception:
        return False

def get_mdadm_version():
    """Get mdadm version information."""
    try:
        result = subprocess.run(
            ["sudo", "mdadm", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )

        return result.stdout.split('\n')[0].strip()
    except Exception as e:
        if debug_mode:
            print('Error fetching mdadm version: ', e)
        return None

def list_raid_devices():
    """List all RAID devices using mdadm."""
    devices = []
    try:
        with open('/proc/mdstat', 'r') as f:
            content = f.read()

        for line in content.split('\n'):
            if line.startswith('md'):
                device = '/dev/' + line.split()[0]
                devices.append(device)
    except Exception as e:
        if debug_mode:
            print('Error reading /proc/mdstat: ', e)
    return devices

def _parse_size_with_units(size_str):
    """Parse size string with units and return numeric value."""
    if not size_str:
        return None

    # Extract the numeric part
    match = re.match(r'(\d+)', size_str)
    if match:
        return int(match.group(1))
    return None

def _parse_timestamp(timestamp_str):
    """Parse timestamp string and return epoch time."""
    if not timestamp_str:
        return None

    try:
        import datetime
        dt = datetime.datetime.strptime(timestamp_str, "%a %b %d %H:%M:%S %Y")
        return int(dt.timestamp())
    except (ValueError, AttributeError):
        return None

def get_raid_info(device):
    """Get comprehensive RAID device information using mdadm."""
    try:
        raid_info = {
            "device": device.split('/')[-1],
            "raid_level": None,
            "state": None,
            "active_devices": 0,
            "total_devices": 0,
            "failed_devices": 0,
            "spare_devices": 0,
            "working_devices": 0,
            "component_devices": [],
            "version": None,
            "creation_time": None,
            "creation_time_epoch": None,
            "update_time": None,
            "update_time_epoch": None,
            "array_size": None,
            "array_size_num": None,
            "used_dev_size": None,
            "used_dev_size_num": None,
            "chunk_size": None,
            "chunk_size_num": None,
            "events": None,
            "events_num": None,
            "name": None,
            "uuid": None,
            "persistence": None,
            "consistency_policy": None,
            "resync_status": None,
            "resync_status_percent": None,
            "check_status": None,
            "check_status_percent": None,
            "rebuild_status": None,
            "rebuild_status_percent": None,
            "preferred_minor": None,
            "physical_disks": None
        }

        detail_result = subprocess.run(
            ["sudo", "mdadm", "--detail", device],
            capture_output=True, text=True, check=True
        )

        in_component_section = False
        device_table_lines = []

        for line in detail_result.stdout.splitlines():
            line = line.strip()

            # Check if we're entering the component devices section
            if "Number   Major   Minor   RaidDevice State" in line or "Number   Major   Minor   RaidDevice" in line:
                in_component_section = True
                device_table_lines.append(line)
                continue

            # Skip if we're not in the component section yet
            if not in_component_section:
                if " : " in line:
                    key, value = line.split(" : ", 1)
                    key = key.strip().lower()
                    key = re.sub(r'[^a-z0-9]', '_', key)
                    key = key.strip('_')
                    value = value.strip()

                    # Map common fields
                    if key == "raid_level":
                        raid_info["raid_level"] = value
                    elif key == "state":
                        raid_info["state"] = value.split(", ")
                    elif key == "active_devices":
                        raid_info["active_devices"] = int(value)
                    elif key == "total_devices":
                        raid_info["total_devices"] = int(value)
                    elif key == "failed_devices":
                        raid_info["failed_devices"] = int(value)
                    elif key == "spare_devices":
                        raid_info["spare_devices"] = int(value)
                    elif key == "working_devices":
                        raid_info["working_devices"] = int(value)
                    elif key == "version":
                        raid_info["version"] = value
                    elif key == "creation_time":
                        raid_info["creation_time"] = value
                        raid_info["creation_time_epoch"] = _parse_timestamp(value)
                    elif key == "update_time":
                        raid_info["update_time"] = value
                        raid_info["update_time_epoch"] = _parse_timestamp(value)
                    elif key == "array_size":
                        raid_info["array_size"] = value
                        raid_info["array_size_num"] = _parse_size_with_units(value)
                    elif key == "used_dev_size":
                        raid_info["used_dev_size"] = value
                        raid_info["used_dev_size_num"] = _parse_size_with_units(value)
                    elif key == "chunk_size":
                        raid_info["chunk_size"] = value
                        raid_info["chunk_size_num"] = _parse_size_with_units(value)
                    elif key == "events":
                        raid_info["events"] = value
                        raid_info["events_num"] = int(value) if value.isdigit() else None
                    elif key == "name":
                        raid_info["name"] = value
                    elif key == "uuid":
                        raid_info["uuid"] = value
                    elif key == "persistence":
                        raid_info["persistence"] = value
                    elif key == "consistency_policy":
                        raid_info["consistency_policy"] = value
                    elif key == "resync_status":
                        raid_info["resync_status"] = value
                        if "%" in value:
                            raid_info["resync_status_percent"] = int(value.split('%')[0])
                    elif key == "check_status":
                        raid_info["check_status"] = value
                        if "%" in value:
                            raid_info["check_status_percent"] = int(value.split('%')[0])
                    elif key == "rebuild_status":
                        raid_info["rebuild_status"] = value
                        if "%" in value:
                            raid_info["rebuild_status_percent"] = int(value.split('%')[0])
                    elif key == "preferred_minor":
                        raid_info["preferred_minor"] = int(value)
                    elif key == "physical_disks":
                        raid_info["physical_disks"] = int(value)
            else:
                device_table_lines.append(line)

        if device_table_lines:
            raid_info["component_devices"] = _parse_device_table(device_table_lines)

        return raid_info

    except Exception as e:
        if debug_mode:
            print(f'Error fetching RAID info for device {device}: {e}')
        return None

def _parse_device_table(table_lines):
    """Parse the device table section from mdadm output."""
    devices = []

    for line in table_lines:
        line = line.strip()

        # Skip header lines and empty lines
        if not line or "Number" in line or "Major" in line:
            continue

        if line and line[0].isdigit():
            parts = line.split()
            if len(parts) >= 4:
                device_info = {
                    "number": int(parts[0]) if parts[0].isdigit() else None,
                    "major": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None,
                    "minor": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None,
                    "raid_device": int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None,
                    "state": [],
                    "device": None
                }

                if len(parts) >= 5:
                    device_info["device"] = parts[-1]
                    device_info["state"] = parts[4:-1]

                devices.append(device_info)

    return devices

@debug('raid_storage_health')
def raid_storage_health():
    """
    Collect health info for all RAID devices managed by mdadm.
    Cached for 60 seconds.
    """
    global _raid_cache
    now = time.time()

    if now - _raid_cache["timestamp"] < 60:
        return _raid_cache["data"]

    if not mdadm_available():
        if debug_mode:
            print("mdadm not installed")
        data = []
    else:
        mdadm_version = get_mdadm_version()

        devices = list_raid_devices()
        if not devices:
            if debug_mode:
                print("No RAID devices found")
            data = []
        else:
            data = [get_raid_info(dev) for dev in devices]
            # Remove None values and add mdadm version
            data = [d for d in data if d is not None]
            for raid_info in data:
                raid_info["mdadm_version"] = mdadm_version

    _raid_cache["timestamp"] = now
    _raid_cache["data"] = data

    return data
