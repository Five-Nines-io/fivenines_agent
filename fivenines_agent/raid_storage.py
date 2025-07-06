import subprocess
import time

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

def get_raid_info(device):
    """Get RAID device information using mdadm."""
    try:
        raid_info = {
            "device": device.split('/')[-1],
            "raid_level": None,
            "state": None,
            "active_devices": 0,
            "total_devices": 0,
            "failed_devices": 0,
            "spare_devices": 0,
            "component_devices": []
        }

        detail_result = subprocess.run(
            ["sudo", "mdadm", "--detail", device],
            capture_output=True, text=True, check=True
        )

        in_component_section = False
        for line in detail_result.stdout.splitlines():
            line = line.strip()

            # Check if we're entering the component devices section
            if "Number   Major   Minor   RaidDevice State" in line:
                in_component_section = True
                continue

            # Skip if we're not in the component section yet
            if not in_component_section:
                if "Raid Level" in line:
                    raid_info["raid_level"] = line.split(":")[1].strip()
                elif "State" in line:
                    raid_info["state"] = line.split(":")[1].strip()
                elif "Active Devices" in line:
                    raid_info["active_devices"] = int(line.split(":")[1].strip())
                elif "Total Devices" in line:
                    raid_info["total_devices"] = int(line.split(":")[1].strip())
                elif "Failed Devices" in line:
                    raid_info["failed_devices"] = int(line.split(":")[1].strip())
                elif "Spare Devices" in line:
                    raid_info["spare_devices"] = int(line.split(":")[1].strip())
            else:
                # We're in the component section, parse device lines
                # Skip empty lines and the header line
                if not line or "Number" in line:
                    continue

                # Parse device lines that start with a number (the device number)
                if line and line[0].isdigit():
                    parts = line.split()
                    if len(parts) >= 7:
                        component = {
                            "device": parts[-1].split('/')[-1],
                            "state": f"{parts[-3]} {parts[-2]}"
                        }
                        raid_info["component_devices"].append(component)

        return raid_info

    except Exception as e:
        if debug_mode:
            print(f'Error fetching RAID info for device {device}: {e}')
        return None

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
