import subprocess
import shutil
import time

from fivenines_agent.env import debug_mode

_raid_cache = {
    "timestamp": 0,
    "data": []
}

def mdadm_available() -> bool:
    """Check if mdadm is available on the system."""
    return shutil.which("mdadm") is not None

def get_mdadm_version():
    """Get mdadm version information."""
    try:
        result = subprocess.run(
            ["mdadm", "--version"],
            capture_output=True, text=True, check=True
        )
        # Extract version from first line
        version_line = result.stdout.split('\n')[0]
        return version_line.strip()
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
        result = subprocess.run(
            ["sudo", "mdadm", "--detail", "--scan"],
            capture_output=True, text=True, check=True
        )

        # Parse the scan output to find our device
        raid_info = None
        for line in result.stdout.splitlines():
            if device in line:
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
                break

        if not raid_info:
            return None

        detail_result = subprocess.run(
            ["sudo", "mdadm", "--detail", device],
            capture_output=True, text=True, check=True
        )

        for line in detail_result.stdout.splitlines():
            line = line.strip()
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
            elif line.startswith("/dev/"):
                component = {
                    "device": line.split()[0].split('/')[-1],
                    "state": line.split()[-1] if len(line.split()) > 1 else "unknown"
                }
                raid_info["component_devices"].append(component)

        return raid_info

    except Exception as e:
        if debug_mode:
            print(f'Error fetching RAID info for device {device}: {e}')
        return None

def raid_storage_health():
    """
    Collect health info for all RAID devices.
    Uses mdadm for all devices.
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
        devices = list_raid_devices()
        if not devices:
            if debug_mode:
                print("No RAID devices found")
            data = []
        else:
            data = [get_raid_info(dev) for dev in devices]
            # Remove None values and add tool version
            data = [d for d in data if d is not None]
            for raid_info in data:
                raid_info["mdadm_version"] = get_mdadm_version()

    _raid_cache["timestamp"] = now
    _raid_cache["data"] = data

    return data
