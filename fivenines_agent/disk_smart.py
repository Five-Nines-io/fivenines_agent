import subprocess
import shutil
import json
import os
import re
import time

from fivenines_agent.env import debug_mode

_disk_smart_cache = {
    "timestamp": 0,
    "data": []
}

def smartctl_available():
    return shutil.which("smartctl") is not None

def list_block_devices():
    """List all /dev/sdX devices (excluding partitions)."""
    devices = []
    try:
        for entry in os.listdir("/dev"):
            if re.match(r'^sd[a-z]$', entry):
                devices.append(f"/dev/{entry}")
    except Exception:
        return []
    return devices

def extract_attribute(attributes, attr_id):
    """Extract the value of a given attribute ID from the SMART data."""
    for attr in attributes:
        if attr.get("id") == attr_id:
            return attr.get("raw", {}).get("value")
    return None

def get_disk_smart_info(device):
    """Get the SMART info of a given block device."""
    try:
        result = subprocess.run(
            ["smartctl", "-A", "-j", device],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        attributes = data.get("ata_smart_attributes", {}).get("table", [])

        return {
            "device": device,
            "status": "ok",
            "smart_passed": data.get("smart_status", {}).get("passed", None),
            "model": data.get("model_name"),
            "serial_number": data.get("serial_number"),
            "temperature_celsius": extract_attribute(attributes, 194),
            "power_on_hours": extract_attribute(attributes, 9),
            "reallocated_sectors": extract_attribute(attributes, 5),
            "pending_sectors": extract_attribute(attributes, 197),
            "offline_uncorrectable": extract_attribute(attributes, 198),
            "crc_errors": extract_attribute(attributes, 199),
        }

    except subprocess.CalledProcessError as e:
        return {"device": device, "status": "error", "error": e.stderr.strip()}
    except json.JSONDecodeError:
        return {"device": device, "status": "error", "error": "Invalid JSON from smartctl"}
    except Exception as e:
        return {"device": device, "status": "error", "error": str(e)}

def disk_smart():
    """Collect SMART info, but only once per minute (cached)."""
    global _disk_smart_cache
    now = time.time()

    if now - _disk_smart_cache["timestamp"] < 60:
        return _disk_smart_cache["data"]

    if not smartctl_available():
        if debug_mode:
            print("smartctl not installed")
        data = []
    else:
        devices = list_block_devices()
        if not devices:
            if debug_mode:
                print("No /dev/sdX devices found")
            data = []
        else:
            data = [get_disk_smart_info(dev) for dev in devices]

    _disk_smart_cache["timestamp"] = now
    _disk_smart_cache["data"] = data
    return data
