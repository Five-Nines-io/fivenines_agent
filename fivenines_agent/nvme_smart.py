import subprocess
import json
import os
import re
import shutil
import time

from fivenines_agent.env import debug_mode

_nvme_smart_cache = {
    "timestamp": 0,
    "data": []
}


def nvme_cli_available():
    """Check if nvme-cli is installed and accessible."""
    return shutil.which("nvme") is not None


def list_nvme_devices():
    """List the NVMe devices visible in /dev/"""
    devices = []
    try:
        for entry in os.listdir('/dev'):
            if re.match(r'^nvme\d+n\d+$', entry):
                devices.append(f'/dev/{entry}')
    except Exception as e:
        return []
    return devices


def get_nvme_smart_info(device):
    """Get the SMART info of a given NVMe device."""
    try:
        result = subprocess.run(
            ["nvme", "smart-log", device, "-o", "json"],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        return {
            "device": device,
            "status": "ok",
            "temperature": data.get("temperature"),
            "percentage_used": data.get("percentage_used"),
            "available_spare": data.get("available_spare"),
            "media_errors": data.get("media_errors"),
            "unsafe_shutdowns": data.get("unsafe_shutdowns"),
            "power_on_hours": data.get("power_on_hours"),
            "critical_warning": data.get("critical_warning"),
            "data_units_written": data.get("data_units_written"),
            "data_units_read": data.get("data_units_read"),
        }
    except subprocess.CalledProcessError as e:
        return {"device": device, "status": "error", "error": e.stderr.strip()}
    except json.JSONDecodeError:
        return {"device": device, "status": "error", "error": "Invalid JSON from nvme-cli"}
    except Exception as e:
        return {"device": device, "status": "error", "error": str(e)}


def nvme_smart():
    """Collect the SMART info of all available NVMe disks, but only once per minute (cached)."""
    global _nvme_smart_cache
    now = time.time()

    if now - _nvme_smart_cache["timestamp"] < 60:
        return _nvme_smart_cache["data"]

    if not nvme_cli_available():
        if debug_mode:
            print("nvme-cli not installed")
        data = []
    else:
        devices = list_nvme_devices()
        if not devices:
            if debug_mode:
                print("No NVMe devices found")
            data = []
        else:
            data = [get_nvme_smart_info(dev) for dev in devices]

    _nvme_smart_cache["timestamp"] = now
    _nvme_smart_cache["data"] = data
    return data
