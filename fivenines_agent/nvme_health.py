import subprocess
import json
import shutil
import time

from fivenines_agent.env import debug_mode

_nvme_cache = {
    "timestamp": 0,
    "data": []
}

def nvme_cli_available() -> bool:
    return shutil.which("nvme") is not None

def list_nvme_devices():
    devices = []

    try:
        raw_data = subprocess.Popen('sudo nvme --list --output-format=json', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0]
        devices_info = json.loads(raw_data)
        for device_info in devices_info['Devices']:
            devices.append(device_info['DevicePath'])
        return devices

    except Exception as e:
        if debug_mode:
            print("Error fetching nvme status information: ", e)
        return []

def get_nvme_info(device):
    """Fetch SMART/health data for a controller or namespace."""
    try:
        result = subprocess.run(
            ["sudo", "nvme", "smart-log", device, "-o", "json"],
            capture_output=True, text=True, check=True
        )
        raw = json.loads(result.stdout)

        return {
            "device": device.split('/')[-1],
            "controller_busy_time": raw.get("controller_busy_time"),
            "temperature": raw.get("temperature") - 273.15, # convert to celsius
            "percentage_used": raw.get("percent_used"),
            "power_cycles": raw.get("power_cycles"),
            "power_on_hours": raw.get("power_on_hours"),
            "host_read_commands": raw.get("host_read_commands"),
            "host_write_commands": raw.get("host_write_commands"),
            "available_spare_percentage": raw.get("avail_spare"),
            "available_spare_threshold_percentage": raw.get("spare_thresh"),
            "media_errors": raw.get("media_errors"),
            "unsafe_shutdowns": raw.get("unsafe_shutdowns"),
            "power_on_hours": raw.get("power_on_hours"),
            "critical_warning": raw.get("critical_warning"),
            "data_units_written": raw.get("data_units_written"),
            "data_units_read": raw.get("data_units_read"),
            "error_information_log_entries": raw.get("num_err_log_entries"),
            "warning_comp_temperature_time": raw.get("warning_temp_time"),
            "critical_comp_temperature_time": raw.get("critical_comp_time"),
        }

    except Exception as e:
        if debug_mode:
            print('Error fetching nvme info for device: ', device, 'error: ', e)
        return None


def nvme_health():
    """
    Collect health info for all NVMe controllers and namespaces.
    Cached for 60 s.
    """
    global _nvme_cache
    now = time.time()

    if now - _nvme_cache["timestamp"] < 60:
        return _nvme_cache["data"]

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
            data = [get_nvme_info(dev) for dev in devices]

    # Remove None values
    data = [d for d in data if d is not None]

    _nvme_cache["timestamp"] = now
    _nvme_cache["data"] = data

    return data
