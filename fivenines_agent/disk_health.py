import subprocess
import shutil
import os
import time

from fivenines_agent.env import debug_mode

_disk_cache = {
    "timestamp": 0,
    "data": []
}

def smartctl_available():
    return shutil.which("smartctl") is not None

def list_block_devices():
    devices = []
    try:
        lines = subprocess.Popen('sudo smartctl --scan', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0].decode().splitlines()
        for line in lines:
            devices.append(line.split(' ')[0])
    except Exception as e:
        if debug_mode:
            print('Error fetching block devices: ', e)
        return []
    return devices

def get_disk_info(device):
    try:
        results = {}

        disk_stats = os.popen('sudo smartctl -A -H {}'.format(device)).read().splitlines()
        for stats in disk_stats:
            if stats.rfind(":") == -1:
                continue
            stats = stats.split(':')
            results[stats[0].strip().replace(' ', '_').replace('-', '_').lower()] = stats[1].strip()
        results["device"] = device.split('/')[-1]

        return clean_results(results)
    except Exception as e:
        if debug_mode:
            print('Error fetching disk info for device: ', device, 'error: ', e)
        return None

def clean_results(results):
    """Clean the results of the SMART info."""
    cleaned_results = {}
    cleaned_results['self_assessment_test_result'] = results["smart_overall_health_self_assessment_test_result"]
    cleaned_results['critical_warning'] = int(results["critical_warning"], 16)
    cleaned_results["temperature"] = int(results["temperature"].split(' ')[0])
    cleaned_results['available_spare_percentage'] = int(results["available_spare"].split('%')[0])
    cleaned_results['available_spare_threshold_percentage'] = int(results["available_spare_threshold"].split('%')[0])
    cleaned_results['percentage_used'] = int(results["percentage_used"].split('%')[0])
    cleaned_results['data_units_read'] = int(results["data_units_read"].split(' ')[0].replace(',', ''))
    cleaned_results['data_units_written'] = int(results["data_units_written"].split(' ')[0].replace(',', ''))
    cleaned_results['host_read_commands'] = int(results["host_read_commands"].replace(',', ''))
    cleaned_results['host_write_commands'] = int(results["host_write_commands"].replace(',', ''))
    cleaned_results['controller_busy_time'] = int(results["controller_busy_time"].replace(',', ''))
    cleaned_results['power_cycles'] = int(results["power_cycles"].replace(",", ""))
    cleaned_results['power_on_hours'] = int(results["power_on_hours"].replace(",", ""))
    cleaned_results['unsafe_shutdowns'] = int(results["unsafe_shutdowns"].replace(",", ""))
    cleaned_results['media_errors'] = int(results["media_and_data_integrity_errors"].replace(',', ''))
    cleaned_results['error_information_log_entries'] = int(results["error_information_log_entries"])
    cleaned_results['warning_comp_temperature_time'] = int(results["warning__comp._temperature_time"])
    cleaned_results['critical_comp_temperature_time'] = int(results["critical_comp._temperature_time"])
    cleaned_results["device"] = results["device"]

    return cleaned_results


def disk_health():
    """Collect SMART info, but only once per minute (cached)."""
    global _disk_cache
    now = time.time()

    if now - _disk_cache["timestamp"] < 60:
        return _disk_cache["data"]

    if not smartctl_available():
        if debug_mode:
            print("smartctl not installed")
        data = []
    else:
        devices = list_block_devices()
        if not devices:
            if debug_mode:
                print("No devices found")
            data = []
        else:
            data = [get_disk_info(dev) for dev in devices]

    print(data)
    # Remove None values
    data = [d for d in data if d is not None]
    print(data)

    _disk_cache["timestamp"] = now
    _disk_cache["data"] = data

    return data
