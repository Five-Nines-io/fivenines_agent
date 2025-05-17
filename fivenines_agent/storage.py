import subprocess
import json
import shutil
import os
import time

from fivenines_agent.env import debug_mode

_health_storage_cache = {
    "timestamp": 0,
    "data": []
}

_identification_storage_cache = {
    "timestamp": 0,
    "data": []
}

# Standard SMART attribute names by ID
SMART_ATTRIBUTE_NAMES = {
    '1': 'raw_read_error_rate',
    '2': 'throughput_performance',
    '3': 'spin_up_time',
    '4': 'start_stop_count',
    '5': 'reallocated_sector_ct',
    '6': 'seek_error_rate',
    '7': 'seek_time_performance',
    '8': 'power_on_hours',
    '9': 'spin_retry_count',
    '10': 'calibration_retry_count',
    '11': 'recalibration_retries',
    '12': 'power_cycle_count',
    '13': 'soft_read_error_rate',
    '183': 'runtime_bad_block',
    '184': 'end_to_end_error',
    '187': 'reported_uncorrectable_errors',
    '188': 'command_timeout',
    '189': 'high_fly_writes',
    '190': 'airflow_temperature_celsius',
    '191': 'g_sense_error_rate',
    '192': 'power_off_retract_count',
    '193': 'load_cycle_count',
    '194': 'temperature_celsius',
    '195': 'hardware_ecc_recovered',
    '196': 'reallocated_event_count',
    '197': 'current_pending_sector',
    '198': 'offline_uncorrectable',
    '199': 'udma_crc_error_count',
    '200': 'multi_zone_error_rate',
    '201': 'soft_read_error_rate',
    '202': 'data_address_mark_errors',
    '203': 'run_out_cancel',
    '204': 'soft_ecc_correction',
    '205': 'thermal_asperity_rate',
    '206': 'flying_height',
    '207': 'spin_high_current',
    '208': 'spin_buzz',
    '209': 'offline_seek_performance',
    '211': 'vibration_during_write',
    '212': 'shock_during_write',
    '220': 'disk_shift',
    '221': 'g_sense_error_rate',
    '222': 'loaded_hours',
    '223': 'load_retry_count',
    '224': 'load_friction',
    '225': 'load_cycle_count',
    '226': 'load_in_time',
    '227': 'torque_amplification_count',
    '228': 'power_off_retract_cycle',
    '230': 'gmr_head_amplitude',
    '231': 'life_left',
    '232': 'endurance_remaining',
    '233': 'media_wearout_indicator',
    '234': 'average_erase_count',
    '235': 'good_block_count',
    '240': 'head_flying_hours',
    '241': 'total_lbas_written',
    '242': 'total_lbas_read',
    '250': 'read_error_retry_rate',
    '251': 'minimum_spares_remaining',
    '252': 'newly_added_bad_flash_block',
    '254': 'free_fall_protection'
}

STORAGE_IDENTIFICATION_ATTRIBUTES = {
    "model_family": "Model Family",
    "device_model": "Device Model",
    "serial_number": "Serial Number",
    "firmware_version": "Firmware Version",
    "user_capacity": "User Capacity",
    "sector_size": "Sector Size",
    "rotation_rate": "Rotation Rate"
}

# Standard NVMe attribute names, values are not used are there for reference
NVME_ATTRIBUTE_NAMES = {
    'temperature': 'Temperature',
    'avail_spare': 'Available Spare',
    'spare_thresh': 'Available Spare Threshold',
    'percent_used': 'Percentage Used',
    'data_units_read': 'Data Units Read',
    'data_units_written': 'Data Units Written',
    'host_read_commands': 'Host Read Commands',
    'host_write_commands': 'Host Write Commands',
    'controller_busy_time': 'Controller Busy Time',
    'power_cycles': 'Power Cycles',
    'power_on_hours': 'Power On Hours',
    'unsafe_shutdowns': 'Unsafe Shutdowns',
    'media_errors': 'Media Errors',
    'num_err_log_entries': 'Error Information Log Entries',
    'warning_temp_time': 'Warning Composite Temperature Time',
    'critical_comp_time': 'Critical Composite Temperature Time'
}

def smartctl_available():
    """Check if smartctl is available on the system."""
    return shutil.which("smartctl") is not None

def nvme_cli_available():
    """Check if nvme-cli is available on the system."""
    return shutil.which("nvme") is not None

def list_storage_devices():
    """List all storage devices using smartctl."""
    devices = []
    try:
        lines = subprocess.Popen('sudo smartctl --scan', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0].decode().splitlines()
        for line in lines:
            devices.append(line.split(' ')[0])
    except Exception as e:
        if debug_mode:
            print('Error fetching storage devices: ', e)
        return []
    return devices

def is_nvme_device(device):
    """Check if a device is an NVMe device."""
    return device.startswith('/dev/nvme')

def get_nvme_enhanced_info(device):
    """Get additional NVMe-specific information using nvme-cli."""
    try:
        result = subprocess.run(
            ["sudo", "nvme", "smart-log", device, "-o", "json"],
            capture_output=True, text=True, check=True
        )
        raw = json.loads(result.stdout)

        # Convert raw values to standardized format
        enhanced_info = {}
        for key, name in NVME_ATTRIBUTE_NAMES.items():
            if key in raw:
                value = raw[key]
                # Special handling for temperature (convert from Kelvin to Celsius)
                if key == 'temperature':
                    key = 'temperature_celsius'
                    value = round(value - 273.15, 1)
                enhanced_info[key] = value

        return enhanced_info
    except Exception as e:
        if debug_mode:
            print('Error fetching NVMe enhanced info for device: ', device, 'error: ', e)
        return {}

def get_storage_info(device):
    """Get storage device information using smartctl and optionally nvme-cli."""
    try:
        results = {}

        # Get basic SMART info using smartctl
        disk_stats = os.popen('sudo smartctl -A -H {}'.format(device)).read().splitlines()

        # Skip header lines until we find the SMART data section
        found_section = False
        current_section = None
        for stats in disk_stats:
            if "=== START OF SMART DATA SECTION ===" in stats:
                found_section = True
                current_section = "nvme"
                continue
            elif "=== START OF READ SMART DATA SECTION ===" in stats:
                found_section = True
                current_section = "ata"
                continue
            if not found_section:
                continue

            if stats.rfind(":") == -1:
                # Handle ATA SMART attributes table
                if current_section == "ata" and "ID#" not in stats and stats.strip():
                    try:
                        parts = stats.split()
                        if len(parts) >= 10:
                            attr_id = parts[0]
                            # Store raw value with ID as key
                            results[f"smart_attr_{attr_id}"] = parts[9]
                    except Exception as e:
                        if debug_mode:
                            print(f'Error parsing ATA attribute: {e}')
                continue

            # Split on first occurrence of colon to handle values that might contain colons
            parts = stats.split(':', 1)
            if len(parts) != 2:
                continue

            key = parts[0].strip().replace(' ', '_').replace('-', '_').lower()
            results[key] = parts[1].strip()

        results["device"] = device.split('/')[-1]
        results["device_type"] = current_section

        # Clean and process the basic SMART info
        cleaned_results = clean_smart_results(results)

        # If it's an NVMe device and nvme-cli is available, get enhanced info
        if is_nvme_device(device) and nvme_cli_available():
            nvme_info = get_nvme_enhanced_info(device)
            # Update cleaned results with NVMe specific data
            cleaned_results.update(nvme_info)

        return cleaned_results

    except Exception as e:
        if debug_mode:
            print('Error fetching storage info for device: ', device, 'error: ', e)
        return None

def safe_int_conversion(value, base=10):
    """Safely convert a string to integer, handling various formats."""
    if not value:
        return None
    try:
        # Remove any non-numeric characters except for minus sign
        cleaned = ''.join(c for c in value if c.isdigit() or c == '-')
        return int(cleaned, base)
    except (ValueError, TypeError):
        return None

def safe_percentage_conversion(value):
    """Safely extract percentage value from string."""
    if not value:
        return None
    try:
        # Extract first number before % or space
        parts = value.split('%')[0].split(' ')[0]
        return safe_int_conversion(parts)
    except (ValueError, TypeError, IndexError):
        return None

def safe_temperature_conversion(value):
    """Safely extract temperature value from string."""
    if not value:
        return None
    try:
        # Extract first number before any unit or space
        parts = value.split(' ')[0]
        return safe_int_conversion(parts)
    except (ValueError, TypeError, IndexError):
        return None

def clean_smart_results(results):
    """Clean and standardize the SMART info results."""
    cleaned_results = {
        "device": results.get("device"),
        "device_type": results.get("device_type")
    }

    # Process basic SMART info
    if 'smart_overall_health_self_assessment_test_result' in results:
        cleaned_results['smart_overall_health'] = results['smart_overall_health_self_assessment_test_result']

    if 'critical_warning' in results:
        cleaned_results['critical_warning'] = safe_int_conversion(results['critical_warning'], 16)

    # Process temperature sensors
    temperature_sensors = {
        key.split('_')[-1]: safe_temperature_conversion(value)
        for key, value in results.items()
        if key.startswith('temperature_sensor_')
    }
    if temperature_sensors:
        cleaned_results['temperature_sensors'] = temperature_sensors

    # Process ATA SMART attributes
    for key, value in results.items():
        if key.startswith('smart_attr_'):
            attr_id = key.split('_')[2]
            attr_name = SMART_ATTRIBUTE_NAMES.get(attr_id, 'unknown')
            raw_value = safe_int_conversion(value)
            if raw_value is not None:
                cleaned_results[attr_name] = raw_value

    return cleaned_results

def get_smartctl_version():
    """Get smartctl version information."""
    try:
        result = subprocess.run(
            ["smartctl", "--version"],
            capture_output=True, text=True, check=True
        )
        # Extract version from first line
        version_line = result.stdout.split('\n')[0]
        return version_line.strip()
    except Exception as e:
        if debug_mode:
            print('Error fetching smartctl version: ', e)
        return None

def get_nvme_cli_version():
    """Get nvme-cli version information."""
    try:
        result = subprocess.run(
            ["nvme", "version"],
            capture_output=True, text=True, check=True
        )
        # Extract version from first line
        version_line = result.stdout.split('\n')[0]
        return version_line.strip()
    except Exception as e:
        if debug_mode:
            print('Error fetching nvme-cli version: ', e)
        return None

def get_storage_identification(device):
    """Get storage device identification using smartctl."""
    try:
        result = subprocess.run(
            ["smartctl", "--identify", device],
            capture_output=True, text=True, check=True
        )

        results = {}
        for line in result.stdout.splitlines():
            for key, value in STORAGE_IDENTIFICATION_ATTRIBUTES.items():
                if line.rfind(value) != -1:
                    results[key] = line.split(value)[1].strip()

        return results
    except Exception as e:
        if debug_mode:
            print('Error fetching storage identification for device: ', device, 'error: ', e)
        return None

def storage_identification():
    """Collect storage identification for all storage devices.
    Uses smartctl for all devices.
    Cached for 60 seconds.
    """
    global _identification_storage_cache
    now = time.time()


    # Cache for 10 minutes, we don't need to update this too often
    # This can change only for hotswapped drives
    if now - _identification_storage_cache["timestamp"] < 600:
        return _identification_storage_cache["data"]

    if not smartctl_available():
        if debug_mode:
            print("smartctl not installed")
        data = []
    else:
        devices = list_storage_devices()
        if not devices:
            if debug_mode:
                print("No storage devices found")
            data = []
        else:
            data = [get_storage_identification(dev) for dev in devices]

    data = [d for d in data if d is not None]

    _identification_storage_cache["timestamp"] = now
    _identification_storage_cache["data"] = data

    return data

def storage_health():
    """
    Collect health info for all storage devices.
    Uses smartctl for all devices and enhances NVMe devices with nvme-cli when available.
    Cached for 60 seconds.
    """
    global _health_storage_cache
    now = time.time()

    if now - _health_storage_cache["timestamp"] < 60:
        return _health_storage_cache["data"]

    if not smartctl_available():
        if debug_mode:
            print("smartctl not installed")
        data = []
    else:
        devices = list_storage_devices()
        if not devices:
            if debug_mode:
                print("No storage devices found")
            data = []
        else:
            # Get tool versions only if we have devices to process
            tool_versions = {
                "smartctl_version": get_smartctl_version() if smartctl_available() else None,
                "nvme_cli_version": get_nvme_cli_version() if nvme_cli_available() else None
            }
            data = [get_storage_info(dev) for dev in devices]
            # Remove None values and add tool versions
            data = [d for d in data if d is not None]
            for device_info in data:
                device_info.update(tool_versions)

    _health_storage_cache["timestamp"] = now
    _health_storage_cache["data"] = data

    return data
