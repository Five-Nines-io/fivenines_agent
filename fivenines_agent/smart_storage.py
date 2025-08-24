import subprocess
import json
import os
import time

from fivenines_agent.debug import debug, log

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
    "Model Number": "model_family",
    "Model Family": "model_family",
    "Device Model": "device_model",
    "Serial Number": "serial_number",
    "Firmware Version": "firmware_version",
    "User Capacity": "total_capacity",
    "Total NVM Capacity": "total_capacity",
    "Sector Size": "sector_size",
    "Rotation Rate": "rotation_rate"
}

# Standard NVMe attribute names, values are not used are there for reference
NVME_ATTRIBUTE_NAMES = {
    'Temperature': 'temperature',
    'Available Spare': 'avail_spare',
    'Available Spare Threshold': 'spare_thresh',
    'Percentage Used': 'percent_used',
    'Data Units Read': 'data_units_read',
    'Data Units Written': 'data_units_written',
    'Host Read Commands': 'host_read_commands',
    'Host Write Commands': 'host_write_commands',
    'Controller Busy Time': 'controller_busy_time',
    'Power Cycles': 'power_cycles',
    'Power On Hours': 'power_on_hours',
    'Unsafe Shutdowns': 'unsafe_shutdowns',
    'Media Errors': 'media_errors',
    'Error Information Log Entries': 'num_err_log_entries',
    'Warning Composite Temperature Time': 'warning_temp_time',
    'Critical Composite Temperature Time': 'critical_comp_time'
}

def smartctl_available():

    """Check if smartctl is available on the system."""
    try:
        subprocess.run(["sudo", "smartctl", "--version"], check=True)
        return True
    except Exception:
        return False

def nvme_cli_available():
    """Check if nvme-cli is available on the system."""
    try:
        subprocess.run(["sudo", "nvme", "version"], check=True)
        return True
    except Exception:
        return False

def is_partition(device):
    """Check if a device is a partition."""
    # NVMe partitions end with 'p' followed by numbers
    if device.startswith('/dev/nvme') and 'p' in device:
        return True
    # SATA/SCSI partitions end with numbers
    if device.startswith('/dev/sd') and device[-1].isdigit():
        return True
    return False

def list_storage_devices():
    """List all storage devices using smartctl."""
    devices = []
    try:
        lines = subprocess.Popen('sudo smartctl --scan', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0].decode().splitlines()
        for line in lines:
            device = line.split(' ')[0]
            if not is_partition(device):
                devices.append(device)
    except Exception as e:
        log(f"Error fetching storage devices: {e}", 'error')
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
        for name, key in NVME_ATTRIBUTE_NAMES.items():
            if key in raw:
                value = raw[key]
                # Special handling for temperature (convert from Kelvin to Celsius)
                if key == 'temperature':
                    key = 'temperature_celsius'
                    value = round(value - 273.15, 1)
                enhanced_info[key] = value

        return enhanced_info
    except Exception as e:
        log(f"Error fetching NVMe enhanced info for device: {device}: {e}", 'error')
        return {}

def get_storage_info(device):
    """Get storage device information using smartctl and optionally nvme-cli."""
    try:
        results = {
            "device": device.split('/')[-1]
        }
        storage_stats = os.popen('sudo smartctl -A -H {}'.format(device)).read().splitlines()

        # Skip header lines until we find the SMART data section
        found_section = False
        current_section = None
        for stats in storage_stats:
            if "=== START OF SMART DATA SECTION ===" in stats:
                found_section = True
                current_section = "nvme"
                results["device_type"] = "nvme"
                continue
            elif "=== START OF READ SMART DATA SECTION ===" in stats:
                found_section = True
                current_section = "ata"
                results["device_type"] = "ata"
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
                            # Use standardized attribute name if available
                            attr_name = SMART_ATTRIBUTE_NAMES.get(attr_id, f"smart_attr_{attr_id}")
                            results[attr_name] = safe_int_conversion(parts[9])
                    except Exception as e:
                        log(f"Error parsing ATA attribute: {e}", 'error')
                continue

            parts = stats.split(':', 1)
            if len(parts) != 2:
                continue

            key = parts[0].strip()
            value = parts[1].strip()

            if key in STORAGE_IDENTIFICATION_ATTRIBUTES:
                results[STORAGE_IDENTIFICATION_ATTRIBUTES[key]] = value
            elif key == "SMART overall-health self-assessment test result":
                results["smart_overall_health"] = value
            elif key == "Critical Warning":
                results["critical_warning"] = safe_int_conversion(value, 16)

        # If it's an NVMe device and nvme-cli is available, get enhanced info
        if current_section == "nvme" and nvme_cli_available():
            nvme_info = get_nvme_enhanced_info(device)
            results.update(nvme_info)

        return results

    except Exception as e:
        log(f"Error fetching storage info for device: {device}: {e}", 'error')
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

def get_smartctl_version():
    """Get smartctl version information."""
    try:
        result = subprocess.run(
            ["sudo", "smartctl", "--version"],
            capture_output=True, text=True, check=True
        )
        # Extract version from first line
        version_line = result.stdout.split('\n')[0]
        return version_line.strip()
    except Exception as e:
        log(f"Error fetching smartctl version: {e}", 'error')
        return None

def get_nvme_cli_version():
    """Get nvme-cli version information."""
    try:
        result = subprocess.run(
            ["sudo", "nvme", "version"],
            capture_output=True, text=True, check=True
        )
        # Extract version from first line
        version_line = result.stdout.split('\n')[0]
        return version_line.strip()
    except Exception as e:
        log(f"Error fetching nvme-cli version: {e}", 'error')
        return None

def get_storage_identification(device):
    """Get storage device identification using smartctl."""
    try:
        result = subprocess.run(
            ["sudo", "smartctl", "-i", device],
            capture_output=True, text=True, check=True
        )

        results = { "device": device.split('/')[-1] }
        for line in result.stdout.splitlines():
            # Split on first occurrence of colon to handle values that might contain colons
            parts = line.split(':', 1)
            if len(parts) != 2:
                continue

            key = parts[0].strip()
            value = parts[1].strip()

            # Use direct mapping to get standardized key
            if key in STORAGE_IDENTIFICATION_ATTRIBUTES:
                results[STORAGE_IDENTIFICATION_ATTRIBUTES[key]] = value

        return results
    except Exception as e:
        log(f"Error fetching storage identification for device: {device}: {e}", 'error')
        return None

@debug('smart_storage_identification')
def smart_storage_identification():
    """Collect storage identification for all storage devices.
    Uses smartctl for all devices.
    Cached for 60 seconds.
    """
    global _identification_storage_cache
    now = time.time()


    # Cache for 10 minutes as we don't need to update this too often
    # This can change only for hotswapped drives
    if now - _identification_storage_cache["timestamp"] < 600:
        return _identification_storage_cache["data"]

    # Get tool versions only if we have devices to process
    tool_versions = {
        "smartctl_version": get_smartctl_version() if smartctl_available() else None,
        "nvme_cli_version": get_nvme_cli_version() if nvme_cli_available() else None
    }

    if tool_versions["smartctl_version"] is None:
        log("smartctl not installed", 'error')
        data = []
    else:
        devices = list_storage_devices()
        if not devices:
            log("No storage devices found", 'error')
            data = []
        else:
            data = [get_storage_identification(dev) for dev in devices]
            data = [d for d in data if d is not None]
            for device_info in data:
                device_info.update(tool_versions)

    _identification_storage_cache["timestamp"] = now
    _identification_storage_cache["data"] = data

    return data

@debug('smart_storage_health')
def smart_storage_health():
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
        log("smartctl not installed", 'error')
        data = []
    else:
        devices = list_storage_devices()
        if not devices:
            log("No storage devices found", 'error')
            data = []
        else:
            data = [get_storage_info(dev) for dev in devices]
            # Remove None values and add tool versions
            data = [d for d in data if d is not None]

    _health_storage_cache["timestamp"] = now
    _health_storage_cache["data"] = data

    return data
