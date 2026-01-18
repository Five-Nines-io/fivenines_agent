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

# SMART attributes where normalized VALUE (0-100%) is more meaningful than RAW_VALUE
# These typically represent wear/life percentages
SMART_LIFE_ATTRIBUTES = {'177', '202', '231', '232', '233'}

# Vendor-specific life attribute mapping
# Maps (pattern_type, pattern) -> attribute_id
# pattern_type: 'model_family' or 'device_model'
# The attribute's normalized VALUE (0-100) represents life remaining
VENDOR_LIFE_ATTRIBUTE_MAP = [
    # Samsung SSDs - use attribute 177 (Wear_Leveling_Count)
    ('model_family', 'Samsung', '177'),
    ('device_model', 'Samsung', '177'),
    # Intel SSDs - use attribute 233 (Media_Wearout_Indicator)
    ('model_family', 'Intel', '233'),
    ('device_model', 'Intel', '233'),
    # Crucial/Micron SSDs - use attribute 202 (Percent_Lifetime_Remain)
    ('model_family', 'Crucial', '202'),
    ('device_model', 'Crucial', '202'),
    ('model_family', 'Micron', '202'),
    ('device_model', 'Micron', '202'),
    # SanDisk SSDs - use attribute 230 or 232
    ('model_family', 'SanDisk', '232'),
    ('device_model', 'SanDisk', '232'),
    # Western Digital SSDs - use attribute 231
    ('model_family', 'Western Digital', '231'),
    ('device_model', 'WD', '231'),
    ('device_model', 'WDC', '231'),
    # Kingston SSDs - use attribute 231
    ('model_family', 'Kingston', '231'),
    ('device_model', 'Kingston', '231'),
    # Toshiba/Kioxia SSDs - use attribute 233
    ('model_family', 'Toshiba', '233'),
    ('device_model', 'Toshiba', '233'),
    ('model_family', 'KIOXIA', '233'),
    ('device_model', 'KIOXIA', '233'),
    # SK Hynix SSDs - use attribute 231
    ('model_family', 'SK hynix', '231'),
    ('device_model', 'SK hynix', '231'),
    ('device_model', 'HFS', '231'),  # SK Hynix model prefix
    # ADATA SSDs - use attribute 231
    ('model_family', 'ADATA', '231'),
    ('device_model', 'ADATA', '231'),
    # Transcend SSDs - use attribute 177
    ('model_family', 'Transcend', '177'),
    ('device_model', 'Transcend', '177'),
    # PNY SSDs - use attribute 231
    ('model_family', 'PNY', '231'),
    ('device_model', 'PNY', '231'),
    # Seagate SSDs - use attribute 231
    ('model_family', 'Seagate', '231'),
    ('device_model', 'Seagate', '231'),
    # Corsair SSDs - use attribute 231
    ('model_family', 'Corsair', '231'),
    ('device_model', 'Corsair', '231'),
    # Plextor SSDs - use attribute 177
    ('model_family', 'Plextor', '177'),
    ('device_model', 'Plextor', '177'),
    # OCZ SSDs - use attribute 233
    ('model_family', 'OCZ', '233'),
    ('device_model', 'OCZ', '233'),
    # Lite-On SSDs - use attribute 177
    ('model_family', 'LITE-ON', '177'),
    ('device_model', 'LITE-ON', '177'),
    # Team Group SSDs - use attribute 231
    ('model_family', 'Team', '231'),
    ('device_model', 'Team', '231'),
    # Patriot SSDs - use attribute 231
    ('model_family', 'Patriot', '231'),
    ('device_model', 'Patriot', '231'),
]

# Fallback priority order for unknown SSDs
# Check these attributes in order, use first one with valid value
LIFE_ATTRIBUTE_FALLBACK_ORDER = ['231', '232', '233', '177', '202']

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
    '177': 'wear_leveling_count',
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

def get_life_attribute_for_drive(model_family, device_model):
    """
    Determine which SMART attribute to use for life remaining based on drive vendor.
    Returns the attribute ID string (e.g., '177') or None if unknown.
    """
    # Try vendor-specific mapping first
    for field_type, pattern, attr_id in VENDOR_LIFE_ATTRIBUTE_MAP:
        value = model_family if field_type == 'model_family' else device_model
        if value and pattern.lower() in value.lower():
            return attr_id
    return None


def calculate_percentage_used(results, model_family=None, device_model=None):
    """
    Calculate unified percentage_used for a drive.

    For NVMe: uses 100 - percent_used
    For SATA SSD: uses vendor-specific attribute or fallback heuristic
    For HDD: returns None (not applicable)

    Returns the percentage used (0-100) or None if not available.
    """
    device_type = results.get('device_type')

    # NVMe drives: use standardized percent_used
    if device_type == 'nvme':
        percent_used = results.get('percent_used')
        if percent_used is not None:
            return percent_used
        return None

    # HDD detection: has rotation rate that's not "Solid State Device"
    rotation_rate = results.get('rotation_rate', '')
    if rotation_rate and 'Solid State' not in rotation_rate:
        return None

    # SATA SSD: try vendor-specific attribute first
    life_attr_id = get_life_attribute_for_drive(model_family, device_model)

    if life_attr_id:
        attr_name = SMART_ATTRIBUTE_NAMES.get(life_attr_id, f"smart_attr_{life_attr_id}")
        pct_key = f"{attr_name}_pct"
        if pct_key in results and results[pct_key] is not None:
            value = results[pct_key]
            return max(0, min(100, 100 - value))

    # Fallback: try common life attributes in priority order
    for attr_id in LIFE_ATTRIBUTE_FALLBACK_ORDER:
        attr_name = SMART_ATTRIBUTE_NAMES.get(attr_id, f"smart_attr_{attr_id}")
        pct_key = f"{attr_name}_pct"
        if pct_key in results and results[pct_key] is not None:
            value = results[pct_key]
            return max(0, min(100, 100 - value))

    return None


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
    """
    Check if smartctl is available and we have permission to run it.
    Uses sudo -n (non-interactive) to detect if sudoers is configured.
    Returns False if:
    - smartctl is not installed
    - sudo is not configured for this user
    - sudo would require a password
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", "smartctl", "--version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log("smartctl availability check timed out", 'error')
        return False
    except Exception:
        return False

def nvme_cli_available():
    """
    Check if nvme-cli is available and we have permission to run it.
    Uses sudo -n (non-interactive) to detect if sudoers is configured.
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", "nvme", "version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log("nvme availability check timed out", 'error')
        return False
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
                            # For wear/life attributes, also capture the normalized VALUE (0-100%)
                            if attr_id in SMART_LIFE_ATTRIBUTES:
                                results[f"{attr_name}_pct"] = safe_int_conversion(parts[3])
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

        # Calculate unified percentage_used
        percentage_used = calculate_percentage_used(
            results,
            model_family=results.get('model_family'),
            device_model=results.get('device_model')
        )
        if percentage_used is not None:
            results['percentage_used'] = percentage_used

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
        log("smartctl unavailable (not installed or no sudo permissions)", 'debug')
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
        log("smartctl unavailable (not installed or no sudo permissions)", 'debug')
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
