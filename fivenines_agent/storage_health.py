import subprocess
import json
import shutil
import os
import time

from fivenines_agent.env import debug_mode

_storage_cache = {
    "timestamp": 0,
    "data": []
}

# Standard SMART attribute names by ID
SMART_ATTRIBUTE_NAMES = {
    '1': 'Raw_Read_Error_Rate',
    '2': 'Throughput_Performance',
    '3': 'Spin_Up_Time',
    '4': 'Start_Stop_Count',
    '5': 'Reallocated_Sector_Ct',
    '6': 'Seek_Error_Rate',
    '7': 'Seek_Time_Performance',
    '8': 'Power_On_Hours',
    '9': 'Spin_Retry_Count',
    '10': 'Calibration_Retry_Count',
    '11': 'Recalibration_Retries',
    '12': 'Power_Cycle_Count',
    '13': 'Soft_Read_Error_Rate',
    '183': 'Runtime_Bad_Block',
    '184': 'End-to-End_Error',
    '187': 'Reported_Uncorrectable_Errors',
    '188': 'Command_Timeout',
    '189': 'High_Fly_Writes',
    '190': 'Airflow_Temperature_Cel',
    '191': 'G-Sense_Error_Rate',
    '192': 'Power-Off_Retract_Count',
    '193': 'Load_Cycle_Count',
    '194': 'Temperature_Celsius',
    '195': 'Hardware_ECC_Recovered',
    '196': 'Reallocated_Event_Count',
    '197': 'Current_Pending_Sector',
    '198': 'Offline_Uncorrectable',
    '199': 'UDMA_CRC_Error_Count',
    '200': 'Multi_Zone_Error_Rate',
    '201': 'Soft_Read_Error_Rate',
    '202': 'Data_Address_Mark_Errors',
    '203': 'Run_Out_Cancel',
    '204': 'Soft_ECC_Correction',
    '205': 'Thermal_Asperity_Rate',
    '206': 'Flying_Height',
    '207': 'Spin_High_Current',
    '208': 'Spin_Buzz',
    '209': 'Offline_Seek_Performance',
    '211': 'Vibration_During_Write',
    '212': 'Shock_During_Write',
    '220': 'Disk_Shift',
    '221': 'G-Sense_Error_Rate',
    '222': 'Loaded_Hours',
    '223': 'Load_Retry_Count',
    '224': 'Load_Friction',
    '225': 'Load_Cycle_Count',
    '226': 'Load-in_Time',
    '227': 'Torque_Amplification_Count',
    '228': 'Power-Off_Retract_Cycle',
    '230': 'GMR_Head_Amplitude',
    '231': 'Life_Left',
    '232': 'Endurance_Remaining',
    '233': 'Media_Wearout_Indicator',
    '234': 'Average_Erase_Count',
    '235': 'Good_Block_Count',
    '240': 'Head_Flying_Hours',
    '241': 'Total_LBAs_Written',
    '242': 'Total_LBAs_Read',
    '250': 'Read_Error_Retry_Rate',
    '251': 'Minimum_Spares_Remaining',
    '252': 'Newly_Added_Bad_Flash_Block',
    '254': 'Free_Fall_Protection'
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
                    value = value - 273.15
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
    smart_attributes = {
        key.split('_')[2]: {
            'name': SMART_ATTRIBUTE_NAMES.get(key.split('_')[2], 'Unknown'),
            'raw_value': safe_int_conversion(value)
        }
        for key, value in results.items()
        if key.startswith('smart_attr_')
    }
    if smart_attributes:
        cleaned_results['smart_attributes'] = smart_attributes

    return cleaned_results

def storage_health():
    """
    Collect health info for all storage devices.
    Uses smartctl for all devices and enhances NVMe devices with nvme-cli when available.
    Cached for 60 seconds.
    """
    global _storage_cache
    now = time.time()

    if now - _storage_cache["timestamp"] < 60:
        return _storage_cache["data"]

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
            data = [get_storage_info(dev) for dev in devices]

    # Remove None values
    data = [d for d in data if d is not None]

    _storage_cache["timestamp"] = now
    _storage_cache["data"] = data

    return data
