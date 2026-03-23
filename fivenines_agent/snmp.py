"""
SNMP network device polling collector.

Uses net-snmp CLI tools (snmpget, snmpbulkwalk) via subprocess.
No Python SNMP library dependency -- just parse CLI output.

Architecture:
  sync_config["snmp_targets"]
       |
       v
  snmp_metrics(targets)
       |
       +---> Check shutil.which("snmpget")
       +---> Filter due devices (_is_device_due)
       +---> ThreadPoolExecutor.map(_poll_device, ...)
       |         each thread runs subprocess.run(["snmpget"/...])
       +---> Aggregate results into {"devices": [...]}
       |
       v
  data["snmp_metrics"] = {"devices": [...]}

Thread safety: each worker thread runs its own subprocess.
No shared mutable state between threads.
"""

import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError

from fivenines_agent.debug import log
from fivenines_agent.env import dry_run
from fivenines_agent.subprocess_utils import get_clean_env


# Module-level singleton
_collector = None

# OID constants
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

# ifTable and ifXTable prefixes
IF_TABLE_PREFIX = "1.3.6.1.2.1.2.2.1"
IF_XTABLE_PREFIX = "1.3.6.1.2.1.31.1.1.1"

# ifTable column number -> (bucket, field_name, converter)
IFTABLE_COLUMNS = {
    "1": ("meta", "if_index", int),
    "3": ("meta", "if_type", int),
    "7": ("meta", "if_admin_status", lambda v: max(0, int(v) - 1)),
    "8": ("meta", "if_oper_status", lambda v: max(0, int(v) - 1)),
    "10": ("counter", "bytes_in", int),
    "11": ("counter", "packets_in", int),
    "13": ("counter", "discards_in", int),
    "14": ("counter", "errors_in", int),
    "16": ("counter", "bytes_out", int),
    "17": ("counter", "packets_out", int),
    "19": ("counter", "discards_out", int),
    "20": ("counter", "errors_out", int),
}

# ifXTable column number -> (bucket, field_name, converter)
IFXTABLE_COLUMNS = {
    "1": ("meta", "if_name", str),
    "3": ("counter", "broadcast_in", int),
    "5": ("counter", "broadcast_out", int),
    "6": ("hc", "bytes_in", int),
    "10": ("hc", "bytes_out", int),
    "15": ("meta", "if_speed", lambda v: int(v) * 1000000),
    "18": ("meta", "if_alias", str),
}

# Settings
SNMP_TIMEOUT = 5  # seconds per SNMP request (-t flag)
SNMP_RETRIES = 1  # retry once on UDP packet loss (-r flag)
EXECUTOR_TIMEOUT = 30  # safety net for entire batch
MAX_WORKERS = 10  # max concurrent device polls


def snmp_metrics(targets):
    """Poll SNMP targets and return metrics.

    Entry point called from agent.py as a special-case collector.
    Requires net-snmp CLI tools (snmpget, snmpbulkwalk).

    Args:
        targets: list of target dicts from sync_config["snmp_targets"]

    Returns:
        dict with "devices" key, or None if snmpget is unavailable
    """
    if not shutil.which("snmpget"):
        log("snmpget not found in PATH, skipping SNMP polling", "error")
        return None

    if not targets:
        return None

    global _collector
    _collector = SNMPCollector(targets)
    result = _collector.poll_all()

    if dry_run() and result and result.get("devices"):
        _print_diagnostics(result["devices"])

    return result


def _print_diagnostics(devices):
    """Print SNMP diagnostic table for dry-run mode."""
    print("")
    print("SNMP Targets:")
    for dev in devices:
        device_id = dev.get("device_id", "?")
        error = dev.get("error")
        if error:
            status = error.get("type", "ERROR").upper()
            if status == "TIMEOUT":
                status = "TIMEOUT ({}s)".format(SNMP_TIMEOUT)
            elif status == "AUTH_ERROR":
                status = "AUTH ERROR"
            print("  {}  -  -  {}".format(device_id[:40], status))
        else:
            sys_info = dev.get("system", {})
            sys_name = sys_info.get("sys_name", "-") or "-"
            ifaces = dev.get("interfaces", [])
            print(
                "  {}  {}  {} interfaces  OK".format(
                    device_id[:20], sys_name[:20], len(ifaces)
                )
            )
    print("")


def _parse_snmp_line(line):
    """Parse one line of SNMP CLI output.

    Handles formats like:
      .1.3.6.1.2.1.1.5.0 = STRING: "EPSONCD1062"
      .1.3.6.1.2.1.2.2.1.10.1 = Counter32: 7010736
      .1.3.6.1.2.1.1.3.0 = Timeticks: (1491600) 4:08:36.00
      .1.3.6.1.2.1.31.1.1.1.1 = No Such Object available ...

    Returns:
        tuple (oid_str, value_str) or None.
        value_str is None for "No Such" responses.
    """
    line = line.strip()
    if not line or " = " not in line:
        return None

    oid_part, value_part = line.split(" = ", 1)
    oid_str = oid_part.strip().lstrip(".")

    if "No Such" in value_part or "No more" in value_part:
        return (oid_str, None)

    # Strip type prefix: "STRING: val", "Counter32: val", etc.
    if ": " in value_part:
        type_str, val = value_part.split(": ", 1)
        type_str = type_str.strip()

        # Timeticks: (1491600) 4:08:36.00 -> extract raw value
        if type_str == "Timeticks":
            if "(" in val and ")" in val:
                val = val[val.index("(") + 1 : val.index(")")]

        val = val.strip().strip('"')
        return (oid_str, val)

    return (oid_str, value_part.strip().strip('"'))


def _run_snmp_cmd(cmd, args, timeout):
    """Run an SNMP CLI command and return (stdout, error_dict_or_None).

    Classifies errors into timeout, auth_error, snmp_error, or unknown.
    """
    try:
        result = subprocess.run(
            [cmd] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=get_clean_env(),
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            lower = stderr.lower()
            if "timeout" in lower or "no response" in lower:
                return None, {"type": "timeout", "message": stderr}
            if "auth" in lower or "usm" in lower or "unknown user" in lower:
                return None, {"type": "auth_error", "message": stderr}
            return None, {"type": "snmp_error", "message": stderr}
        return result.stdout, None
    except subprocess.TimeoutExpired:
        return None, {
            "type": "timeout",
            "message": "Command timed out after {}s".format(timeout),
        }
    except Exception as e:
        return None, {"type": "unknown", "message": str(e)}


class SNMPCollector:
    """Polls SNMP devices using net-snmp CLI tools.

    Manages per-device interval tracking and concurrent polling
    via ThreadPoolExecutor.
    """

    def __init__(self, targets):
        self.targets = targets
        if not hasattr(SNMPCollector, "_last_poll_times"):
            SNMPCollector._last_poll_times = {}
        if not hasattr(SNMPCollector, "_last_results"):
            SNMPCollector._last_results = {}

    def poll_all(self):
        """Poll all due SNMP targets concurrently.

        Returns:
            dict: {"devices": [device_dict, ...]}
        """
        # Prune stale state
        current_ids = {t["device_id"] for t in self.targets}
        stale_ids = set(SNMPCollector._last_poll_times.keys()) - current_ids
        for device_id in stale_ids:
            SNMPCollector._last_poll_times.pop(device_id, None)
            SNMPCollector._last_results.pop(device_id, None)

        due_targets = [t for t in self.targets if self._is_device_due(t)]

        if not due_targets:
            cached = [
                SNMPCollector._last_results[t["device_id"]]
                for t in self.targets
                if t["device_id"] in SNMPCollector._last_results
            ]
            return {"devices": cached}

        devices = []
        workers = min(len(due_targets), MAX_WORKERS)
        batch_deadline = time.monotonic() + EXECUTOR_TIMEOUT

        try:
            executor = ThreadPoolExecutor(max_workers=workers)
            try:
                futures = {
                    executor.submit(self._poll_device, target): target
                    for target in due_targets
                }

                for future in futures:
                    target = futures[future]
                    device_id = target["device_id"]
                    remaining = max(0.1, batch_deadline - time.monotonic())
                    result = None
                    try:
                        result = future.result(timeout=remaining)
                        devices.append(result)
                    except FuturesTimeoutError:
                        log(
                            "SNMP executor timeout for device {}".format(
                                device_id
                            ),
                            "error",
                        )
                        devices.append(
                            {
                                "device_id": device_id,
                                "error": {
                                    "type": "timeout",
                                    "message": "Executor timeout after {}s"
                                    .format(EXECUTOR_TIMEOUT),
                                },
                            }
                        )
                    except Exception as e:
                        log(
                            "SNMP error for device {}: {}".format(
                                device_id, e
                            ),
                            "error",
                        )
                        devices.append(
                            {
                                "device_id": device_id,
                                "error": {
                                    "type": "unknown",
                                    "message": str(e),
                                },
                            }
                        )

                    SNMPCollector._last_poll_times[device_id] = (
                        time.monotonic()
                    )
                    if result and result.get("error") is None:
                        SNMPCollector._last_results[device_id] = result
            finally:
                executor.shutdown(wait=False)
        except Exception as e:
            log("SNMP ThreadPoolExecutor error: {}".format(e), "error")

        # Include cached results for not-yet-due devices
        polled_ids = {t["device_id"] for t in due_targets}
        for target in self.targets:
            did = target["device_id"]
            if did not in polled_ids and did in SNMPCollector._last_results:
                devices.append(SNMPCollector._last_results[did])

        return {"devices": devices}

    def _is_device_due(self, target):
        """Check if a device is due for polling based on its interval."""
        device_id = target["device_id"]
        interval = target.get("interval", 60)
        last_poll = SNMPCollector._last_poll_times.get(device_id, 0)
        return (time.monotonic() - last_poll) >= interval

    def _build_base_args(self, target):
        """Build CLI args for SNMP version and authentication.

        Returns:
            tuple: (args_list, error_dict_or_None)
        """
        version = target.get("version", "v2c")
        ip = target.get("ip", "127.0.0.1")
        port = target.get("port", 161)
        host = "{}:{}".format(ip, port) if port != 161 else ip

        args = ["-t", str(SNMP_TIMEOUT), "-r", str(SNMP_RETRIES), "-On"]

        if version == "v2c":
            community = target.get("community", "public")
            args.extend(["-v2c", "-c", community])
        elif version == "v3":
            username = target.get("username")
            if not username:
                return None, {
                    "type": "unknown",
                    "message": "Missing username for SNMPv3",
                }

            sec_level = target.get("security_level", "no_auth_no_priv")
            level_map = {
                "no_auth_no_priv": "noAuthNoPriv",
                "auth_no_priv": "authNoPriv",
                "auth_priv": "authPriv",
            }
            args.extend([
                "-v3",
                "-l", level_map.get(sec_level, "noAuthNoPriv"),
                "-u", username,
            ])

            if sec_level in ("auth_no_priv", "auth_priv"):
                auth_proto = {"md5": "MD5", "sha": "SHA"}
                args.extend([
                    "-a",
                    auth_proto.get(
                        target.get("auth_protocol", "sha"), "SHA"
                    ),
                    "-A", target.get("auth_password", ""),
                ])
            if sec_level == "auth_priv":
                priv_proto = {"des": "DES", "aes": "AES"}
                args.extend([
                    "-x",
                    priv_proto.get(
                        target.get("priv_protocol", "aes"), "AES"
                    ),
                    "-X", target.get("priv_password", ""),
                ])
        else:
            return None, {
                "type": "unknown",
                "message": "Unsupported SNMP version: {}".format(version),
            }

        args.append(host)
        return args, None

    def _poll_device(self, target):
        """Poll a single SNMP device. Runs in a worker thread."""
        device_id = target["device_id"]

        base_args, error = self._build_base_args(target)
        if error:
            return {"device_id": device_id, "error": error}

        capabilities = target.get("capabilities", ["system", "if_table"])
        result = {"device_id": device_id}

        if "system" in capabilities:
            system, error = self._poll_system(base_args)
            if error:
                log(
                    "SNMP system poll failed for {}: {}".format(
                        device_id, error.get("message", "")
                    ),
                    "error",
                )
                return {"device_id": device_id, "error": error}
            result["system"] = system

        if "if_table" in capabilities:
            ifaces, counters, hc, error = self._poll_interfaces(base_args)
            if error:
                log(
                    "SNMP interface poll failed for {}: {}".format(
                        device_id, error.get("message", "")
                    ),
                    "error",
                )
                return {"device_id": device_id, "error": error}
            result["interfaces"] = ifaces
            result["interface_metrics"] = counters
            result["hc_counters"] = hc

        return result

    def _poll_system(self, base_args):
        """Get system info via snmpget.

        Returns:
            tuple: (system_dict, error_dict_or_None)
        """
        args = base_args + [OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_UPTIME]
        stdout, error = _run_snmp_cmd("snmpget", args, SNMP_TIMEOUT + 5)
        if error:
            return None, error

        system = {}
        for line in stdout.splitlines():
            parsed = _parse_snmp_line(line)
            if not parsed or parsed[1] is None:
                continue
            oid, val = parsed
            if oid == OID_SYS_NAME:
                system["sys_name"] = val
            elif oid == OID_SYS_DESCR:
                system["sys_descr"] = val
            elif oid == OID_SYS_UPTIME:
                try:
                    system["sys_uptime"] = int(val) * 10
                except (ValueError, TypeError):
                    system["sys_uptime"] = 0

        return system, None

    def _poll_interfaces(self, base_args):
        """Walk ifTable and ifXTable via snmpbulkwalk.

        Returns:
            tuple: (interfaces_list, counters_list, hc_bool,
                    error_dict_or_None)
        """
        interfaces = {}
        counters = {}
        hc_counters = False

        # Walk ifTable (required)
        args = base_args + [IF_TABLE_PREFIX]
        stdout, error = _run_snmp_cmd(
            "snmpbulkwalk", args, SNMP_TIMEOUT * 3 + 5
        )
        if error:
            return None, None, False, error

        self._parse_table(
            stdout, IF_TABLE_PREFIX, IFTABLE_COLUMNS,
            interfaces, counters, None
        )

        # Walk ifXTable (optional -- may not be supported)
        hc_data = {}
        hc_supported = True
        args = base_args + [IF_XTABLE_PREFIX]
        stdout, error = _run_snmp_cmd(
            "snmpbulkwalk", args, SNMP_TIMEOUT * 3 + 5
        )
        if not error and stdout:
            hc_supported = self._parse_table(
                stdout, IF_XTABLE_PREFIX, IFXTABLE_COLUMNS,
                interfaces, counters, hc_data
            )

        # Apply HC counters (override 32-bit bytes_in/bytes_out)
        if hc_supported and hc_data:
            hc_counters = True
            for idx, fields in hc_data.items():
                if idx in counters:
                    counters[idx].update(fields)

        # Fill defaults for missing ifXTable fields
        for iface in interfaces.values():
            iface.setdefault("if_name", "")
            iface.setdefault("if_alias", "")
            iface.setdefault("if_speed", 0)

        # Ensure counters exist for all discovered interfaces
        for if_index in interfaces:
            counters.setdefault(if_index, {"if_index": if_index})

        for idx in counters:
            for field in (
                "bytes_in", "bytes_out", "packets_in", "packets_out",
                "errors_in", "errors_out", "discards_in", "discards_out",
                "broadcast_in", "broadcast_out",
            ):
                counters[idx].setdefault(field, 0)

        return (
            list(interfaces.values()),
            list(counters.values()),
            hc_counters,
            None,
        )

    def _parse_table(
        self, stdout, prefix, columns, interfaces, counters, hc_data
    ):
        """Parse snmpbulkwalk output for a table.

        Populates interfaces/counters/hc_data dicts in place.

        Returns:
            bool: True if HC counters are supported (no noSuch seen).
        """
        hc_supported = True
        for line in stdout.splitlines():
            parsed = _parse_snmp_line(line)
            if not parsed:
                continue
            oid, val = parsed
            if val is None:
                hc_supported = False
                continue
            if not oid.startswith(prefix + "."):
                continue
            suffix = oid[len(prefix) + 1 :]
            parts = suffix.split(".", 1)
            if len(parts) != 2:
                continue
            column, if_index_str = parts
            try:
                if_index = int(if_index_str)
            except (ValueError, TypeError):
                continue
            if column not in columns:
                continue
            bucket, field_name, converter = columns[column]
            try:
                value = converter(val)
            except (ValueError, TypeError):
                continue
            if bucket == "meta":
                interfaces.setdefault(if_index, {"if_index": if_index})
                interfaces[if_index][field_name] = value
            elif bucket == "hc" and hc_data is not None and hc_supported:
                hc_data.setdefault(if_index, {})
                hc_data[if_index][field_name] = value
            elif bucket == "counter":
                counters.setdefault(if_index, {"if_index": if_index})
                counters[if_index][field_name] = value
        return hc_supported
