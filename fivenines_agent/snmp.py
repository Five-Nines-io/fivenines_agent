"""
SNMP network device polling collector.

Polls SNMP-capable network devices (switches, routers, firewalls, printers)
and returns metrics for the fivenines API. Supports SNMPv2c and SNMPv3.

Architecture:
  sync_config["snmp_targets"]
       |
       v
  snmp_metrics(targets)  <-- lazy import pysnmp
       |
       +---> Pre-build sessions (main thread)
       +---> Filter due devices (_is_device_due)
       +---> ThreadPoolExecutor.map(_poll_device, ...)  (concurrent)
       |         each thread runs asyncio.run(_async_poll_device(...))
       |         so all SNMP ops share one event loop per device
       +---> Aggregate results into {"devices": [...]}
       |
       v
  data["snmp_metrics"] = {"devices": [...]}

Thread safety: _session_cache is read-only within worker threads.
All mutations happen in the main thread before/after executor.map().
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from fivenines_agent.debug import log
from fivenines_agent.env import dry_run


# Module-level singleton
_collector = None


# OID constants
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

# ifTable OIDs (1-indexed by ifIndex)
OID_IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
OID_IF_IN_UCAST_PKTS = "1.3.6.1.2.1.2.2.1.11"
OID_IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
OID_IF_OUT_UCAST_PKTS = "1.3.6.1.2.1.2.2.1.17"
OID_IF_OUT_DISCARDS = "1.3.6.1.2.1.2.2.1.19"
OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"

# ifXTable OIDs
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_IN_BROADCAST_PKTS = "1.3.6.1.2.1.31.1.1.1.3"
OID_IF_OUT_BROADCAST_PKTS = "1.3.6.1.2.1.31.1.1.1.5"
OID_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.10"
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

# SNMP timeout and retry settings
SNMP_TIMEOUT = 5  # seconds per device
SNMP_RETRIES = 1  # retry once on UDP packet loss
EXECUTOR_TIMEOUT = 30  # safety net for entire tick
MAX_WORKERS = 10  # max concurrent SNMP polls


def snmp_metrics(targets):
    """Poll SNMP targets and return metrics.

    This is the module entry point, called from agent.py as a special-case
    collector. Lazily imports pysnmp on first call.

    Args:
        targets: list of target dicts from sync_config["snmp_targets"]

    Returns:
        dict with "devices" key, or None if pysnmp is unavailable
    """
    try:
        import pysnmp  # noqa: F401
    except ImportError:
        log("pysnmp not installed, skipping SNMP polling", "error")
        return None

    if not targets:
        return None

    global _collector
    _collector = SNMPCollector(targets)
    result = _collector.poll_all()

    # Dry-run diagnostic output
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
            iface_count = len(ifaces)
            print(
                "  {}  {}  {} interfaces  OK".format(
                    device_id[:20], sys_name[:20], iface_count
                )
            )
    print("")


class SNMPCollector:
    """Collector for SNMP network device metrics.

    Manages session caching, per-device interval tracking, and concurrent
    polling via ThreadPoolExecutor.
    """

    def __init__(self, targets):
        self.targets = targets
        # Instance state for interval tracking
        if not hasattr(SNMPCollector, "_last_poll_times"):
            SNMPCollector._last_poll_times = {}

    def poll_all(self):
        """Poll all due SNMP targets concurrently.

        Returns:
            dict: {"devices": [device_dict, ...]}
        """
        # Prune stale poll times (devices no longer in targets)
        current_ids = {t["device_id"] for t in self.targets}
        stale_poll_ids = set(SNMPCollector._last_poll_times.keys()) - current_ids
        for device_id in stale_poll_ids:
            del SNMPCollector._last_poll_times[device_id]

        # Filter devices that are due for polling
        due_targets = [t for t in self.targets if self._is_device_due(t)]

        if not due_targets:
            return {"devices": []}

        # Pre-build auth data in main thread (no event loop needed).
        # Transport is created inside asyncio.run() in _poll_device
        # because UdpTransportTarget binds to the event loop that
        # creates it -- it cannot survive loop destruction.
        auth_data = {}
        for target in due_targets:
            auth_data[target["device_id"]] = self._build_auth(target)

        # Poll devices concurrently with a single batch-wide deadline
        devices = []
        workers = min(len(due_targets), MAX_WORKERS)
        batch_deadline = time.monotonic() + EXECUTOR_TIMEOUT

        try:
            executor = ThreadPoolExecutor(max_workers=workers)
            try:
                futures = {
                    executor.submit(
                        self._poll_device, target, auth_data[target["device_id"]]
                    ): target
                    for target in due_targets
                }

                for future in futures:
                    target = futures[future]
                    device_id = target["device_id"]
                    remaining = max(0.1, batch_deadline - time.monotonic())
                    try:
                        result = future.result(timeout=remaining)
                        devices.append(result)
                    except FuturesTimeoutError:
                        log(
                            "SNMP executor timeout for device {}".format(device_id),
                            "error",
                        )
                        devices.append(
                            {
                                "device_id": device_id,
                                "error": {
                                    "type": "timeout",
                                    "message": "Executor timeout after {}s".format(
                                        EXECUTOR_TIMEOUT
                                    ),
                                },
                            }
                        )
                    except Exception as e:
                        log(
                            "SNMP unexpected error for device {}: {}".format(
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

                    # Update last poll time regardless of outcome
                    SNMPCollector._last_poll_times[device_id] = time.monotonic()
            finally:
                # Don't wait for stuck workers - pysnmp timeout is the
                # primary mechanism; this is the safety net.
                executor.shutdown(wait=False)
        except Exception as e:
            log("SNMP ThreadPoolExecutor error: {}".format(e), "error")

        return {"devices": devices}

    def _is_device_due(self, target):
        """Check if a device is due for polling based on its interval."""
        device_id = target["device_id"]
        interval = target.get("interval", 60)
        last_poll = SNMPCollector._last_poll_times.get(device_id, 0)
        return (time.monotonic() - last_poll) >= interval

    def _build_auth(self, target):
        """Build SNMP auth data (sync, no event loop needed).

        Returns:
            tuple: (auth_data, target_config) or (None, error_dict)
        """
        from pysnmp.hlapi.v3arch.asyncio import (
            CommunityData,
            UsmUserData,
            usmAesCfb128Protocol,
            usmDESPrivProtocol,
            usmHMACMD5AuthProtocol,
            usmHMACSHAAuthProtocol,
        )

        try:
            version = target.get("version", "v2c")

            if version == "v2c":
                community = target.get("community", "public")
                auth = CommunityData(community)
            elif version == "v3":
                auth_proto_map = {
                    "md5": usmHMACMD5AuthProtocol,
                    "sha": usmHMACSHAAuthProtocol,
                }
                priv_proto_map = {
                    "des": usmDESPrivProtocol,
                    "aes": usmAesCfb128Protocol,
                }

                username = target["username"]
                security_level = target.get("security_level", "no_auth_no_priv")

                kwargs = {"userName": username}
                if security_level in ("auth_no_priv", "auth_priv"):
                    kwargs["authKey"] = target.get("auth_password", "")
                    kwargs["authProtocol"] = auth_proto_map.get(
                        target.get("auth_protocol", "sha")
                    )
                if security_level == "auth_priv":
                    kwargs["privKey"] = target.get("priv_password", "")
                    kwargs["privProtocol"] = priv_proto_map.get(
                        target.get("priv_protocol", "aes")
                    )

                auth = UsmUserData(**kwargs)
            else:
                return (
                    None,
                    {
                        "type": "unknown",
                        "message": "Unsupported SNMP version: {}".format(version),
                    },
                )

            return (auth, None)

        except KeyError as e:
            return (
                None,
                {
                    "type": "unknown",
                    "message": "Missing config field: {}".format(e),
                },
            )
        except Exception as e:
            return (
                None,
                {
                    "type": "unknown",
                    "message": "Session build error: {}".format(e),
                },
            )

    def _poll_device(self, target, auth_result):
        """Poll a single SNMP device. Runs in a worker thread.

        Wraps the entire async poll in a single asyncio.run() so all
        SNMP operations (including transport creation) share one event
        loop. pysnmp v7's UdpTransportTarget binds to the loop that
        creates it and cannot survive loop destruction.
        """
        device_id = target["device_id"]

        # Check for auth build error
        if auth_result[0] is None:
            return {"device_id": device_id, "error": auth_result[1]}

        auth = auth_result[0]

        try:
            async def _bounded_poll():
                from pysnmp.hlapi.v3arch.asyncio import UdpTransportTarget

                # Create transport inside the event loop so it binds
                # to the same loop used for all SNMP operations.
                ip = target.get("ip", "127.0.0.1")
                port = target.get("port", 161)
                transport = await UdpTransportTarget.create(
                    (ip, port), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES
                )
                return await asyncio.wait_for(
                    self._async_poll_device(device_id, target, auth, transport),
                    timeout=EXECUTOR_TIMEOUT,
                )

            return asyncio.run(_bounded_poll())
        except asyncio.TimeoutError:
            log(
                "SNMP async timeout for device {}".format(device_id),
                "error",
            )
            return {
                "device_id": device_id,
                "error": {
                    "type": "timeout",
                    "message": "SNMP poll timed out after {}s".format(
                        EXECUTOR_TIMEOUT
                    ),
                },
            }
        except Exception as e:
            error_type = "unknown"
            message = str(e)
            e_str = str(e).lower()

            if "timeout" in e_str or "request timed out" in e_str:
                error_type = "timeout"
                message = "SNMP request to {} timed out after {}s".format(
                    target.get("ip", "?"), SNMP_TIMEOUT
                )
            elif "usm" in e_str or "auth" in e_str or "wrong" in e_str:
                error_type = "auth_error"

            log(
                "SNMP poll error for device {}: {}".format(device_id, e),
                "error",
            )
            return {
                "device_id": device_id,
                "error": {"type": error_type, "message": message},
            }

    async def _async_poll_device(self, device_id, target, auth, transport):
        """Async implementation of device polling.

        All SNMP operations run under a single event loop here.
        """
        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            get_cmd,
            walk_cmd,
        )

        async def _subtree_walk(engine, auth, transport, ctx, obj_type, prefix):
            """Walk an OID subtree, stopping when OIDs leave the prefix.

            pysnmp v7's walk_cmd does not stop at subtree boundaries -
            it walks the entire MIB. This wrapper checks each returned
            OID and stops when it no longer starts with the prefix.
            """
            async for err_ind, err_st, err_idx, var_binds in walk_cmd(
                engine, auth, transport, ctx, obj_type,
            ):
                if err_ind or err_st:
                    yield err_ind, err_st, err_idx, var_binds
                    return
                # Check if OIDs are still within our subtree
                filtered = []
                out_of_subtree = False
                for oid, val in var_binds:
                    if str(oid).startswith(prefix + "."):
                        filtered.append((oid, val))
                    else:
                        out_of_subtree = True
                if filtered:
                    yield err_ind, err_st, err_idx, filtered
                if out_of_subtree:
                    return

        capabilities = target.get("capabilities", ["system", "if_table"])
        engine = SnmpEngine()
        ctx = ContextData()
        result = {"device_id": device_id}

        # Poll system info
        if "system" in capabilities:
            system = await self._async_poll_system(
                engine, auth, transport, ctx, get_cmd, ObjectIdentity, ObjectType
            )
            if system is not None:
                result["system"] = system

        # Poll interfaces
        if "if_table" in capabilities:
            interfaces = await self._async_poll_interfaces(
                engine, auth, transport, ctx, _subtree_walk, ObjectIdentity, ObjectType
            )
            if interfaces is not None:
                result["interfaces"] = interfaces

                if_indexes = [iface["if_index"] for iface in interfaces]
                if if_indexes:
                    counters, hc = await self._async_poll_counters(
                        engine, auth, transport, ctx, _subtree_walk,
                        ObjectIdentity, ObjectType, if_indexes
                    )
                    result["interface_metrics"] = counters
                    result["hc_counters"] = hc

        return result

    async def _async_poll_system(
        self, engine, auth, transport, ctx, get_cmd, ObjectIdentity, ObjectType
    ):
        """Poll system info OIDs (sysName, sysDescr, sysUptime)."""
        error_indication, error_status, error_index, var_binds = await get_cmd(
            engine,
            auth,
            transport,
            ctx,
            ObjectType(ObjectIdentity(OID_SYS_NAME)),
            ObjectType(ObjectIdentity(OID_SYS_DESCR)),
            ObjectType(ObjectIdentity(OID_SYS_UPTIME)),
        )

        if error_indication:
            raise Exception(str(error_indication))
        if error_status:
            raise Exception(
                "SNMP error: {} at {}".format(
                    error_status.prettyPrint(),
                    error_index and var_binds[int(error_index) - 1][0] or "?",
                )
            )

        result = {}
        for oid, val in var_binds:
            oid_str = str(oid)
            val_str = str(val)
            if OID_SYS_NAME in oid_str:
                result["sys_name"] = val_str
            elif OID_SYS_DESCR in oid_str:
                result["sys_descr"] = val_str
            elif OID_SYS_UPTIME in oid_str:
                # sysUptime is in centiseconds, convert to ms
                try:
                    result["sys_uptime"] = int(val) * 10
                except (ValueError, TypeError):
                    result["sys_uptime"] = 0

        return result

    async def _async_poll_interfaces(
        self, engine, auth, transport, ctx, walk_cmd, ObjectIdentity, ObjectType
    ):
        """Poll interface table metadata (ifTable + ifXTable).

        Uses single walks of the entire ifTable and ifXTable subtrees
        instead of per-column walks (19 walks -> 2 walks).
        """
        interfaces = {}

        # Map ifTable column OIDs to field names and converters
        # OID format: 1.3.6.1.2.1.2.2.1.<column>.<ifIndex>
        IF_TABLE_PREFIX = "1.3.6.1.2.1.2.2.1"
        iftable_columns = {
            "1": ("if_index", int),
            "3": ("if_type", int),
            "7": ("if_admin_status", lambda v: max(0, int(v) - 1)),
            "8": ("if_oper_status", lambda v: max(0, int(v) - 1)),
        }

        # Single walk of entire ifTable
        iftable_error = None
        async for error_indication, error_status, error_index, var_binds in walk_cmd(
            engine, auth, transport, ctx,
            ObjectType(ObjectIdentity(IF_TABLE_PREFIX)), IF_TABLE_PREFIX,
        ):
            if error_indication:
                iftable_error = str(error_indication)
                break
            if error_status:
                iftable_error = "SNMP error: {}".format(
                    error_status.prettyPrint()
                )
                break
            for oid, val in var_binds:
                oid_str = str(oid)
                # Parse column and ifIndex from OID
                # e.g. 1.3.6.1.2.1.2.2.1.3.1 -> column=3, if_index=1
                suffix = oid_str[len(IF_TABLE_PREFIX) + 1:]
                parts = suffix.split(".", 1)
                if len(parts) != 2:
                    continue
                column, if_index_str = parts
                try:
                    if_index = int(if_index_str)
                except (ValueError, TypeError):
                    continue
                if column in iftable_columns:
                    field_name, converter = iftable_columns[column]
                    if if_index not in interfaces:
                        interfaces[if_index] = {"if_index": if_index}
                    try:
                        interfaces[if_index][field_name] = converter(val)
                    except (ValueError, TypeError):
                        pass

        if iftable_error:
            raise Exception("IF-MIB walk failed: {}".format(iftable_error))

        # Single walk of entire ifXTable (may not be supported)
        # OID format: 1.3.6.1.2.1.31.1.1.1.<column>.<ifIndex>
        IF_XTABLE_PREFIX = "1.3.6.1.2.1.31.1.1.1"
        ifxtable_columns = {
            "1": ("if_name", str),
            "18": ("if_alias", str),
            "15": ("if_speed", lambda v: int(v) * 1000000),
        }

        async for error_indication, error_status, error_index, var_binds in walk_cmd(
            engine, auth, transport, ctx,
            ObjectType(ObjectIdentity(IF_XTABLE_PREFIX)), IF_XTABLE_PREFIX,
        ):
            if error_indication or error_status:
                break
            for oid, val in var_binds:
                oid_str = str(oid)
                suffix = oid_str[len(IF_XTABLE_PREFIX) + 1:]
                parts = suffix.split(".", 1)
                if len(parts) != 2:
                    continue
                column, if_index_str = parts
                try:
                    if_index = int(if_index_str)
                except (ValueError, TypeError):
                    continue
                if column in ifxtable_columns and if_index in interfaces:
                    field_name, converter = ifxtable_columns[column]
                    try:
                        interfaces[if_index][field_name] = converter(val)
                    except (ValueError, TypeError):
                        pass

        # Fill defaults for missing ifXTable fields
        for iface in interfaces.values():
            iface.setdefault("if_name", "")
            iface.setdefault("if_alias", "")
            iface.setdefault("if_speed", 0)

        return list(interfaces.values())

    async def _async_poll_counters(
        self, engine, auth, transport, ctx, walk_cmd,
        ObjectIdentity, ObjectType, if_indexes
    ):
        """Poll interface counters, preferring 64-bit HC counters.

        Tries a single walk of ifXTable for HC counters first.
        Falls back to a single walk of ifTable for all 32-bit counters.
        This is 1-2 walks instead of 12+ per-column walks.
        """
        counters = {idx: {"if_index": idx} for idx in if_indexes}
        hc_counters = False

        # Map ifXTable columns for HC counters + broadcast
        # OID: 1.3.6.1.2.1.31.1.1.1.<column>.<ifIndex>
        IF_XTABLE_PREFIX = "1.3.6.1.2.1.31.1.1.1"
        hc_columns = {
            "6": "bytes_in",       # ifHCInOctets
            "10": "bytes_out",     # ifHCOutOctets
            "3": "broadcast_in",   # ifInBroadcastPkts
            "5": "broadcast_out",  # ifOutBroadcastPkts (corrected from spec: actually column 5)
        }

        # Try single walk of ifXTable for HC counters
        hc_data = {}
        hc_supported = True
        try:
            async for err_ind, err_st, err_idx, var_binds in walk_cmd(
                engine, auth, transport, ctx,
                ObjectType(ObjectIdentity(IF_XTABLE_PREFIX)), IF_XTABLE_PREFIX,
            ):
                if err_ind or err_st:
                    hc_supported = False
                    break
                for oid, val in var_binds:
                    oid_str = str(oid)
                    val_str = str(val)
                    if "noSuch" in val_str:
                        hc_supported = False
                        break
                    suffix = oid_str[len(IF_XTABLE_PREFIX) + 1:]
                    parts = suffix.split(".", 1)
                    if len(parts) != 2:
                        continue
                    column, if_index_str = parts
                    try:
                        if_index = int(if_index_str)
                    except (ValueError, TypeError):
                        continue
                    if column in hc_columns and if_index in counters:
                        hc_data.setdefault(if_index, {})
                        hc_data[if_index][hc_columns[column]] = int(val)
                if not hc_supported:
                    break
        except Exception:
            hc_supported = False

        if hc_supported and hc_data:
            hc_counters = True
            for idx, fields in hc_data.items():
                counters[idx].update(fields)

        # Single walk of ifTable for remaining counters (and bytes if no HC)
        # OID: 1.3.6.1.2.1.2.2.1.<column>.<ifIndex>
        IF_TABLE_PREFIX = "1.3.6.1.2.1.2.2.1"
        iftable_counter_columns = {
            "11": "packets_in",    # ifInUcastPkts
            "13": "discards_in",   # ifInDiscards
            "14": "errors_in",     # ifInErrors
            "17": "packets_out",   # ifOutUcastPkts
            "19": "discards_out",  # ifOutDiscards
            "20": "errors_out",    # ifOutErrors
        }
        if not hc_counters:
            iftable_counter_columns["10"] = "bytes_in"   # ifInOctets
            iftable_counter_columns["16"] = "bytes_out"  # ifOutOctets

        try:
            async for err_ind, err_st, err_idx, var_binds in walk_cmd(
                engine, auth, transport, ctx,
                ObjectType(ObjectIdentity(IF_TABLE_PREFIX)), IF_TABLE_PREFIX,
            ):
                if err_ind or err_st:
                    break
                for oid, val in var_binds:
                    oid_str = str(oid)
                    suffix = oid_str[len(IF_TABLE_PREFIX) + 1:]
                    parts = suffix.split(".", 1)
                    if len(parts) != 2:
                        continue
                    column, if_index_str = parts
                    try:
                        if_index = int(if_index_str)
                    except (ValueError, TypeError):
                        continue
                    if column in iftable_counter_columns and if_index in counters:
                        try:
                            counters[if_index][iftable_counter_columns[column]] = int(val)
                        except (ValueError, TypeError):
                            pass
        except Exception:
            pass

        # Fill defaults
        for idx in counters:
            counters[idx].setdefault("bytes_in", 0)
            counters[idx].setdefault("bytes_out", 0)
            counters[idx].setdefault("packets_in", 0)
            counters[idx].setdefault("packets_out", 0)
            counters[idx].setdefault("errors_in", 0)
            counters[idx].setdefault("errors_out", 0)
            counters[idx].setdefault("discards_in", 0)
            counters[idx].setdefault("discards_out", 0)
            counters[idx].setdefault("broadcast_in", 0)
            counters[idx].setdefault("broadcast_out", 0)

        return (list(counters.values()), hc_counters)
