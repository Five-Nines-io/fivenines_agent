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
import hashlib
import json
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
        # Instance state for session caching and interval tracking
        if not hasattr(SNMPCollector, "_last_poll_times"):
            SNMPCollector._last_poll_times = {}
        if not hasattr(SNMPCollector, "_session_cache"):
            SNMPCollector._session_cache = {}

    def poll_all(self):
        """Poll all due SNMP targets concurrently.

        Returns:
            dict: {"devices": [device_dict, ...]}
        """
        # Prune stale session cache entries (devices no longer in targets)
        current_ids = {t["device_id"] for t in self.targets}
        stale_ids = set(SNMPCollector._session_cache.keys()) - current_ids
        for device_id in stale_ids:
            del SNMPCollector._session_cache[device_id]

        # Also prune stale poll times
        stale_poll_ids = set(SNMPCollector._last_poll_times.keys()) - current_ids
        for device_id in stale_poll_ids:
            del SNMPCollector._last_poll_times[device_id]

        # Filter devices that are due for polling
        due_targets = [t for t in self.targets if self._is_device_due(t)]

        if not due_targets:
            return {"devices": []}

        # Pre-build sessions in main thread (thread safety)
        sessions = {}
        for target in due_targets:
            sessions[target["device_id"]] = self._build_session(target)

        # Poll devices concurrently
        devices = []
        workers = min(len(due_targets), MAX_WORKERS)

        try:
            executor = ThreadPoolExecutor(max_workers=workers)
            try:
                futures = {
                    executor.submit(
                        self._poll_device, target, sessions[target["device_id"]]
                    ): target
                    for target in due_targets
                }

                for future in futures:
                    target = futures[future]
                    device_id = target["device_id"]
                    try:
                        result = future.result(timeout=EXECUTOR_TIMEOUT)
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

    def _build_session(self, target):
        """Build or retrieve a cached SNMP session.

        Returns:
            tuple: (auth_data, transport_target) for pysnmp hlapi calls,
                   or (None, error_dict) on failure
        """
        from pysnmp.hlapi.v3arch.asyncio import (
            CommunityData,
            UdpTransportTarget,
            UsmUserData,
            usmAesCfb128Protocol,
            usmDESPrivProtocol,
            usmHMACMD5AuthProtocol,
            usmHMACSHAAuthProtocol,
        )

        device_id = target["device_id"]
        config_hash = hashlib.sha256(
            json.dumps(target, sort_keys=True).encode()
        ).hexdigest()

        # Check cache
        cached = SNMPCollector._session_cache.get(device_id)
        if cached and cached[2] == config_hash:
            return (cached[0], cached[1])

        # Build new session
        try:
            version = target.get("version", "v2c")
            ip = target["ip"]
            port = target.get("port", 161)

            # pysnmp v7 uses an async factory method for UdpTransportTarget
            transport = asyncio.run(
                UdpTransportTarget.create(
                    (ip, port), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES
                )
            )

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

            # Cache the session
            SNMPCollector._session_cache[device_id] = (auth, transport, config_hash)
            return (auth, transport)

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

    def _poll_device(self, target, session):
        """Poll a single SNMP device. Runs in a worker thread.

        Wraps the entire async poll in a single asyncio.run() so all
        SNMP operations share one event loop (required by pysnmp v7).
        """
        device_id = target["device_id"]

        # Check for session build error
        if session[0] is None:
            return {"device_id": device_id, "error": session[1]}

        auth, transport = session

        try:
            return asyncio.run(
                self._async_poll_device(device_id, target, auth, transport)
            )
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
                engine, auth, transport, ctx, walk_cmd, ObjectIdentity, ObjectType
            )
            if interfaces is not None:
                result["interfaces"] = interfaces

                if_indexes = [iface["if_index"] for iface in interfaces]
                if if_indexes:
                    counters, hc = await self._async_poll_counters(
                        engine, auth, transport, ctx, walk_cmd,
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
        """Poll interface table metadata (ifTable + ifXTable)."""
        interfaces = {}

        # Walk ifTable for basic info
        iftable_error = None
        for oid_prefix, field_name, converter in [
            (OID_IF_INDEX, "if_index", int),
            (OID_IF_TYPE, "if_type", int),
            (OID_IF_ADMIN_STATUS, "if_admin_status", lambda v: max(0, int(v) - 1)),
            (OID_IF_OPER_STATUS, "if_oper_status", lambda v: max(0, int(v) - 1)),
        ]:
            async for error_indication, error_status, error_index, var_binds in walk_cmd(
                engine, auth, transport, ctx,
                ObjectType(ObjectIdentity(oid_prefix)),
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
                    parts = oid_str.split(".")
                    if_index = int(parts[-1])
                    if if_index not in interfaces:
                        interfaces[if_index] = {"if_index": if_index}
                    try:
                        interfaces[if_index][field_name] = converter(val)
                    except (ValueError, TypeError):
                        pass

        # If ifTable walk failed entirely, raise so caller surfaces it
        if iftable_error and not interfaces:
            raise Exception("IF-MIB walk failed: {}".format(iftable_error))

        # Walk ifXTable for extended info (ifName, ifAlias, ifHighSpeed)
        for oid_prefix, field_name, converter in [
            (OID_IF_NAME, "if_name", str),
            (OID_IF_ALIAS, "if_alias", str),
            (OID_IF_HIGH_SPEED, "if_speed", lambda v: int(v) * 1000000),
        ]:
            async for error_indication, error_status, error_index, var_binds in walk_cmd(
                engine, auth, transport, ctx,
                ObjectType(ObjectIdentity(oid_prefix)),
            ):
                if error_indication or error_status:
                    # ifXTable may not be supported, that's OK
                    break
                for oid, val in var_binds:
                    oid_str = str(oid)
                    parts = oid_str.split(".")
                    if_index = int(parts[-1])
                    if if_index in interfaces:
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
        """Poll interface counters, preferring 64-bit HC counters."""
        counters = {idx: {"if_index": idx} for idx in if_indexes}
        hc_counters = False

        # Helper to walk an OID and collect values by ifIndex
        async def _walk_oid(oid_prefix):
            data = {}
            try:
                async for err_ind, err_st, err_idx, var_binds in walk_cmd(
                    engine, auth, transport, ctx,
                    ObjectType(ObjectIdentity(oid_prefix)),
                ):
                    if err_ind or err_st:
                        break
                    for oid, val in var_binds:
                        parts = str(oid).split(".")
                        if_index = int(parts[-1])
                        val_str = str(val)
                        if "noSuch" in val_str:
                            return None  # OID not supported
                        data[if_index] = int(val)
            except Exception:
                pass
            return data if data else None

        # Try 64-bit HC counters first
        hc_in = await _walk_oid(OID_IF_HC_IN_OCTETS)
        if hc_in:
            hc_counters = True
            for idx, val in hc_in.items():
                if idx in counters:
                    counters[idx]["bytes_in"] = val
            hc_out = await _walk_oid(OID_IF_HC_OUT_OCTETS)
            if hc_out:
                for idx, val in hc_out.items():
                    if idx in counters:
                        counters[idx]["bytes_out"] = val
        else:
            # Fallback to 32-bit counters
            for oid_prefix, field in [
                (OID_IF_IN_OCTETS, "bytes_in"),
                (OID_IF_OUT_OCTETS, "bytes_out"),
            ]:
                data = await _walk_oid(oid_prefix)
                if data:
                    for idx, val in data.items():
                        if idx in counters:
                            counters[idx][field] = val

        # Poll remaining counter OIDs (always 32-bit)
        counter_oids = [
            (OID_IF_IN_UCAST_PKTS, "packets_in"),
            (OID_IF_OUT_UCAST_PKTS, "packets_out"),
            (OID_IF_IN_ERRORS, "errors_in"),
            (OID_IF_OUT_ERRORS, "errors_out"),
            (OID_IF_IN_DISCARDS, "discards_in"),
            (OID_IF_OUT_DISCARDS, "discards_out"),
            (OID_IF_IN_BROADCAST_PKTS, "broadcast_in"),
            (OID_IF_OUT_BROADCAST_PKTS, "broadcast_out"),
        ]

        for oid_prefix, field in counter_oids:
            data = await _walk_oid(oid_prefix)
            if data:
                for idx, val in data.items():
                    if idx in counters:
                        counters[idx][field] = val

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
