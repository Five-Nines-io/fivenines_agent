"""
SNMP network device polling collector.

Uses net-snmp CLI tools (snmpget, snmpbulkwalk) via subprocess.
No Python SNMP library dependency -- just parse CLI output.

Architecture:
  sync_config["snmp_targets"]
       |
       v
  snmp_metrics(targets, tick_started)
       |
       +---> Check shutil.which("snmpget")
       +---> Report polls kept in flight that have finished; skip the
       |         devices whose poll is still running
       +---> Filter due devices (_is_device_due), oldest poll first
       +---> ThreadPoolExecutor.submit(_poll_device) per due device,
       |         results read against a 30s batch deadline (queued:
       |         cancelled; running: kept in _in_flight);
       |         each thread runs subprocess.run(["snmpget"/...])
       +---> Aggregate results into {"devices": [...]}
       +---> Append cached successes of not-due devices (_replay_cached;
       |         a failed poll evicts the device's entry)
       |
       v
  data["snmp_metrics"] = {"devices": [...]}

Thread safety: each worker thread runs its own subprocess.
No shared mutable state between threads.
"""

import hashlib
import json
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait

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
# A poll kept in flight ends within ~60s by its own subprocess timeouts; one
# still running this long after its tick started is stuck (an snmpget in
# uninterruptible sleep), and its device reports a counted failure each tick.
IN_FLIGHT_LIMIT = 180

# The target fields a poll reads (_build_base_args, _poll_device): a change
# to any of them is a different target. The interval only decides when.
POLLING_FIELDS = (
    "ip", "port", "version", "community", "username", "security_level",
    "auth_protocol", "auth_password", "priv_protocol", "priv_password",
    "capabilities", "custom_oids",
)


def snmp_metrics(targets, tick_started=None):
    """Poll SNMP targets and return metrics.

    Entry point called from agent.py as a special-case collector.
    Requires net-snmp CLI tools (snmpget, snmpbulkwalk).

    Args:
        targets: list of target dicts from sync_config["snmp_targets"]
        tick_started: time.monotonic() at the start of the agent's
            collection tick (see SNMPCollector._is_device_due); None: the
            current time

    Returns:
        dict with "devices" key, or None if snmpget is unavailable
    """
    if not shutil.which("snmpget"):
        log("snmpget not found in PATH, skipping SNMP polling", "error")
        return None

    if not targets:
        return None

    global _collector
    _collector = SNMPCollector(targets, tick_started)
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
      .1.3.6.1.2.1.2.2.1.8.1 = INTEGER: up(1)
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
        # INTEGER: up(1) -> "1". A host that loads MIBs (RHEL family,
        # snmp-mibs-downloader) labels enumerations, and the int() converters
        # dropped every interface's type and admin/oper status. -Oe asks for
        # the bare number, but it is a toggle applied BEFORE snmp.conf is
        # read, so "printNumericEnums no" there wins.
        if type_str in ("Timeticks", "INTEGER"):
            if "(" in val and ")" in val:
                val = val[val.index("(") + 1 : val.index(")")]

        val = val.strip().strip('"')
        return (oid_str, val)

    return (oid_str, value_part.strip().strip('"'))


def _polling_key(target):
    """A digest of the POLLING_FIELDS present (an absent field and a null
    one poll differently): no second plaintext copy of the credentials.
    None, instead of raising, when the target cannot be serialized (a
    hostile nesting depth)."""
    try:
        blob = json.dumps(
            {f: target[f] for f in POLLING_FIELDS if f in target},
            sort_keys=True,
            default=str,
        )
    except (RecursionError, TypeError, ValueError):
        return None
    return hashlib.sha256(blob.encode()).hexdigest()


def _executor_timeout(device_id):
    """The entry for a poll the batch deadline cut off. The server records
    it without counting it as a device failure."""
    log("SNMP executor timeout for device {}".format(device_id), "error")
    return {
        "device_id": device_id,
        "error": {
            "type": "timeout",
            "message": "Executor timeout after {}s".format(EXECUTOR_TIMEOUT),
        },
    }


def _read_poll(device_id, future):
    """A finished poll's device dict, or an error if the poll raised."""
    try:
        return future.result()
    except Exception as e:
        log("SNMP error for device {}: {}".format(device_id, e), "error")
        return {
            "device_id": device_id,
            "error": {"type": "unknown", "message": str(e)},
        }


class _Ticket:
    """Lets a submitted poll run only once submit() has returned its future.
    submit() queues the work BEFORE starting a thread; when the start then
    fails (a pids limit), an idle worker could still run a poll that nothing
    tracks, whose answer is lost and whose device gets polled again."""

    def __init__(self):
        self.accepted = False
        self._decided = threading.Event()

    def decide(self, accepted):
        self.accepted = accepted
        self._decided.set()

    def wait(self):
        self._decided.wait()
        return self.accepted


def _late(result):
    """A poll answered after its batch, without its counters: the server
    stamps them with this tick's time, a tick or more after they were read,
    which would skew every rate computed across them."""
    return {
        k: v
        for k, v in result.items()
        if k not in ("interface_metrics", "custom_metrics")
    }


def _stuck(device_id):
    """A COUNTED failure (unlike an executor timeout) for a device whose poll
    has been running past IN_FLIGHT_LIMIT, so it can reach unreachable."""
    return {
        "device_id": device_id,
        "error": {
            "type": "timeout",
            "message": "SNMP poll still running after {}s".format(
                IN_FLIGHT_LIMIT
            ),
        },
    }


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

    A device that is not due is reported by replaying its last SUCCESSFUL
    result, marked "cached": true. A failed poll evicts that result: the
    server resets a device's failure streak on every success it receives,
    so replaying one between failed polls kept an outage from ever reaching
    unreachable (#161). After a failure, a not-due tick reports nothing but
    the answer of a poll kept in flight, once it finishes.
    """

    def __init__(self, targets, tick_started=None):
        self.targets = targets
        self.tick_started = tick_started
        if not hasattr(SNMPCollector, "_last_poll_times"):
            SNMPCollector._last_poll_times = {}
        if not hasattr(SNMPCollector, "_last_results"):
            SNMPCollector._last_results = {}
        if not hasattr(SNMPCollector, "_polling_keys"):
            SNMPCollector._polling_keys = {}
        if not hasattr(SNMPCollector, "_in_flight"):
            SNMPCollector._in_flight = {}

    def poll_all(self):
        """Poll all due SNMP targets concurrently.

        Returns:
            dict: {"devices": [device_dict, ...]}
        """
        # Prune stale state. A removed device's poll still in flight stays
        # there until it ends (below): forgotten, a re-added device would be
        # polled again on top of it.
        current_ids = {t["device_id"] for t in self.targets}
        known_ids = set(SNMPCollector._last_poll_times) | set(
            SNMPCollector._polling_keys
        )
        for device_id in known_ids - current_ids:
            SNMPCollector._last_poll_times.pop(device_id, None)
            SNMPCollector._last_results.pop(device_id, None)
            SNMPCollector._polling_keys.pop(device_id, None)

        # A device whose POLLING_FIELDS changed loses its poll time: due at
        # once (or as soon as a poll of the old target still in flight ends),
        # its old answer is replaced or evicted by that poll instead of
        # replayed until its interval runs out. A target whose key cannot be
        # computed is never replayed: its old answer may be another target's.
        for target in self.targets:
            device_id = target["device_id"]
            key = _polling_key(target)
            if key is None:
                SNMPCollector._last_results.pop(device_id, None)
            elif SNMPCollector._polling_keys.get(device_id, key) != key:
                SNMPCollector._last_poll_times.pop(device_id, None)
            SNMPCollector._polling_keys[device_id] = key

        # A poll still running when its batch ended (below) is reported once
        # it has finished, on a later tick, unless its target changed or went
        # away since. Until then its device is not polled again: never two
        # polls against one device.
        devices = []
        busy_ids = set()
        for device_id, (future, key, started, stuck) in list(
            SNMPCollector._in_flight.items()
        ):
            if not future.done():
                busy_ids.add(device_id)
                if (
                    device_id in current_ids
                    and self._tick_time() - started >= IN_FLIGHT_LIMIT
                ):
                    self._report(devices, device_id, _stuck(device_id))
                    SNMPCollector._in_flight[device_id] = (
                        future, key, started, True
                    )
                continue
            del SNMPCollector._in_flight[device_id]
            current = SNMPCollector._polling_keys.get(device_id)
            if key is None or key != current or stuck:
                # A removed target's answer (its key was pruned), the old
                # target's, or one reported stuck meanwhile, whose success
                # would clear the failures reported for it: dropped, and the
                # device is polled afresh.
                SNMPCollector._last_poll_times.pop(device_id, None)
                continue
            busy_ids.add(device_id)
            late = _late(_read_poll(device_id, future))
            self._report(devices, device_id, late)

        # Oldest poll first: a device cut off before its poll started is
        # left unstamped (below), so it goes ahead of every device polled
        # since instead of being cut off again.
        due_targets = sorted(
            (
                t
                for t in self.targets
                if t["device_id"] not in busy_ids and self._is_device_due(t)
            ),
            key=lambda t: SNMPCollector._last_poll_times.get(
                t["device_id"], float("-inf")
            ),
        )
        no_replay_ids = busy_ids | {t["device_id"] for t in due_targets}

        if not due_targets:
            return {"devices": devices + self._replay_cached(no_replay_ids)}

        workers = min(len(due_targets), MAX_WORKERS)
        batch_deadline = time.monotonic() + EXECUTOR_TIMEOUT
        # Stamped with the agent tick's start (see _is_device_due). Before
        # #161 a poll was stamped when it FINISHED, so a ~10s timed-out poll
        # left the device 50s old on the next 60s tick: not due, polled
        # every OTHER tick.
        stamp = self._tick_time()

        try:
            executor = ThreadPoolExecutor(max_workers=workers)
            try:
                futures = {}
                for target in due_targets:
                    ticket = None
                    accepted = False
                    try:
                        ticket = _Ticket()
                        future = executor.submit(
                            self._poll_accepted, target, ticket
                        )
                        futures[future] = target
                        accepted = True  # only once it is tracked
                    except Exception as e:
                        # Out of threads (a pids limit) or memory: the rest
                        # stay unstamped, due next tick, and the polls
                        # already submitted are still read below.
                        log("SNMP submit failed: {}".format(e), "error")
                        break
                    finally:
                        # Whatever was raised: an undecided ticket would hold
                        # its worker, and the agent's exit, forever.
                        if ticket is not None:
                            ticket.decide(accepted)

                for future, target in futures.items():
                    device_id = target["device_id"]
                    # Past the deadline, only a finished poll is read: waiting
                    # 0.1s more on each pending one stretched a big batch past
                    # the watchdog.
                    wait(
                        [future],
                        timeout=max(0.0, batch_deadline - time.monotonic()),
                    )
                    if future.cancel():
                        # Still queued: it never runs. Left unstamped, the
                        # device stays due and goes ahead of every device
                        # polled since.
                        self._report(
                            devices, device_id, _executor_timeout(device_id)
                        )
                        continue
                    if future.done():
                        result = _read_poll(device_id, future)
                    else:
                        # Already running: it cannot be stopped, and its
                        # answer is reported once it finishes. Dropped, the
                        # answer of a device that always finished just past
                        # the deadline was never counted (the server does not
                        # count an executor timeout): it never reached
                        # unreachable.
                        SNMPCollector._in_flight[device_id] = (
                            future,
                            SNMPCollector._polling_keys.get(device_id),
                            stamp,
                            False,  # reported stuck
                        )
                        result = _executor_timeout(device_id)
                    SNMPCollector._last_poll_times[device_id] = stamp
                    self._report(devices, device_id, result)
            finally:
                # Never waits on a running poll.
                executor.shutdown(wait=False)
        except Exception as e:
            log("SNMP ThreadPoolExecutor error: {}".format(e), "error")

        devices.extend(self._replay_cached(no_replay_ids))

        return {"devices": devices}

    def _poll_accepted(self, target, ticket):
        """Poll `target` unless its submit() failed (see _Ticket)."""
        if not ticket.wait():
            return None
        return self._poll_device(target)

    def _report(self, devices, device_id, result):
        """Add a poll's outcome to this tick's devices. A success is cached
        for replay; anything else evicts the device's cached success."""
        devices.append(result)
        if result.get("error") is None:
            SNMPCollector._last_results[device_id] = result
        else:
            SNMPCollector._last_results.pop(device_id, None)

    def _replay_cached(self, no_replay_ids):
        """Cached last successes of the devices not due this tick. A device
        polled this tick, or with a poll in flight, is never replayed.

        Copies marked "cached": true, so the server can tell a replay from
        an answer and the marker never reaches the cache itself.
        """
        return [
            dict(SNMPCollector._last_results[t["device_id"]], cached=True)
            for t in self.targets
            if t["device_id"] not in no_replay_ids
            and t["device_id"] in SNMPCollector._last_results
        ]

    def _tick_time(self):
        """The agent tick's start when known, else the current time."""
        if self.tick_started is not None:
            return self.tick_started
        return time.monotonic()

    def _is_device_due(self, target):
        """Check if a device is due for polling based on its interval.

        Polls are stamped with, and compared against, the START of the
        agent's tick, so a device is never polled on two ticks closer than
        its interval while its POLLING_FIELDS are unchanged. Tick starts are at least one collection interval
        apart: a device whose interval equals the agent's is due every tick
        however long the collectors before SNMP took, and one between two
        ticks waits for the later. A device never polled is due at once.
        """
        last_poll = SNMPCollector._last_poll_times.get(target["device_id"])
        if last_poll is None:
            return True
        interval = target.get("interval", 60)
        return self._tick_time() - last_poll >= interval

    def _build_base_args(self, target):
        """Build CLI args for SNMP version and authentication.

        Returns:
            tuple: (args_list, error_dict_or_None)
        """
        version = target.get("version", "v2c")
        ip = target.get("ip", "127.0.0.1")
        port = target.get("port", 161)
        host = "{}:{}".format(ip, port) if port != 161 else ip

        # -On: numeric OIDs. -Oe: enumerations as bare integers, not "up(1)"
        # (_parse_snmp_line accepts both; snmp.conf can override -Oe).
        args = [
            "-t", str(SNMP_TIMEOUT), "-r", str(SNMP_RETRIES), "-On", "-Oe",
        ]

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

        custom_oids = target.get("custom_oids", [])
        if custom_oids:
            custom, error = self._poll_custom_oids(base_args, custom_oids)
            if error:
                log(
                    "SNMP custom OID poll failed for {}: {}".format(
                        device_id, error.get("message", "")
                    ),
                    "error",
                )
                # Non-fatal: include partial result with custom error
                result["custom_metrics_error"] = error
            else:
                result["custom_metrics"] = custom

        return result

    def _poll_custom_oids(self, base_args, custom_oids):
        """Get custom OIDs via snmpget.

        Args:
            base_args: CLI args for auth/version
            custom_oids: list of {"name": str, "oid": str, "type": str}
                type is "gauge", "counter", or "string"

        Returns:
            tuple: (metrics_list, error_dict_or_None)
        """
        oids = [entry["oid"] for entry in custom_oids]
        args = base_args + oids
        stdout, error = _run_snmp_cmd("snmpget", args, SNMP_TIMEOUT + 5)
        if error:
            return None, error

        # Build OID -> entry lookup
        oid_map = {entry["oid"]: entry for entry in custom_oids}

        metrics = []
        for line in stdout.splitlines():
            parsed = _parse_snmp_line(line)
            if not parsed or parsed[1] is None:
                continue
            oid, val = parsed
            entry = oid_map.get(oid)
            if not entry:
                continue
            metric = {"name": entry["name"], "oid": oid}
            oid_type = entry.get("type", "gauge")
            if oid_type == "string":
                metric["value"] = val
            else:
                try:
                    metric["value"] = int(val)
                except (ValueError, TypeError):
                    try:
                        metric["value"] = float(val)
                    except (ValueError, TypeError):
                        metric["value"] = val
            metrics.append(metric)

        return metrics, None

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
