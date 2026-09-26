"""Tests for SNMP network device polling collector (subprocess-based)."""

import subprocess
import time
from concurrent.futures import Future
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from fivenines_agent.snmp import (
    EXECUTOR_TIMEOUT,
    IF_TABLE_PREFIX,
    IF_XTABLE_PREFIX,
    IFTABLE_COLUMNS,
    IFXTABLE_COLUMNS,
    MAX_WORKERS,
    OID_SYS_DESCR,
    OID_SYS_NAME,
    OID_SYS_UPTIME,
    SNMP_RETRIES,
    SNMP_TIMEOUT,
    SNMPCollector,
    _parse_snmp_line,
    _polling_key,
    _print_diagnostics,
    _run_snmp_cmd,
    snmp_metrics,
)


# --- Helper fixtures ---


def _make_target(
    device_id="dev-1",
    ip="192.168.1.10",
    version="v2c",
    community="public",
    interval=60,
    capabilities=None,
    port=161,
    **kwargs,
):
    """Create a target dict matching sync_config format."""
    target = {
        "device_id": device_id,
        "ip": ip,
        "version": version,
        "interval": interval,
        "capabilities": capabilities or ["system", "if_table"],
        "port": port,
    }
    if version == "v2c":
        target["community"] = community
    target.update(kwargs)
    return target


def _make_v3_target(
    device_id="dev-v3",
    security_level="auth_priv",
    **kwargs,
):
    """Create an SNMPv3 target."""
    defaults = {
        "ip": "192.168.1.20",
        "version": "v3",
        "interval": 60,
        "capabilities": ["system", "if_table"],
        "username": "snmpuser",
        "security_level": security_level,
        "auth_protocol": "sha",
        "auth_password": "authpass123",
        "priv_protocol": "aes",
        "priv_password": "privpass123",
    }
    defaults.update(kwargs)
    defaults["device_id"] = device_id
    return defaults


# Sample CLI outputs matching real device responses
SYSTEM_OUTPUT = """\
.1.3.6.1.2.1.1.5.0 = STRING: "CoreSwitch1"
.1.3.6.1.2.1.1.1.0 = STRING: "Cisco IOS 15.2"
.1.3.6.1.2.1.1.3.0 = Timeticks: (8640000) 1:00:00:00.00
"""

IFTABLE_OUTPUT = """\
.1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2
.1.3.6.1.2.1.2.2.1.3.1 = INTEGER: 6
.1.3.6.1.2.1.2.2.1.3.2 = INTEGER: 6
.1.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.7.2 = INTEGER: 2
.1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.8.2 = INTEGER: 2
.1.3.6.1.2.1.2.2.1.10.1 = Counter32: 1000000
.1.3.6.1.2.1.2.2.1.10.2 = Counter32: 2000000
.1.3.6.1.2.1.2.2.1.11.1 = Counter32: 5000
.1.3.6.1.2.1.2.2.1.11.2 = Counter32: 6000
.1.3.6.1.2.1.2.2.1.13.1 = Counter32: 10
.1.3.6.1.2.1.2.2.1.13.2 = Counter32: 20
.1.3.6.1.2.1.2.2.1.14.1 = Counter32: 0
.1.3.6.1.2.1.2.2.1.14.2 = Counter32: 1
.1.3.6.1.2.1.2.2.1.16.1 = Counter32: 500000
.1.3.6.1.2.1.2.2.1.16.2 = Counter32: 600000
.1.3.6.1.2.1.2.2.1.17.1 = Counter32: 4000
.1.3.6.1.2.1.2.2.1.17.2 = Counter32: 4500
.1.3.6.1.2.1.2.2.1.19.1 = Counter32: 5
.1.3.6.1.2.1.2.2.1.19.2 = Counter32: 8
.1.3.6.1.2.1.2.2.1.20.1 = Counter32: 0
.1.3.6.1.2.1.2.2.1.20.2 = Counter32: 2
"""

IFXTABLE_OUTPUT = """\
.1.3.6.1.2.1.31.1.1.1.1.1 = STRING: "GigabitEthernet0/1"
.1.3.6.1.2.1.31.1.1.1.1.2 = STRING: "GigabitEthernet0/2"
.1.3.6.1.2.1.31.1.1.1.3.1 = Counter32: 100
.1.3.6.1.2.1.31.1.1.1.3.2 = Counter32: 200
.1.3.6.1.2.1.31.1.1.1.5.1 = Counter32: 50
.1.3.6.1.2.1.31.1.1.1.5.2 = Counter32: 60
.1.3.6.1.2.1.31.1.1.1.6.1 = Counter64: 9000000000
.1.3.6.1.2.1.31.1.1.1.6.2 = Counter64: 8000000000
.1.3.6.1.2.1.31.1.1.1.10.1 = Counter64: 7000000000
.1.3.6.1.2.1.31.1.1.1.10.2 = Counter64: 6000000000
.1.3.6.1.2.1.31.1.1.1.15.1 = Gauge32: 1000
.1.3.6.1.2.1.31.1.1.1.15.2 = Gauge32: 1000
.1.3.6.1.2.1.31.1.1.1.18.1 = STRING: "Uplink"
.1.3.6.1.2.1.31.1.1.1.18.2 = STRING: "Server"
"""

# The same ifTable columns as net-snmp prints them on a host that loads MIBs
LABELLED_IFTABLE = """\
.1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2
.1.3.6.1.2.1.2.2.1.3.1 = INTEGER: ethernetCsmacd(6)
.1.3.6.1.2.1.2.2.1.3.2 = INTEGER: ieee8023adLag(161)
.1.3.6.1.2.1.2.2.1.7.1 = INTEGER: up(1)
.1.3.6.1.2.1.2.2.1.7.2 = INTEGER: down(2)
.1.3.6.1.2.1.2.2.1.8.1 = INTEGER: up(1)
.1.3.6.1.2.1.2.2.1.8.2 = INTEGER: lowerLayerDown(7)
"""

IFXTABLE_NO_SUPPORT = """\
.1.3.6.1.2.1.31.1.1.1.1 = No Such Object available on this agent at this OID
"""

PRINTER_IFTABLE = """\
.1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.3.1 = INTEGER: 6
.1.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.10.1 = Counter32: 7010736
.1.3.6.1.2.1.2.2.1.11.1 = Counter32: 43630
.1.3.6.1.2.1.2.2.1.13.1 = Counter32: 2386
.1.3.6.1.2.1.2.2.1.14.1 = Counter32: 0
.1.3.6.1.2.1.2.2.1.16.1 = Counter32: 3870844
.1.3.6.1.2.1.2.2.1.17.1 = Counter32: 31479
.1.3.6.1.2.1.2.2.1.19.1 = Counter32: 0
.1.3.6.1.2.1.2.2.1.20.1 = Counter32: 0
"""


@pytest.fixture(autouse=True)
def _reset_collector_state():
    """Reset class-level state between tests."""
    SNMPCollector._last_poll_times = {}
    SNMPCollector._last_results = {}
    SNMPCollector._polling_keys = {}
    SNMPCollector._in_flight = {}
    yield
    SNMPCollector._last_poll_times = {}
    SNMPCollector._last_results = {}
    SNMPCollector._polling_keys = {}
    SNMPCollector._in_flight = {}


class _Clock:
    """Stands in for the snmp module's `time`: monotonic() returns `now`, so
    tick spacing and poll duration are exact rather than wall-clock."""

    def __init__(self, now=1000.0):
        self.now = now

    def monotonic(self):
        return self.now


class _FakeExecutor:
    """Runs nothing. When the batch deadline has passed, the first `done`
    polls submitted have finished with poll(target), the next `running` are
    still running, and the rest are still queued."""

    def __init__(self, poll=None, done=0, running=0, threads=None):
        self.poll = poll
        self.done = done
        self.running = running
        self.threads = threads  # submits that can start a thread
        self.submitted = []
        self.futures = []
        self.shutdown_args = None

    def submit(self, fn, target, *args):
        if self.threads is not None and len(self.submitted) >= self.threads:
            raise RuntimeError("can't start new thread")
        future = Future()
        n = len(self.submitted)
        self.submitted.append(target["device_id"])
        if n < self.done + self.running:
            future.set_running_or_notify_cancel()
        if n < self.done:
            future.set_result(self.poll(target))
        self.futures.append(future)
        return future

    def shutdown(self, wait=True, cancel_futures=False):
        self.shutdown_args = (wait, cancel_futures)


def _fake_pool(executor):
    """Patch the pool, with the batch deadline already passed."""
    return patch.multiple(
        "fivenines_agent.snmp",
        ThreadPoolExecutor=lambda max_workers: executor,
        EXECUTOR_TIMEOUT=0,
    )


OK_POLL = [
    (SYSTEM_OUTPUT, None),
    (IFTABLE_OUTPUT, None),
    (IFXTABLE_OUTPUT, None),
]
DOWN = (None, {"type": "timeout", "message": "Timeout: No Response"})


def _outcome(devices):
    """What one tick reported for dev-1: "ok", "cached", "error" or None."""
    assert len(devices) <= 1
    if not devices:
        return None
    dev = devices[0]
    if "error" in dev:
        return "error"
    return "cached" if dev.get("cached") else "ok"


def _mock_run(stdout="", stderr="", returncode=0):
    """Create a mock subprocess.CompletedProcess."""
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


# ================================================================
# Tests for _parse_snmp_line()
# ================================================================


class TestParseSnmpLine:
    def test_string_value(self):
        line = '.1.3.6.1.2.1.1.5.0 = STRING: "EPSONCD1062"'
        assert _parse_snmp_line(line) == ("1.3.6.1.2.1.1.5.0", "EPSONCD1062")

    def test_integer_value(self):
        line = ".1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1"
        assert _parse_snmp_line(line) == ("1.3.6.1.2.1.2.2.1.1.1", "1")

    def test_counter32(self):
        line = ".1.3.6.1.2.1.2.2.1.10.1 = Counter32: 7010736"
        assert _parse_snmp_line(line) == (
            "1.3.6.1.2.1.2.2.1.10.1", "7010736"
        )

    def test_counter64(self):
        line = ".1.3.6.1.2.1.31.1.1.1.6.1 = Counter64: 9000000000"
        assert _parse_snmp_line(line) == (
            "1.3.6.1.2.1.31.1.1.1.6.1", "9000000000"
        )

    def test_gauge32(self):
        line = ".1.3.6.1.2.1.2.2.1.5.1 = Gauge32: 0"
        assert _parse_snmp_line(line) == ("1.3.6.1.2.1.2.2.1.5.1", "0")

    def test_timeticks(self):
        line = ".1.3.6.1.2.1.1.3.0 = Timeticks: (1491600) 4:08:36.00"
        assert _parse_snmp_line(line) == ("1.3.6.1.2.1.1.3.0", "1491600")

    @pytest.mark.parametrize(
        "value, number",
        [
            ("up(1)", "1"),
            ("not-present(-1)", "-1"),
            ("l2vlan(135)", "135"),
            ("other_type(3)", "3"),
        ],
    )
    def test_enumeration_reads_as_its_number(self, value, number):
        """REGRESSION (#162): a host that loads MIBs prints an enumeration
        as label(N), and int("up(1)") dropped every interface's status.
        Like Timeticks, the value is the number in parentheses."""
        line = ".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: {}".format(value)
        assert _parse_snmp_line(line) == ("1.3.6.1.2.1.2.2.1.8.1", number)

    def test_parenthesized_string_is_data(self):
        """Only an INTEGER is read that way: a string ending in "(N)" is
        the value itself. Unquoted, as a host that loads MIBs prints a
        DisplayString (ifAlias) -- the same hosts that label enums."""
        line = ".1.3.6.1.2.1.31.1.1.1.18.1 = STRING: uplink(2)"
        assert _parse_snmp_line(line) == (
            "1.3.6.1.2.1.31.1.1.1.18.1", "uplink(2)"
        )

    def test_no_such_object(self):
        line = (
            ".1.3.6.1.2.1.31.1.1.1.1 = "
            "No Such Object available on this agent at this OID"
        )
        oid, val = _parse_snmp_line(line)
        assert oid == "1.3.6.1.2.1.31.1.1.1.1"
        assert val is None

    def test_no_more_variables(self):
        line = ".1.3.6.1.2.1.2.2.1.22.1 = No more variables left in this MIB"
        oid, val = _parse_snmp_line(line)
        assert val is None

    def test_empty_line(self):
        assert _parse_snmp_line("") is None

    def test_no_equals(self):
        assert _parse_snmp_line("some random text") is None

    def test_whitespace_handling(self):
        line = "  .1.3.6.1.2.1.1.5.0 = STRING: \"test\"  "
        assert _parse_snmp_line(line) == ("1.3.6.1.2.1.1.5.0", "test")

    def test_value_without_type_prefix(self):
        line = ".1.3.6.1.2.1.1.5.0 = test_value"
        assert _parse_snmp_line(line) == ("1.3.6.1.2.1.1.5.0", "test_value")

    def test_hex_string(self):
        line = ".1.3.6.1.2.1.2.2.1.6.1 = Hex-STRING: 64 C6 D2 CD 10 62"
        oid, val = _parse_snmp_line(line)
        assert oid == "1.3.6.1.2.1.2.2.1.6.1"
        assert val == "64 C6 D2 CD 10 62"


# ================================================================
# Tests for _run_snmp_cmd()
# ================================================================


class TestRunSnmpCmd:
    @patch("fivenines_agent.snmp.get_clean_env")
    @patch("fivenines_agent.snmp.subprocess.run")
    def test_success(self, mock_run, mock_env):
        mock_env.return_value = {}
        mock_run.return_value = _mock_run(stdout="output\n")
        stdout, error = _run_snmp_cmd("snmpget", ["-v2c", "host"], 10)
        assert stdout == "output\n"
        assert error is None
        mock_run.assert_called_once()

    @patch("fivenines_agent.snmp.get_clean_env")
    @patch("fivenines_agent.snmp.subprocess.run")
    def test_timeout_in_stderr(self, mock_run, mock_env):
        mock_env.return_value = {}
        mock_run.return_value = _mock_run(
            returncode=1, stderr="Timeout: No Response from host"
        )
        stdout, error = _run_snmp_cmd("snmpget", [], 10)
        assert stdout is None
        assert error["type"] == "timeout"

    @patch("fivenines_agent.snmp.get_clean_env")
    @patch("fivenines_agent.snmp.subprocess.run")
    def test_auth_error(self, mock_run, mock_env):
        mock_env.return_value = {}
        mock_run.return_value = _mock_run(
            returncode=1, stderr="Authentication failure"
        )
        stdout, error = _run_snmp_cmd("snmpget", [], 10)
        assert error["type"] == "auth_error"

    @patch("fivenines_agent.snmp.get_clean_env")
    @patch("fivenines_agent.snmp.subprocess.run")
    def test_unknown_user(self, mock_run, mock_env):
        mock_env.return_value = {}
        mock_run.return_value = _mock_run(
            returncode=1, stderr="Unknown user name"
        )
        stdout, error = _run_snmp_cmd("snmpget", [], 10)
        assert error["type"] == "auth_error"

    @patch("fivenines_agent.snmp.get_clean_env")
    @patch("fivenines_agent.snmp.subprocess.run")
    def test_generic_snmp_error(self, mock_run, mock_env):
        mock_env.return_value = {}
        mock_run.return_value = _mock_run(
            returncode=1, stderr="Some SNMP error"
        )
        stdout, error = _run_snmp_cmd("snmpget", [], 10)
        assert error["type"] == "snmp_error"

    @patch("fivenines_agent.snmp.get_clean_env")
    @patch("fivenines_agent.snmp.subprocess.run")
    def test_subprocess_timeout(self, mock_run, mock_env):
        mock_env.return_value = {}
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="snmpget", timeout=10)
        stdout, error = _run_snmp_cmd("snmpget", [], 10)
        assert error["type"] == "timeout"
        assert "timed out" in error["message"]

    @patch("fivenines_agent.snmp.get_clean_env")
    @patch("fivenines_agent.snmp.subprocess.run")
    def test_unexpected_exception(self, mock_run, mock_env):
        mock_env.return_value = {}
        mock_run.side_effect = OSError("file not found")
        stdout, error = _run_snmp_cmd("snmpget", [], 10)
        assert error["type"] == "unknown"
        assert "file not found" in error["message"]

    @patch("fivenines_agent.snmp.get_clean_env")
    @patch("fivenines_agent.snmp.subprocess.run")
    def test_no_response_stderr(self, mock_run, mock_env):
        mock_env.return_value = {}
        mock_run.return_value = _mock_run(
            returncode=2, stderr="No Response from 192.168.1.10"
        )
        stdout, error = _run_snmp_cmd("snmpget", [], 10)
        assert error["type"] == "timeout"

    @patch("fivenines_agent.snmp.get_clean_env")
    @patch("fivenines_agent.snmp.subprocess.run")
    def test_usm_error(self, mock_run, mock_env):
        mock_env.return_value = {}
        mock_run.return_value = _mock_run(
            returncode=1, stderr="USM error: wrong credentials"
        )
        stdout, error = _run_snmp_cmd("snmpget", [], 10)
        assert error["type"] == "auth_error"


# ================================================================
# Tests for snmp_metrics() entry point
# ================================================================


class TestSnmpMetrics:
    @patch("fivenines_agent.snmp.shutil.which")
    def test_no_snmpget_returns_none(self, mock_which):
        mock_which.return_value = None
        result = snmp_metrics([_make_target()])
        assert result is None

    @patch("fivenines_agent.snmp.shutil.which")
    def test_empty_targets_returns_none(self, mock_which):
        mock_which.return_value = "/usr/bin/snmpget"
        result = snmp_metrics([])
        assert result is None

    @patch("fivenines_agent.snmp.shutil.which")
    def test_none_targets_returns_none(self, mock_which):
        mock_which.return_value = "/usr/bin/snmpget"
        result = snmp_metrics(None)
        assert result is None

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    @patch("fivenines_agent.snmp.shutil.which")
    def test_successful_poll(self, mock_which, mock_cmd):
        mock_which.return_value = "/usr/bin/snmpget"
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
        ]
        result = snmp_metrics([_make_target()])
        assert result is not None
        assert len(result["devices"]) == 1
        dev = result["devices"][0]
        assert dev["device_id"] == "dev-1"
        assert dev["system"]["sys_name"] == "CoreSwitch1"
        assert len(dev["interfaces"]) == 2
        assert len(dev["interface_metrics"]) == 2
        assert dev["hc_counters"] is True

    @patch("fivenines_agent.snmp.SNMPCollector")
    @patch("fivenines_agent.snmp.shutil.which")
    def test_tick_start_reaches_collector(self, mock_which, mock_cls):
        mock_which.return_value = "/usr/bin/snmpget"
        mock_cls.return_value.poll_all.return_value = {"devices": []}
        targets = [_make_target()]
        snmp_metrics(targets, tick_started=1000.0)
        mock_cls.assert_called_once_with(targets, 1000.0)

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    @patch("fivenines_agent.snmp.shutil.which")
    def test_dry_run_prints_diagnostics(self, mock_which, mock_cmd, capsys):
        mock_which.return_value = "/usr/bin/snmpget"
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
        ]
        with patch("fivenines_agent.snmp.dry_run", return_value=True):
            snmp_metrics([_make_target()])
        captured = capsys.readouterr()
        assert "SNMP Targets:" in captured.out
        assert "CoreSwitch1" in captured.out


# ================================================================
# Tests for SNMPCollector._build_base_args()
# ================================================================


class TestBuildBaseArgs:
    def test_v2c_default(self):
        target = _make_target()
        collector = SNMPCollector([target])
        args, error = collector._build_base_args(target)
        assert error is None
        assert "-v2c" in args
        assert "-c" in args
        idx = args.index("-c")
        assert args[idx + 1] == "public"
        assert "192.168.1.10" in args
        assert "-On" in args
        assert "-Oe" in args  # numeric enums (#162)

    def test_v2c_custom_community(self):
        target = _make_target(community="secret")
        collector = SNMPCollector([target])
        args, _ = collector._build_base_args(target)
        idx = args.index("-c")
        assert args[idx + 1] == "secret"

    def test_v2c_custom_port(self):
        target = _make_target(port=1161)
        collector = SNMPCollector([target])
        args, _ = collector._build_base_args(target)
        assert "192.168.1.10:1161" in args

    def test_v2c_default_port(self):
        target = _make_target(port=161)
        collector = SNMPCollector([target])
        args, _ = collector._build_base_args(target)
        assert "192.168.1.10" in args
        assert "192.168.1.10:161" not in args

    def test_v3_auth_priv(self):
        target = _make_v3_target(security_level="auth_priv")
        collector = SNMPCollector([target])
        args, error = collector._build_base_args(target)
        assert error is None
        assert "-v3" in args
        assert "-l" in args
        idx = args.index("-l")
        assert args[idx + 1] == "authPriv"
        assert "-u" in args
        idx = args.index("-u")
        assert args[idx + 1] == "snmpuser"
        assert "-a" in args
        assert "-A" in args
        assert "-x" in args
        assert "-X" in args

    def test_v3_auth_no_priv(self):
        target = _make_v3_target(security_level="auth_no_priv")
        collector = SNMPCollector([target])
        args, _ = collector._build_base_args(target)
        assert "-a" in args
        assert "-A" in args
        assert "-x" not in args
        assert "-X" not in args

    def test_v3_no_auth_no_priv(self):
        target = _make_v3_target(security_level="no_auth_no_priv")
        collector = SNMPCollector([target])
        args, _ = collector._build_base_args(target)
        assert "-a" not in args
        assert "-x" not in args

    def test_v3_missing_username(self):
        target = _make_v3_target()
        del target["username"]
        collector = SNMPCollector([target])
        args, error = collector._build_base_args(target)
        assert args is None
        assert error["type"] == "unknown"
        assert "username" in error["message"].lower()

    def test_v3_md5_des(self):
        target = _make_v3_target(
            auth_protocol="md5", priv_protocol="des"
        )
        collector = SNMPCollector([target])
        args, _ = collector._build_base_args(target)
        idx_a = args.index("-a")
        assert args[idx_a + 1] == "MD5"
        idx_x = args.index("-x")
        assert args[idx_x + 1] == "DES"

    def test_unsupported_version(self):
        target = _make_target(version="v1")
        collector = SNMPCollector([target])
        args, error = collector._build_base_args(target)
        assert args is None
        assert error["type"] == "unknown"
        assert "v1" in error["message"]

    def test_timeout_and_retries(self):
        target = _make_target()
        collector = SNMPCollector([target])
        args, _ = collector._build_base_args(target)
        idx_t = args.index("-t")
        assert args[idx_t + 1] == str(SNMP_TIMEOUT)
        idx_r = args.index("-r")
        assert args[idx_r + 1] == str(SNMP_RETRIES)


# ================================================================
# Tests for SNMPCollector._poll_system()
# ================================================================


class TestPollSystem:
    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_success(self, mock_cmd):
        mock_cmd.return_value = (SYSTEM_OUTPUT, None)
        collector = SNMPCollector([_make_target()])
        system, error = collector._poll_system(["-v2c", "-c", "public", "host"])
        assert error is None
        assert system["sys_name"] == "CoreSwitch1"
        assert system["sys_descr"] == "Cisco IOS 15.2"
        assert system["sys_uptime"] == 86400000  # 8640000 * 10

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_timeout_error(self, mock_cmd):
        mock_cmd.return_value = (
            None, {"type": "timeout", "message": "No Response"}
        )
        collector = SNMPCollector([_make_target()])
        system, error = collector._poll_system([])
        assert system is None
        assert error["type"] == "timeout"

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_empty_output(self, mock_cmd):
        mock_cmd.return_value = ("", None)
        collector = SNMPCollector([_make_target()])
        system, error = collector._poll_system([])
        assert error is None
        assert system == {}

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_invalid_uptime(self, mock_cmd):
        output = '.1.3.6.1.2.1.1.3.0 = STRING: "not_a_number"\n'
        mock_cmd.return_value = (output, None)
        collector = SNMPCollector([_make_target()])
        system, error = collector._poll_system([])
        assert error is None
        assert system["sys_uptime"] == 0


# ================================================================
# Tests for SNMPCollector._poll_interfaces()
# ================================================================


class TestPollInterfaces:
    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_full_switch(self, mock_cmd):
        """Switch with ifTable + ifXTable + HC counters."""
        mock_cmd.side_effect = [
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
        ]
        collector = SNMPCollector([_make_target()])
        ifaces, counters, hc, error = collector._poll_interfaces(
            ["-v2c", "-c", "public", "host"]
        )
        assert error is None
        assert len(ifaces) == 2
        assert len(counters) == 2
        assert hc is True

        # Check interface metadata
        iface1 = next(i for i in ifaces if i["if_index"] == 1)
        assert iface1["if_type"] == 6
        assert iface1["if_admin_status"] == 0  # 1-indexed -> 0-indexed
        assert iface1["if_oper_status"] == 0
        assert iface1["if_name"] == "GigabitEthernet0/1"
        assert iface1["if_alias"] == "Uplink"
        assert iface1["if_speed"] == 1000000000  # 1000 * 1M

        iface2 = next(i for i in ifaces if i["if_index"] == 2)
        assert iface2["if_admin_status"] == 1  # down (2-1=1)

        # Check counters with HC override
        c1 = next(c for c in counters if c["if_index"] == 1)
        assert c1["bytes_in"] == 9000000000  # HC override
        assert c1["bytes_out"] == 7000000000  # HC override
        assert c1["packets_in"] == 5000
        assert c1["broadcast_in"] == 100

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_labelled_enums(self, mock_cmd):
        """REGRESSION (#162): a walk from a host that loads MIBs keeps the
        type and admin/oper status of every interface."""
        mock_cmd.side_effect = [(LABELLED_IFTABLE, None), ("", None)]
        collector = SNMPCollector([_make_target()])
        ifaces, _, _, error = collector._poll_interfaces([])
        assert error is None
        iface1 = next(i for i in ifaces if i["if_index"] == 1)
        assert iface1["if_type"] == 6
        assert iface1["if_admin_status"] == 0  # up(1)
        assert iface1["if_oper_status"] == 0  # up(1)
        iface2 = next(i for i in ifaces if i["if_index"] == 2)
        assert iface2["if_type"] == 161  # a LACP bond: a label with digits
        assert iface2["if_admin_status"] == 1  # down(2)
        assert iface2["if_oper_status"] == 6  # lowerLayerDown(7)

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_printer_no_ifxtable(self, mock_cmd):
        """Printer with only ifTable (no ifXTable support)."""
        mock_cmd.side_effect = [
            (PRINTER_IFTABLE, None),
            (IFXTABLE_NO_SUPPORT, None),
        ]
        collector = SNMPCollector([_make_target()])
        ifaces, counters, hc, error = collector._poll_interfaces([])
        assert error is None
        assert len(ifaces) == 1
        assert hc is False

        iface = ifaces[0]
        assert iface["if_index"] == 1
        assert iface["if_name"] == ""  # default
        assert iface["if_alias"] == ""  # default
        assert iface["if_speed"] == 0  # default

        c = counters[0]
        assert c["bytes_in"] == 7010736  # 32-bit, no HC
        assert c["bytes_out"] == 3870844
        assert c["discards_in"] == 2386
        assert c["broadcast_in"] == 0  # default

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_iftable_error(self, mock_cmd):
        mock_cmd.return_value = (
            None, {"type": "timeout", "message": "No Response"}
        )
        collector = SNMPCollector([_make_target()])
        ifaces, counters, hc, error = collector._poll_interfaces([])
        assert ifaces is None
        assert error["type"] == "timeout"

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_ifxtable_error_nonfatal(self, mock_cmd):
        """ifXTable errors should not fail the whole poll."""
        mock_cmd.side_effect = [
            (PRINTER_IFTABLE, None),
            (None, {"type": "timeout", "message": "timed out"}),
        ]
        collector = SNMPCollector([_make_target()])
        ifaces, counters, hc, error = collector._poll_interfaces([])
        assert error is None
        assert len(ifaces) == 1
        assert hc is False

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_empty_iftable(self, mock_cmd):
        mock_cmd.side_effect = [("", None), ("", None)]
        collector = SNMPCollector([_make_target()])
        ifaces, counters, hc, error = collector._poll_interfaces([])
        assert error is None
        assert ifaces == []
        assert counters == []
        assert hc is False

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_oids_outside_prefix_filtered(self, mock_cmd):
        """OIDs from another subtree should be ignored."""
        mixed_output = (
            ".1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1\n"
            ".1.3.6.1.2.1.43.5.1.1.1.1 = INTEGER: 32\n"  # printer MIB
        )
        mock_cmd.side_effect = [(mixed_output, None), ("", None)]
        collector = SNMPCollector([_make_target()])
        ifaces, counters, hc, error = collector._poll_interfaces([])
        assert len(ifaces) == 1
        assert ifaces[0]["if_index"] == 1

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_counter_defaults(self, mock_cmd):
        """All counter fields should default to 0."""
        minimal = ".1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1\n"
        mock_cmd.side_effect = [(minimal, None), ("", None)]
        collector = SNMPCollector([_make_target()])
        ifaces, counters, hc, error = collector._poll_interfaces([])
        c = counters[0]
        for field in (
            "bytes_in", "bytes_out", "packets_in", "packets_out",
            "errors_in", "errors_out", "discards_in", "discards_out",
            "broadcast_in", "broadcast_out",
        ):
            assert c[field] == 0


# ================================================================
# Tests for SNMPCollector._poll_device()
# ================================================================


class TestPollDevice:
    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_successful_poll(self, mock_cmd):
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
        ]
        target = _make_target()
        collector = SNMPCollector([target])
        result = collector._poll_device(target)
        assert result["device_id"] == "dev-1"
        assert "system" in result
        assert "interfaces" in result
        assert "interface_metrics" in result
        assert "error" not in result

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_system_only(self, mock_cmd):
        mock_cmd.return_value = (SYSTEM_OUTPUT, None)
        target = _make_target(capabilities=["system"])
        collector = SNMPCollector([target])
        result = collector._poll_device(target)
        assert "system" in result
        assert "interfaces" not in result

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_if_table_only(self, mock_cmd):
        mock_cmd.side_effect = [
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
        ]
        target = _make_target(capabilities=["if_table"])
        collector = SNMPCollector([target])
        result = collector._poll_device(target)
        assert "system" not in result
        assert "interfaces" in result

    def test_unsupported_version_error(self):
        target = _make_target(version="v1")
        collector = SNMPCollector([target])
        result = collector._poll_device(target)
        assert result["error"]["type"] == "unknown"
        assert "v1" in result["error"]["message"]

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_system_error_returns_error(self, mock_cmd):
        mock_cmd.return_value = (
            None, {"type": "timeout", "message": "No Response"}
        )
        target = _make_target()
        collector = SNMPCollector([target])
        result = collector._poll_device(target)
        assert result["error"]["type"] == "timeout"


# ================================================================
# Tests for SNMPCollector.poll_all()
# ================================================================


class TestPollAll:
    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_single_device(self, mock_cmd):
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
        ]
        collector = SNMPCollector([_make_target()])
        result = collector.poll_all()
        assert len(result["devices"]) == 1

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_device_not_due(self, mock_cmd):
        """Devices not yet due for polling should return cached results.
        (Was skipped on Windows as flaky: a device never polled read as
        "polled at boot", not due on a runner up for less than 3600s.)"""
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
        ]
        target = _make_target(interval=3600)
        collector = SNMPCollector([target])

        # First poll - should actually poll
        result1 = collector.poll_all()
        assert len(result1["devices"]) == 1

        # Second poll - should return cached
        collector2 = SNMPCollector([target])
        result2 = collector2.poll_all()
        assert len(result2["devices"]) == 1
        assert result2["devices"][0]["device_id"] == "dev-1"

    def test_all_cached_no_due(self):
        """When no devices are due, return cached results only."""
        SNMPCollector._last_poll_times["dev-1"] = time.monotonic()
        SNMPCollector._last_results["dev-1"] = {
            "device_id": "dev-1",
            "system": {"sys_name": "cached"},
        }
        target = _make_target(interval=3600)
        collector = SNMPCollector([target])
        result = collector.poll_all()
        assert len(result["devices"]) == 1
        assert result["devices"][0]["system"]["sys_name"] == "cached"

    def test_stale_devices_pruned(self):
        """Devices no longer in targets should be removed from cache."""
        SNMPCollector._last_poll_times["old-device"] = time.monotonic()
        SNMPCollector._last_results["old-device"] = {
            "device_id": "old-device"
        }
        SNMPCollector._polling_keys["cut-off"] = "0" * 64  # never stamped
        SNMPCollector._in_flight["in-flight"] = (
            Future(), "0" * 64, 900.0, False
        )
        target = _make_target(device_id="new-device")
        # Force it to be due
        SNMPCollector._last_poll_times["new-device"] = 0

        with patch("fivenines_agent.snmp._run_snmp_cmd") as mock_cmd:
            mock_cmd.side_effect = [
                (SYSTEM_OUTPUT, None),
                (IFTABLE_OUTPUT, None),
                (IFXTABLE_OUTPUT, None),
            ]
            collector = SNMPCollector([target])
            collector.poll_all()

        assert "old-device" not in SNMPCollector._last_poll_times
        assert "old-device" not in SNMPCollector._last_results
        assert set(SNMPCollector._polling_keys) == {"new-device"}
        assert SNMPCollector._in_flight == {}

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_mixed_due_and_cached(self, mock_cmd):
        """Poll due devices and include cached results for not-due ones."""
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
        ]
        # dev-1 is cached and not due
        SNMPCollector._last_poll_times["dev-1"] = time.monotonic()
        SNMPCollector._last_results["dev-1"] = {
            "device_id": "dev-1",
            "system": {"sys_name": "cached"},
        }
        # dev-2 is due
        target1 = _make_target(device_id="dev-1", interval=3600)
        target2 = _make_target(device_id="dev-2", interval=60)

        collector = SNMPCollector([target1, target2])
        result = collector.poll_all()
        assert len(result["devices"]) == 2
        ids = {d["device_id"] for d in result["devices"]}
        assert ids == {"dev-1", "dev-2"}

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_error_device_not_cached(self, mock_cmd):
        """Failed polls should not be cached."""
        mock_cmd.return_value = (
            None, {"type": "timeout", "message": "No Response"}
        )
        target = _make_target()
        collector = SNMPCollector([target])
        result = collector.poll_all()
        assert result["devices"][0]["error"]["type"] == "timeout"
        assert "dev-1" not in SNMPCollector._last_results


# ================================================================
# Tests for _is_device_due()
# ================================================================


class TestIsDeviceDue:
    def test_never_polled(self):
        target = _make_target()
        collector = SNMPCollector([target])
        assert collector._is_device_due(target) is True

    def test_recently_polled(self):
        target = _make_target(interval=3600)
        SNMPCollector._last_poll_times["dev-1"] = time.monotonic()
        collector = SNMPCollector([target])
        assert collector._is_device_due(target) is False

    def test_interval_elapsed(self):
        target = _make_target(interval=60)
        SNMPCollector._last_poll_times["dev-1"] = time.monotonic() - 61
        collector = SNMPCollector([target])
        assert collector._is_device_due(target) is True

    def test_due_every_tick_when_interval_equals_the_agents(self):
        """Stamps and checks both use the tick START, which is at least one
        collection interval after the last one: however long the collectors
        before SNMP took, a 60s device on a 60s agent is due every tick."""
        SNMPCollector._last_poll_times["dev-1"] = 1000.0
        target = _make_target(interval=60)
        assert SNMPCollector([target], 1060.0)._is_device_due(target) is True

    def test_due_exactly_once_the_interval_has_elapsed(self):
        SNMPCollector._last_poll_times["dev-1"] = 1000.0
        target = _make_target(interval=75)
        assert SNMPCollector([target], 1074.9)._is_device_due(target) is False
        assert SNMPCollector([target], 1075.0)._is_device_due(target) is True

    def test_never_polled_faster_than_its_interval(self):
        """A 90s device on a 60s agent waits for the second tick (120s), it
        is not polled every 60s."""
        SNMPCollector._last_poll_times["dev-1"] = 1000.0
        target = _make_target(interval=90)
        assert SNMPCollector([target], 1060.0)._is_device_due(target) is False
        assert SNMPCollector([target], 1120.0)._is_device_due(target) is True

    def test_due_check_uses_the_tick_start_not_the_current_time(self):
        """Where SNMP runs within the tick is irrelevant once the tick start
        is known; without one, the current time is used."""
        clock = _Clock(1119.0)  # SNMP ran late in its tick
        SNMPCollector._last_poll_times["dev-1"] = 1000.0
        target = _make_target(interval=90)
        with patch("fivenines_agent.snmp.time", clock):
            assert SNMPCollector([target], 1060.0)._is_device_due(target) is False
            assert SNMPCollector([target])._is_device_due(target) is True

    def test_never_polled_is_due_right_after_boot(self):
        """monotonic() counts from boot: a device never polled must not wait
        until the host has been up for one interval."""
        clock = _Clock(5.0)
        target = _make_target(interval=60)
        with patch("fivenines_agent.snmp.time", clock):
            assert SNMPCollector([target])._is_device_due(target) is True

    def test_interval_too_large_for_a_float_is_not_due(self):
        """A server-pushed int past float range must read "not due", not
        raise: an exception here nulls every device on the host. Pins the
        interval out of any float arithmetic."""
        SNMPCollector._last_poll_times["dev-1"] = 1000.0
        target = _make_target(interval=10**400)
        assert SNMPCollector([target], 1060.0)._is_device_due(target) is False


# ================================================================
# Tests for replay, the batch deadline and target changes (#161)
# ================================================================


class TestReplayAfterFailure:
    """REGRESSION (#161): the last success was replayed on the ticks between
    failed polls, the server reset the failure streak on each replay, and an
    outage never reached unreachable."""

    def _ticks(self, clock, target, starts, offsets=None):
        """Run one agent tick at each start time, SNMP running `offset`
        seconds into the tick; dev-1's outcome per tick."""
        outcomes = []
        with patch("fivenines_agent.snmp.time", clock):
            for start, offset in zip(starts, offsets or [0] * len(starts)):
                clock.now = start + offset
                collector = SNMPCollector([target], start)
                outcomes.append(_outcome(collector.poll_all()["devices"]))
        return outcomes

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_outage_at_defaults_fails_every_tick(self, mock_cmd):
        """60s device interval, 60s agent tick, and a timed-out poll takes
        ~10s (-t 5 -r 1). Stamped when it finished, the device was 50s old
        on the next tick, not due, and the last success was replayed. SNMP
        also runs at a different point of each tick (the collectors before
        it vary), which must not matter either."""
        clock = _Clock()
        responses = iter(OK_POLL)

        def snmp_cmd(cmd, args, timeout):
            try:
                return next(responses)
            except StopIteration:
                clock.now += 10
                return DOWN

        mock_cmd.side_effect = snmp_cmd
        outcomes = self._ticks(
            clock,
            _make_target(interval=60),
            [1000, 1060, 1120, 1180],
            offsets=[9.0, 0.5, 20.0, 0.1],
        )
        assert outcomes == ["ok", "error", "error", "error"]

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_not_due_tick_after_a_failure_reports_nothing(self, mock_cmd):
        """error, not-due tick, error, not-due tick, error: nothing between
        the failures, never the success from before them."""
        mock_cmd.side_effect = OK_POLL + [DOWN, DOWN, DOWN]
        outcomes = self._ticks(
            _Clock(),
            _make_target(interval=120),
            [1000, 1060, 1120, 1180, 1240, 1300, 1360],
        )
        assert outcomes == [
            "ok", "cached", "error", None, "error", None, "error",
        ]

    def test_executor_failure_evicts_the_cached_success(self):
        clock = _Clock()
        SNMPCollector._last_poll_times["dev-1"] = 900.0
        SNMPCollector._last_results["dev-1"] = {
            "device_id": "dev-1",
            "system": {"sys_name": "cached"},
        }
        target = _make_target(interval=60)
        collector = SNMPCollector([target])
        with patch("fivenines_agent.snmp.time", clock), patch.object(
            collector, "_poll_device", side_effect=RuntimeError("boom")
        ):
            devices = collector.poll_all()["devices"]
        assert _outcome(devices) == "error"
        assert "dev-1" not in SNMPCollector._last_results
        # It was polled (it raised): stamped, next poll at its interval.
        assert SNMPCollector._last_poll_times["dev-1"] == 1000.0

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_mixed_tick_replays_only_the_not_due_device(self, mock_cmd):
        """On a tick that polls some devices, the not-due ones are replayed
        marked cached, and a failure evicts only the device that failed."""
        mock_cmd.return_value = DOWN
        clock = _Clock()
        SNMPCollector._last_poll_times.update({"dev-1": 990.0, "dev-2": 900.0})
        for did in ("dev-1", "dev-2"):
            SNMPCollector._last_results[did] = {
                "device_id": did,
                "system": {"sys_name": did},
            }
        targets = [
            _make_target(device_id="dev-1", interval=300),
            _make_target(device_id="dev-2", interval=60),
        ]
        with patch("fivenines_agent.snmp.time", clock):
            devices = SNMPCollector(targets).poll_all()["devices"]
        by_id = {d["device_id"]: d for d in devices}
        assert set(by_id) == {"dev-1", "dev-2"}
        assert by_id["dev-2"]["error"]["type"] == "timeout"
        assert by_id["dev-1"]["cached"] is True
        assert by_id["dev-1"]["system"] == {"sys_name": "dev-1"}
        assert "dev-2" not in SNMPCollector._last_results
        assert "cached" not in SNMPCollector._last_results["dev-1"]

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_replay_is_marked_and_the_cache_is_not(self, mock_cmd):
        mock_cmd.side_effect = OK_POLL
        clock = _Clock()
        target = _make_target(interval=300)
        with patch("fivenines_agent.snmp.time", clock):
            fresh = SNMPCollector([target], 1000.0).poll_all()["devices"][0]
            clock.now = 1060
            replay = SNMPCollector([target], 1060.0).poll_all()["devices"][0]
        assert "cached" not in fresh
        assert replay["cached"] is True
        assert {k: v for k, v in replay.items() if k != "cached"} == fresh
        assert "cached" not in SNMPCollector._last_results["dev-1"]

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_poll_is_stamped_with_the_tick_start(self, mock_cmd):
        """Not when the poll finished, not even when SNMP started: the tick
        began at 990, SNMP ran at 1000 and the poll took 10s."""
        clock = _Clock()

        def slow_timeout(cmd, args, timeout):
            clock.now += 10
            return DOWN

        mock_cmd.side_effect = slow_timeout
        with patch("fivenines_agent.snmp.time", clock):
            SNMPCollector([_make_target()], 990.0).poll_all()
            assert SNMPCollector._last_poll_times["dev-1"] == 990.0
            # Without a tick start, the time the batch started.
            clock.now = 2000.0
            SNMPCollector._last_poll_times.clear()
            SNMPCollector([_make_target()]).poll_all()
        assert SNMPCollector._last_poll_times["dev-1"] == 2000.0


class TestBatchDeadline:
    """The 30s batch deadline bounds the tick. Past it a poll still queued
    is cancelled; one already running is kept in flight and reported once
    it finishes, and its device is not polled again meanwhile."""

    def test_executor_timeout_evicts_the_cached_success(self):
        """A poll the batch deadline cuts off evicts the cached success. One
        still queued is cancelled and never runs: left unstamped, still due.
        One already running cannot be stopped: stamped, and kept in flight
        to be reported when it finishes."""
        for did in ("dev-1", "dev-2"):
            SNMPCollector._last_poll_times[did] = 900.0
            SNMPCollector._last_results[did] = {"device_id": did}
        targets = [
            _make_target(device_id="dev-1"),
            _make_target(device_id="dev-2"),
        ]
        executor = _FakeExecutor(running=1)
        with _fake_pool(executor):
            devices = SNMPCollector(targets, 1000.0).poll_all()["devices"]
        assert [d["error"]["message"][:16] for d in devices] == [
            "Executor timeout", "Executor timeout",
        ]
        assert SNMPCollector._last_results == {}
        assert [f.cancelled() for f in executor.futures] == [False, True]
        assert SNMPCollector._last_poll_times == {
            "dev-1": 1000.0, "dev-2": 900.0,
        }
        future, _, started, stuck = SNMPCollector._in_flight["dev-1"]
        assert future is executor.futures[0] and started == 1000.0
        assert stuck is False
        assert list(SNMPCollector._in_flight) == ["dev-1"]
        # The tick never waits on the running poll.
        assert executor.shutdown_args[0] is False

    def test_late_answer_is_reported_once_the_poll_finishes(self):
        """REGRESSION: an outage of 21-30 dead devices on one host ends the
        third 10s round just past the 30s deadline, every tick: the same
        devices only ever reported an (uncounted) executor timeout and
        never reached unreachable. Their answer now arrives a tick late."""
        targets = [
            _make_target(device_id="dev-1"),
            _make_target(device_id="dev-2"),
        ]
        first = _FakeExecutor(running=1)
        with _fake_pool(first):
            SNMPCollector(targets[:1], 1000.0).poll_all()
        first.futures[0].set_result({"device_id": "dev-1", "error": DOWN[1]})
        second = _FakeExecutor(
            poll=lambda t: {"device_id": t["device_id"]}, done=1
        )
        with _fake_pool(second):
            devices = SNMPCollector(targets, 1060.0).poll_all()["devices"]
        assert devices[0] == {"device_id": "dev-1", "error": DOWN[1]}
        assert second.submitted == ["dev-2"]  # dev-1 reported, not re-polled
        assert SNMPCollector._in_flight == {}

    def test_device_still_being_polled_is_not_polled_again(self):
        """Two polls never run against one device at once."""
        target = _make_target(device_id="dev-1")
        first = _FakeExecutor(running=1)
        with _fake_pool(first):
            SNMPCollector([target], 1000.0).poll_all()
        second = _FakeExecutor()
        with _fake_pool(second):
            devices = SNMPCollector([target], 1060.0).poll_all()["devices"]
        assert second.submitted == []
        assert devices == []
        assert SNMPCollector._in_flight["dev-1"][0] is first.futures[0]
        # Finished by the next tick, with nothing else due: still reported.
        first.futures[0].set_result({"device_id": "dev-1", "error": DOWN[1]})
        third = _FakeExecutor()
        with _fake_pool(third):
            devices = SNMPCollector([target], 1120.0).poll_all()["devices"]
        assert devices == [{"device_id": "dev-1", "error": DOWN[1]}]
        assert third.submitted == []

    def test_pending_polls_share_one_batch_deadline(self):
        """The first wait gets the whole budget, the rest what is left: no
        poll gets a fresh 30s once the batch has spent it."""
        clock = _Clock(1000.0)
        waits = []

        def fake_wait(futures, timeout):
            waits.append(timeout)
            clock.now += timeout  # nothing finished: the wait ran out

        targets = [_make_target(device_id="dev-%d" % i) for i in range(3)]
        with patch("fivenines_agent.snmp.time", clock), patch(
            "fivenines_agent.snmp.wait", fake_wait
        ), patch(
            "fivenines_agent.snmp.ThreadPoolExecutor",
            lambda max_workers: _FakeExecutor(),
        ):
            # The tick started 20s earlier: the budget is SNMP's own.
            SNMPCollector(targets, 980.0).poll_all()
        assert waits == [30, 0.0, 0.0]

    def test_no_waiting_on_pending_polls_past_the_deadline(self):
        """Waiting 0.1s more on each pending poll stretched a big batch
        without bound: 1000 dead targets took minutes, past the watchdog."""
        targets = [_make_target(device_id="dev-%d" % i) for i in range(200)]
        started = time.monotonic()
        with _fake_pool(_FakeExecutor()):
            devices = SNMPCollector(targets, 1000.0).poll_all()["devices"]
        assert time.monotonic() - started < 5  # 20s at 0.1s a poll
        assert len(devices) == 200

    def test_oldest_poll_goes_first_so_every_device_gets_its_turn(self):
        """REGRESSION: the server does not count an executor timeout as a
        failure, and the pool always took the targets in config order, so
        in an outage bigger than one batch the same tail was cut off every
        tick and never reached unreachable."""
        targets = [
            _make_target(device_id=d, interval=60)
            for d in ("dev-1", "dev-2", "dev-3", "dev-4")
        ]
        orders = []
        for start in (1000.0, 1060.0, 1120.0, 1180.0):
            executor = _FakeExecutor(
                poll=lambda t: {"device_id": t["device_id"], "error": DOWN[1]},
                done=2,
            )
            with _fake_pool(executor):
                SNMPCollector(targets, start).poll_all()
            orders.append(executor.submitted)
        assert orders == [
            ["dev-1", "dev-2", "dev-3", "dev-4"],
            ["dev-3", "dev-4", "dev-1", "dev-2"],
            ["dev-1", "dev-2", "dev-3", "dev-4"],
            ["dev-3", "dev-4", "dev-1", "dev-2"],
        ]

    def test_late_success_is_reported_once_without_its_counters(self):
        """Its counters were read a tick or more before this tick's ts,
        which the server stamps them with: sent, they would skew rates."""
        target = _make_target(interval=300)
        first = _FakeExecutor(running=1)
        with _fake_pool(first):
            SNMPCollector([target], 1000.0).poll_all()
        answer = {
            "device_id": "dev-1",
            "system": {"sys_uptime": 42},
            "interfaces": [{"if_index": 1}],
            "interface_metrics": [{"if_index": 1, "bytes_in": 7}],
            "custom_metrics": [{"name": "cpu", "value": 3}],
        }
        first.futures[0].set_result(answer)
        with _fake_pool(_FakeExecutor()):
            devices = SNMPCollector([target], 1060.0).poll_all()["devices"]
        late = {
            "device_id": "dev-1",
            "system": {"sys_uptime": 42},
            "interfaces": [{"if_index": 1}],
        }
        assert devices == [late]
        with _fake_pool(_FakeExecutor()):
            devices = SNMPCollector([target], 1120.0).poll_all()["devices"]
        assert devices == [dict(late, cached=True)]

    def test_late_poll_that_raised_is_an_error_entry(self):
        targets = [
            _make_target(device_id="dev-1"),
            _make_target(device_id="dev-2"),
        ]
        first = _FakeExecutor(running=1)
        with _fake_pool(first):
            SNMPCollector(targets[:1], 1000.0).poll_all()
        first.futures[0].set_exception(RuntimeError("boom"))
        second = _FakeExecutor(
            poll=lambda t: {"device_id": t["device_id"]}, done=1
        )
        with _fake_pool(second):
            devices = SNMPCollector(targets, 1060.0).poll_all()["devices"]
        assert devices[0]["error"] == {"type": "unknown", "message": "boom"}
        assert devices[1] == {"device_id": "dev-2"}

    def test_stuck_poll_is_a_counted_failure_every_tick(self):
        """An snmpget in uninterruptible sleep outlives its own timeouts:
        the device must still reach unreachable, without a second poll."""
        target = _make_target()
        first = _FakeExecutor(running=1)
        with _fake_pool(first):
            SNMPCollector([target], 1000.0).poll_all()
        for start in (1120.0, 1179.0):
            with _fake_pool(_FakeExecutor()):
                devices = SNMPCollector([target], start).poll_all()["devices"]
            assert devices == []  # younger than IN_FLIGHT_LIMIT
        for start in (1180.0, 1240.0, 1300.0):
            executor = _FakeExecutor()
            with _fake_pool(executor):
                devices = SNMPCollector([target], start).poll_all()["devices"]
            assert [d["error"]["message"] for d in devices] == [
                "SNMP poll still running after 180s"
            ]
            assert executor.submitted == []

    def test_poll_finishing_as_it_is_cancelled_is_read(self):
        """Running at the deadline, done a moment later: cancel() fails
        and the answer, already there, is read rather than kept in
        flight."""

        class _FinishesAtCancel(Future):
            def cancel(self):
                self.set_result({"device_id": "dev-1"})
                return False

        class _Pool(_FakeExecutor):
            def submit(self, fn, target, *args):
                future = _FinishesAtCancel()
                future.set_running_or_notify_cancel()
                return future

        with _fake_pool(_Pool()):
            devices = SNMPCollector([_make_target()], 1000.0).poll_all()[
                "devices"
            ]
        assert devices == [{"device_id": "dev-1"}]
        assert SNMPCollector._in_flight == {}

    def test_late_answer_after_a_long_tick_is_not_stuck(self):
        """With ticks 180s+ apart, a poll that finished just after its
        deadline is late, not stuck: its answer is reported, and its device
        waits for its interval."""
        target = _make_target(interval=3600)
        first = _FakeExecutor(running=1)
        with _fake_pool(first):
            SNMPCollector([target], 1000.0).poll_all()
        first.futures[0].set_result({"device_id": "dev-1", "error": DOWN[1]})
        second = _FakeExecutor()
        with _fake_pool(second):
            devices = SNMPCollector([target], 1300.0).poll_all()["devices"]
        assert devices == [{"device_id": "dev-1", "error": DOWN[1]}]
        assert second.submitted == []
        assert SNMPCollector._last_poll_times == {"dev-1": 1000.0}

    def test_submit_failure_keeps_the_polls_already_submitted(self):
        """Out of threads mid-batch, with a real pool: what was submitted is
        still read, the rest stays unstamped, and the poll a failed submit()
        had already queued never runs (an idle worker would take it)."""
        import threading as real_threading

        starts = []
        start = real_threading.Thread.start
        orphan_queued = real_threading.Event()

        def start_once(thread):
            starts.append(thread)
            if len(starts) > 1:
                orphan_queued.set()  # submit() queued its work first
                raise RuntimeError("can't start new thread")
            start(thread)

        ran = []

        def poll(target):
            ran.append(target["device_id"])
            if target["device_id"] == "dev-1":
                # Busy until the orphan is queued, so the second submit()
                # must start a thread; then free to pick the orphan up.
                orphan_queued.wait(5)
            return {"device_id": target["device_id"]}

        targets = [_make_target(device_id=d) for d in ("dev-1", "dev-2", "dev-3")]
        with patch.object(real_threading.Thread, "start", start_once), patch.object(
            SNMPCollector, "_poll_device", side_effect=poll
        ):
            devices = SNMPCollector(targets, 1000.0).poll_all()["devices"]
            time.sleep(0.3)  # the worker has taken the orphan by now
        assert devices == [{"device_id": "dev-1"}]
        assert ran == ["dev-1"]
        assert SNMPCollector._last_poll_times == {"dev-1": 1000.0}

    def test_any_submit_error_decides_the_ticket(self):
        """An undecided ticket would block a worker, and the agent's exit
        (which joins pool threads), forever."""
        tickets = []

        class _Raises(_FakeExecutor):
            def submit(self, fn, target, ticket):
                tickets.append(ticket)
                raise MemoryError()

        with _fake_pool(_Raises()):
            devices = SNMPCollector([_make_target()], 1000.0).poll_all()[
                "devices"
            ]
        assert devices == []
        # Checked without waiting: an undecided ticket must fail, not hang.
        assert [(t._decided.is_set(), t.accepted) for t in tickets] == [
            (True, False)
        ]

    @pytest.mark.parametrize("error", [RuntimeError, MemoryError])
    def test_submit_failure_ends_the_batch(self, error):
        """The first failed submit() ends it: out of threads or memory, the
        next ones would only queue more work that never polls. The polls
        already submitted are still read, not left running untracked."""

        class _FailsOnce(_FakeExecutor):
            def submit(self, fn, target, *args):
                self.attempts = getattr(self, "attempts", 0) + 1
                if self.attempts == 2:
                    raise error("no resources")
                return super().submit(fn, target, *args)

        targets = [_make_target(device_id=d) for d in ("dev-1", "dev-2", "dev-3")]
        executor = _FailsOnce(poll=lambda t: {"device_id": t["device_id"]}, done=3)
        with _fake_pool(executor):
            devices = SNMPCollector(targets, 1000.0).poll_all()["devices"]
        assert executor.submitted == ["dev-1"]
        assert devices == [{"device_id": "dev-1"}]

    def test_answer_of_a_stuck_poll_is_dropped(self):
        """REGRESSION: after counted "still running" failures, the stuck
        poll's own success would read as a recovery on the server. Recovery
        needs a fresh poll, made at once."""
        target = _make_target(interval=3600)
        first = _FakeExecutor(running=1)
        with _fake_pool(first):
            SNMPCollector([target], 1000.0).poll_all()
        with _fake_pool(_FakeExecutor()):
            stuck = SNMPCollector([target], 1180.0).poll_all()["devices"]
        assert stuck[0]["error"]["message"].startswith("SNMP poll still")
        first.futures[0].set_result({"device_id": "dev-1", "system": {}})
        fresh = _FakeExecutor(
            poll=lambda t: {"device_id": t["device_id"], "error": DOWN[1]},
            done=1,
        )
        with _fake_pool(fresh):
            devices = SNMPCollector([target], 1240.0).poll_all()["devices"]
        assert fresh.submitted == ["dev-1"]
        assert devices == [{"device_id": "dev-1", "error": DOWN[1]}]


class TestPollingKey:
    """A change to what a target polls (POLLING_FIELDS) is a new target:
    polled at once, never answered with the old target's result."""

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_changed_polling_config_is_polled_at_once(self, mock_cmd):
        """REGRESSION: re-addressed, a device replayed its OLD address's last
        success until its interval ran out, up to an hour."""
        mock_cmd.side_effect = OK_POLL + [DOWN]
        old = _make_target(interval=3600)
        new = _make_target(interval=3600, ip="192.168.1.99")
        first = SNMPCollector([old], 1000.0).poll_all()["devices"]
        second = SNMPCollector([new], 1060.0).poll_all()["devices"]
        assert _outcome(first) == "ok"
        assert _outcome(second) == "error"
        assert "192.168.1.99" in mock_cmd.call_args_list[-1].args[1]
        assert "dev-1" not in SNMPCollector._last_results
        # Then back to its interval: not polled again on the next tick.
        third = SNMPCollector([new], 1120.0).poll_all()["devices"]
        assert _outcome(third) is None
        assert mock_cmd.call_count == 4

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_field_the_poll_does_not_read_is_not_a_config_change(
        self, mock_cmd
    ):
        """Only POLLING_FIELDS count: a field the server adds later, or one
        that changes every tick, must not reset the interval."""
        mock_cmd.side_effect = OK_POLL
        SNMPCollector([_make_target(interval=3600)], 1000.0).poll_all()
        target = _make_target(interval=3600, name="renamed")
        devices = SNMPCollector([target], 1060.0).poll_all()["devices"]
        assert _outcome(devices) == "cached"

    def test_polling_key_holds_no_credentials(self):
        target = _make_v3_target()
        with patch.object(SNMPCollector, "_poll_device", return_value={}):
            SNMPCollector([target], 1000.0).poll_all()
        key = SNMPCollector._polling_keys["dev-v3"]
        assert len(key) == 64 and int(key, 16) >= 0  # a SHA-256 digest

    def test_absent_and_null_field_are_different_targets(self):
        """An absent community polls as "public", a null one does not."""
        assert _polling_key({"ip": "a"}) != _polling_key(
            {"ip": "a", "community": None}
        )

    @pytest.mark.parametrize(
        "field, value",
        [
            ("ip", "192.168.1.99"),
            ("port", 1161),
            ("version", "v3"),
            ("community", "private"),
            ("username", "other"),
            ("security_level", "auth_priv"),
            ("auth_protocol", "md5"),
            ("auth_password", "new-auth"),
            ("priv_protocol", "des"),
            ("priv_password", "new-priv"),
            ("capabilities", ["system"]),
            ("custom_oids", [{"name": "x", "oid": "1.3.6.1.2.1.1.7.0"}]),
        ],
    )
    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_every_polling_field_change_is_polled_at_once(
        self, mock_cmd, field, value
    ):
        """Hard-coded, not read from POLLING_FIELDS: dropping a field from
        the tuple must fail its case here."""
        mock_cmd.side_effect = OK_POLL + [DOWN]
        SNMPCollector([_make_target(interval=3600)], 1000.0).poll_all()
        changed = dict(_make_target(interval=3600), **{field: value})
        devices = SNMPCollector([changed], 1060.0).poll_all()["devices"]
        assert _outcome(devices) == "error"

    def test_unserializable_target_does_not_raise(self):
        """A hostile nesting depth must not null SNMP for every device, and
        with no key to compare, a change of address behind it could not be
        seen: such a target is never replayed."""
        nested = []
        for _ in range(100000):
            nested = [nested]
        target = _make_target(interval=3600, custom_oids=nested)
        answer = {"device_id": "dev-1", "system": {"sys_name": "old"}}
        with patch.object(SNMPCollector, "_poll_device", return_value=answer):
            first = SNMPCollector([target], 1000.0).poll_all()["devices"]
            second = SNMPCollector([target], 1060.0).poll_all()["devices"]
        assert SNMPCollector._polling_keys["dev-1"] is None
        assert first == [answer]
        assert second == []

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_interval_change_alone_keeps_the_device_state(self, mock_cmd):
        """The interval only decides when: changing it is not a new target."""
        mock_cmd.side_effect = OK_POLL
        SNMPCollector([_make_target(interval=3600)], 1000.0).poll_all()
        target = _make_target(interval=1800)
        devices = SNMPCollector([target], 1060.0).poll_all()["devices"]
        assert _outcome(devices) == "cached"

    def test_config_change_waits_for_the_running_poll_then_drops_it(self):
        """The old target's poll keeps the device busy until it ends, then
        its answer is dropped and the new target is polled."""
        first = _FakeExecutor(running=1)
        with _fake_pool(first):
            SNMPCollector([_make_target()], 1000.0).poll_all()
        new = _make_target(ip="192.168.1.99")
        second = _FakeExecutor()
        with _fake_pool(second):
            SNMPCollector([new], 1060.0).poll_all()
        assert second.submitted == []  # never two polls at once
        first.futures[0].set_result({"device_id": "dev-1"})
        third = _FakeExecutor(
            poll=lambda t: {"device_id": t["device_id"], "error": DOWN[1]},
            done=1,
        )
        with _fake_pool(third):
            devices = SNMPCollector([new], 1120.0).poll_all()["devices"]
        assert third.submitted == ["dev-1"]
        assert devices == [{"device_id": "dev-1", "error": DOWN[1]}]

    def test_in_flight_answer_of_a_target_without_key_is_dropped(self):
        """With no key, a change of address behind it cannot be seen: the
        answer is not reported and the device is polled afresh."""
        nested = []
        for _ in range(100000):
            nested = [nested]
        target = _make_target(custom_oids=nested)
        first = _FakeExecutor(running=1)
        with _fake_pool(first):
            SNMPCollector([target], 1000.0).poll_all()
        first.futures[0].set_result({"device_id": "dev-1", "system": {}})
        second = _FakeExecutor()
        with _fake_pool(second):
            devices = SNMPCollector([target], 1060.0).poll_all()["devices"]
        assert second.submitted == ["dev-1"]
        assert {"device_id": "dev-1", "system": {}} not in devices

    def test_target_that_gets_a_key_is_polled_at_once(self):
        nested = []
        for _ in range(100000):
            nested = [nested]
        with patch.object(SNMPCollector, "_poll_device", return_value={}):
            SNMPCollector(
                [_make_target(interval=3600, custom_oids=nested)], 1000.0
            ).poll_all()
        executor = _FakeExecutor()
        with _fake_pool(executor):
            SNMPCollector(
                [_make_target(interval=3600, ip="192.168.1.99")], 1060.0
            ).poll_all()
        assert executor.submitted == ["dev-1"]

    def test_key_ignores_the_order_of_keys_in_a_dict(self):
        assert _polling_key(
            {"custom_oids": [{"name": "x", "oid": "1.3"}]}
        ) == _polling_key({"custom_oids": [{"oid": "1.3", "name": "x"}]})


# ================================================================
# Tests for _print_diagnostics()
# ================================================================


class TestPrintDiagnostics:
    def test_successful_device(self, capsys):
        devices = [
            {
                "device_id": "dev-1",
                "system": {"sys_name": "Switch1"},
                "interfaces": [{"if_index": 1}, {"if_index": 2}],
            }
        ]
        _print_diagnostics(devices)
        out = capsys.readouterr().out
        assert "SNMP Targets:" in out
        assert "Switch1" in out
        assert "2 interfaces" in out
        assert "OK" in out

    def test_timeout_device(self, capsys):
        devices = [
            {
                "device_id": "dev-1",
                "error": {"type": "timeout", "message": "No Response"},
            }
        ]
        _print_diagnostics(devices)
        out = capsys.readouterr().out
        assert "TIMEOUT" in out

    def test_auth_error_device(self, capsys):
        devices = [
            {
                "device_id": "dev-1",
                "error": {"type": "auth_error", "message": "bad creds"},
            }
        ]
        _print_diagnostics(devices)
        out = capsys.readouterr().out
        assert "AUTH ERROR" in out

    def test_generic_error(self, capsys):
        devices = [
            {
                "device_id": "dev-1",
                "error": {"type": "unknown", "message": "something broke"},
            }
        ]
        _print_diagnostics(devices)
        out = capsys.readouterr().out
        assert "UNKNOWN" in out


# ================================================================
# Tests for _parse_table()
# ================================================================


class TestParseTable:
    def test_iftable_parsing(self):
        collector = SNMPCollector([_make_target()])
        interfaces = {}
        counters = {}
        hc_supported = collector._parse_table(
            IFTABLE_OUTPUT, IF_TABLE_PREFIX, IFTABLE_COLUMNS,
            interfaces, counters, None
        )
        assert hc_supported is True
        assert 1 in interfaces
        assert 2 in interfaces
        assert interfaces[1]["if_type"] == 6
        assert counters[1]["bytes_in"] == 1000000
        assert counters[2]["bytes_out"] == 600000

    def test_ifxtable_parsing(self):
        collector = SNMPCollector([_make_target()])
        interfaces = {1: {"if_index": 1}, 2: {"if_index": 2}}
        counters = {1: {"if_index": 1}, 2: {"if_index": 2}}
        hc_data = {}
        hc_supported = collector._parse_table(
            IFXTABLE_OUTPUT, IF_XTABLE_PREFIX, IFXTABLE_COLUMNS,
            interfaces, counters, hc_data
        )
        assert hc_supported is True
        assert interfaces[1]["if_name"] == "GigabitEthernet0/1"
        assert interfaces[1]["if_speed"] == 1000000000
        assert hc_data[1]["bytes_in"] == 9000000000
        assert counters[1]["broadcast_in"] == 100

    def test_nosuch_disables_hc(self):
        collector = SNMPCollector([_make_target()])
        interfaces = {}
        counters = {}
        hc_data = {}
        hc_supported = collector._parse_table(
            IFXTABLE_NO_SUPPORT, IF_XTABLE_PREFIX, IFXTABLE_COLUMNS,
            interfaces, counters, hc_data
        )
        assert hc_supported is False
        assert len(hc_data) == 0

    def test_malformed_suffix_skipped(self):
        bad_output = ".1.3.6.1.2.1.2.2.1 = INTEGER: 1\n"
        collector = SNMPCollector([_make_target()])
        interfaces = {}
        counters = {}
        collector._parse_table(
            bad_output, IF_TABLE_PREFIX, IFTABLE_COLUMNS,
            interfaces, counters, None
        )
        assert len(interfaces) == 0

    def test_unknown_column_skipped(self):
        output = ".1.3.6.1.2.1.2.2.1.99.1 = INTEGER: 42\n"
        collector = SNMPCollector([_make_target()])
        interfaces = {}
        counters = {}
        collector._parse_table(
            output, IF_TABLE_PREFIX, IFTABLE_COLUMNS,
            interfaces, counters, None
        )
        assert len(interfaces) == 0
        assert len(counters) == 0

    def test_invalid_value_skipped(self):
        output = ".1.3.6.1.2.1.2.2.1.10.1 = STRING: \"not_a_number\"\n"
        collector = SNMPCollector([_make_target()])
        interfaces = {}
        counters = {}
        collector._parse_table(
            output, IF_TABLE_PREFIX, IFTABLE_COLUMNS,
            interfaces, counters, None
        )
        assert len(counters) == 0

    def test_hc_data_none_skips_hc(self):
        """When hc_data is None, HC bucket entries are ignored."""
        collector = SNMPCollector([_make_target()])
        interfaces = {1: {"if_index": 1}}
        counters = {1: {"if_index": 1}}
        collector._parse_table(
            IFXTABLE_OUTPUT, IF_XTABLE_PREFIX, IFXTABLE_COLUMNS,
            interfaces, counters, None  # hc_data=None
        )
        # HC fields should not appear in counters
        assert "bytes_in" not in counters[1] or counters[1]["bytes_in"] != 9000000000


# ================================================================
# Tests for constants and configuration
# ================================================================


class TestConstants:
    def test_iftable_columns_complete(self):
        """All expected ifTable columns are mapped."""
        expected = {"1", "3", "7", "8", "10", "11", "13", "14",
                    "16", "17", "19", "20"}
        assert set(IFTABLE_COLUMNS.keys()) == expected

    def test_ifxtable_columns_complete(self):
        """All expected ifXTable columns are mapped."""
        expected = {"1", "3", "5", "6", "10", "15", "18"}
        assert set(IFXTABLE_COLUMNS.keys()) == expected

    def test_admin_status_conversion(self):
        """Admin/oper status should be 0-indexed (subtract 1)."""
        converter = IFTABLE_COLUMNS["7"][2]
        assert converter("1") == 0  # up
        assert converter("2") == 1  # down
        assert converter("3") == 2  # testing

    def test_if_speed_conversion(self):
        """ifHighSpeed is in Mbps, convert to bps."""
        converter = IFXTABLE_COLUMNS["15"][2]
        assert converter("1000") == 1000000000
        assert converter("100") == 100000000

    def test_settings(self):
        assert SNMP_TIMEOUT == 5
        assert SNMP_RETRIES == 1
        assert EXECUTOR_TIMEOUT == 30
        assert MAX_WORKERS == 10


# ================================================================
# Tests for edge cases (coverage gaps)
# ================================================================


class TestEdgeCases:
    def test_init_creates_class_attrs(self):
        """First SNMPCollector creates class-level dicts."""
        # Remove class attrs to test the hasattr branches
        if hasattr(SNMPCollector, "_last_poll_times"):
            del SNMPCollector._last_poll_times
        if hasattr(SNMPCollector, "_last_results"):
            del SNMPCollector._last_results
        del SNMPCollector._polling_keys
        del SNMPCollector._in_flight
        collector = SNMPCollector([_make_target()])
        assert hasattr(SNMPCollector, "_last_poll_times")
        assert hasattr(SNMPCollector, "_last_results")
        assert SNMPCollector._polling_keys == {}
        assert SNMPCollector._in_flight == {}

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_executor_timeout(self, mock_cmd):
        """Executor timeout when _poll_device takes too long."""
        import fivenines_agent.snmp as snmp_mod

        original_timeout = snmp_mod.EXECUTOR_TIMEOUT
        snmp_mod.EXECUTOR_TIMEOUT = 0.01  # Force immediate timeout

        def slow_poll(*args, **kwargs):
            import time
            time.sleep(1)
            return {"device_id": "dev-1"}

        target = _make_target()
        collector = SNMPCollector([target])
        with patch.object(collector, "_poll_device", side_effect=slow_poll):
            result = collector.poll_all()

        snmp_mod.EXECUTOR_TIMEOUT = original_timeout
        assert len(result["devices"]) == 1
        assert result["devices"][0]["error"]["type"] == "timeout"
        assert "Executor timeout" in result["devices"][0]["error"]["message"]

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_executor_unexpected_exception(self, mock_cmd):
        """Unexpected exception from _poll_device."""
        target = _make_target()
        collector = SNMPCollector([target])
        with patch.object(
            collector, "_poll_device",
            side_effect=RuntimeError("boom")
        ):
            result = collector.poll_all()
        assert result["devices"][0]["error"]["type"] == "unknown"
        assert "boom" in result["devices"][0]["error"]["message"]

    @patch("fivenines_agent.snmp.ThreadPoolExecutor")
    def test_executor_creation_failure(self, mock_executor_cls):
        """ThreadPoolExecutor constructor raises."""
        mock_executor_cls.side_effect = RuntimeError("no threads")
        target = _make_target()
        collector = SNMPCollector([target])
        result = collector.poll_all()
        assert result["devices"] == []

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_poll_device_interface_error(self, mock_cmd):
        """Interface poll error returns error dict."""
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (None, {"type": "timeout", "message": "No Response"}),
        ]
        target = _make_target()
        collector = SNMPCollector([target])
        result = collector._poll_device(target)
        assert result["error"]["type"] == "timeout"

    def test_parse_table_invalid_if_index(self):
        """Non-numeric ifIndex should be skipped."""
        output = ".1.3.6.1.2.1.2.2.1.1.abc = INTEGER: 1\n"
        collector = SNMPCollector([_make_target()])
        interfaces = {}
        counters = {}
        collector._parse_table(
            output, IF_TABLE_PREFIX, IFTABLE_COLUMNS,
            interfaces, counters, None
        )
        assert len(interfaces) == 0

    def test_parse_table_oid_outside_prefix(self):
        """OIDs not starting with prefix should be skipped."""
        output = ".1.3.6.1.2.1.99.1.1.1 = INTEGER: 42\n"
        collector = SNMPCollector([_make_target()])
        interfaces = {}
        counters = {}
        collector._parse_table(
            output, IF_TABLE_PREFIX, IFTABLE_COLUMNS,
            interfaces, counters, None
        )
        assert len(interfaces) == 0

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_poll_system_nosuch_lines_skipped(self, mock_cmd):
        """noSuch lines in system output should be skipped."""
        output = (
            '.1.3.6.1.2.1.1.5.0 = STRING: "Switch"\n'
            ".1.3.6.1.2.1.1.1.0 = No Such Object\n"
            ".1.3.6.1.2.1.1.3.0 = Timeticks: (100) 0:00:01.00\n"
        )
        mock_cmd.return_value = (output, None)
        collector = SNMPCollector([_make_target()])
        system, error = collector._poll_system([])
        assert error is None
        assert system["sys_name"] == "Switch"
        assert "sys_descr" not in system
        assert system["sys_uptime"] == 1000

    def test_parse_table_empty_lines_skipped(self):
        """Empty lines in walk output should be skipped."""
        output = "\n.1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1\n\n"
        collector = SNMPCollector([_make_target()])
        interfaces = {}
        counters = {}
        collector._parse_table(
            output, IF_TABLE_PREFIX, IFTABLE_COLUMNS,
            interfaces, counters, None
        )
        assert len(interfaces) == 1

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_custom_oids_success(self, mock_cmd):
        """Custom OIDs are polled and returned."""
        custom_output = (
            '.1.3.6.1.4.1.9.9.109.1.1.1.1.8.1 = Gauge32: 42\n'
            '.1.3.6.1.4.1.9.9.48.1.1.1.5.1 = Gauge32: 1048576\n'
        )
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
            (custom_output, None),
        ]
        target = _make_target(
            custom_oids=[
                {
                    "name": "cpu_usage",
                    "oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
                    "type": "gauge",
                },
                {
                    "name": "memory_free",
                    "oid": "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
                    "type": "gauge",
                },
            ]
        )
        collector = SNMPCollector([target])
        result = collector._poll_device(target)
        assert "custom_metrics" in result
        assert len(result["custom_metrics"]) == 2
        cpu = next(m for m in result["custom_metrics"]
                   if m["name"] == "cpu_usage")
        assert cpu["value"] == 42
        mem = next(m for m in result["custom_metrics"]
                   if m["name"] == "memory_free")
        assert mem["value"] == 1048576

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_custom_oids_string_type(self, mock_cmd):
        """String-type custom OIDs return string values."""
        custom_output = (
            '.1.3.6.1.4.1.9.9.1.0 = STRING: "IOS 15.2"\n'
        )
        mock_cmd.return_value = (custom_output, None)
        collector = SNMPCollector([_make_target()])
        metrics, error = collector._poll_custom_oids(
            ["-v2c", "-c", "public", "host"],
            [{"name": "firmware", "oid": "1.3.6.1.4.1.9.9.1.0",
              "type": "string"}],
        )
        assert error is None
        assert metrics[0]["value"] == "IOS 15.2"

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_custom_oids_error_nonfatal(self, mock_cmd):
        """Custom OID errors don't fail the whole device poll."""
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
            (None, {"type": "timeout", "message": "No Response"}),
        ]
        target = _make_target(
            custom_oids=[
                {"name": "cpu", "oid": "1.3.6.1.4.1.9.1.0",
                 "type": "gauge"},
            ]
        )
        collector = SNMPCollector([target])
        result = collector._poll_device(target)
        assert "error" not in result  # device poll succeeds
        assert "custom_metrics_error" in result
        assert result["custom_metrics_error"]["type"] == "timeout"
        assert "system" in result  # other data still present

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_custom_oids_empty_list(self, mock_cmd):
        """Empty custom_oids list should not trigger extra snmpget."""
        mock_cmd.side_effect = [
            (SYSTEM_OUTPUT, None),
            (IFTABLE_OUTPUT, None),
            (IFXTABLE_OUTPUT, None),
        ]
        target = _make_target(custom_oids=[])
        collector = SNMPCollector([target])
        result = collector._poll_device(target)
        assert "custom_metrics" not in result
        assert mock_cmd.call_count == 3  # system + ifTable + ifXTable

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_custom_oids_nosuch_skipped(self, mock_cmd):
        """OIDs returning noSuch should be skipped."""
        custom_output = (
            ".1.3.6.1.4.1.9.1.0 = No Such Object\n"
            ".1.3.6.1.4.1.9.2.0 = Gauge32: 99\n"
        )
        mock_cmd.return_value = (custom_output, None)
        collector = SNMPCollector([_make_target()])
        metrics, error = collector._poll_custom_oids(
            [],
            [
                {"name": "missing", "oid": "1.3.6.1.4.1.9.1.0",
                 "type": "gauge"},
                {"name": "present", "oid": "1.3.6.1.4.1.9.2.0",
                 "type": "gauge"},
            ],
        )
        assert error is None
        assert len(metrics) == 1
        assert metrics[0]["name"] == "present"
        assert metrics[0]["value"] == 99

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_custom_oids_float_value(self, mock_cmd):
        """Non-integer numeric values should parse as float."""
        custom_output = '.1.3.6.1.4.1.9.1.0 = STRING: "42.5"\n'
        mock_cmd.return_value = (custom_output, None)
        collector = SNMPCollector([_make_target()])
        metrics, error = collector._poll_custom_oids(
            [],
            [{"name": "temp", "oid": "1.3.6.1.4.1.9.1.0",
              "type": "gauge"}],
        )
        assert metrics[0]["value"] == 42.5

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_custom_oids_default_type_gauge(self, mock_cmd):
        """Missing type field defaults to gauge (numeric)."""
        custom_output = '.1.3.6.1.4.1.9.1.0 = Gauge32: 77\n'
        mock_cmd.return_value = (custom_output, None)
        collector = SNMPCollector([_make_target()])
        metrics, error = collector._poll_custom_oids(
            [],
            [{"name": "val", "oid": "1.3.6.1.4.1.9.1.0"}],
        )
        assert metrics[0]["value"] == 77

    @patch("fivenines_agent.snmp._run_snmp_cmd")
    def test_custom_oids_unparseable_value(self, mock_cmd):
        """Non-numeric gauge values fall back to string."""
        custom_output = '.1.3.6.1.4.1.9.1.0 = STRING: "not_a_number"\n'
        mock_cmd.return_value = (custom_output, None)
        collector = SNMPCollector([_make_target()])
        metrics, error = collector._poll_custom_oids(
            [],
            [{"name": "val", "oid": "1.3.6.1.4.1.9.1.0",
              "type": "gauge"}],
        )
        assert metrics[0]["value"] == "not_a_number"

    def test_parse_table_nosuch_in_middle(self):
        """noSuch in middle of walk should disable HC but keep parsing."""
        output = (
            ".1.3.6.1.2.1.31.1.1.1.1.1 = STRING: \"eth0\"\n"
            ".1.3.6.1.2.1.31.1.1.1.6.1 = No Such Object\n"
            ".1.3.6.1.2.1.31.1.1.1.18.1 = STRING: \"Uplink\"\n"
        )
        collector = SNMPCollector([_make_target()])
        interfaces = {1: {"if_index": 1}}
        counters = {}
        hc_data = {}
        hc_supported = collector._parse_table(
            output, IF_XTABLE_PREFIX, IFXTABLE_COLUMNS,
            interfaces, counters, hc_data
        )
        assert hc_supported is False
        assert interfaces[1]["if_name"] == "eth0"
        assert interfaces[1]["if_alias"] == "Uplink"
        assert len(hc_data) == 0
