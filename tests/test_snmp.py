"""Tests for SNMP network device polling collector (subprocess-based)."""

import subprocess
import time
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
    yield
    SNMPCollector._last_poll_times = {}
    SNMPCollector._last_results = {}


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
        """Devices not yet due for polling should return cached results."""
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
        collector = SNMPCollector([_make_target()])
        assert hasattr(SNMPCollector, "_last_poll_times")
        assert hasattr(SNMPCollector, "_last_results")

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
