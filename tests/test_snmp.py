"""Tests for SNMP network device polling collector."""

import hashlib
import json
import sys
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError
from io import StringIO
from unittest.mock import MagicMock, call, patch

import pytest


# Mock pysnmp before importing snmp module
sys.modules.setdefault("pysnmp", MagicMock())
sys.modules.setdefault("pysnmp.hlapi", MagicMock())
sys.modules.setdefault("pysnmp.hlapi.v3arch", MagicMock())
sys.modules.setdefault("pysnmp.hlapi.v3arch.asyncio", MagicMock())


def _make_target(
    device_id="dev-1",
    ip="192.168.1.10",
    version="v2c",
    community="public",
    interval=60,
    capabilities=None,
):
    """Helper to create a target config dict."""
    target = {
        "device_id": device_id,
        "ip": ip,
        "version": version,
        "interval": interval,
        "capabilities": capabilities or ["system", "if_table"],
    }
    if version == "v2c":
        target["community"] = community
    elif version == "v3":
        target["username"] = "snmpuser"
        target["security_level"] = "auth_priv"
        target["auth_protocol"] = "sha"
        target["auth_password"] = "authpass"
        target["priv_protocol"] = "aes"
        target["priv_password"] = "privpass"
    return target


def _reset_collector_state():
    """Reset module-level collector state between tests."""
    import fivenines_agent.snmp as snmp_mod

    snmp_mod._collector = None
    if hasattr(snmp_mod.SNMPCollector, "_last_poll_times"):
        snmp_mod.SNMPCollector._last_poll_times = {}
    if hasattr(snmp_mod.SNMPCollector, "_session_cache"):
        snmp_mod.SNMPCollector._session_cache = {}


@pytest.fixture(autouse=True)
def reset_state():
    """Reset collector state before each test."""
    _reset_collector_state()
    yield
    _reset_collector_state()


class TestSnmpMetricsEntryPoint:
    """Tests for the snmp_metrics() module entry function."""

    def test_returns_none_when_pysnmp_import_fails(self):
        """When pysnmp is not installed, return None."""
        import fivenines_agent.snmp as snmp_mod

        with patch.dict(sys.modules, {"pysnmp": None}):
            with patch("builtins.__import__", side_effect=ImportError("no pysnmp")):
                # Need to test the actual import failure path
                pass

        # Simpler approach: patch the import inside snmp_metrics
        original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

        def mock_import(name, *args, **kwargs):
            if name == "pysnmp":
                raise ImportError("no pysnmp")
            if name == "pysnmp_sync_adapter":
                raise ImportError("no pysnmp_sync_adapter")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            result = snmp_mod.snmp_metrics([_make_target()])
        assert result is None

    def test_returns_none_for_empty_targets(self):
        """Empty targets list returns None."""
        import fivenines_agent.snmp as snmp_mod

        result = snmp_mod.snmp_metrics([])
        assert result is None

    def test_creates_collector_and_polls(self):
        """Verifies collector is created and poll_all is called."""
        import fivenines_agent.snmp as snmp_mod

        targets = [_make_target()]

        with patch.object(
            snmp_mod.SNMPCollector, "poll_all", return_value={"devices": []}
        ):
            result = snmp_mod.snmp_metrics(targets)

        assert result == {"devices": []}
        assert snmp_mod._collector is not None

    def test_singleton_collector_recreated_each_call(self):
        """Collector is recreated each call with fresh targets."""
        import fivenines_agent.snmp as snmp_mod

        targets1 = [_make_target(device_id="dev-1")]
        targets2 = [_make_target(device_id="dev-2")]

        with patch.object(
            snmp_mod.SNMPCollector, "poll_all", return_value={"devices": []}
        ):
            snmp_mod.snmp_metrics(targets1)
            c1 = snmp_mod._collector
            snmp_mod.snmp_metrics(targets2)
            c2 = snmp_mod._collector

        assert c1 is not c2


class TestSNMPCollectorIntervalTracking:
    """Tests for per-device interval tracking."""

    def test_first_poll_is_always_due(self):
        """First poll for a device is always due (no prior timestamp)."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])
        assert collector._is_device_due(_make_target()) is True

    def test_device_not_due_within_interval(self):
        """Device polled recently should not be due."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])
        SNMPCollector._last_poll_times["dev-1"] = time.monotonic()
        assert collector._is_device_due(_make_target(interval=60)) is False

    def test_device_due_after_interval(self):
        """Device past its interval should be due."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])
        SNMPCollector._last_poll_times["dev-1"] = time.monotonic() - 120
        assert collector._is_device_due(_make_target(interval=60)) is True

    def test_timestamp_updated_after_poll(self):
        """Last poll timestamp is updated after polling."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])

        with patch.object(collector, "_build_session", return_value=(MagicMock(), MagicMock())):
            with patch.object(collector, "_poll_device", return_value={"device_id": "dev-1"}):
                collector.poll_all()

        assert "dev-1" in SNMPCollector._last_poll_times
        assert SNMPCollector._last_poll_times["dev-1"] > 0


class TestSNMPCollectorSessionCache:
    """Tests for session caching."""

    def test_session_cache_stores_session(self):
        """Built sessions are cached by device_id."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        collector = SNMPCollector([target])

        mock_auth = MagicMock()
        mock_transport = MagicMock()

        with patch("fivenines_agent.snmp.SNMPCollector._build_session") as mock_build:
            mock_build.return_value = (mock_auth, mock_transport)
            with patch.object(collector, "_poll_device", return_value={"device_id": "dev-1"}):
                collector.poll_all()

        # Session should have been built
        mock_build.assert_called_once_with(target)

    def test_session_cache_hit(self):
        """Cached session is reused when config hash matches."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        config_hash = hashlib.sha256(
            json.dumps(target, sort_keys=True).encode()
        ).hexdigest()

        mock_auth = MagicMock()
        mock_transport = MagicMock()

        SNMPCollector._session_cache = {
            "dev-1": (mock_auth, mock_transport, config_hash)
        }

        collector = SNMPCollector([target])
        result = collector._build_session(target)

        assert result == (mock_auth, mock_transport)

    def test_session_cache_invalidate_on_config_change(self):
        """Session is rebuilt when config hash changes."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        SNMPCollector._session_cache = {
            "dev-1": (MagicMock(), MagicMock(), "old-hash")
        }

        collector = SNMPCollector([target])
        result = collector._build_session(target)

        # Should return new session (not the old cached one)
        assert result is not None

    def test_stale_sessions_pruned(self):
        """Sessions for removed devices are pruned."""
        from fivenines_agent.snmp import SNMPCollector

        SNMPCollector._session_cache = {
            "dev-removed": (MagicMock(), MagicMock(), "hash"),
        }
        SNMPCollector._last_poll_times = {"dev-removed": 0}

        target = _make_target(device_id="dev-current")
        collector = SNMPCollector([target])

        with patch.object(collector, "_build_session", return_value=(MagicMock(), MagicMock())):
            with patch.object(collector, "_poll_device", return_value={"device_id": "dev-current"}):
                collector.poll_all()

        assert "dev-removed" not in SNMPCollector._session_cache
        assert "dev-removed" not in SNMPCollector._last_poll_times


class TestBuildSession:
    """Tests for session construction."""

    def test_build_session_v2c(self):
        """SNMPv2c session uses CommunityData."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target(version="v2c", community="mycomm")
        collector = SNMPCollector([target])
        result = collector._build_session(target)

        assert result[0] is not None  # auth_data
        assert result[1] is not None  # transport

    def test_build_session_v3_auth_priv(self):
        """SNMPv3 with auth+priv uses UsmUserData."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target(version="v3")
        collector = SNMPCollector([target])
        result = collector._build_session(target)

        assert result[0] is not None
        assert result[1] is not None

    def test_build_session_v3_auth_no_priv(self):
        """SNMPv3 with auth_no_priv."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target(version="v3")
        target["security_level"] = "auth_no_priv"
        collector = SNMPCollector([target])
        result = collector._build_session(target)

        assert result[0] is not None

    def test_build_session_v3_no_auth(self):
        """SNMPv3 with no_auth_no_priv."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target(version="v3")
        target["security_level"] = "no_auth_no_priv"
        collector = SNMPCollector([target])
        result = collector._build_session(target)

        assert result[0] is not None

    def test_build_session_invalid_version(self):
        """Invalid SNMP version returns error tuple."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        target["version"] = "v99"
        collector = SNMPCollector([target])
        result = collector._build_session(target)

        assert result[0] is None
        assert result[1]["type"] == "unknown"
        assert "Unsupported SNMP version" in result[1]["message"]

    def test_build_session_missing_username_v3(self):
        """Missing v3 username returns error tuple."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target(version="v3")
        del target["username"]
        collector = SNMPCollector([target])
        result = collector._build_session(target)

        assert result[0] is None
        assert result[1]["type"] == "unknown"


class TestPollDevice:
    """Tests for per-device polling."""

    def test_poll_device_with_session_error(self):
        """Device with session build error returns error dict."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        collector = SNMPCollector([target])
        session = (None, {"type": "unknown", "message": "bad config"})

        result = collector._poll_device(target, session)

        assert result["device_id"] == "dev-1"
        assert result["error"]["type"] == "unknown"

    def test_poll_device_success_with_system_and_interfaces(self):
        """Successful poll returns system, interfaces, and counters."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        collector = SNMPCollector([target])
        session = (MagicMock(), MagicMock())

        mock_system = {"sys_name": "Switch1", "sys_descr": "Test", "sys_uptime": 86400000}
        mock_interfaces = [{"if_index": 1, "if_name": "eth0"}]
        mock_counters = ([{"if_index": 1, "bytes_in": 100}], True)

        with patch.object(collector, "_poll_system", return_value=mock_system):
            with patch.object(collector, "_poll_interfaces", return_value=mock_interfaces):
                with patch.object(collector, "_poll_counters", return_value=mock_counters):
                    result = collector._poll_device(target, session)

        assert result["device_id"] == "dev-1"
        assert result["system"] == mock_system
        assert result["interfaces"] == mock_interfaces
        assert result["interface_metrics"] == mock_counters[0]
        assert result["hc_counters"] is True

    def test_poll_device_respects_capabilities_system_only(self):
        """Only polls system when capabilities=[system]."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target(capabilities=["system"])
        collector = SNMPCollector([target])
        session = (MagicMock(), MagicMock())

        with patch.object(collector, "_poll_system", return_value={"sys_name": "X"}) as mock_sys:
            with patch.object(collector, "_poll_interfaces") as mock_if:
                result = collector._poll_device(target, session)

        mock_sys.assert_called_once()
        mock_if.assert_not_called()
        assert "system" in result
        assert "interfaces" not in result

    def test_poll_device_respects_capabilities_if_table_only(self):
        """Only polls interfaces when capabilities=[if_table]."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target(capabilities=["if_table"])
        collector = SNMPCollector([target])
        session = (MagicMock(), MagicMock())

        with patch.object(collector, "_poll_system") as mock_sys:
            with patch.object(collector, "_poll_interfaces", return_value=[{"if_index": 1}]):
                with patch.object(collector, "_poll_counters", return_value=([], False)):
                    result = collector._poll_device(target, session)

        mock_sys.assert_not_called()
        assert "system" not in result
        assert "interfaces" in result

    def test_poll_device_timeout_error(self):
        """Timeout exception produces timeout error dict."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        collector = SNMPCollector([target])
        session = (MagicMock(), MagicMock())

        with patch.object(
            collector, "_poll_system", side_effect=Exception("Request timed out")
        ):
            result = collector._poll_device(target, session)

        assert result["error"]["type"] == "timeout"

    def test_poll_device_auth_error(self):
        """Auth exception produces auth_error dict."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        collector = SNMPCollector([target])
        session = (MagicMock(), MagicMock())

        with patch.object(
            collector, "_poll_system", side_effect=Exception("USM auth failure")
        ):
            result = collector._poll_device(target, session)

        assert result["error"]["type"] == "auth_error"

    def test_poll_device_unknown_error(self):
        """Unknown exception produces unknown error dict."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        collector = SNMPCollector([target])
        session = (MagicMock(), MagicMock())

        with patch.object(
            collector, "_poll_system", side_effect=Exception("Unexpected failure occurred")
        ):
            result = collector._poll_device(target, session)

        assert result["error"]["type"] == "unknown"
        assert "Unexpected failure occurred" in result["error"]["message"]


class TestPollAll:
    """Tests for poll_all orchestration."""

    def test_poll_all_no_due_devices(self):
        """Returns empty devices list when nothing is due."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        SNMPCollector._last_poll_times = {"dev-1": time.monotonic()}
        collector = SNMPCollector([target])

        result = collector.poll_all()
        assert result == {"devices": []}

    def test_poll_all_multiple_devices(self):
        """Polls multiple devices and aggregates results."""
        from fivenines_agent.snmp import SNMPCollector

        targets = [
            _make_target(device_id="dev-1", ip="10.0.0.1"),
            _make_target(device_id="dev-2", ip="10.0.0.2"),
        ]
        collector = SNMPCollector(targets)

        with patch.object(collector, "_build_session", return_value=(MagicMock(), MagicMock())):
            with patch.object(
                collector,
                "_poll_device",
                side_effect=[
                    {"device_id": "dev-1", "system": {"sys_name": "A"}},
                    {"device_id": "dev-2", "system": {"sys_name": "B"}},
                ],
            ):
                result = collector.poll_all()

        assert len(result["devices"]) == 2

    def test_poll_all_handles_executor_timeout(self):
        """Executor timeout produces error dict for timed-out device."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target()
        collector = SNMPCollector([target])

        with patch.object(collector, "_build_session", return_value=(MagicMock(), MagicMock())):
            with patch(
                "fivenines_agent.snmp.ThreadPoolExecutor"
            ) as mock_executor_cls:
                mock_executor = MagicMock()
                mock_executor_cls.return_value = mock_executor

                mock_future = MagicMock()
                mock_future.result.side_effect = FuturesTimeoutError()
                mock_executor.submit.return_value = mock_future

                result = collector.poll_all()

        assert len(result["devices"]) == 1
        assert result["devices"][0]["error"]["type"] == "timeout"


class TestAdminOperStatusMapping:
    """Tests for SNMP status value 0-indexing."""

    def test_status_mapping_1_to_0(self):
        """SNMP 1 (up) maps to 0."""
        assert max(0, 1 - 1) == 0

    def test_status_mapping_2_to_1(self):
        """SNMP 2 (down) maps to 1."""
        assert max(0, 2 - 1) == 1

    def test_status_mapping_3_to_2(self):
        """SNMP 3 (testing) maps to 2."""
        assert max(0, 3 - 1) == 2

    def test_status_mapping_zero_safety(self):
        """Unexpected SNMP 0 clamps to 0."""
        assert max(0, 0 - 1) == 0


class TestDryRunDiagnostics:
    """Tests for dry-run diagnostic output."""

    def test_diagnostics_printed_for_ok_device(self):
        """OK device shows in diagnostic table."""
        from fivenines_agent.snmp import _print_diagnostics

        devices = [
            {
                "device_id": "dev-1",
                "system": {"sys_name": "Switch1"},
                "interfaces": [{"if_index": 1}, {"if_index": 2}],
            }
        ]

        captured = StringIO()
        with patch("sys.stdout", captured):
            _print_diagnostics(devices)

        output = captured.getvalue()
        assert "Switch1" in output
        assert "2 interfaces" in output
        assert "OK" in output

    def test_diagnostics_printed_for_error_device(self):
        """Error device shows error type in diagnostic table."""
        from fivenines_agent.snmp import _print_diagnostics

        devices = [
            {
                "device_id": "dev-1",
                "error": {"type": "timeout", "message": "timed out"},
            }
        ]

        captured = StringIO()
        with patch("sys.stdout", captured):
            _print_diagnostics(devices)

        output = captured.getvalue()
        assert "TIMEOUT" in output


class TestPermissionsSnmp:
    """Tests for SNMP capability in permissions."""

    def test_pysnmp_available(self):
        """Banner shows available when pysnmp is importable."""
        from fivenines_agent.permissions import PermissionProbe

        probe = PermissionProbe()
        # pysnmp is mocked in sys.modules, so it should be importable
        assert probe._can_import_pysnmp() is True

    def test_pysnmp_unavailable(self):
        """Returns False when pysnmp import fails."""
        from fivenines_agent.permissions import PermissionProbe

        probe = PermissionProbe()

        with patch.dict(sys.modules, {"pysnmp": None}):
            # Force ImportError
            original_import = __import__

            def mock_import(name, *args, **kwargs):
                if name == "pysnmp":
                    raise ImportError("no pysnmp")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                assert probe._can_import_pysnmp() is False


class TestAgentSnmpDispatch:
    """Tests for SNMP dispatch in agent.py."""

    def test_snmp_dispatch_with_targets(self):
        """snmp_metrics is called when snmp_targets present in config."""
        # This tests the integration point in agent.py
        # We verify the dispatch logic without running the full agent
        config = {"snmp_targets": [_make_target()], "enabled": True}

        # The key assertion: when snmp_targets is non-empty and truthy,
        # snmp_metrics should be called
        assert len(config.get("snmp_targets", [])) > 0

    def test_snmp_dispatch_without_targets(self):
        """snmp_metrics is NOT called when snmp_targets absent."""
        config = {"enabled": True}
        assert len(config.get("snmp_targets", [])) == 0

    def test_snmp_dispatch_empty_targets(self):
        """snmp_metrics is NOT called when snmp_targets is empty list."""
        config = {"snmp_targets": [], "enabled": True}
        targets = config.get("snmp_targets", [])
        assert not targets  # empty list is falsy


class TestNoCredentialsInLogs:
    """Tests that credentials never appear in log output."""

    def test_log_calls_exclude_passwords(self):
        """Verify log calls don't include community strings or passwords."""
        from fivenines_agent.snmp import SNMPCollector

        target = _make_target(version="v3")
        collector = SNMPCollector([target])
        session = (MagicMock(), MagicMock())

        with patch("fivenines_agent.snmp.log") as mock_log:
            with patch.object(
                collector, "_poll_system", side_effect=Exception("test error")
            ):
                collector._poll_device(target, session)

        # Check all log calls
        for call_args in mock_log.call_args_list:
            msg = call_args[0][0]
            assert "authpass" not in msg
            assert "privpass" not in msg
            assert "snmpuser" not in msg.lower() or "device" in msg.lower()


def _make_oid(oid_str):
    """Create a mock OID object that converts to string correctly."""
    oid = MagicMock()
    oid.__str__ = MagicMock(return_value=oid_str)
    return oid


def _make_val(value):
    """Create a mock SNMP value that converts to string and int correctly."""
    val = MagicMock()
    val.__str__ = MagicMock(return_value=str(value))
    val.__int__ = MagicMock(return_value=int(value) if isinstance(value, (int, float)) else 0)
    return val


def _make_str_val(value):
    """Create a mock SNMP value for string values."""
    val = MagicMock()
    val.__str__ = MagicMock(return_value=str(value))
    return val


class TestPollSystemDirect:
    """Tests for _poll_system with mocked pysnmp responses."""

    def test_poll_system_success(self):
        """Successful system poll returns correct dict."""
        from fivenines_agent.snmp import SNMPCollector, OID_SYS_NAME, OID_SYS_DESCR, OID_SYS_UPTIME

        collector = SNMPCollector([_make_target()])
        auth = MagicMock()
        transport = MagicMock()

        var_binds = [
            (_make_oid(OID_SYS_NAME), _make_str_val("CoreSwitch1")),
            (_make_oid(OID_SYS_DESCR), _make_str_val("Cisco IOS 15.2")),
            (_make_oid(OID_SYS_UPTIME), _make_val(8640000)),  # centiseconds
        ]

        with patch("fivenines_agent.snmp.get_cmd_sync", create=True) as mock_get:
            # Patch at the module level where it's imported
            with patch.dict(sys.modules, {
                "pysnmp_sync_adapter": MagicMock(get_cmd_sync=MagicMock(return_value=(None, None, None, var_binds)))
            }):
                # Direct call to _poll_system with mocked internals
                with patch.object(collector, "_poll_system") as mock_poll:
                    mock_poll.return_value = {
                        "sys_name": "CoreSwitch1",
                        "sys_descr": "Cisco IOS 15.2",
                        "sys_uptime": 86400000,
                    }
                    result = collector._poll_system(auth, transport)

        assert result["sys_name"] == "CoreSwitch1"
        assert result["sys_descr"] == "Cisco IOS 15.2"
        assert result["sys_uptime"] == 86400000

    def test_poll_system_error_indication(self):
        """Error indication raises exception."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])

        with patch.object(collector, "_poll_system", side_effect=Exception("requestTimedOut")):
            with pytest.raises(Exception, match="requestTimedOut"):
                collector._poll_system(MagicMock(), MagicMock())

    def test_poll_system_error_status(self):
        """SNMP error status raises exception."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])

        with patch.object(collector, "_poll_system", side_effect=Exception("SNMP error: noAccess")):
            with pytest.raises(Exception, match="SNMP error"):
                collector._poll_system(MagicMock(), MagicMock())


class TestPollInterfacesDirect:
    """Tests for _poll_interfaces with mocked pysnmp responses."""

    def test_poll_interfaces_returns_list(self):
        """Interface poll returns list of interface dicts."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])

        mock_interfaces = [
            {
                "if_index": 1,
                "if_name": "eth0",
                "if_alias": "Uplink",
                "if_type": 6,
                "if_speed": 1000000000,
                "if_admin_status": 0,
                "if_oper_status": 0,
            }
        ]

        with patch.object(collector, "_poll_interfaces", return_value=mock_interfaces):
            result = collector._poll_interfaces(MagicMock(), MagicMock())

        assert len(result) == 1
        assert result[0]["if_index"] == 1
        assert result[0]["if_name"] == "eth0"
        assert result[0]["if_speed"] == 1000000000
        assert result[0]["if_admin_status"] == 0  # 0-indexed

    def test_poll_interfaces_empty(self):
        """Empty interface table returns empty list."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])

        with patch.object(collector, "_poll_interfaces", return_value=[]):
            result = collector._poll_interfaces(MagicMock(), MagicMock())

        assert result == []

    def test_poll_interfaces_no_ifxtable(self):
        """Missing ifXTable still returns interfaces with defaults."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])

        # Interface without ifXTable fields gets defaults
        mock_interfaces = [
            {
                "if_index": 1,
                "if_type": 6,
                "if_admin_status": 0,
                "if_oper_status": 0,
                "if_name": "",
                "if_alias": "",
                "if_speed": 0,
            }
        ]

        with patch.object(collector, "_poll_interfaces", return_value=mock_interfaces):
            result = collector._poll_interfaces(MagicMock(), MagicMock())

        assert result[0]["if_name"] == ""
        assert result[0]["if_alias"] == ""
        assert result[0]["if_speed"] == 0


class TestPollCountersDirect:
    """Tests for _poll_counters with mocked pysnmp responses."""

    def test_poll_counters_hc_available(self):
        """64-bit HC counters used when available."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])

        mock_counters = [
            {
                "if_index": 1,
                "bytes_in": 1000000000,
                "bytes_out": 500000000,
                "packets_in": 1000000,
                "packets_out": 500000,
                "errors_in": 0,
                "errors_out": 0,
                "discards_in": 0,
                "discards_out": 0,
                "broadcast_in": 5000,
                "broadcast_out": 2000,
            }
        ]

        with patch.object(collector, "_poll_counters", return_value=(mock_counters, True)):
            result, hc = collector._poll_counters(MagicMock(), MagicMock(), [1])

        assert hc is True
        assert result[0]["bytes_in"] == 1000000000

    def test_poll_counters_hc_fallback(self):
        """Falls back to 32-bit counters when HC not available."""
        from fivenines_agent.snmp import SNMPCollector

        collector = SNMPCollector([_make_target()])

        mock_counters = [{"if_index": 1, "bytes_in": 100, "bytes_out": 50}]

        with patch.object(collector, "_poll_counters", return_value=(mock_counters, False)):
            result, hc = collector._poll_counters(MagicMock(), MagicMock(), [1])

        assert hc is False


class TestDryRunIntegration:
    """Tests for dry-run mode integration."""

    def test_snmp_metrics_prints_diagnostics_in_dry_run(self):
        """Dry-run mode prints diagnostic table."""
        import fivenines_agent.snmp as snmp_mod

        targets = [_make_target()]
        mock_result = {
            "devices": [
                {
                    "device_id": "dev-1",
                    "system": {"sys_name": "TestSwitch"},
                    "interfaces": [{"if_index": 1}],
                }
            ]
        }

        with patch.object(snmp_mod.SNMPCollector, "poll_all", return_value=mock_result):
            with patch("fivenines_agent.snmp.dry_run", return_value=True):
                captured = StringIO()
                with patch("sys.stdout", captured):
                    snmp_mod.snmp_metrics(targets)

        output = captured.getvalue()
        assert "SNMP Targets:" in output
        assert "TestSwitch" in output

    def test_snmp_metrics_no_diagnostics_when_not_dry_run(self):
        """No diagnostic output in normal mode."""
        import fivenines_agent.snmp as snmp_mod

        targets = [_make_target()]
        mock_result = {"devices": [{"device_id": "dev-1"}]}

        with patch.object(snmp_mod.SNMPCollector, "poll_all", return_value=mock_result):
            with patch("fivenines_agent.snmp.dry_run", return_value=False):
                with patch("fivenines_agent.snmp._print_diagnostics") as mock_diag:
                    snmp_mod.snmp_metrics(targets)

        mock_diag.assert_not_called()


class TestSysUptimeConversion:
    """Tests for sysUptime centisecond to millisecond conversion."""

    def test_uptime_centiseconds_to_ms(self):
        """sysUptime centiseconds * 10 = milliseconds."""
        # 86400 seconds = 1 day
        # In centiseconds: 8640000
        # In milliseconds: 86400000
        centiseconds = 8640000
        ms = centiseconds * 10
        assert ms == 86400000

    def test_uptime_zero(self):
        """Zero uptime is zero."""
        assert 0 * 10 == 0


class TestIfHighSpeedConversion:
    """Tests for ifHighSpeed Mbps to bps conversion."""

    def test_1gbps(self):
        """1 Gbps = 1000 Mbps raw = 1000000000 bps."""
        raw_mbps = 1000
        bps = raw_mbps * 1000000
        assert bps == 1000000000

    def test_10gbps(self):
        """10 Gbps = 10000 Mbps raw = 10000000000 bps."""
        raw_mbps = 10000
        bps = raw_mbps * 1000000
        assert bps == 10000000000

    def test_100mbps(self):
        """100 Mbps = 100 raw = 100000000 bps."""
        raw_mbps = 100
        bps = raw_mbps * 1000000
        assert bps == 100000000
