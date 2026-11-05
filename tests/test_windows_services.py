"""Tests for the Windows services collector (fivenines_agent/windows_services.py).

On Linux the Service Control Manager is a fake win32service module serving the
contract fixture's 'scm' inputs; on Windows, test_real_service_control_manager
reads the runner's own services through pywin32 and ctypes.
"""

import json
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

import fivenines_agent.windows_services as ws
from fivenines_agent.collectors import collect_metrics
from fivenines_agent.windows_services import probe_access, windows_services

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "windows_services_contract_payload.json"
)


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


def _scenario(name):
    return next(s for s in _load_fixture()["scenarios"] if s["name"] == name)


@pytest.fixture(autouse=True)
def _reset_module_state():
    ws._stalled_worker = None
    ws._query_config2 = None
    yield
    ws._stalled_worker = None
    ws._query_config2 = None


class FakeScmError(Exception):
    """pywintypes.error: (winerror, funcname, strerror), .winerror set."""

    def __init__(self, winerror, funcname="Fake"):
        super().__init__(winerror, funcname, f"error {winerror}")
        self.winerror = winerror


class FakeHandle:
    def __init__(self, number, name):
        self.number = number
        self.name = name

    def __int__(self):
        return self.number


class FakeWin32Service:
    """The pywin32 calls the collector makes, served from a fixture 'scm'."""

    def __init__(self, scm):
        self.scm = scm
        self.handles = {}
        self.open_handles = set()
        self.calls = []

    def _handle(self, name):
        handle = FakeHandle(len(self.handles) + 1, name)
        self.handles[handle.number] = name
        self.open_handles.add(handle.number)
        return handle

    def _config(self, handle):
        return next(
            row["config"]
            for row in self.scm["services"]
            if row["ServiceName"] == handle.name
        )

    def OpenSCManager(self, machine, database, access):
        assert (machine, database) == (None, None)
        assert access == ws.SC_MANAGER_CONNECT | ws.SC_MANAGER_ENUMERATE_SERVICE
        if self.scm.get("open_error"):
            raise FakeScmError(self.scm["open_error"], "OpenSCManager")
        return self._handle(None)

    def EnumServicesStatusEx(self, scm, service_type, service_state):
        assert scm.number in self.open_handles
        assert (service_type, service_state) == (0x30, 0x3)
        if self.scm.get("enum_error"):
            raise FakeScmError(self.scm["enum_error"], "EnumServicesStatusEx")
        return [
            {k: v for k, v in row.items() if k != "config"}
            for row in self.scm["services"]
        ]

    def OpenService(self, scm, name, access):
        assert scm.number in self.open_handles
        assert access == ws.SERVICE_QUERY_CONFIG
        self.calls.append(("OpenService", name))
        config = next(
            row["config"] for row in self.scm["services"] if row["ServiceName"] == name
        )
        if config.get("open_error"):
            raise FakeScmError(config["open_error"], "OpenService")
        return self._handle(name)

    def QueryServiceConfig(self, handle):
        assert handle.number in self.open_handles
        config = self._config(handle)
        if config.get("start_type_error"):
            raise FakeScmError(config["start_type_error"], "QueryServiceConfig")
        return (16, config["start_type"], 1, "C:\\x.exe", "", 0, [], "LocalSystem", "x")

    def QueryServiceConfig2(self, handle, level):
        assert handle.number in self.open_handles
        assert level == ws.SERVICE_CONFIG_DELAYED_AUTO_START_INFO
        config = self._config(handle)
        if config.get("delayed_error"):
            raise FakeScmError(config["delayed_error"], "QueryServiceConfig2")
        return config["delayed"]

    def trigger_count(self, number):
        assert number in self.open_handles
        config = self._config(FakeHandle(number, self.handles[number]))
        if config.get("triggers_error"):
            raise OSError(f"error {config['triggers_error']}")
        return config["triggers"]

    def CloseServiceHandle(self, handle):
        assert handle.number in self.open_handles
        self.open_handles.remove(handle.number)


def _collect(scm):
    """windows_services() on 'Windows', against a fake SCM. Returns
    (result_or_exception, fake)."""
    fake = FakeWin32Service(scm)
    with patch.dict(sys.modules, {"win32service": fake}), patch.object(
        ws, "is_windows", return_value=True
    ), patch.object(ws, "_trigger_count", side_effect=fake.trigger_count):
        try:
            result = windows_services()
        except Exception as e:  # the dispatcher's job; returned for the asserts
            result = e
    assert not fake.open_handles, "every SCM and service handle is closed"
    return result, fake


# --- cross-repo contract -----------------------------------------------------


@pytest.mark.parametrize("name", [s["name"] for s in _load_fixture()["scenarios"]])
def test_contract_fixture_round_trip(name):
    """SHARED FIXTURE (cross-repo contract): fixtures/windows_services_contract_payload.json.

    Asserted on both sides:
    - here: each scenario's 'scm' is served by a fake win32service and the
      dispatcher's output for config {'windows_services': true} must equal
      scenario['payload']['windows_services'] (a raised read is the null);
    - fivenines-server: its collect spec posts payload['windows_services']
      under data['windows_services'].

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    scenario = _scenario(name)
    fake = FakeWin32Service(scenario["scm"])
    data, telemetry = {}, {}
    with patch.dict(sys.modules, {"win32service": fake}), patch.object(
        ws, "is_windows", return_value=True
    ), patch.object(ws, "_trigger_count", side_effect=fake.trigger_count):
        collect_metrics({"windows_services": True}, data, telemetry)
    assert data == scenario["payload"]
    assert not fake.open_handles
    if scenario["payload"]["windows_services"] is None:
        assert telemetry["windows_services"]["errors"]


def test_contract_entries_have_exactly_the_documented_keys():
    keys = {
        "name",
        "display_name",
        "state",
        "start_type",
        "delayed_auto_start",
        "trigger_start",
        "pid",
        "exit_code",
        "service_exit_code",
    }
    for scenario in _load_fixture()["scenarios"]:
        block = scenario["payload"]["windows_services"]
        for entry in (block or {"services": []})["services"]:
            assert set(entry) == keys, entry
            assert entry["state"] in set(ws.STATES.values())
            assert entry["start_type"] in set(ws.START_TYPES.values()) | {None}


def test_fixture_agent_min_version():
    assert _load_fixture()["agent_min_version"] == "1.23.0"


def test_fixture_is_ascii():
    with open(_FIXTURE_PATH, "rb") as f:
        f.read().decode("ascii")


# --- the read ----------------------------------------------------------------


def test_not_windows_reports_none_without_importing_pywin32():
    with patch.object(ws, "is_windows", return_value=False), patch.object(
        ws, "call_bounded"
    ) as bounded:
        assert windows_services() is None
    bounded.assert_not_called()


def _row(name, **overrides):
    row = {
        "ServiceName": name,
        "DisplayName": name,
        "ServiceType": 16,
        "CurrentState": 4,
        "ControlsAccepted": 0,
        "Win32ExitCode": 0,
        "ServiceSpecificExitCode": 0,
        "CheckPoint": 0,
        "WaitHint": 0,
        "ProcessId": 100,
        "ServiceFlags": 0,
        "config": {"start_type": 2, "delayed": False, "triggers": 0},
    }
    row.update(overrides)
    return row


def test_unknown_state_and_start_type_read_as_null():
    rows = [
        _row(
            "a",
            CurrentState=99,
            config={"start_type": 9, "delayed": False, "triggers": 0},
        )
    ]
    result, _ = _collect({"services": rows})
    entry = result["services"][0]
    assert entry["state"] is None
    assert entry["start_type"] is None


def test_start_type_read_failure_keeps_the_other_fields():
    rows = [_row("a", config={"start_type_error": 5, "delayed": True, "triggers": 3})]
    result, _ = _collect({"services": rows})
    entry = result["services"][0]
    assert entry["start_type"] is None
    assert entry["delayed_auto_start"] is True
    assert entry["trigger_start"] is True


def test_names_are_scrubbed_for_the_wire():
    """A lone surrogate (malformed UTF-16 in the registry) or a NUL must not
    reach the server's JSON parser as is."""
    rows = [_row("bad\ud800name", DisplayName="dis\x00play")]
    result, _ = _collect({"services": rows})
    entry = result["services"][0]
    entry_json = json.dumps(entry, ensure_ascii=False).encode("utf-8")
    assert b"\x00" not in entry_json
    assert entry["name"] == "bad?name"
    assert entry["display_name"] == "display"


def test_sort_is_case_insensitive_and_stable_on_case():
    rows = [_row("b"), _row("B"), _row("a"), _row("C")]
    result, _ = _collect({"services": rows})
    assert [s["name"] for s in result["services"]] == ["a", "B", "b", "C"]


def test_over_the_cap_raises_rather_than_truncating():
    rows = [_row(f"s{i}") for i in range(3)]
    with patch.object(ws, "MAX_SERVICES", 2):
        result, fake = _collect({"services": rows})
    assert isinstance(result, ws.TooManyServices)
    assert "3 services listed, over the 2" in str(result)
    assert not fake.calls, "no per-service read before the cap check"


def test_user_services_do_not_count_toward_the_cap():
    rows = [_row("a"), _row("t", ServiceType=0x60), _row("t_1", ServiceType=0xE0)]
    with patch.object(ws, "MAX_SERVICES", 1):
        result, fake = _collect({"services": rows})
    assert [s["name"] for s in result["services"]] == ["a"]
    assert fake.calls == [("OpenService", "a")]


def test_missing_pywin32_raises_import_error():
    with patch.dict(sys.modules, {"win32service": None}), patch.object(
        ws, "is_windows", return_value=True
    ):
        with pytest.raises(ImportError):
            windows_services()


def test_scm_handle_is_closed_when_a_service_read_raises():
    """A bug past the per-field guards must not leak the SCM handle."""
    rows = [_row("a")]
    fake = FakeWin32Service({"services": rows})
    with patch.dict(sys.modules, {"win32service": fake}), patch.object(
        ws, "is_windows", return_value=True
    ), patch.object(ws, "_service_entry", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError, match="boom"):
            windows_services()
    assert not fake.open_handles


def test_blocked_read_is_abandoned_then_single_flight():
    """A wedged services.exe must not hold the collection loop: the tick gets
    None at the deadline, later ticks start no second read while the first is
    blocked, and collection resumes once it returns."""
    release = threading.Event()
    calls = []

    def blocked_read():
        calls.append(1)
        release.wait(5)  # bounded, so a missing join FAILS instead of hanging
        return {"services": []}

    with patch.object(ws, "is_windows", return_value=True), patch.object(
        ws, "SCM_READ_TIMEOUT", 0.05
    ), patch.object(ws, "_read_services", side_effect=blocked_read), patch.object(
        ws, "log"
    ) as log:
        start = time.monotonic()
        assert windows_services() is None
        assert time.monotonic() - start < 1
        assert ws._stalled_worker.daemon
        assert log.call_args_list[-1].args[1] == "error"

        assert windows_services() is None
        assert len(calls) == 1
        assert log.call_args_list[-1].args[1] == "debug"

        release.set()
        ws._stalled_worker.join(5)
        with patch.object(ws, "SCM_READ_TIMEOUT", 5):
            assert windows_services() == {"services": []}
        assert len(calls) == 2
        assert ws._stalled_worker is None


# --- the capability probe ------------------------------------------------------


def test_probe_access_opens_and_closes_the_scm():
    fake = FakeWin32Service({"services": []})
    with patch.dict(sys.modules, {"win32service": fake}):
        assert probe_access() == (True, None)
    assert not fake.open_handles


def test_probe_access_without_pywin32():
    with patch.dict(sys.modules, {"win32service": None}):
        available, reason = probe_access()
    assert available is False
    assert reason.startswith("pywin32 not installed: ")


def test_probe_access_when_the_scm_refuses():
    fake = FakeWin32Service({"open_error": 5})
    with patch.dict(sys.modules, {"win32service": fake}):
        available, reason = probe_access()
    assert available is False
    assert reason.startswith("Service Control Manager unavailable: FakeScmError: ")


# --- the trigger count (ctypes) --------------------------------------------------


class _FakeQuery:
    """QueryServiceConfig2W: answers from a list of (ok, needed, ctriggers)."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.sizes = []

    def __call__(self, handle, level, buffer, size, needed):
        import ctypes

        assert level == ws.SERVICE_CONFIG_TRIGGER_INFO
        assert handle == 42
        self.sizes.append(size)
        ok, need, triggers = self.answers.pop(0)
        needed._obj.value = need  # ctypes.byref(DWORD) -> the DWORD
        if ok:
            ctypes.c_uint32.from_buffer(buffer).value = triggers
        return ok


@pytest.fixture
def last_error():
    """ctypes.get_last_error exists on Windows only."""
    import ctypes

    holder = {"value": 0}
    with patch.object(ctypes, "get_last_error", lambda: holder["value"], create=True):
        yield holder


def test_trigger_count_reads_the_first_member(last_error):
    query = _FakeQuery([(True, 0, 3)])
    with patch.object(ws, "_query_config2_w", return_value=query):
        assert ws._trigger_count(42) == 3
    assert query.sizes == [ws._TRIGGER_BUFFER_BYTES]


def test_trigger_count_retries_once_with_the_size_needed(last_error):
    last_error["value"] = ws.ERROR_INSUFFICIENT_BUFFER
    query = _FakeQuery([(False, 10000, 0), (True, 0, 2)])
    with patch.object(ws, "_query_config2_w", return_value=query):
        assert ws._trigger_count(42) == 2
    assert query.sizes == [ws._TRIGGER_BUFFER_BYTES, 10000]


def test_trigger_count_gives_up_after_the_retry(last_error):
    last_error["value"] = ws.ERROR_INSUFFICIENT_BUFFER
    query = _FakeQuery([(False, 10000, 0), (False, 12000, 0)])
    with patch.object(ws, "_query_config2_w", return_value=query):
        with pytest.raises(OSError, match="error 122"):
            ws._trigger_count(42)


def test_trigger_count_raises_on_another_error(last_error):
    last_error["value"] = 5
    query = _FakeQuery([(False, 0, 0)])
    with patch.object(ws, "_query_config2_w", return_value=query):
        with pytest.raises(OSError, match="error 5"):
            ws._trigger_count(42)


def test_trigger_count_raises_when_the_buffer_was_not_too_small(last_error):
    """122 with a `needed` the buffer already had: retrying cannot help."""
    last_error["value"] = ws.ERROR_INSUFFICIENT_BUFFER
    query = _FakeQuery([(False, 100, 0)])
    with patch.object(ws, "_query_config2_w", return_value=query):
        with pytest.raises(OSError, match="error 122"):
            ws._trigger_count(42)
    assert query.sizes == [ws._TRIGGER_BUFFER_BYTES]


def test_query_config2_w_is_bound_once_with_its_argument_types():
    import ctypes
    import ctypes.wintypes

    function = MagicMock()
    library = MagicMock(QueryServiceConfig2W=function)
    with patch.object(ctypes, "WinDLL", return_value=library, create=True) as dll:
        assert ws._query_config2_w() is function
        assert ws._query_config2_w() is function
    dll.assert_called_once_with("advapi32", use_last_error=True)
    assert len(function.argtypes) == 5
    assert function.restype is ctypes.wintypes.BOOL


# --- the real thing, on the Windows test runner ---------------------------------


@pytest.mark.skipif(
    sys.platform != "win32", reason="the Service Control Manager is Windows-only"
)
def test_real_service_control_manager():
    """pywin32's EnumServicesStatusEx keys, the per-service reads and the
    ctypes trigger read, against the runner's own services."""
    assert probe_access() == (True, None)
    result = windows_services()
    services = {s["name"].casefold(): s for s in result["services"]}
    event_log = services["eventlog"]
    assert event_log["state"] == "running"
    assert event_log["start_type"] == "automatic"
    assert isinstance(event_log["pid"], int) and event_log["pid"] > 0
    assert event_log["delayed_auto_start"] is False
    assert event_log["trigger_start"] is False
    # A Windows Server has trigger-start and delayed-start services.
    assert any(s["trigger_start"] is True for s in services.values())
    assert any(s["delayed_auto_start"] is True for s in services.values())
    # Per-user services (template and per-logon instances) are left out.
    assert not any(name.startswith("cdpusersvc") for name in services)
