"""Tests for the Windows disk-health collector.

The collector shells out to PowerShell with a hard timeout (D11). These tests
cover the parsing/normalization, the DiskNumber join (MSFT_PhysicalDisk to
MSFT_Disk), the reliability-counter merge, the shared contract fixture, and
every failure path (timeout, non-zero exit, PowerShell missing, malformed
JSON, non-Windows host). The real WMI classes are exercised by the Windows CI
step that attaches VHDX disks (ci/windows-disk-number-check.py)."""

import json
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import fivenines_agent.disk_health_windows as dhw
from fivenines_agent.collectors import collect_metrics
from fivenines_agent.disk_health_windows import (
    WMI_TIMEOUT_SECONDS,
    _rows,
    _run_powershell,
    disk_health_windows,
)

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "disk_health_contract_payload.json"
)


def _completed(stdout="", stderr="", returncode=0):
    return SimpleNamespace(
        stdout=stdout.encode("utf-8"),
        stderr=stderr.encode("utf-8"),
        returncode=returncode,
    )


def _collect(physical, counters=None):
    """disk_health_windows() on 'Windows', each query served its JSON."""

    def fake_run(query):
        if "MSFT_PhysicalDisk" in query:
            return physical
        return counters

    with patch.object(dhw, "is_windows", return_value=True), patch.object(
        dhw, "_run_powershell", side_effect=fake_run
    ):
        return disk_health_windows()


def _pd(device_id, unique_id, **extra):
    row = {
        "FriendlyName": "Disk",
        "BusType": 17,
        "ObjectId": f"obj-{device_id}",
        "SerialNumber": f"SN{device_id}",
        "DeviceId": device_id,
        "UniqueId": unique_id,
    }
    row.update(extra)
    return row


# --- _run_powershell ---


def test_run_powershell_runs_windows_powershell_with_the_timeout():
    with patch.object(
        dhw.subprocess, "run", return_value=_completed(stdout="[]")
    ) as run:
        _run_powershell("dummy")
    args, kwargs = run.call_args
    assert args[0] == [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "dummy",
    ]
    assert kwargs["timeout"] == WMI_TIMEOUT_SECONDS


def test_run_powershell_returns_the_parsed_json_as_is():
    """The combined query's object comes back as an object, not a list."""
    payload = {"PhysicalDisk": [], "Disk": None}
    with patch.object(
        dhw.subprocess, "run", return_value=_completed(stdout=json.dumps(payload))
    ):
        assert _run_powershell("dummy") == payload


def test_run_powershell_passes_list_through():
    payload = json.dumps([{"FriendlyName": "SSD"}, {"FriendlyName": "HDD"}])
    with patch.object(dhw.subprocess, "run", return_value=_completed(stdout=payload)):
        assert len(_run_powershell("dummy")) == 2


def test_run_powershell_empty_output_returns_empty_list():
    with patch.object(dhw.subprocess, "run", return_value=_completed(stdout="")):
        assert _run_powershell("dummy") == []


def test_run_powershell_timeout_returns_none():
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="powershell", timeout=WMI_TIMEOUT_SECONDS)

    with patch.object(dhw.subprocess, "run", side_effect=raise_timeout):
        assert _run_powershell("dummy") is None


def test_run_powershell_missing_powershell_returns_none():
    with patch.object(
        dhw.subprocess, "run", side_effect=FileNotFoundError("powershell not found")
    ):
        assert _run_powershell("dummy") is None


def test_run_powershell_nonzero_exit_returns_none():
    with patch.object(
        dhw.subprocess, "run", return_value=_completed(stderr="oops", returncode=1)
    ):
        assert _run_powershell("dummy") is None


def test_run_powershell_invalid_json_returns_none():
    with patch.object(
        dhw.subprocess, "run", return_value=_completed(stdout="{not json")
    ):
        assert _run_powershell("dummy") is None


# --- _rows ---


def test_rows_wraps_a_single_row_collapsed_into_an_object():
    """ConvertTo-Json returns a dict for a single row; normalized to a list."""
    assert _rows({"FriendlyName": "SSD"}) == [{"FriendlyName": "SSD"}]


def test_rows_passes_a_list_through():
    assert _rows([{"a": 1}, {"a": 2}]) == [{"a": 1}, {"a": 2}]


@pytest.mark.parametrize("value", [None, 42, "text", True])
def test_rows_rejects_what_is_not_row_shaped(value):
    assert _rows(value) is None


# --- the query ---


def test_query_never_reads_location():
    """MSFT_Disk.Location is a file path holding a user name for a profile
    container: never selected, so it cannot be sent or logged."""
    assert "Location" not in dhw._PHYSICAL_DISK_QUERY
    assert "Path" not in dhw._PHYSICAL_DISK_QUERY


def test_query_reads_both_classes_in_one_process():
    """One process for MSFT_PhysicalDisk and MSFT_Disk: the 5s bound covers
    both, the tick's worst case stays two processes (this one, reliability)."""
    q = dhw._PHYSICAL_DISK_QUERY
    assert "-ClassName MSFT_PhysicalDisk" in q and "-ClassName MSFT_Disk " in q
    assert "$ErrorActionPreference = 'Stop'" in q
    assert "catch { $disks = $null }" in q


def test_collector_spawns_two_processes_at_most():
    with patch.object(dhw, "is_windows", return_value=True), patch.object(
        dhw.subprocess,
        "run",
        return_value=_completed(stdout='{"PhysicalDisk": [], "Disk": []}'),
    ) as run:
        assert disk_health_windows() == []
    assert run.call_count == 2


# --- disk_health_windows: failures ---


def test_disk_health_windows_returns_none_on_non_windows():
    with patch.object(dhw, "is_windows", return_value=False):
        assert disk_health_windows() is None


def test_disk_health_windows_returns_none_on_physical_query_failure():
    """If the MSFT_PhysicalDisk query fails, return None."""
    assert _collect(None) is None


@pytest.mark.parametrize("physical", [[], [{"FriendlyName": "SSD"}], 42])
def test_disk_health_windows_returns_none_when_the_output_is_not_the_object(physical):
    """The query always prints one object; anything else (an empty output
    included) is a failure, not an empty disk list."""
    assert _collect(physical) is None


@pytest.mark.parametrize("value", [None, "text", 42])
def test_disk_health_windows_returns_none_when_physical_disks_are_not_rows(value):
    assert _collect({"PhysicalDisk": value, "Disk": []}) is None


def test_disk_health_windows_reports_no_disks_as_an_empty_list():
    assert _collect({"PhysicalDisk": [], "Disk": []}, []) == []


# --- DiskNumber ---


def test_disk_number_joins_device_id_to_number_confirmed_by_unique_id():
    physical = [_pd("1", "eui.B"), _pd("0", "eui.A"), _pd("2", "6002248A", BusType=15)]
    disks = [
        {"Number": 2, "UniqueId": "6002248A"},
        {"Number": 0, "UniqueId": "eui.A"},
        {"Number": 1, "UniqueId": "eui.B"},
    ]
    result = _collect({"PhysicalDisk": physical, "Disk": disks}, [])
    assert [(r["BusType"], r["DiskNumber"]) for r in result] == [
        (17, 1),
        (17, 0),
        (15, 2),
    ]


def test_disk_number_join_keys_are_never_sent():
    result = _collect(
        {
            "PhysicalDisk": [_pd("0", "eui.A")],
            "Disk": [{"Number": 0, "UniqueId": "eui.A"}],
        },
        [],
    )
    assert "DeviceId" not in result[0] and "UniqueId" not in result[0]
    assert set(result[0]) == {
        "FriendlyName",
        "BusType",
        "ObjectId",
        "SerialNumber",
        "DiskNumber",
    }


def test_single_rows_collapsed_into_objects():
    """ConvertTo-Json may collapse a one-element list into an object: both
    lists are accepted in either form."""
    result = _collect(
        {"PhysicalDisk": _pd("0", "eui.A"), "Disk": {"Number": 0, "UniqueId": "eui.A"}},
        [],
    )
    assert len(result) == 1 and result[0]["DiskNumber"] == 0


def test_disk_number_is_null_for_a_pool_member():
    """A Storage Spaces pool member keeps its MSFT_PhysicalDisk row (and its
    DeviceId) but has no MSFT_Disk row: unknown, not guessed."""
    physical = [
        _pd("0", "eui.A"),
        _pd("2", "6002248A", BusType=15),
        _pd("3", "6002248B", BusType=15),
    ]
    disks = [{"Number": 0, "UniqueId": "eui.A"}, {"Number": 4, "UniqueId": "C0EE"}]
    result = _collect({"PhysicalDisk": physical, "Disk": disks}, [])
    assert [r["DiskNumber"] for r in result] == [0, None, None]


def test_disk_number_is_null_for_every_disk_when_msft_disk_failed():
    result = _collect(
        {"PhysicalDisk": [_pd("0", "eui.A"), _pd("1", "eui.B")], "Disk": None}, []
    )
    assert [r["DiskNumber"] for r in result] == [None, None]


def test_disk_number_is_null_when_the_unique_ids_disagree():
    """DeviceId 1 names disk 1, but disk 1 is another disk: not confirmed."""
    result = _collect(
        {
            "PhysicalDisk": [_pd("1", "eui.X")],
            "Disk": [{"Number": 1, "UniqueId": "eui.B"}],
        },
        [],
    )
    assert result[0]["DiskNumber"] is None


@pytest.mark.parametrize("unique_id", [None, ""])
def test_disk_number_is_null_without_a_unique_id_to_confirm(unique_id):
    result = _collect(
        {
            "PhysicalDisk": [_pd("0", unique_id)],
            "Disk": [{"Number": 0, "UniqueId": unique_id}],
        },
        [],
    )
    assert result[0]["DiskNumber"] is None


@pytest.mark.parametrize("device_id", [0, None, ["0"], "007", "1001", " 0", "0x0"])
def test_disk_number_is_null_when_device_id_does_not_spell_the_number(device_id):
    """DeviceId is a string spelling exactly the number: "0". An integer, a
    list, padding or another spelling is not a match (and cannot raise)."""
    disks = [{"Number": 0, "UniqueId": "eui.A"}, {"Number": 7, "UniqueId": "eui.A7"}]
    result = _collect({"PhysicalDisk": [_pd(device_id, "eui.A")], "Disk": disks}, [])
    assert result[0]["DiskNumber"] is None


@pytest.mark.parametrize("number", [True, -1, "0", 0.0, None])
def test_msft_disk_rows_with_an_unusable_number_are_ignored(number):
    result = _collect(
        {
            "PhysicalDisk": [_pd("0", "eui.A")],
            "Disk": [{"Number": number, "UniqueId": "eui.A"}],
        },
        [],
    )
    assert result[0]["DiskNumber"] is None


def test_a_number_held_by_two_msft_disk_rows_is_not_trusted():
    disks = [{"Number": 0, "UniqueId": "eui.A"}, {"Number": 0, "UniqueId": "eui.A"}]
    result = _collect({"PhysicalDisk": [_pd("0", "eui.A")], "Disk": disks}, [])
    assert result[0]["DiskNumber"] is None


def test_non_dict_msft_disk_rows_are_skipped():
    disks = ["not-a-dict", {"Number": 0, "UniqueId": "eui.A"}]
    result = _collect({"PhysicalDisk": [_pd("0", "eui.A")], "Disk": disks}, [])
    assert result[0]["DiskNumber"] == 0


def test_cloned_images_sharing_a_unique_id_keep_their_own_numbers():
    """A copied VHDX keeps the virtual disk id its UniqueId derives from: the
    number comes from DeviceId, the UniqueId only confirms it."""
    physical = [_pd("2", "6002248A", BusType=15), _pd("3", "6002248A", BusType=15)]
    disks = [
        {"Number": 3, "UniqueId": "6002248A"},
        {"Number": 2, "UniqueId": "6002248A"},
    ]
    result = _collect({"PhysicalDisk": physical, "Disk": disks}, [])
    assert [r["DiskNumber"] for r in result] == [2, 3]


# --- reliability merge ---


def test_disk_health_windows_returns_disks_without_reliability_when_counters_fail():
    """If reliability query fails, disks still come back without the merge."""
    result = _collect({"PhysicalDisk": [_pd("0", "eui.A")], "Disk": []}, None)
    assert len(result) == 1
    assert "reliability" not in result[0]


def test_disk_health_windows_merges_reliability_by_object_id():
    counters = [
        {"DeviceId": "obj-0", "Temperature": 45, "PowerOnHours": 1234, "Wear": 5}
    ]
    result = _collect({"PhysicalDisk": [_pd("0", "eui.A")], "Disk": []}, counters)
    assert result[0]["reliability"]["Temperature"] == 45
    assert result[0]["reliability"]["PowerOnHours"] == 1234


def test_disk_health_windows_merges_reliability_by_serial_number_fallback():
    """When ObjectId doesn't match, SerialNumber is the secondary join key."""
    counters = [{"DeviceId": "SN0", "Temperature": 30}]
    result = _collect({"PhysicalDisk": [_pd("0", "eui.A")], "Disk": []}, counters)
    assert result[0]["reliability"]["Temperature"] == 30


def test_disk_health_windows_merges_a_single_counter_collapsed_into_an_object():
    counters = {"DeviceId": "obj-0", "Temperature": 41}
    result = _collect({"PhysicalDisk": [_pd("0", "eui.A")], "Disk": []}, counters)
    assert result[0]["reliability"]["Temperature"] == 41


def test_disk_health_windows_ignores_non_dict_disk_entries():
    """Defensive: a malformed disk entry doesn't crash the merge loop."""
    counters = [{"DeviceId": "obj-0", "Temperature": 40}]
    result = _collect(
        {"PhysicalDisk": ["not-a-dict", _pd("0", "eui.A")], "Disk": []}, counters
    )
    assert len(result) == 2
    assert result[1]["reliability"]["Temperature"] == 40


def test_disk_health_windows_handles_no_counter_match():
    """A disk with no matching reliability entry stays bare, no error."""
    counters = [{"DeviceId": "obj-other", "Temperature": 50}]
    result = _collect({"PhysicalDisk": [_pd("0", "eui.A")], "Disk": []}, counters)
    assert "reliability" not in result[0]


# --- cross-repo contract (fivenines-server) ----------------------------------


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


def _serve(wmi):
    """subprocess.run serving a scenario's 'wmi' outputs: null is a failed
    process (exit 1), anything else is what ConvertTo-Json printed."""

    def fake_run(argv, **kwargs):
        query = argv[-1]
        key = "reliability" if "MSFT_StorageReliabilityCounter" in query else "physical"
        value = wmi[key]
        if value is None:
            return _completed(stderr="Get-CimInstance : Access denied", returncode=1)
        return _completed(stdout=json.dumps(value))

    return fake_run


@pytest.mark.parametrize("name", [s["name"] for s in _load_fixture()["scenarios"]])
def test_contract_fixture_round_trip(name):
    """SHARED FIXTURE (cross-repo contract): fixtures/disk_health_contract_payload.json.

    Asserted on both sides:
    - here: each scenario's 'wmi' outputs are served to the collector's two
      PowerShell processes, and the dispatcher's output for config
      {'disk_health': true} must equal scenario['payload'];
    - fivenines-server: its collect spec posts payload['disk_health'] under
      data['disk_health'].

    Change the payload shape only in lockstep with the server spec and its
    byte-identical fixture copy.
    """
    scenario = next(s for s in _load_fixture()["scenarios"] if s["name"] == name)
    data = {}
    with patch.object(dhw, "is_windows", return_value=True), patch.object(
        dhw.subprocess, "run", side_effect=_serve(scenario["wmi"])
    ):
        collect_metrics({"disk_health": True}, data, {})
    assert data == scenario["payload"]


def test_contract_rows_keep_every_existing_key_and_add_disk_number():
    """ADDITIVE: the keys agents sent before DiskNumber, unchanged, plus it."""
    keys = {
        "FriendlyName",
        "MediaType",
        "HealthStatus",
        "OperationalStatus",
        "Size",
        "SerialNumber",
        "BusType",
        "SpindleSpeed",
        "ObjectId",
        "DiskNumber",
    }
    seen_file_backed = False
    for scenario in _load_fixture()["scenarios"]:
        for row in scenario["payload"]["disk_health"] or []:
            assert set(row) - {"reliability"} == keys, row
            assert type(row["BusType"]) is int
            assert row["DiskNumber"] is None or type(row["DiskNumber"]) is int
            seen_file_backed |= row["BusType"] == 15 and row["DiskNumber"] is not None
    assert seen_file_backed, "the fixture shows a numbered File Backed Virtual disk"


def test_contract_fixture_has_the_single_row_case():
    """One scenario serves ConvertTo-Json's collapsed single-row objects."""
    assert any(
        isinstance(s["wmi"]["physical"], dict)
        and isinstance(s["wmi"]["physical"]["PhysicalDisk"], dict)
        for s in _load_fixture()["scenarios"]
    )


def test_contract_fixture_never_holds_a_location():
    with open(_FIXTURE_PATH) as f:
        text = f.read()
    assert '"Location"' not in text


def test_fixture_is_ascii():
    with open(_FIXTURE_PATH, "rb") as f:
        f.read().decode("ascii")
