import time
from unittest import mock
from unittest.mock import patch

import pytest

from fivenines_agent import cache as cache_mod
from fivenines_agent import smart_storage


@pytest.fixture(autouse=True)
def _reset_cache():
    """Reset the shared TTL cache before AND after each test.

    Symmetric teardown (matching the autouse convention in test_packages.py)
    stops a test that stamps the cache with the real clock from leaking a stale
    entry into a later test that exercises the real collectors.
    """
    smart_storage._cache._entries.clear()
    yield
    smart_storage._cache._entries.clear()


class _FakeClock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    """Deterministic clock for TTL expiry tests (patches the cache's time)."""
    c = _FakeClock()
    monkeypatch.setattr(cache_mod, "time", c)
    yield c


def _proc(returncode=0, stdout=""):
    proc = mock.Mock()
    proc.returncode = returncode
    proc.stdout = stdout
    return proc


def _nvme_smartctl_proc():
    return _proc(
        stdout=(
            "=== START OF SMART DATA SECTION ===\n"
            "SMART overall-health self-assessment test result: PASSED\n"
            "Critical Warning: 0x0c\n"
        )
    )


def _ata_smartctl_proc():
    return _proc(
        stdout=(
            "=== START OF READ SMART DATA SECTION ===\n"
            "  9 Power_On_Hours        0x0032   100   100   000    Old_age   1234\n"
        )
    )


# --- safe_int_conversion --------------------------------------------------


def test_safe_int_conversion_parses_hex_and_decimal():
    """Hex Critical Warning values with a-f must not be silently zeroed.

    Regression for the bug where '0x0c' was stripped to '00' and read as a
    healthy drive. int(value, 16) parses the 0x prefix directly.
    """
    assert smart_storage.safe_int_conversion("0x00", 16) == 0
    assert smart_storage.safe_int_conversion("0x0c", 16) == 12
    assert smart_storage.safe_int_conversion("0x0f", 16) == 15
    assert smart_storage.safe_int_conversion("0x1a", 16) == 26
    # Base-10 path is unchanged, including trailing-text and signed values.
    assert smart_storage.safe_int_conversion("1234") == 1234
    assert smart_storage.safe_int_conversion("100 (raw)") == 100
    assert smart_storage.safe_int_conversion("-5") == -5
    assert smart_storage.safe_int_conversion("") is None
    assert smart_storage.safe_int_conversion("nonsense") is None
    # Annotated values take only the LEADING valid run -- a trailing annotation
    # must not inject digits into the result (the fallback path).
    assert smart_storage.safe_int_conversion("12 (200)") == 12  # not 12200
    assert smart_storage.safe_int_conversion("0c foo", 16) == 12  # not 0x0cf=207
    # Radix-prefixed + annotated hex: strip the 0x, then leading run -- must NOT
    # collapse to 0 (a dangerous "healthy" critical_warning).
    assert smart_storage.safe_int_conversion("0x04 (foo)", 16) == 4
    assert smart_storage.safe_int_conversion("0x0c (A)", 16) == 12


# --- get_smartctl_version / get_nvme_cli_version (self-checking) ----------


def test_get_smartctl_version_parses_first_line(monkeypatch):
    monkeypatch.setattr(
        smart_storage.subprocess,
        "run",
        lambda *_a, **_k: _proc(0, "smartctl 7.2 2020-12-30 r5155\nCopyright\n"),
    )
    assert smart_storage.get_smartctl_version() == "smartctl 7.2 2020-12-30 r5155"


def test_get_smartctl_version_none_when_unavailable(monkeypatch):
    """Non-zero exit (no smartctl / no passwordless sudo) -> None, quietly."""
    monkeypatch.setattr(smart_storage.subprocess, "run", lambda *_a, **_k: _proc(1, ""))
    assert smart_storage.get_smartctl_version() is None


def test_get_nvme_cli_version_parses_first_line(monkeypatch):
    monkeypatch.setattr(
        smart_storage.subprocess,
        "run",
        lambda *_a, **_k: _proc(0, "nvme version 2.1\n"),
    )
    assert smart_storage.get_nvme_cli_version() == "nvme version 2.1"


def test_get_nvme_cli_version_none_when_unavailable(monkeypatch):
    monkeypatch.setattr(smart_storage.subprocess, "run", lambda *_a, **_k: _proc(1, ""))
    assert smart_storage.get_nvme_cli_version() is None


def test_version_fetchers_none_on_empty_stdout(monkeypatch):
    """rc=0 but empty stdout -> None (honors the 'unreadable -> emit nothing' contract)."""
    monkeypatch.setattr(
        smart_storage.subprocess, "run", lambda *_a, **_k: _proc(0, "\n")
    )
    assert smart_storage.get_smartctl_version() is None
    assert smart_storage.get_nvme_cli_version() is None


def test_smartctl_available_reflects_probe(monkeypatch):
    """smartctl_available is True only when the sudo -n probe exits 0."""
    monkeypatch.setattr(
        smart_storage.subprocess, "run", lambda *_a, **_k: _proc(0, "smartctl 7.2\n")
    )
    assert smart_storage.smartctl_available() is True
    monkeypatch.setattr(smart_storage.subprocess, "run", lambda *_a, **_k: _proc(1, ""))
    assert smart_storage.smartctl_available() is False


def test_nvme_cli_available_reflects_probe(monkeypatch):
    """nvme_cli_available is True only when the sudo -n probe exits 0."""
    monkeypatch.setattr(
        smart_storage.subprocess, "run", lambda *_a, **_k: _proc(0, "nvme 2.1\n")
    )
    assert smart_storage.nvme_cli_available() is True
    monkeypatch.setattr(smart_storage.subprocess, "run", lambda *_a, **_k: _proc(1, ""))
    assert smart_storage.nvme_cli_available() is False


def test_version_fetchers_none_on_timeout(monkeypatch):
    """A stuck sudo (TimeoutExpired) returns None instead of stalling the loop."""

    def boom(*_a, **_k):
        raise smart_storage.subprocess.TimeoutExpired(cmd="x", timeout=5)

    monkeypatch.setattr(smart_storage.subprocess, "run", boom)
    assert smart_storage.get_smartctl_version() is None
    assert smart_storage.get_nvme_cli_version() is None


def test_version_fetchers_none_on_unexpected_error(monkeypatch):
    """Any other subprocess failure returns None quietly."""

    def boom(*_a, **_k):
        raise RuntimeError("nope")

    monkeypatch.setattr(smart_storage.subprocess, "run", boom)
    assert smart_storage.get_smartctl_version() is None
    assert smart_storage.get_nvme_cli_version() is None


# --- smart_storage_identification -----------------------------------------


def test_identification_no_nvme_device_does_not_fetch_nvme_version(monkeypatch):
    """REGRESSION: with only ATA devices, `nvme version` must never run.

    get_nvme_cli_version IS the `sudo -n nvme version` call now, so asserting it
    is never invoked pins 'no nvme shell-out on ATA-only hosts'.
    """
    monkeypatch.setattr(smart_storage, "get_smartctl_version", lambda: "smartctl 7.2")
    monkeypatch.setattr(
        smart_storage, "list_storage_devices", lambda: ["/dev/sda", "/dev/sdb"]
    )
    monkeypatch.setattr(
        smart_storage,
        "get_storage_identification",
        lambda dev: {"device": dev.split("/")[-1]},
    )

    nvme_version = mock.Mock(return_value="nvme 2.1")
    monkeypatch.setattr(smart_storage, "get_nvme_cli_version", nvme_version)

    data = smart_storage.smart_storage_identification()

    nvme_version.assert_not_called()
    assert len(data) == 2
    for device_info in data:
        assert device_info["smartctl_version"] == "smartctl 7.2"
        # Key stays present (shape stable for the backend), value is null.
        assert device_info["nvme_cli_version"] is None


def test_identification_with_nvme_device_fetches_nvme_version_once(monkeypatch):
    """An NVMe device present -> nvme version fetched once and reported."""
    monkeypatch.setattr(smart_storage, "get_smartctl_version", lambda: "smartctl 7.2")
    monkeypatch.setattr(
        smart_storage, "list_storage_devices", lambda: ["/dev/sda", "/dev/nvme0"]
    )
    monkeypatch.setattr(
        smart_storage,
        "get_storage_identification",
        lambda dev: {"device": dev.split("/")[-1]},
    )

    nvme_version = mock.Mock(return_value="nvme 2.1")
    monkeypatch.setattr(smart_storage, "get_nvme_cli_version", nvme_version)

    data = smart_storage.smart_storage_identification()

    nvme_version.assert_called_once()
    assert len(data) == 2
    for device_info in data:
        assert device_info["nvme_cli_version"] == "nvme 2.1"


def test_identification_nvme_present_but_cli_unavailable(monkeypatch):
    """NVMe device present but nvme-cli unusable -> version fetch returns None."""
    monkeypatch.setattr(smart_storage, "get_smartctl_version", lambda: "smartctl 7.2")
    monkeypatch.setattr(smart_storage, "list_storage_devices", lambda: ["/dev/nvme0"])
    monkeypatch.setattr(
        smart_storage,
        "get_storage_identification",
        lambda dev: {"device": dev.split("/")[-1]},
    )

    nvme_version = mock.Mock(return_value=None)
    monkeypatch.setattr(smart_storage, "get_nvme_cli_version", nvme_version)

    data = smart_storage.smart_storage_identification()

    nvme_version.assert_called_once()
    assert data[0]["nvme_cli_version"] is None


def test_identification_smartctl_unavailable_returns_empty(monkeypatch):
    """smartctl unusable (get_smartctl_version returns None) -> empty data.

    Covers both 'smartctl not installed / no sudo' and 'version unreadable':
    both now manifest as get_smartctl_version() returning None. Device
    discovery and the nvme fetch must not run.
    """
    monkeypatch.setattr(smart_storage, "get_smartctl_version", lambda: None)
    list_devices = mock.Mock()
    monkeypatch.setattr(smart_storage, "list_storage_devices", list_devices)
    nvme_version = mock.Mock()
    monkeypatch.setattr(smart_storage, "get_nvme_cli_version", nvme_version)

    assert smart_storage.smart_storage_identification() == []
    list_devices.assert_not_called()
    nvme_version.assert_not_called()


def test_identification_no_devices_returns_empty(monkeypatch):
    """smartctl present but zero devices -> empty data, no nvme fetch."""
    monkeypatch.setattr(smart_storage, "get_smartctl_version", lambda: "smartctl 7.2")
    monkeypatch.setattr(smart_storage, "list_storage_devices", lambda: [])
    nvme_version = mock.Mock()
    monkeypatch.setattr(smart_storage, "get_nvme_cli_version", nvme_version)

    assert smart_storage.smart_storage_identification() == []
    nvme_version.assert_not_called()


def test_identification_cache_hit_skips_all_work(monkeypatch):
    """Fresh cache (<600s) returns cached data without touching subprocess paths."""
    smart_storage._cache._entries["identification"] = (
        time.monotonic(),
        [{"device": "cached"}],
        600,
    )

    smartctl_version = mock.Mock()
    monkeypatch.setattr(smart_storage, "get_smartctl_version", smartctl_version)

    assert smart_storage.smart_storage_identification() == [{"device": "cached"}]
    smartctl_version.assert_not_called()


def test_identification_cache_hit_within_ttl(clock):
    calls = []

    def fake_id(dev):
        calls.append(dev)
        return {"device": dev.split("/")[-1]}

    with patch.multiple(
        smart_storage,
        get_smartctl_version=lambda: "7.0",
        get_nvme_cli_version=lambda: None,
        list_storage_devices=lambda: ["/dev/sda"],
        get_storage_identification=fake_id,
    ):
        smart_storage.smart_storage_identification()
        clock.t += 300  # inside 600s TTL
        smart_storage.smart_storage_identification()

    assert calls == ["/dev/sda"]  # computed once


# --- smart_storage_health / get_storage_info ------------------------------


def test_health_probes_nvme_availability_once_for_multi_nvme(monkeypatch):
    """End-to-end: several NVMe devices share a single memoized `nvme version`.

    Devices are gated by PARSED output (current_section == nvme), and the probe
    is consulted once even though every device enriches.
    """
    monkeypatch.setattr(smart_storage, "smartctl_available", lambda: True)
    monkeypatch.setattr(
        smart_storage,
        "list_storage_devices",
        lambda: ["/dev/nvme0", "/dev/nvme1", "/dev/nvme2"],
    )
    monkeypatch.setattr(
        smart_storage.subprocess, "run", lambda *_a, **_k: _nvme_smartctl_proc()
    )
    monkeypatch.setattr(
        smart_storage, "calculate_percentage_used", lambda *_a, **_k: None
    )
    nvme_available = mock.Mock(return_value=True)
    monkeypatch.setattr(smart_storage, "nvme_cli_available", nvme_available)
    enhanced = mock.Mock(return_value={"percent_used": 7})
    monkeypatch.setattr(smart_storage, "get_nvme_enhanced_info", enhanced)

    data = smart_storage.smart_storage_health()

    nvme_available.assert_called_once()  # memoized across all 3 devices
    assert enhanced.call_count == 3  # but each NVMe device still enriched
    assert len(data) == 3
    for device_info in data:
        assert device_info["device_type"] == "nvme"
        assert device_info["critical_warning"] == 12  # 0x0c parsed correctly
        assert device_info["percent_used"] == 7  # enrichment merged in


def test_health_no_nvme_section_never_probes(monkeypatch):
    """REGRESSION: devices whose PARSED output is ATA never probe nvme-cli.

    This is the exact-equivalence guard: gating is by parsed current_section,
    not the device path, so an NVMe device under an exotic name would still be
    enriched (and an ATA device never triggers a probe).
    """
    monkeypatch.setattr(smart_storage, "smartctl_available", lambda: True)
    monkeypatch.setattr(
        smart_storage, "list_storage_devices", lambda: ["/dev/sda", "/dev/sdb"]
    )
    monkeypatch.setattr(
        smart_storage.subprocess, "run", lambda *_a, **_k: _ata_smartctl_proc()
    )
    monkeypatch.setattr(
        smart_storage, "calculate_percentage_used", lambda *_a, **_k: None
    )
    nvme_available = mock.Mock(return_value=True)
    monkeypatch.setattr(smart_storage, "nvme_cli_available", nvme_available)

    data = smart_storage.smart_storage_health()

    nvme_available.assert_not_called()
    assert all(device_info["device_type"] == "ata" for device_info in data)


def test_memoized_nvme_probe_runs_underlying_check_once(monkeypatch):
    """The probe factory caches the first nvme_cli_available() result."""
    underlying = mock.Mock(return_value=True)
    monkeypatch.setattr(smart_storage, "nvme_cli_available", underlying)

    probe = smart_storage._memoized_nvme_probe()
    assert probe() is True
    assert probe() is True
    assert probe() is True

    underlying.assert_called_once()


def test_health_smartctl_unavailable_returns_empty(monkeypatch):
    """No smartctl -> empty health data, device discovery never attempted."""
    monkeypatch.setattr(smart_storage, "smartctl_available", lambda: False)
    list_devices = mock.Mock()
    monkeypatch.setattr(smart_storage, "list_storage_devices", list_devices)

    assert smart_storage.smart_storage_health() == []
    list_devices.assert_not_called()


def test_health_no_devices_returns_empty(monkeypatch):
    """smartctl present but zero devices -> empty health data, nvme never probed."""
    monkeypatch.setattr(smart_storage, "smartctl_available", lambda: True)
    monkeypatch.setattr(smart_storage, "list_storage_devices", lambda: [])
    nvme_available = mock.Mock()
    monkeypatch.setattr(smart_storage, "nvme_cli_available", nvme_available)

    assert smart_storage.smart_storage_health() == []
    nvme_available.assert_not_called()


def test_health_happy_filters_none(monkeypatch):
    """A device whose info collection failed (None) is dropped from the payload."""

    def fake_info(dev, nvme_available=None):
        return None if dev == "/dev/sdb" else {"device": "sda"}

    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        list_storage_devices=lambda: ["/dev/sda", "/dev/sdb"],
        get_storage_info=fake_info,
    ):
        assert smart_storage.smart_storage_health() == [{"device": "sda"}]


def test_health_cache_hit_skips_all_work(monkeypatch):
    """Fresh health cache (<60s) returns cached data without re-collecting."""
    smart_storage._cache._entries["health"] = (
        time.monotonic(),
        [{"device": "cached"}],
        60,
    )

    smartctl = mock.Mock()
    monkeypatch.setattr(smart_storage, "smartctl_available", smartctl)

    assert smart_storage.smart_storage_health() == [{"device": "cached"}]
    smartctl.assert_not_called()


def test_health_cache_hit_within_ttl(clock):
    calls = []

    def fake_info(dev, nvme_available=None):
        calls.append(dev)
        return {"device": dev.split("/")[-1]}

    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        list_storage_devices=lambda: ["/dev/sda"],
        get_storage_info=fake_info,
    ):
        first = smart_storage.smart_storage_health()
        clock.t += 30  # inside 60s TTL
        second = smart_storage.smart_storage_health()

    assert first == second == [{"device": "sda"}]
    assert calls == ["/dev/sda"]  # computed exactly once


def test_health_recomputes_after_ttl(clock):
    calls = []

    def fake_info(dev, nvme_available=None):
        calls.append(dev)
        return {"device": dev.split("/")[-1]}

    with patch.multiple(
        smart_storage,
        smartctl_available=lambda: True,
        list_storage_devices=lambda: ["/dev/sda"],
        get_storage_info=fake_info,
    ):
        smart_storage.smart_storage_health()
        clock.t += 60  # TTL elapsed
        smart_storage.smart_storage_health()

    assert calls == ["/dev/sda", "/dev/sda"]  # recomputed


def test_get_storage_info_honors_nvme_available_flag(monkeypatch):
    """get_storage_info enriches an NVMe device only when told nvme-cli is usable,
    and the parsed/derived fields are actually written into the result."""
    monkeypatch.setattr(
        smart_storage.subprocess,
        "run",
        lambda *_a, **_k: _proc(
            stdout=(
                "=== START OF SMART DATA SECTION ===\n"
                "SMART overall-health self-assessment test result: PASSED\n"
                "Critical Warning: 0x0c\n"
            )
        ),
    )
    monkeypatch.setattr(
        smart_storage, "calculate_percentage_used", lambda *_a, **_k: 95
    )

    enhanced = mock.Mock(return_value={"percent_used": 5})
    monkeypatch.setattr(smart_storage, "get_nvme_enhanced_info", enhanced)

    # Probe says nvme-cli is usable -> enhanced info is fetched AND merged.
    res = smart_storage.get_storage_info("/dev/nvme0", nvme_available=lambda: True)
    enhanced.assert_called_once_with("/dev/nvme0")
    assert res["device"] == "nvme0"
    assert res["device_type"] == "nvme"
    assert res["critical_warning"] == 12  # 0x0c, not silently zeroed
    assert res["percent_used"] == 5  # results.update(nvme_info) ran
    assert res["percentage_used"] == 95  # percentage_used write path ran

    # Probe says nvme-cli is not usable -> enhanced info is skipped, but the
    # smartctl-parsed fields are still present.
    enhanced.reset_mock()
    res2 = smart_storage.get_storage_info("/dev/nvme0", nvme_available=lambda: False)
    enhanced.assert_not_called()
    assert "percent_used" not in res2
    assert res2["critical_warning"] == 12


# --- data-path timeouts (a wedged drive must not stall the loop) ----------


def test_data_path_subprocess_calls_set_timeout(monkeypatch):
    """Every data-collection smartctl/nvme call passes a timeout, so a wedged
    drive cannot block the single-threaded collection loop forever."""
    seen = []

    def spy(cmd, *_a, **kwargs):
        seen.append(kwargs.get("timeout"))
        proc = mock.Mock()
        proc.returncode = 0
        if "--scan" in cmd:
            proc.stdout = b""  # list_storage_devices does .decode()
        elif "smart-log" in cmd:
            proc.stdout = "{}"  # get_nvme_enhanced_info does json.loads
        else:
            proc.stdout = ""  # -A -H / -i do .splitlines()
        return proc

    monkeypatch.setattr(smart_storage.subprocess, "run", spy)
    monkeypatch.setattr(
        smart_storage, "calculate_percentage_used", lambda *_a, **_k: None
    )

    smart_storage.list_storage_devices()
    smart_storage.get_storage_info("/dev/sda")
    smart_storage.get_storage_identification("/dev/sda")
    smart_storage.get_nvme_enhanced_info("/dev/nvme0")

    assert seen, "no subprocess calls were made"
    # Pin the value with a literal (NOT the constant -- that would move with a
    # mutation): a regression shrinking the cap below the slow-but-healthy-drive
    # budget must fail here. And confirm every call uses the shared constant.
    assert smart_storage._DATA_SUBPROCESS_TIMEOUT == 30
    assert all(
        t == smart_storage._DATA_SUBPROCESS_TIMEOUT for t in seen
    ), f"a data-path call did not use the shared timeout: {seen}"


def test_data_path_degrades_on_timeout(monkeypatch):
    """A timed-out data call degrades to a safe value instead of propagating."""

    def boom(*_a, **_k):
        raise smart_storage.subprocess.TimeoutExpired(cmd="smartctl", timeout=30)

    monkeypatch.setattr(smart_storage.subprocess, "run", boom)

    assert smart_storage.list_storage_devices() == []
    assert smart_storage.get_storage_info("/dev/sda") is None
    assert smart_storage.get_storage_identification("/dev/sda") is None
    assert smart_storage.get_nvme_enhanced_info("/dev/nvme0") == {}


def test_get_storage_info_gates_on_parsed_section_not_device_path(monkeypatch):
    """Enrichment is gated on PARSED output (current_section), NOT the device path.

    A device whose path is not /dev/nvme* but whose smartctl output parses as
    NVMe must still be enriched. This pins the exact-equivalence choice: the
    health path deliberately does NOT use the is_nvme_device path heuristic here
    (only identification does, because `smartctl -i` has no SMART section).
    """
    monkeypatch.setattr(
        smart_storage.subprocess, "run", lambda *_a, **_k: _nvme_smartctl_proc()
    )
    monkeypatch.setattr(
        smart_storage, "calculate_percentage_used", lambda *_a, **_k: None
    )
    enhanced = mock.Mock(return_value={"percent_used": 9})
    monkeypatch.setattr(smart_storage, "get_nvme_enhanced_info", enhanced)

    # Non-/dev/nvme path, but the parsed SMART section is NVMe.
    res = smart_storage.get_storage_info("/dev/sda", nvme_available=lambda: True)

    enhanced.assert_called_once_with("/dev/sda")  # gated on section, not path
    assert res["device_type"] == "nvme"
    assert res["percent_used"] == 9


def test_sudo_probe_passes_timeout(monkeypatch):
    """The availability/version probe must also pass a timeout, so a wedged tool
    at probe time cannot hang the loop either."""
    seen = []

    def spy(cmd, *_a, **kwargs):
        seen.append(kwargs.get("timeout"))
        return _proc(0, "smartctl 7.2\n")

    monkeypatch.setattr(smart_storage.subprocess, "run", spy)

    smart_storage.get_smartctl_version()
    smart_storage.smartctl_available()

    assert seen, "no probe calls were made"
    assert all(t is not None for t in seen), f"a probe call had no timeout: {seen}"
