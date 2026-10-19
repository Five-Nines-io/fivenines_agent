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
    """No smartctl -> device discovery fails -> empty health data. There is no
    separate smartctl_available() spawn anymore: the scan's own failure is the
    availability signal."""
    list_devices = mock.Mock(return_value=[])
    monkeypatch.setattr(smart_storage, "list_storage_devices", list_devices)

    assert smart_storage.smart_storage_health() == []
    list_devices.assert_called_once()


def test_health_no_devices_returns_empty(monkeypatch):
    """smartctl present but zero devices -> empty health data, nvme never probed."""
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

    list_devices = mock.Mock()
    monkeypatch.setattr(smart_storage, "list_storage_devices", list_devices)

    assert smart_storage.smart_storage_health() == [{"device": "cached"}]
    list_devices.assert_not_called()


def test_health_cache_hit_within_ttl(clock):
    calls = []

    def fake_info(dev, nvme_available=None):
        calls.append(dev)
        return {"device": dev.split("/")[-1]}

    with patch.multiple(
        smart_storage,
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


def test_identification_runs_smartctl_in_the_c_locale(monkeypatch):
    """#172: smartctl formats `User Capacity` with the locale's thousands
    separator and total_capacity ships that string as is, so the same disk read
    "500,107,862,016 bytes" or "500.107.862.016 bytes" depending on the host's
    LANG. Under C smartctl falls back to its own ",", the en_US spelling. The
    stand-in answers like smartctl does -- the de_DE "." unless the child runs
    in C -- so losing the pin fails the total_capacity assertion itself."""
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")

    def locale_aware_smartctl(cmd, **kwargs):
        sep = "," if kwargs["env"].get("LC_ALL") == "C" else "."
        return _proc(
            stdout=f"User Capacity:    500{sep}107{sep}862{sep}016 bytes [500 GB]\n"
        )

    monkeypatch.setattr(smart_storage.subprocess, "run", locale_aware_smartctl)
    info = smart_storage.get_storage_identification("/dev/sda")
    assert info["total_capacity"] == "500,107,862,016 bytes [500 GB]"


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
    smart_storage.nvme_cli_available()

    assert seen, "no probe calls were made"
    assert all(t is not None for t in seen), f"a probe call had no timeout: {seen}"


# --- realistic smartctl / nvme-cli output ---------------------------------

SMARTCTL_BANNER = (
    "smartctl 7.3 2022-02-28 r5338 [x86_64-linux-6.1.0-18-amd64] (local build)\n"
    "Copyright (C) 2002-22, Bruce Allen, Christian Franke, www.smartmontools.org\n"
    "\n"
)

# `smartctl -A -H /dev/sda` on a Samsung SATA SSD.
SMARTCTL_AH_SAMSUNG_SSD = SMARTCTL_BANNER + (
    "=== START OF READ SMART DATA SECTION ===\n"
    "SMART overall-health self-assessment test result: PASSED\n"
    "\n"
    "SMART Attributes Data Structure revision number: 1\n"
    "Vendor Specific SMART Attributes with Thresholds:\n"
    "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED"
    "  WHEN_FAILED RAW_VALUE\n"
    "  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always"
    "       -       0\n"
    "  9 Power_On_Hours          0x0032   095   095   000    Old_age   Always"
    "       -       21567\n"
    " 12 Power_Cycle_Count       0x0032   099   099   000    Old_age   Always"
    "       -       512\n"
    "177 Wear_Leveling_Count     0x0013   097   097   000    Pre-fail  Always"
    "       -       42\n"
    "179 Used_Rsvd_Blk_Cnt_Tot   0x0013   100   100   010    Pre-fail  Always"
    "       -       0\n"
    "194 Temperature_Celsius     0x0022   067   052   000    Old_age   Always"
    "       -       33 (Min/Max 18/48)\n"
    "241 Total_LBAs_Written      0x0032   099   099   000    Old_age   Always"
    "       -       28745830212\n"
    "\n"
)

# `smartctl -A -H /dev/nvme0`.
SMARTCTL_AH_NVME = SMARTCTL_BANNER + (
    "=== START OF SMART DATA SECTION ===\n"
    "SMART overall-health self-assessment test result: PASSED\n"
    "\n"
    "SMART/Health Information (NVMe Log 0x02)\n"
    "Critical Warning:                   0x00\n"
    "Temperature:                        36 Celsius\n"
    "Available Spare:                    100%\n"
    "Percentage Used:                    3%\n"
    "Power On Hours:                     7,890\n"
)

# `nvme smart-log /dev/nvme0 -o json` (nvme-cli 1.x key names).
NVME_SMART_LOG_JSON = """{
  "critical_warning" : 0,
  "temperature" : 310,
  "avail_spare" : 100,
  "spare_thresh" : 10,
  "percent_used" : 3,
  "endurance_grp_critical_warning_summary" : 0,
  "data_units_read" : 12345678,
  "data_units_written" : 23456789,
  "host_read_commands" : 345678901,
  "host_write_commands" : 456789012,
  "controller_busy_time" : 1234,
  "power_cycles" : 56,
  "power_on_hours" : 7890,
  "unsafe_shutdowns" : 12,
  "media_errors" : 0,
  "num_err_log_entries" : 34,
  "warning_temp_time" : 0,
  "critical_comp_time" : 0,
  "temperature_sensor_1" : 310,
  "thm_temp1_trans_count" : 0
}
"""

NVME_ENHANCED_EXPECTED = {
    "temperature_celsius": 36.9,  # 310 K
    "avail_spare": 100,
    "spare_thresh": 10,
    "percent_used": 3,
    "data_units_read": 12345678,
    "data_units_written": 23456789,
    "host_read_commands": 345678901,
    "host_write_commands": 456789012,
    "controller_busy_time": 1234,
    "power_cycles": 56,
    "power_on_hours": 7890,
    "unsafe_shutdowns": 12,
    "media_errors": 0,
    "num_err_log_entries": 34,
    "warning_temp_time": 0,
    "critical_comp_time": 0,
}

# `smartctl -i /dev/sda`.
SMARTCTL_I_SAMSUNG_SSD = SMARTCTL_BANNER + (
    "=== START OF INFORMATION SECTION ===\n"
    "Model Family:     Samsung based SSDs\n"
    "Device Model:     Samsung SSD 860 EVO 500GB\n"
    "Serial Number:    S3Z2NB0K123456A\n"
    "LU WWN Device Id: 5 002538 e40a1b2c3\n"
    "Firmware Version: RVT03B6Q\n"
    "User Capacity:    500,107,862,016 bytes [500 GB]\n"
    "Sector Size:      512 bytes logical/physical\n"
    "Rotation Rate:    Solid State Device\n"
    "Form Factor:      2.5 inches\n"
    "Local Time is:    Tue Feb 13 08:15:30 2024 UTC\n"
    "SMART support is: Enabled\n"
    "\n"
)


# --- get_life_attribute_for_drive / calculate_percentage_used -------------


def test_life_attribute_matches_vendor_in_family_or_model_case_insensitively():
    life = smart_storage.get_life_attribute_for_drive
    assert life("Samsung based SSDs", None) == "177"
    assert life(None, "INTEL SSDSC2KB480G8") == "233"
    assert life("Crucial/Micron Client SSDs", "CT500MX500SSD1") == "202"
    assert life(None, "WDC WDS500G2B0A-00SM50") == "231"
    assert life("Unknown family", "ACME SSD 1TB") is None
    assert life(None, None) is None


def test_percentage_used_nvme_reads_percent_used_verbatim():
    calc = smart_storage.calculate_percentage_used
    assert calc({"device_type": "nvme", "percent_used": 3}) == 3
    assert calc({"device_type": "nvme"}) is None


def test_percentage_used_none_for_rotational_drive():
    """A spinning disk has no wear figure, whatever life-like attribute it
    happens to expose."""
    results = {
        "device_type": "ata",
        "rotation_rate": "7200 rpm",
        "data_address_mark_errors_pct": 100,
    }
    assert smart_storage.calculate_percentage_used(results) is None


def test_percentage_used_vendor_attribute_wins_over_fallback_order():
    """An Intel SSD exposes 232 (Available_Reservd_Space) AND 233
    (Media_Wearout_Indicator); its vendor entry picks 233 although 232
    comes first in the fallback order."""
    results = {
        "device_type": "ata",
        "rotation_rate": "Solid State Device",
        "endurance_remaining_pct": 100,
        "media_wearout_indicator_pct": 20,
    }
    assert (
        smart_storage.calculate_percentage_used(
            results, model_family="Intel 730 and DC S35x0/3610/3700 Series SSDs"
        )
        == 80
    )


def test_percentage_used_falls_back_when_vendor_attribute_unread():
    """Samsung maps to 177; when that value is missing the fallback order
    still finds 231."""
    results = {"wear_leveling_count_pct": None, "life_left_pct": 90}
    assert (
        smart_storage.calculate_percentage_used(
            results, model_family="Samsung based SSDs"
        )
        == 10
    )


def test_percentage_used_fallback_clamps_and_none_without_attributes():
    calc = smart_storage.calculate_percentage_used
    # Unknown vendor: first fallback attribute present is used.
    assert calc({"endurance_remaining_pct": 0}, device_model="ACME SSD") == 100
    # A normalized VALUE above 100 clamps to 0, never a negative percentage.
    assert calc({"endurance_remaining_pct": 120}) == 0
    assert calc({"device_type": "ata"}) is None


# --- is_partition / list_storage_devices ----------------------------------


@pytest.mark.parametrize(
    "device, expected",
    [
        ("/dev/nvme0n1p1", True),
        ("/dev/sda1", True),
        ("/dev/sda", False),
        ("/dev/nvme0", False),
        ("/dev/nvme0n1", False),
        ("/dev/bus/0", False),
    ],
)
def test_is_partition(device, expected):
    assert smart_storage.is_partition(device) is expected


def test_list_storage_devices_parses_scan_and_drops_partitions(monkeypatch):
    scan = (
        b"/dev/sda -d sat # /dev/sda [SAT], ATA device\n"
        b"/dev/sda1 -d sat # /dev/sda1 [SAT], ATA device\n"
        b"/dev/sdb -d scsi # /dev/sdb, SCSI device\n"
        b"/dev/nvme0 -d nvme # /dev/nvme0, NVMe device\n"
    )
    run = mock.Mock(return_value=_proc(0, scan))
    monkeypatch.setattr(smart_storage, "run_privileged", run)

    assert smart_storage.list_storage_devices() == [
        "/dev/sda",
        "/dev/sdb",
        "/dev/nvme0",
    ]
    cmd = run.call_args.args[0]
    assert cmd[0] == "sudo"
    assert cmd[-2:] == ["smartctl", "--scan"]


# --- get_nvme_enhanced_info -----------------------------------------------


def test_nvme_enhanced_info_maps_smart_log_json(monkeypatch):
    """Whitelisted keys only, temperature converted from Kelvin."""
    run = mock.Mock(return_value=_proc(0, NVME_SMART_LOG_JSON))
    monkeypatch.setattr(smart_storage, "run_privileged", run)

    assert smart_storage.get_nvme_enhanced_info("/dev/nvme0") == NVME_ENHANCED_EXPECTED
    cmd = run.call_args.args[0]
    assert cmd[0] == "sudo"
    assert cmd[-5:] == ["nvme", "smart-log", "/dev/nvme0", "-o", "json"]


def test_nvme_enhanced_info_empty_and_logged_on_bad_json(monkeypatch):
    monkeypatch.setattr(
        smart_storage, "run_privileged", mock.Mock(return_value=_proc(0, "{trunc"))
    )
    log = mock.Mock()
    monkeypatch.setattr(smart_storage, "log", log)

    assert smart_storage.get_nvme_enhanced_info("/dev/nvme0") == {}
    message, level = log.call_args.args
    assert level == "error"
    assert "/dev/nvme0" in message


# --- get_storage_info on real output ---------------------------------------


def test_get_storage_info_parses_ata_attribute_table(monkeypatch):
    """The banner before the section is skipped, the table header and blank
    lines are not rows, every row maps by ID (unknown IDs as smart_attr_N),
    life attributes also keep their normalized VALUE, and percentage_used is
    derived from it."""
    run = mock.Mock(return_value=_proc(0, SMARTCTL_AH_SAMSUNG_SSD))
    monkeypatch.setattr(smart_storage, "run_privileged", run)

    info = smart_storage.get_storage_info("/dev/sda")

    cmd = run.call_args.args[0]
    assert cmd[0] == "sudo"
    assert cmd[-4:] == ["smartctl", "-A", "-H", "/dev/sda"]
    # Wire names are spelled out. Row 9 pins TODAY's bug: SMART_ATTRIBUTE_NAMES
    # is shifted by one for ids 6-10 against smartmontools (9 is
    # Power_On_Hours, 10 Spin_Retry_Count), so power-on hours ship as
    # spin_retry_count (#229). A fix must change this line.
    assert info == {
        "device": "sda",
        "device_type": "ata",
        "smart_overall_health": "PASSED",
        "reallocated_sector_ct": 0,
        "spin_retry_count": 21567,
        "power_cycle_count": 512,
        "wear_leveling_count": 42,
        "wear_leveling_count_pct": 97,
        "smart_attr_179": 0,
        "temperature_celsius": 33,
        "total_lbas_written": 28745830212,
        "percentage_used": 3,
    }


def test_get_storage_info_bad_attribute_row_is_skipped_and_logged(monkeypatch):
    """One attribute row that fails to parse is logged and skipped; the
    rest of the table and the device itself still ship."""
    monkeypatch.setattr(
        smart_storage,
        "run_privileged",
        mock.Mock(return_value=_proc(0, SMARTCTL_AH_SAMSUNG_SSD)),
    )
    real_convert = smart_storage.safe_int_conversion

    def convert(value, base=10):
        if value == "512":  # Power_Cycle_Count's raw value
            raise RuntimeError("unparseable row")
        return real_convert(value, base)

    monkeypatch.setattr(smart_storage, "safe_int_conversion", convert)
    log = mock.Mock()
    monkeypatch.setattr(smart_storage, "log", log)

    info = smart_storage.get_storage_info("/dev/sda")

    assert "power_cycle_count" not in info
    assert info["reallocated_sector_ct"] == 0
    assert info["total_lbas_written"] == 28745830212
    assert info["wear_leveling_count_pct"] == 97
    log.assert_called_once()
    message, level = log.call_args.args
    assert level == "error"
    assert "unparseable row" in message


def test_get_storage_info_nvme_end_to_end_with_nvme_cli(monkeypatch):
    """smartctl's NVMe section plus nvme-cli's smart-log, both through the
    sudo boundary; percentage_used is nvme-cli's percent_used."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "smart-log" in cmd:
            return _proc(0, NVME_SMART_LOG_JSON)
        return _proc(0, SMARTCTL_AH_NVME)

    monkeypatch.setattr(smart_storage, "run_privileged", fake_run)

    info = smart_storage.get_storage_info("/dev/nvme0", nvme_available=lambda: True)

    assert info == {
        "device": "nvme0",
        "device_type": "nvme",
        "smart_overall_health": "PASSED",
        "critical_warning": 0,
        **NVME_ENHANCED_EXPECTED,
        "percentage_used": 3,
    }
    assert len(calls) == 2


def test_get_storage_info_maps_identification_keys_in_section(monkeypatch):
    """Identification keys are mapped wherever they appear after the section
    header, and a rotational Rotation Rate keeps a life attribute from being
    read as SSD wear."""
    out = (
        "=== START OF READ SMART DATA SECTION ===\n"
        "Device Model:     ST2000DM008-2FR102\n"
        "Rotation Rate:    7200 rpm\n"
        "177 Wear_Leveling_Count     0x0013   097   097   000    Pre-fail  Always"
        "       -       42\n"
    )
    monkeypatch.setattr(
        smart_storage, "run_privileged", mock.Mock(return_value=_proc(0, out))
    )

    info = smart_storage.get_storage_info("/dev/sdb")

    assert info["device_model"] == "ST2000DM008-2FR102"
    assert info["rotation_rate"] == "7200 rpm"
    assert info["wear_leveling_count_pct"] == 97
    assert "percentage_used" not in info


# --- get_storage_identification on real output -----------------------------


def test_get_storage_identification_parses_information_section(monkeypatch):
    """Mapped keys only; the banner, the section header and blank lines carry
    no colon-separated pair and are skipped."""
    run = mock.Mock(return_value=_proc(0, SMARTCTL_I_SAMSUNG_SSD))
    monkeypatch.setattr(smart_storage, "run_privileged", run)

    info = smart_storage.get_storage_identification("/dev/sda")

    cmd = run.call_args.args[0]
    assert cmd[0] == "sudo"
    assert cmd[-3:] == ["smartctl", "-i", "/dev/sda"]
    assert info == {
        "device": "sda",
        "model_family": "Samsung based SSDs",
        "device_model": "Samsung SSD 860 EVO 500GB",
        "serial_number": "S3Z2NB0K123456A",
        "firmware_version": "RVT03B6Q",
        "total_capacity": "500,107,862,016 bytes [500 GB]",
        "sector_size": "512 bytes logical/physical",
        "rotation_rate": "Solid State Device",
    }


# --- safe_temperature_conversion --------------------------------------------


def test_safe_temperature_conversion():
    convert = smart_storage.safe_temperature_conversion
    assert convert("36 Celsius") == 36
    assert convert("36") == 36
    assert convert("") is None
    assert convert(None) is None
    assert convert("n/a") is None
    # Undecoded output (bytes) is not text: None, never a TypeError.
    assert convert(b"36 Celsius") is None
