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
    assert cmd[-7:] == ["smartctl", "-i", "-A", "-H", "-l", "ssd", "/dev/sda"]
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


# --- real worn SSDs: the wear figure the dashboard shows (#230) -----------
#
# `smartctl -i -A -H -l ssd` on two SATA SSDs from a field report, rebuilt
# from their `smartctl -x` (serial numbers and WWNs replaced). Before #230 the
# agent read neither identity nor Device Statistics, the fallback order picked
# 232 Available_Reservd_Space, and the dashboard showed 99% and 100% life for
# drives at 1% and 72% by their Media_Wearout_Indicator.

SMARTCTL_74_BANNER = (
    "smartctl 7.4 2023-08-01 r5530 [x86_64-linux-6.8.0-147-generic] (local build)\n"
    "Copyright (C) 2002-23, Bruce Allen, Christian Franke, www.smartmontools.org\n"
    "\n"
)

# In smartctl's drive database: Model Family names the vendor.
INTEL_S4510_INFO = (
    "=== START OF INFORMATION SECTION ===\n"
    "Model Family:     Intel S4510/S4610/S4500/S4600 Series SSDs\n"
    "Device Model:     INTEL SSDSC2KB480G8\n"
    "Serial Number:    TESTSERIAL0000001\n"
    "LU WWN Device Id: 5 5cd2e4 000000001\n"
    "Firmware Version: XCV10100\n"
    "User Capacity:    480,103,981,056 bytes [480 GB]\n"
    "Sector Sizes:     512 bytes logical, 4096 bytes physical\n"
    "Rotation Rate:    Solid State Device\n"
    "Form Factor:      2.5 inches\n"
    "TRIM Command:     Available, deterministic, zeroed\n"
    "Device is:        In smartctl database 7.3/5528\n"
    "ATA Version is:   ACS-3 T13/2161-D revision 5\n"
    "SATA Version is:  SATA 3.2, 6.0 Gb/s (current: 6.0 Gb/s)\n"
    "Local Time is:    Sat Oct 31 21:26:22 2026 UTC\n"
    "SMART support is: Available - device has SMART capability.\n"
    "SMART support is: Enabled\n"
    "\n"
)

# Rated endurance used up: 233 is at its floor (001) while 232, spare blocks,
# still reads 099.
INTEL_S4510_ATTRIBUTES = (
    "=== START OF READ SMART DATA SECTION ===\n"
    "SMART overall-health self-assessment test result: PASSED\n"
    "\n"
    "SMART Attributes Data Structure revision number: 1\n"
    "Vendor Specific SMART Attributes with Thresholds:\n"
    "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n"
    "  5 Reallocated_Sector_Ct   0x0032   099   099   000    Old_age   Always       -       2\n"
    "  9 Power_On_Hours          0x0032   100   100   000    Old_age   Always       -       67155\n"
    " 12 Power_Cycle_Count       0x0032   100   100   000    Old_age   Always       -       31\n"
    "170 Available_Reservd_Space 0x0033   099   099   010    Pre-fail  Always       -       0\n"
    "171 Program_Fail_Count      0x0032   100   100   000    Old_age   Always       -       1\n"
    "172 Erase_Fail_Count        0x0032   100   100   000    Old_age   Always       -       0\n"
    "174 Unsafe_Shutdown_Count   0x0032   100   100   000    Old_age   Always       -       29\n"
    "175 Power_Loss_Cap_Test     0x0033   100   100   010    Pre-fail  Always       -       2693 (31 65535)\n"
    "183 SATA_Downshift_Count    0x0032   100   100   000    Old_age   Always       -       0\n"
    "184 End-to-End_Error_Count  0x0033   100   100   090    Pre-fail  Always       -       0\n"
    "187 Uncorrectable_Error_Cnt 0x0032   100   100   000    Old_age   Always       -       0\n"
    "190 Drive_Temperature       0x0022   060   056   000    Old_age   Always       -       40 (Min/Max 31/44)\n"
    "192 Unsafe_Shutdown_Count   0x0032   100   100   000    Old_age   Always       -       29\n"
    "194 Temperature_Celsius     0x0022   100   100   000    Old_age   Always       -       40\n"
    "197 Pending_Sector_Count    0x0012   100   100   000    Old_age   Always       -       0\n"
    "199 CRC_Error_Count         0x003e   100   100   000    Old_age   Always       -       0\n"
    "225 Host_Writes_32MiB       0x0032   100   100   000    Old_age   Always       -       135420975\n"
    "226 Workld_Media_Wear_Indic 0x0032   100   100   000    Old_age   Always       -       102390\n"
    "227 Workld_Host_Reads_Perc  0x0032   100   100   000    Old_age   Always       -       1\n"
    "228 Workload_Minutes        0x0032   100   100   000    Old_age   Always       -       4029179\n"
    "232 Available_Reservd_Space 0x0033   099   099   010    Pre-fail  Always       -       0\n"
    "233 Media_Wearout_Indicator 0x0032   001   001   000    Old_age   Always       -       0\n"
    "234 Thermal_Throttle_Status 0x0032   100   100   000    Old_age   Always       -       0/0\n"
    "235 Power_Loss_Cap_Test     0x0033   100   100   010    Pre-fail  Always       -       2693 (31 65535)\n"
    "241 Host_Writes_32MiB       0x0032   100   100   000    Old_age   Always       -       135420975\n"
    "242 Host_Reads_32MiB        0x0032   100   100   000    Old_age   Always       -       2326984\n"
    "243 NAND_Writes_32MiB       0x0032   100   100   000    Old_age   Always       -       184610382\n"
    "\n"
)

# The drive's own figure: 104% of its rated endurance used.
INTEL_S4510_DEVSTAT = (
    "Device Statistics (GP Log 0x04)\n"
    "Page  Offset Size        Value Flags Description\n"
    "0x07  =====  =               =  ===  == Solid State Device Statistics (rev 1) ==\n"
    "0x07  0x008  1             104  ---  Percentage Used Endurance Indicator\n"
    "                                |||_ C monitored condition met\n"
    "                                ||__ D supports DSN\n"
    "                                |___ N normalized value\n"
    "\n"
)

# NOT in smartctl's drive database: no Model Family line, every attribute
# under its generic name; only the Device Model names the vendor.
TOSHIBA_HK6_INFO = (
    "=== START OF INFORMATION SECTION ===\n"
    "Device Model:     TOSHIBA KHK61RSE960G\n"
    "Serial Number:    TESTSERIAL0000002\n"
    "LU WWN Device Id: 5 8ce38e 000000002\n"
    "Firmware Version: 1DET6102\n"
    "User Capacity:    960,197,124,096 bytes [960 GB]\n"
    "Sector Sizes:     512 bytes logical, 4096 bytes physical\n"
    "Rotation Rate:    Solid State Device\n"
    "Form Factor:      2.5 inches\n"
    "TRIM Command:     Available, deterministic, zeroed\n"
    "Device is:        Not in smartctl database 7.3/5528\n"
    "ATA Version is:   ACS-3 (minor revision not indicated)\n"
    "SATA Version is:  SATA 3.2, 6.0 Gb/s (current: 6.0 Gb/s)\n"
    "Local Time is:    Sat Oct 31 22:32:20 2026 CET\n"
    "SMART support is: Available - device has SMART capability.\n"
    "SMART support is: Enabled\n"
    "\n"
)

TOSHIBA_HK6_ATTRIBUTES = (
    "=== START OF READ SMART DATA SECTION ===\n"
    "SMART overall-health self-assessment test result: PASSED\n"
    "\n"
    "SMART Attributes Data Structure revision number: 4258\n"
    "Vendor Specific SMART Attributes with Thresholds:\n"
    "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n"
    "  5 Reallocated_Sector_Ct   0x0013   100   100   010    Pre-fail  Always       -       0\n"
    "  9 Power_On_Hours          0x0012   100   100   000    Old_age   Always       -       56260\n"
    " 12 Power_Cycle_Count       0x0032   100   100   000    Old_age   Always       -       3\n"
    "173 Unknown_Attribute       0x0012   172   172   000    Old_age   Always       -       28\n"
    "175 Program_Fail_Count_Chip 0x0033   100   100   099    Pre-fail  Always       -       10084583211008\n"
    "179 Used_Rsvd_Blk_Cnt_Tot   0x0013   100   100   010    Pre-fail  Always       -       0\n"
    "181 Program_Fail_Cnt_Total  0x0032   100   100   000    Old_age   Always       -       0\n"
    "182 Erase_Fail_Count_Total  0x0032   100   100   000    Old_age   Always       -       0\n"
    "183 Runtime_Bad_Block       0x0032   100   100   000    Old_age   Always       -       0\n"
    "184 End-to-End_Error        0x0033   100   100   090    Pre-fail  Always       -       0\n"
    "187 Reported_Uncorrect      0x0032   100   100   000    Old_age   Always       -       0\n"
    "190 Airflow_Temperature_Cel 0x0022   076   071   000    Old_age   Always       -       24 (Min/Max 18/29)\n"
    "192 Power-Off_Retract_Count 0x0032   100   100   000    Old_age   Always       -       0\n"
    "194 Temperature_Celsius     0x0022   073   068   000    Old_age   Always       -       27 (Min/Max 21/32)\n"
    "197 Current_Pending_Sector  0x0012   100   100   000    Old_age   Always       -       0\n"
    "199 UDMA_CRC_Error_Count    0x000a   100   100   000    Old_age   Always       -       0\n"
    "232 Available_Reservd_Space 0x0013   100   100   010    Pre-fail  Always       -       0\n"
    "233 Media_Wearout_Indicator 0x0012   072   072   000    Old_age   Always       -       28\n"
    "234 Unknown_Attribute       0x0032   100   100   000    Old_age   Always       -       0\n"
    "241 Total_LBAs_Written      0x0032   100   100   000    Old_age   Always       -       111407976\n"
    "242 Total_LBAs_Read         0x0032   100   100   000    Old_age   Always       -       6581295\n"
    "243 Unknown_Attribute       0x0012   100   100   000    Old_age   Always       -       0\n"
    "249 Unknown_Attribute       0x0032   100   100   000    Old_age   Always       -       3885064\n"
    "\n"
)

TOSHIBA_HK6_DEVSTAT = (
    "Device Statistics (GP Log 0x04)\n"
    "Page  Offset Size        Value Flags Description\n"
    "0x07  =====  =               =  ===  == Solid State Device Statistics (rev 1) ==\n"
    "0x07  0x008  1              28  N--  Percentage Used Endurance Indicator\n"
    "                                |||_ C monitored condition met\n"
    "                                ||__ D supports DSN\n"
    "                                |___ N normalized value\n"
    "\n"
)


def _run_health(monkeypatch, *parts):
    run = mock.Mock(return_value=_proc(0, SMARTCTL_74_BANNER + "".join(parts)))
    monkeypatch.setattr(smart_storage, "run_privileged", run)
    return smart_storage.get_storage_info("/dev/sdb"), run.call_args.args[0]


@pytest.mark.parametrize(
    "parts, expected",
    [
        # Today's read: Device Statistics win, passing 100 like NVMe's figure.
        ((INTEL_S4510_INFO, INTEL_S4510_ATTRIBUTES, INTEL_S4510_DEVSTAT), 104),
        ((TOSHIBA_HK6_INFO, TOSHIBA_HK6_ATTRIBUTES, TOSHIBA_HK6_DEVSTAT), 28),
        # No Device Statistics page: the identity picks the vendor attribute
        # (Intel and Toshiba: 233), found by Model Family or by Device Model.
        ((INTEL_S4510_INFO, INTEL_S4510_ATTRIBUTES), 99),
        ((TOSHIBA_HK6_INFO, TOSHIBA_HK6_ATTRIBUTES), 28),
        # Neither (the pre-#230 read): 232 is named Available_Reservd_Space,
        # so the fallback order skips it for 233. It used to ship 1 and 0.
        ((INTEL_S4510_ATTRIBUTES,), 99),
        ((TOSHIBA_HK6_ATTRIBUTES,), 28),
    ],
    ids=[
        "intel-devstat",
        "toshiba-devstat",
        "intel-vendor-family",
        "toshiba-vendor-model",
        "intel-names-only",
        "toshiba-names-only",
    ],
)
def test_worn_ssd_reports_its_real_wear(monkeypatch, parts, expected):
    info, cmd = _run_health(monkeypatch, *parts)

    assert cmd == ["sudo", "smartctl", "-i", "-A", "-H", "-l", "ssd", "/dev/sdb"]
    assert info["percentage_used"] == expected


def test_worn_ssd_entry_keeps_its_wire_shape(monkeypatch):
    """The identity and the Device Statistics rows only feed percentage_used:
    no identity key ships in the health entry, no Device Statistics row is
    read as an attribute (they have ten tokens or more too), and the life
    attributes still ship their normalized VALUE."""
    info, _ = _run_health(
        monkeypatch, INTEL_S4510_INFO, INTEL_S4510_ATTRIBUTES, INTEL_S4510_DEVSTAT
    )

    assert info["device"] == "sdb"
    assert info["device_type"] == "ata"
    assert info["smart_overall_health"] == "PASSED"
    assert info["media_wearout_indicator"] == 0
    assert info["media_wearout_indicator_pct"] == 1
    assert info["endurance_remaining_pct"] == 99
    assert info["smart_attr_243"] == 184610382
    assert not set(smart_storage.STORAGE_IDENTIFICATION_ATTRIBUTES.values()) & set(info)
    assert not [key for key in info if key.startswith("smart_attr_0x")]


def test_endurance_indicator_flagged_invalid_falls_back_to_attributes(monkeypatch):
    """smartctl prints '-' in the value column when the drive flags the
    indicator invalid: the attribute heuristics decide instead."""
    invalid = TOSHIBA_HK6_DEVSTAT.replace(
        "  28  N--  Percentage", "   -  N--  Percentage"
    )
    assert invalid != TOSHIBA_HK6_DEVSTAT

    info, _ = _run_health(
        monkeypatch, TOSHIBA_HK6_INFO, TOSHIBA_HK6_ATTRIBUTES, invalid
    )

    assert info["percentage_used"] == 28  # 233 by Device Model, not 104 or 0


def test_spinning_disk_identity_from_info_section_drops_wear(monkeypatch):
    """-i's Rotation Rate reaches the spinning-disk check, so a life-like
    attribute on an HDD ships no percentage_used (and no rotation_rate)."""
    info, _ = _run_health(
        monkeypatch,
        "=== START OF INFORMATION SECTION ===\n"
        "Device Model:     ST2000DM008-2FR102\n"
        "Rotation Rate:    7200 rpm\n"
        "\n",
        "=== START OF READ SMART DATA SECTION ===\n"
        "177 Wear_Leveling_Count     0x0013   097   097   000    Pre-fail  Always"
        "       -       42\n",
    )

    assert info["wear_leveling_count_pct"] == 97
    assert "percentage_used" not in info
    assert "rotation_rate" not in info


def test_percentage_used_endurance_indicator_wins_verbatim():
    calc = smart_storage.calculate_percentage_used
    results = {"device_type": "ata", "media_wearout_indicator_pct": 1}
    # Wins over the vendor attribute (which would say 99), and passes 100.
    assert calc(results, device_model="INTEL SSDSC2KB480G8", endurance_used=104) == 104
    assert calc(results, endurance_used=0) == 0
    # A spinning disk still reports no wear, whatever it claims.
    hdd = {"device_type": "ata", "rotation_rate": "7200 rpm"}
    assert calc(hdd, endurance_used=5) is None


def test_percentage_used_skips_attributes_named_as_something_else():
    calc = smart_storage.calculate_percentage_used
    # OCZ SandForce: the OCZ vendor entry says 233, which smartctl names
    # SandForce_Internal (VALUE 000) there; 231 SSD_Life_Left is the wear.
    sandforce = {
        "device_type": "ata",
        "media_wearout_indicator_pct": 0,
        "life_left_pct": 90,
    }
    names = {"233": "SandForce_Internal", "231": "SSD_Life_Left"}
    assert calc(sandforce, device_model="OCZ-VERTEX3", attribute_names=names) == 10
    # Every candidate named as something else: unknown, not 0% used.
    dell = {
        "device_type": "ata",
        "endurance_remaining_pct": 100,
        "media_wearout_indicator_pct": 100,
    }
    dell_names = {"232": "Available_Reservd_Space", "233": "Total_LBAs_Written"}
    assert (
        calc(
            dell,
            model_family="Dell Certified Intel S4x00/D3-S4x10 Series SSDs",
            attribute_names=dell_names,
        )
        is None
    )


def test_not_wear_names_leave_wear_and_generic_names_alone():
    """The deny list never holds a wear name, nor the generic names an older
    smartctl gives 231/202 on a drive it does not know (they keep counting)."""
    keep = {
        "Media_Wearout_Indicator",
        "Wear_Leveling_Count",
        "SSD_Life_Left",
        "Percent_Lifetime_Remain",
        "Remaining_Lifetime_Perc",
        "Temperature_Celsius",
        "Data_Address_Mark_Errs",
    }
    assert not keep & smart_storage.NOT_WEAR_ATTRIBUTE_NAMES


def test_nvme_identity_from_info_section_ships_unchanged_entry(monkeypatch):
    # Value: protects=NVMe health entry with -i output keeps pre-#230 keys and nvme-cli percentage_used; fails_when=info parse leaks identity keys or swallows the NVMe section; why_new=NVMe e2e test has no INFORMATION section; seam=none; no_claim=Device Statistics on NVMe
    def fake_run(cmd, **kwargs):
        if "smart-log" in cmd:
            return _proc(0, NVME_SMART_LOG_JSON)
        return _proc(
            0,
            SMARTCTL_BANNER + "=== START OF INFORMATION SECTION ===\n"
            "Model Number:                       Samsung SSD 980 PRO 1TB\n"
            "Serial Number:                      TESTSERIAL0000003\n"
            "Firmware Version:                   5B2QGXA7\n"
            "\n" + SMARTCTL_AH_NVME.removeprefix(SMARTCTL_BANNER),
        )

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


# A Plextor M6S as smartctl's drive database names it: 177 Wear_Leveling_Count
# (the vendor wear attribute), 232 Available_Reservd_Space, 233
# Media_Wearout_Indicator. The vendor id and the fallback order disagree here.
PLEXTOR_M6S_INFO = (
    "=== START OF INFORMATION SECTION ===\n"
    "Model Family:     Plextor M3/M5/M6/M7 Series SSDs\n"
    "Device Model:     PLEXTOR PX-256M6S\n"
    "Rotation Rate:    Solid State Device\n"
    "\n"
)

PLEXTOR_M6S_ATTRIBUTES = (
    "=== START OF READ SMART DATA SECTION ===\n"
    "SMART overall-health self-assessment test result: PASSED\n"
    "\n"
    "ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE\n"
    "177 Wear_Leveling_Count     0x0003   091   091   000    Pre-fail  Always       -       256\n"
    "232 Available_Reservd_Space 0x0003   100   100   010    Pre-fail  Always       -       0\n"
    "233 Media_Wearout_Indicator 0x0003   096   096   000    Pre-fail  Always       -       0\n"
    "\n"
)


def test_identity_picks_the_vendor_attribute_over_the_fallback_order(monkeypatch):
    """The -i identity decides which attribute is the wear figure: Plextor's
    177 (VALUE 091 -> 9 used) wins over the fallback order's 233 (VALUE 096
    -> 4 used), which is what the same attributes read without an identity."""
    with_identity, _ = _run_health(
        monkeypatch, PLEXTOR_M6S_INFO, PLEXTOR_M6S_ATTRIBUTES
    )
    without_identity, _ = _run_health(monkeypatch, PLEXTOR_M6S_ATTRIBUTES)

    assert with_identity["percentage_used"] == 9
    assert without_identity["percentage_used"] == 4


# smartctl 6.2 and 6.3 (CentOS 7.0-7.4, Debian 8, Ubuntu 14.04) print Device
# Statistics with a DECIMAL page number and mark a normalized value with a '~'
# suffix; the rows below use smartmontools RELEASE_6_2 ataprint.cpp's own
# format strings.
OLD_SMARTCTL_DEVSTAT = (
    "Device Statistics (GP Log 0x04)\n"
    "Page Offset Size         Value  Description\n"
    + "%3d%s%s (rev %d) ==\n"
    % (7, "  =====  =                =  == ", "Solid State Device Statistics", 1)
    + "%3d  0x%03x  %d%c %15s%c %s\n"
    % (7, 8, 1, " ", "104", "~", "Percentage Used Endurance Indicator")
    + "%30s|_ ~ normalized value\n" % ""
    + "\n"
)


def test_old_smartctl_decimal_device_statistics_are_read_not_parsed_as_attributes(
    monkeypatch,
):
    """The decimal page title has ten tokens and starts with "7": it must not
    become SMART attribute 7 (a new seek_time_performance key, or an
    overwritten real one), and the decimal value row still feeds the
    endurance indicator (104, where the attributes would say 99)."""
    info, _ = _run_health(
        monkeypatch, INTEL_S4510_INFO, INTEL_S4510_ATTRIBUTES, OLD_SMARTCTL_DEVSTAT
    )

    assert info["percentage_used"] == 104
    assert "seek_time_performance" not in info


def test_unknown_rotation_rate_is_not_a_spinning_disk():
    """smartctl prints "Unknown (0x....)" for a reserved rotation value, which
    some SSDs and USB bridges report: only "<N> rpm" means a spinning disk."""
    calc = smart_storage.calculate_percentage_used
    ssd = {"device_type": "ata", "rotation_rate": "Unknown (0x0005)"}
    assert calc(ssd, endurance_used=12) == 12
    assert calc({**ssd, "media_wearout_indicator_pct": 90}) == 10
