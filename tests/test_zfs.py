"""Tests for the ZFS pool health collector."""

import json
import os

import pytest

from fivenines_agent import zfs

# ---------------------------------------------------------------------------
# Canned `zpool` CLI output for the shared contract scenario. These strings are
# the source the fixture was generated from; the round-trip test re-derives the
# payload and asserts equality with tests/fixtures/zfs_contract_payload.json.
# ---------------------------------------------------------------------------

VERSION_OUT = "zfs-2.2.2-1\nzfs-kmod-2.2.2-1\n"

POOL_NAMES_OUT = "rpool\ntank\n"

LIST_SUMMARY_OUT = (
    "rpool\tONLINE\t1000204886016\t500102443008\t500102443008\t5\t50\t1.00\n"
    "tank\tDEGRADED\t4000787030016\t1200236109004\t2800550921012\t12\t30\t1.00\n"
)

STATUS_RPOOL = (
    "  pool: rpool\n"
    " state: ONLINE\n"
    "  scan: scrub repaired 0B in 00:12:34 with 0 errors on Sun Jul  7 03:12:34 2026\n"
    "config:\n"
    "\n"
    "\tNAME        STATE     READ WRITE CKSUM\n"
    "\trpool       ONLINE       0     0     0\n"
    "\t  mirror-0  ONLINE       0     0     0\n"
    "\t    sda     ONLINE       0     0     0\n"
    "\t    sdb     ONLINE       0     0     0\n"
    "\n"
    "errors: No known data errors\n"
)

STATUS_TANK = (
    "  pool: tank\n"
    " state: DEGRADED\n"
    "status: One or more devices is currently being resilvered.\n"
    "action: Wait for the resilver to complete.\n"
    "  scan: resilver in progress since Mon Jul 13 01:00:00 2026\n"
    "\t1234567890 scanned at 12345678/s, 987654321 issued at 9876543/s, 4000787030016 total\n"
    "\t500000000 resilvered, 42.13% done, 00:34:56 to go\n"
    "config:\n"
    "\n"
    "\tNAME        STATE     READ WRITE CKSUM\n"
    "\ttank        DEGRADED     0     0     0\n"
    "\t  mirror-0  DEGRADED     0     0     0\n"
    "\t    sdc     ONLINE       0     0     0\n"
    "\t    sdd     FAULTED      3     0     0  too many errors\n"
    "\n"
    "errors: No known data errors\n"
)


class FakeProc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_passes_through_to_subprocess(monkeypatch):
    """_run is a thin wrapper: clean env, no raise, pipes captured."""
    captured = {}

    def fake(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return FakeProc(0, "ok")

    monkeypatch.setattr(zfs.subprocess, "run", fake)
    proc = zfs._run(["zpool", "version"])
    assert proc.stdout == "ok"
    assert captured["cmd"] == ["zpool", "version"]
    assert captured["kwargs"]["check"] is False
    assert captured["kwargs"]["timeout"] == zfs._SUBPROCESS_TIMEOUT


def test_run_timeout_returns_synthetic_failure(monkeypatch):
    """A hung zpool must not hang the tick. TimeoutExpired is caught in _run and
    returned as a failed result -- indistinguishable from a failed command, so
    every downstream failure path applies unchanged. No exception escapes."""

    def boom(cmd, **kwargs):
        raise zfs.subprocess.TimeoutExpired(cmd, zfs._SUBPROCESS_TIMEOUT)

    monkeypatch.setattr(zfs.subprocess, "run", boom)
    proc = zfs._run(["zpool", "status", "-pPLv", "rpool"])
    assert proc.returncode != 0
    assert proc.stdout == ""
    assert "timeout" in proc.stderr


def _contract_run(cmd):
    """Dispatcher matching the contract scenario (all commands succeed)."""
    if "version" in cmd:
        return FakeProc(0, VERSION_OUT)
    if "status" in cmd:
        pool = cmd[-1]
        return FakeProc(0, STATUS_RPOOL if pool == "rpool" else STATUS_TANK)
    if "-Hp" in cmd:
        return FakeProc(0, LIST_SUMMARY_OUT)
    if "list" in cmd:
        return FakeProc(0, POOL_NAMES_OUT)
    raise AssertionError("unexpected cmd: {}".format(cmd))


@pytest.fixture(autouse=True)
def _reset_cache():
    """Each test starts with a cold cache."""
    zfs._zfs_cache["timestamp"] = 0
    zfs._zfs_cache["data"] = []
    yield


# ---------------------------------------------------------------------------
# Shared contract round-trip
# ---------------------------------------------------------------------------

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "zfs_contract_payload.json"
)


def test_contract_fixture_round_trip(monkeypatch):
    """SHARED FIXTURE (cross-repo contract): fixtures/zfs_contract_payload.json.

    The same file is asserted on both sides:
    - here: zfs_storage_health(**config) must equal the scenario payload with
      only zfs._run and shutil.which mocked (canned CLI above), pinning the
      whole probe -> parse -> payload pipeline;
    - fivenines-server: its ZFS ingester posts the payload under data["zfs"].

    Change the payload shape only in lockstep with the server spec and its copy.
    """
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)
    scenario = fixture["scenarios"]["healthy_and_degraded"]

    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")
    monkeypatch.setattr(zfs, "_run", _contract_run)

    out = zfs.zfs_storage_health(**scenario["config"])

    assert out == scenario["payload"]


def test_contract_fixture_null_scenario(monkeypatch):
    """The collection-failure scenario pins data["zfs"] = null: a real listing
    failure must produce exactly None (the server keys off this to NOT prune)."""
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)
    scenario = fixture["scenarios"]["collection_failure"]
    assert scenario["payload"] is None  # the pinned contract value

    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(1, "", "boom"))

    assert zfs.zfs_storage_health(**scenario["config"]) is None


def test_contract_health_code_mapping_matches_fixture():
    """The numeric health codes are a stable contract; guard against renumbering."""
    with open(_FIXTURE_PATH) as f:
        fixture = json.load(f)
    for code_str, state in fixture["health_code_contract"].items():
        if code_str == "_note" or code_str == "null":
            continue
        assert zfs._HEALTH_CODES[state] == int(code_str)
    # Every code in the module is documented in the fixture, and vice versa.
    documented = {
        v
        for k, v in fixture["health_code_contract"].items()
        if k not in ("_note", "null")
    }
    assert documented == set(zfs._HEALTH_CODES)


# ---------------------------------------------------------------------------
# zfs_available / get_zfs_version / list_zfs_pools
# ---------------------------------------------------------------------------


def test_zfs_available_true(monkeypatch):
    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")
    assert zfs.zfs_available() is True


def test_zfs_available_false(monkeypatch):
    monkeypatch.setattr(zfs.shutil, "which", lambda _: None)
    assert zfs.zfs_available() is False


def test_get_zfs_version_ok(monkeypatch):
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(0, VERSION_OUT))
    assert zfs.get_zfs_version() == "zfs-2.2.2-1"


def test_get_zfs_version_failure(monkeypatch):
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(1, "", "boom"))
    assert zfs.get_zfs_version() is None


def test_get_zfs_version_empty(monkeypatch):
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(0, "\n"))
    assert zfs.get_zfs_version() is None


def test_list_zfs_pools_ok(monkeypatch):
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(0, POOL_NAMES_OUT))
    assert zfs.list_zfs_pools() == ["rpool", "tank"]


def test_list_zfs_pools_failure(monkeypatch):
    """Command failure -> None (distinct from [] = zero pools)."""
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(2, "", "boom"))
    assert zfs.list_zfs_pools() is None


def test_list_zfs_pools_empty(monkeypatch):
    """Command succeeded, zero pools -> [] (distinct from None = failure)."""
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(0, ""))
    assert zfs.list_zfs_pools() == []


# ---------------------------------------------------------------------------
# _safe_int
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("42", 42),
        ("3.9", 3),  # float string -> truncated int
        (7, 7),
        ("-", None),  # invalid -> default
        (None, None),
    ],
)
def test_safe_int(value, expected):
    assert zfs._safe_int(value) == expected


def test_safe_int_custom_default():
    assert zfs._safe_int("nope", 60) == 60


# ---------------------------------------------------------------------------
# _health_code
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "health,code",
    [
        ("ONLINE", 0),
        ("DEGRADED", 1),
        ("FAULTED", 2),
        ("OFFLINE", 3),
        ("REMOVED", 4),
        ("UNAVAIL", 5),
        ("SUSPENDED", 6),  # missing from the original issue, added here
        ("online", 0),  # case-insensitive
        (" DEGRADED ", 1),  # whitespace tolerant
    ],
)
def test_health_code_known(health, code):
    assert zfs._health_code(health) == code


@pytest.mark.parametrize("health", [None, "", "WEIRD_STATE"])
def test_health_code_unknown(health):
    assert zfs._health_code(health) is None


# ---------------------------------------------------------------------------
# _count_degraded_vdevs
# ---------------------------------------------------------------------------


def test_count_degraded_vdevs_none_tree():
    assert zfs._count_degraded_vdevs(None) is None


def test_count_degraded_vdevs_healthy():
    tree = zfs._parse_zpool_status(STATUS_RPOOL)["rpool"]["vdev_tree"]
    assert zfs._count_degraded_vdevs(tree) == 0


def test_count_degraded_vdevs_degraded():
    tree = zfs._parse_zpool_status(STATUS_TANK)["tank"]["vdev_tree"]
    # mirror-0 (DEGRADED) + sdd (FAULTED)
    assert zfs._count_degraded_vdevs(tree) == 2


def test_count_degraded_vdevs_ignores_spares_and_states():
    tree = {
        "children": [
            {
                "state": "ONLINE",
                "children": [
                    {"state": "AVAIL"},  # spare, healthy -> not counted
                    {"state": "INUSE"},  # spare, healthy -> not counted
                    {"state": "REMOVED"},  # counted
                ],
            },
            {"state": None},  # missing state -> not counted
        ]
    }
    assert zfs._count_degraded_vdevs(tree) == 1


def test_count_degraded_vdevs_reaches_section_devices_via_parser():
    """Pin the parser invariant _count_degraded_vdevs' docstring relies on: a
    FAULTED device in a SECTION (logs) is reachable through 'children' by the
    walk. Exercises the real parser, not a hand-built tree, and confirms the
    device is counted exactly once despite also living in tree['logs']."""
    text = (
        "  pool: tank\n"
        " state: DEGRADED\n"
        "  scan: none requested\n"
        "config:\n"
        "\n"
        "\tNAME        STATE     READ WRITE CKSUM\n"
        "\ttank        DEGRADED     0     0     0\n"
        "\t  sda       ONLINE       0     0     0\n"
        "\tlogs\n"
        "\t  sdb       FAULTED      0     0     0\n"
        "\n"
        "errors: No known data errors\n"
    )
    tree = zfs._parse_zpool_status(text)["tank"]["vdev_tree"]
    assert [d["name"] for d in tree["logs"]] == ["sdb"]  # in the section list...
    assert zfs._count_degraded_vdevs(tree) == 1  # ...and counted once via children


# ---------------------------------------------------------------------------
# _parse_resilver_progress
# ---------------------------------------------------------------------------


def test_resilver_progress_none():
    assert zfs._parse_resilver_progress(None) is None


def test_resilver_progress_not_resilvering():
    assert zfs._parse_resilver_progress("scrub repaired 0B with 0 errors") == 0.0


def test_resilver_progress_in_progress():
    text = "resilver in progress since ... 42.13% done, 00:34:56 to go"
    assert zfs._parse_resilver_progress(text) == 42.13


def test_resilver_progress_in_progress_no_percent():
    # Resilvering but the percent is not (yet) present -> best-effort 0.0
    assert zfs._parse_resilver_progress("resilver in progress since ...") == 0.0


# ---------------------------------------------------------------------------
# _parse_scrub_errors
# ---------------------------------------------------------------------------


def test_scrub_errors_none_text():
    assert zfs._parse_scrub_errors(None) is None


def test_scrub_errors_none_requested():
    assert zfs._parse_scrub_errors("none requested") is None


def test_scrub_errors_in_progress():
    # A scrub in progress is not a completed scrub -> unknown
    assert zfs._parse_scrub_errors("scrub in progress since ... 10% done") is None


def test_scrub_errors_completed_clean():
    text = "scrub repaired 0B in 00:12:34 with 0 errors on Sun ..."
    assert zfs._parse_scrub_errors(text) == 0


def test_scrub_errors_completed_with_errors():
    text = "scrub repaired 1.5M in 01:02:03 with 7 errors on Sun ..."
    assert zfs._parse_scrub_errors(text) == 7


def test_scrub_errors_completed_but_unparseable_count():
    # Defensive: "scrub repaired" present but no "with N errors" token.
    assert zfs._parse_scrub_errors("scrub repaired 0B on Sun ...") is None


# ---------------------------------------------------------------------------
# _parse_zpool_status
# ---------------------------------------------------------------------------


def test_parse_status_simple_tree():
    pools = zfs._parse_zpool_status(STATUS_RPOOL)
    assert set(pools) == {"rpool"}
    tree = pools["rpool"]["vdev_tree"]
    assert tree["name"] == "rpool"
    assert tree["state"] == "ONLINE"
    assert [c["name"] for c in tree["children"]] == ["mirror-0"]
    leaves = tree["children"][0]["children"]
    assert [(d["name"], d["state"]) for d in leaves] == [
        ("sda", "ONLINE"),
        ("sdb", "ONLINE"),
    ]
    assert pools["rpool"]["errors"] == "No known data errors"
    assert "with 0 errors" in pools["rpool"]["scan_full"]


def test_parse_status_multiline_scan_captured():
    """The resilver continuation lines (with the percent) must be captured."""
    pools = zfs._parse_zpool_status(STATUS_TANK)
    scan_full = pools["tank"]["scan_full"]
    assert "resilver in progress" in scan_full
    assert "42.13% done" in scan_full
    assert pools["tank"]["vdev_tree"]["children"][0]["children"][1] == {
        "name": "sdd",
        "state": "FAULTED",
        "read": 3,
        "write": 0,
        "cksum": 0,
    }


def test_parse_status_multiple_pools():
    pools = zfs._parse_zpool_status(STATUS_RPOOL + STATUS_TANK)
    assert set(pools) == {"rpool", "tank"}


def test_parse_status_ignores_preamble_before_first_pool():
    """Lines before the first 'pool:' header (no current pool) are skipped."""
    pools = zfs._parse_zpool_status("no pools available\n" + STATUS_RPOOL)
    assert set(pools) == {"rpool"}


# A crafted status covering: both section-header forms (colon + bare), a spare
# with only 2 columns (_num IndexError), a device with a scaled count (_num
# ValueError), all four section lists, and a device shallower than the root
# (the _push_by_indent root-fallback branch).
STATUS_SECTIONS = (
    "  pool: mix\n"
    " state: ONLINE\n"
    "  scan: none requested\n"
    "config:\n"
    "\n"
    "\tNAME        STATE     READ WRITE CKSUM\n"
    "\tmix         ONLINE       0     0     0\n"
    "\t  raidz1-0  ONLINE       0     0     0\n"
    "\t    sda     ONLINE     1.2K    0     0\n"
    "\t    sdb     ONLINE       0     0     0\n"
    "\tlogs\n"
    "\t  sdc       ONLINE       0     0     0\n"
    "\tcache\n"
    "\t  nvme0     ONLINE       0     0     0\n"
    "\tspecial:\n"
    "\t  sdd       ONLINE       0     0     0\n"
    "\tspares\n"
    "\t  sde       AVAIL\n"
    "\n"
    "errors: No known data errors\n"
)


def test_parse_status_sections_and_edge_columns():
    pools = zfs._parse_zpool_status(STATUS_SECTIONS)
    tree = pools["mix"]["vdev_tree"]
    # Section lists populated.
    assert [d["name"] for d in tree["logs"]] == ["sdc"]
    assert [d["name"] for d in tree["cache"]] == ["nvme0"]
    assert [d["name"] for d in tree["special"]] == ["sdd"]
    assert [d["name"] for d in tree["spares"]] == ["sde"]
    # Scaled count "1.2K" is not an int -> None (no crash).
    sda = tree["children"][0]["children"][0]
    assert sda["name"] == "sda" and sda["read"] is None
    # Spare row had only 2 columns -> numeric fields None.
    sde = tree["spares"][0]
    assert sde == {
        "name": "sde",
        "state": "AVAIL",
        "read": None,
        "write": None,
        "cksum": None,
    }


def test_parse_status_device_shallower_than_root():
    """A device indented at/above the root pops the stack empty (root fallback)."""
    text = (
        "  pool: weird\n"
        " state: ONLINE\n"
        "config:\n"
        "\n"
        "\tNAME     STATE\n"
        "\t    weird   ONLINE 0 0 0\n"  # root, deeply indented
        "\t  shallow ONLINE 0 0 0\n"  # shallower than root -> attaches to root
    )
    tree = zfs._parse_zpool_status(text)["weird"]["vdev_tree"]
    assert tree["name"] == "weird"
    assert [c["name"] for c in tree["children"]] == ["shallow"]


# ---------------------------------------------------------------------------
# _zpool_list_summary
# ---------------------------------------------------------------------------


def test_zpool_list_summary_ok(monkeypatch):
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(0, LIST_SUMMARY_OUT))
    summary = zfs._zpool_list_summary()
    assert summary["rpool"]["health"] == "ONLINE"
    assert summary["rpool"]["summary"]["size_bytes"] == 1000204886016
    assert summary["rpool"]["summary"]["dedup_ratio"] == 1.0


def test_zpool_list_summary_dedup_dash_and_short_lines(monkeypatch):
    out = (
        "z\tONLINE\t100\t50\t50\t0\t50\t-\n"  # dedup '-' -> None
        "\n"  # blank -> filtered
        "short\tONLINE\t1\t2\n"  # <8 cols -> skipped
    )
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(0, out))
    summary = zfs._zpool_list_summary()
    assert set(summary) == {"z"}
    assert summary["z"]["summary"]["dedup_ratio"] is None


def test_zpool_list_summary_command_failure(monkeypatch):
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(1, "", "boom"))
    assert zfs._zpool_list_summary() == {}


# ---------------------------------------------------------------------------
# get_zfs_pool_info
# ---------------------------------------------------------------------------


def test_get_zfs_pool_info_normal(monkeypatch):
    monkeypatch.setattr(zfs, "_run", _contract_run)
    info = zfs.get_zfs_pool_info("tank")
    assert info["health"] == "DEGRADED"
    assert info["health_code"] == 1
    assert info["degraded_vdevs"] == 2
    assert info["resilver_progress"] == 42.13
    assert info["scrub_errors"] is None
    assert info["fragmentation"] == 12
    assert "zfs_version" not in info  # added by the caller, not here


def test_get_zfs_pool_info_status_p_fallback(monkeypatch):
    """`zpool status -pPLv` unsupported (old ZFS) -> retry `-PLv`."""
    calls = []

    def run(cmd):
        calls.append(list(cmd))
        if "version" in cmd:
            return FakeProc(0, VERSION_OUT)
        if "status" in cmd:
            if "-pPLv" in cmd:
                return FakeProc(2, "", "invalid option 'p'")
            return FakeProc(0, STATUS_RPOOL)
        if "-Hp" in cmd:
            return FakeProc(0, LIST_SUMMARY_OUT)
        return FakeProc(0, POOL_NAMES_OUT)

    monkeypatch.setattr(zfs, "_run", run)
    info = zfs.get_zfs_pool_info("rpool")
    assert info["health"] == "ONLINE"
    assert info["degraded_vdevs"] == 0  # parsed from the -PLv fallback output
    assert ["zpool", "status", "-pPLv", "rpool"] in calls
    assert ["zpool", "status", "-PLv", "rpool"] in calls


def test_get_zfs_pool_info_status_fails_but_in_summary(monkeypatch):
    """Both status calls fail; health still comes from `zpool list`."""

    def run(cmd):
        if "status" in cmd:
            return FakeProc(1, "", "status failed")
        if "-Hp" in cmd:
            return FakeProc(0, LIST_SUMMARY_OUT)
        return FakeProc(0, POOL_NAMES_OUT)

    monkeypatch.setattr(zfs, "_run", run)
    info = zfs.get_zfs_pool_info("rpool")
    assert info["health"] == "ONLINE"
    assert info["health_code"] == 0
    assert info["degraded_vdevs"] is None  # no vdev tree available
    assert info["resilver_progress"] is None
    assert info["scrub_errors"] is None
    assert info["vdev_tree"] is None
    assert info["fragmentation"] == 5  # still from list summary


def test_get_zfs_pool_info_unavailable_returns_none(monkeypatch):
    """Status fails AND pool absent from list summary -> None."""

    def run(cmd):
        if "status" in cmd:
            return FakeProc(1, "", "no such pool")
        return FakeProc(0, "")  # empty list summary

    monkeypatch.setattr(zfs, "_run", run)
    assert zfs.get_zfs_pool_info("ghost") is None


def test_get_zfs_pool_info_exception_returns_none(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")

    monkeypatch.setattr(zfs, "_zpool_list_summary", boom)
    assert zfs.get_zfs_pool_info("rpool") is None


def test_get_zfs_pool_info_status_timeout_degrades_to_list(monkeypatch):
    """A hung `zpool status` (both -pPLv and -PLv) is caught in _run as a
    failure, so the pool degrades to list-only health -- same outcome as
    test_get_zfs_pool_info_status_fails_but_in_summary, reached via a real
    timeout rather than a non-zero return code."""

    def run(cmd, **kwargs):
        if "status" in cmd:
            raise zfs.subprocess.TimeoutExpired(cmd, zfs._SUBPROCESS_TIMEOUT)
        return FakeProc(0, LIST_SUMMARY_OUT)  # `zpool list -Hp` still answers

    monkeypatch.setattr(zfs.subprocess, "run", run)
    info = zfs.get_zfs_pool_info("rpool")
    assert info["health"] == "ONLINE"
    assert info["degraded_vdevs"] is None
    assert info["resilver_progress"] is None
    assert info["vdev_tree"] is None


def test_get_zfs_pool_info_all_timeout_returns_none(monkeypatch):
    """Both `zpool status` and `zpool list` hang -> no health anywhere -> None,
    and no exception escapes."""

    def run(cmd, **kwargs):
        raise zfs.subprocess.TimeoutExpired(cmd, zfs._SUBPROCESS_TIMEOUT)

    monkeypatch.setattr(zfs.subprocess, "run", run)
    assert zfs.get_zfs_pool_info("rpool") is None


# ---------------------------------------------------------------------------
# zfs_storage_health
# ---------------------------------------------------------------------------


def test_storage_health_full(monkeypatch):
    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")
    monkeypatch.setattr(zfs, "_run", _contract_run)
    data = zfs.zfs_storage_health()
    assert [p["name"] for p in data] == ["rpool", "tank"]
    assert all("zfs_version" in p for p in data)
    # Cache populated.
    assert zfs._zfs_cache["data"] == data


def test_storage_health_cache_hit(monkeypatch):
    sentinel = [{"name": "cached"}]
    zfs._zfs_cache["timestamp"] = zfs.time.time()
    zfs._zfs_cache["data"] = sentinel

    def explode(_):
        raise AssertionError("_run must not be called on a cache hit")

    monkeypatch.setattr(zfs, "_run", explode)
    assert zfs.zfs_storage_health(interval=60) is sentinel


def test_storage_health_not_available_returns_none(monkeypatch):
    """zpool binary gone mid-run -> collection failure -> None (NOT [], which
    the server would read as 'zero pools' and prune health rows on)."""
    monkeypatch.setattr(zfs.shutil, "which", lambda _: None)
    assert zfs.zfs_storage_health() is None


def test_storage_health_no_pools_returns_empty(monkeypatch):
    """Listing succeeded with genuinely zero pools -> [] (safe to prune)."""
    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")

    def run(cmd):
        if "version" in cmd:
            return FakeProc(0, VERSION_OUT)
        return FakeProc(0, "")  # `zpool list` succeeds, reports zero pools

    monkeypatch.setattr(zfs, "_run", run)
    assert zfs.zfs_storage_health() == []


def test_storage_health_list_failure_returns_none(monkeypatch):
    """`zpool list` itself fails -> collection failure -> None, not []."""
    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")
    monkeypatch.setattr(zfs, "_run", lambda cmd: FakeProc(1, "", "boom"))
    assert zfs.zfs_storage_health() is None


def test_storage_health_all_pools_timeout_returns_none(monkeypatch):
    """Pool list answers, but every per-pool call hangs -> all reads None ->
    collection failure -> None (we KNOW pools exist, we just couldn't read
    them). A wedged host never hangs the tick and never falsely prunes."""
    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")

    def run(cmd, **kwargs):
        if "-H" in cmd:  # `zpool list -H -o name` (pool names) answers
            return FakeProc(0, POOL_NAMES_OUT)
        raise zfs.subprocess.TimeoutExpired(cmd, zfs._SUBPROCESS_TIMEOUT)

    monkeypatch.setattr(zfs.subprocess, "run", run)
    assert zfs.zfs_storage_health() is None


def test_storage_health_filters_none_pool_info(monkeypatch):
    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")
    monkeypatch.setattr(zfs, "get_zfs_version", lambda: "zfs-2.2.2")
    monkeypatch.setattr(zfs, "list_zfs_pools", lambda: ["good", "bad"])
    monkeypatch.setattr(
        zfs,
        "get_zfs_pool_info",
        lambda name: None if name == "bad" else {"name": name},
    )
    data = zfs.zfs_storage_health()
    assert data == [{"name": "good", "zfs_version": "zfs-2.2.2"}]


def test_storage_health_custom_interval_is_ttl(monkeypatch):
    """A custom interval becomes the cache TTL."""
    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")
    monkeypatch.setattr(zfs, "_run", _contract_run)
    # Warm the cache 30s ago; interval=60 -> still fresh (no re-probe).
    zfs.zfs_storage_health(interval=1)  # populate
    warmed = zfs._zfs_cache["data"]
    zfs._zfs_cache["timestamp"] = zfs.time.time() - 30

    def explode(_):
        raise AssertionError("should be a cache hit within interval")

    monkeypatch.setattr(zfs, "_run", explode)
    assert zfs.zfs_storage_health(interval=60) is warmed


def test_storage_health_negative_interval_uses_default(monkeypatch):
    """A negative interval falls back to the default TTL rather than never caching."""
    monkeypatch.setattr(zfs.shutil, "which", lambda _: "/usr/sbin/zpool")
    monkeypatch.setattr(zfs, "_run", _contract_run)
    data = zfs.zfs_storage_health(interval=-5)
    assert [p["name"] for p in data] == ["rpool", "tank"]
