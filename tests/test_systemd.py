"""Tests for fivenines_agent.systemd module."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from fivenines_agent import systemd
from fivenines_agent.systemd import (
    ALL_PROPERTIES,
    DEFAULT_UNIT_TYPES,
    EXEC_ARGV_RE,
    HEALTH_PROPERTIES,
    IDENTITY_PROPERTIES,
    INVENTORY_PROPERTIES,
    LIST_VALUED_PROPERTIES,
    MAX_DRILLDOWN_WORKERS,
    MIN_SYSTEMD_VERSION_REVERSE_DEPS,
    RUNTIME_FIELDS_TO_STRIP,
    VOLATILE_STATE_PROPERTIES,
    SystemdCollector,
    _canonical_inventory_hash,
    _canonicalize_unit,
    _config_unit_types,
    _extract_exec_record,
    _normalize_property_for_hash,
    _normalize_unit_types,
    _parse_exec_property,
    _parse_journalctl_failed,
    _parse_list_units,
    _parse_reverse_deps,
    _parse_show_bulk,
    _run_subprocess,
    _systemd_version,
    force_inventory_resend,
    refresh_runtime_caches,
    reset_collector,
    systemd_inventory_sync,
    systemd_metrics,
)


@pytest.fixture(autouse=True)
def _reset_systemd():
    """Clear module-level singleton + class-level state between tests."""
    reset_collector()
    yield
    reset_collector()


# ============================================================
# Constants & top-level structure
# ============================================================


def test_runtime_fields_strip_set_includes_main_pid():
    assert "MainPID" in RUNTIME_FIELDS_TO_STRIP
    assert "ExecMainStartTimestamp" in RUNTIME_FIELDS_TO_STRIP


def test_identity_shared_by_health_and_inventory():
    """Health and inventory both carry the identity/drift fields, but inventory
    must NOT carry the volatile state fields (or the hash flaps on restart)."""
    assert set(IDENTITY_PROPERTIES).issubset(set(HEALTH_PROPERTIES))
    assert set(IDENTITY_PROPERTIES).issubset(set(INVENTORY_PROPERTIES))
    # Volatile state belongs to health only, never inventory.
    assert not set(VOLATILE_STATE_PROPERTIES) & set(INVENTORY_PROPERTIES)


def test_all_properties_is_union_of_health_and_inventory():
    """The single shared `show` fetch must cover both property sets."""
    assert set(HEALTH_PROPERTIES).issubset(set(ALL_PROPERTIES))
    assert set(INVENTORY_PROPERTIES).issubset(set(ALL_PROPERTIES))


def test_volatile_state_fields_are_stripped_from_hash():
    """Every volatile field must be in the strip set so an ALL_PROPERTIES fetch
    canonicalizes to the same hash as a config-only fetch."""
    assert set(VOLATILE_STATE_PROPERTIES).issubset(RUNTIME_FIELDS_TO_STRIP)


def test_list_valued_properties_in_inventory():
    assert LIST_VALUED_PROPERTIES.issubset(set(INVENTORY_PROPERTIES))


# ============================================================
# _systemd_version
# ============================================================


def test_systemd_version_returns_int():
    fake = MagicMock(returncode=0, stdout="systemd 252 (252.4-1ubuntu3.1)\n")
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            assert _systemd_version() == 252


def test_systemd_version_centos_7_returns_219():
    fake = MagicMock(returncode=0, stdout="systemd 219\n")
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            assert _systemd_version() == 219


def test_systemd_version_no_systemctl():
    with patch("fivenines_agent.systemd.shutil.which", return_value=None):
        assert _systemd_version() is None


def test_systemd_version_timeout():
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch(
            "fivenines_agent.systemd.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="systemctl", timeout=5),
        ):
            assert _systemd_version() is None


def test_systemd_version_oserror():
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch(
            "fivenines_agent.systemd.subprocess.run", side_effect=OSError("no exec")
        ):
            assert _systemd_version() is None


def test_systemd_version_non_zero_exit():
    fake = MagicMock(returncode=1, stdout="")
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            assert _systemd_version() is None


def test_systemd_version_unparseable_first_line():
    fake = MagicMock(returncode=0, stdout="not-systemd output\n")
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            assert _systemd_version() is None


def test_systemd_version_non_int_version():
    fake = MagicMock(returncode=0, stdout="systemd vNEXT\n")
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            assert _systemd_version() is None


def test_systemd_version_empty_stdout():
    fake = MagicMock(returncode=0, stdout="")
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            assert _systemd_version() is None


# ============================================================
# _run_subprocess
# ============================================================


def test_run_subprocess_missing_binary():
    with patch("fivenines_agent.systemd.shutil.which", return_value=None):
        stdout, error = _run_subprocess("foo", ["--bar"], 5)
    assert stdout is None
    assert error == {"type": "missing", "message": "foo not in PATH"}


def test_run_subprocess_success():
    fake = MagicMock(returncode=0, stdout="hello\n")
    with patch("fivenines_agent.systemd.shutil.which", return_value="/bin/foo"):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            stdout, error = _run_subprocess("foo", ["bar"], 5)
    assert stdout == "hello\n"
    assert error is None


def test_run_subprocess_timeout():
    with patch("fivenines_agent.systemd.shutil.which", return_value="/bin/foo"):
        with patch(
            "fivenines_agent.systemd.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="foo", timeout=5),
        ):
            stdout, error = _run_subprocess("foo", [], 5)
    assert stdout is None
    assert error["type"] == "timeout"
    assert "5s" in error["message"]


def test_run_subprocess_oserror():
    with patch("fivenines_agent.systemd.shutil.which", return_value="/bin/foo"):
        with patch(
            "fivenines_agent.systemd.subprocess.run", side_effect=OSError("boom")
        ):
            stdout, error = _run_subprocess("foo", [], 5)
    assert stdout is None
    assert error == {"type": "unknown", "message": "boom"}


def test_run_subprocess_cli_error_with_stderr():
    fake = MagicMock(returncode=1, stdout="", stderr="bad arg\n")
    with patch("fivenines_agent.systemd.shutil.which", return_value="/bin/foo"):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            stdout, error = _run_subprocess("foo", [], 5)
    assert stdout is None
    assert error == {"type": "cli_error", "message": "bad arg"}


def test_run_systemctl_delegates_to_run_subprocess():
    """The systemctl wrapper just calls _run_subprocess with 'systemctl'."""
    with patch(
        "fivenines_agent.systemd._run_subprocess", return_value=("ok", None)
    ) as m:
        from fivenines_agent.systemd import _run_systemctl

        result = _run_systemctl(["status"], timeout=7)
    assert result == ("ok", None)
    m.assert_called_once_with("systemctl", ["status"], 7)


def test_run_journalctl_delegates_to_run_subprocess():
    """The journalctl wrapper just calls _run_subprocess with 'journalctl'."""
    with patch(
        "fivenines_agent.systemd._run_subprocess", return_value=("log", None)
    ) as m:
        from fivenines_agent.systemd import _run_journalctl

        result = _run_journalctl(["-u", "x"], timeout=8)
    assert result == ("log", None)
    m.assert_called_once_with("journalctl", ["-u", "x"], 8)


def test_run_subprocess_cli_error_empty_stderr():
    fake = MagicMock(returncode=2, stdout="", stderr="")
    with patch("fivenines_agent.systemd.shutil.which", return_value="/bin/foo"):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            stdout, error = _run_subprocess("foo", [], 5)
    assert stdout is None
    assert error == {"type": "cli_error", "message": "exit 2"}


# ============================================================
# _parse_list_units
# ============================================================


LIST_UNITS_OUTPUT = """\
nginx.service     loaded active   running A high performance web server
fail2ban.service  loaded inactive dead    Authentication failure monitoring
broken.service    loaded failed   failed  A failing service
cron.timer        loaded active   waiting Daily cron jobs
ssh.socket        loaded active   listening OpenBSD Secure Shell
"""


def test_parse_list_units_happy():
    units = _parse_list_units(LIST_UNITS_OUTPUT)
    assert units == [
        "nginx.service",
        "fail2ban.service",
        "broken.service",
        "cron.timer",
        "ssh.socket",
    ]


def test_parse_list_units_empty_input():
    assert _parse_list_units("") == []


def test_parse_list_units_none_input():
    assert _parse_list_units(None) == []


def test_parse_list_units_skips_not_found():
    output = (
        "missing.service     not-found inactive dead Unit not found\n"
        "real.service        loaded    active   running A real one\n"
    )
    assert _parse_list_units(output) == ["real.service"]


def test_parse_list_units_skips_short_lines():
    output = "tooshort\nreal.service loaded active running Real\n"
    assert _parse_list_units(output) == ["real.service"]


def test_parse_list_units_skips_blank_lines():
    output = "\n\nreal.service loaded active running Real\n\n"
    assert _parse_list_units(output) == ["real.service"]


# ============================================================
# _parse_show_bulk
# ============================================================


SHOW_BULK_TWO_UNITS = """\
Id=nginx.service
LoadState=loaded
ActiveState=active
SubState=running
Result=success
NRestarts=0
ActiveEnterTimestamp=Mon 2024-01-15 10:00:00 UTC
InactiveEnterTimestamp=
UnitFileState=enabled

Id=fail2ban.service
LoadState=loaded
ActiveState=failed
SubState=failed
Result=exit-code
NRestarts=3
ActiveEnterTimestamp=Mon 2024-01-15 09:00:00 UTC
InactiveEnterTimestamp=Mon 2024-01-15 09:30:00 UTC
UnitFileState=enabled
"""


def test_parse_show_bulk_two_units():
    result = _parse_show_bulk(SHOW_BULK_TWO_UNITS)
    assert set(result.keys()) == {"nginx.service", "fail2ban.service"}
    assert result["nginx.service"]["ActiveState"] == "active"
    assert result["fail2ban.service"]["NRestarts"] == "3"


def test_parse_show_bulk_empty():
    assert _parse_show_bulk("") == {}


def test_parse_show_bulk_none():
    assert _parse_show_bulk(None) == {}


def test_parse_show_bulk_block_without_id_skipped():
    block = (
        "LoadState=loaded\nActiveState=active\n\nId=real.service\nLoadState=loaded\n"
    )
    result = _parse_show_bulk(block)
    assert list(result.keys()) == ["real.service"]


def test_parse_show_bulk_skips_lines_without_equals():
    block = "Id=nginx.service\nLoadState=loaded\nNot-a-property\n"
    result = _parse_show_bulk(block)
    assert result["nginx.service"]["LoadState"] == "loaded"
    assert "Not-a-property" not in result["nginx.service"]


def test_parse_show_bulk_leading_and_trailing_blank_blocks():
    """Stripped empty blocks are skipped (covers the early-continue path)."""
    block = "\n\nId=nginx.service\nLoadState=loaded\n\n   \n"
    result = _parse_show_bulk(block)
    assert list(result.keys()) == ["nginx.service"]


def test_parse_show_bulk_value_with_equals_sign():
    block = "Id=nginx.service\nEnvironment=PATH=/usr/bin:/bin\n"
    result = _parse_show_bulk(block)
    assert result["nginx.service"]["Environment"] == "PATH=/usr/bin:/bin"


# ============================================================
# _parse_journalctl_failed
# ============================================================


def test_parse_journalctl_happy():
    lines = [
        json.dumps({"MESSAGE": "Failed to start nginx", "_PID": "1234"}),
        json.dumps({"MESSAGE": "config error at line 42"}),
    ]
    result = _parse_journalctl_failed("\n".join(lines))
    assert result == ["Failed to start nginx", "config error at line 42"]


def test_parse_journalctl_empty():
    assert _parse_journalctl_failed("") == []


def test_parse_journalctl_none():
    assert _parse_journalctl_failed(None) == []


def test_parse_journalctl_malformed_json_skipped():
    lines = [
        "not-json",
        json.dumps({"MESSAGE": "valid message"}),
    ]
    assert _parse_journalctl_failed("\n".join(lines)) == ["valid message"]


def test_parse_journalctl_byte_array_message():
    """journalctl emits binary messages as int arrays."""
    msg_bytes = list(b"binary message")
    line = json.dumps({"MESSAGE": msg_bytes})
    assert _parse_journalctl_failed(line) == ["binary message"]


def test_parse_journalctl_byte_array_invalid():
    """Invalid byte arrays don't crash; they're skipped or replaced."""
    # Wrong type inside list raises TypeError on bytes()
    line = json.dumps({"MESSAGE": ["not-an-int"]})
    # Should not raise; falls back to empty
    result = _parse_journalctl_failed(line)
    assert result == []


def test_parse_journalctl_missing_message_key():
    line = json.dumps({"_PID": "1234"})
    assert _parse_journalctl_failed(line) == []


def test_parse_journalctl_empty_message():
    line = json.dumps({"MESSAGE": ""})
    assert _parse_journalctl_failed(line) == []


def test_parse_journalctl_blank_lines_skipped():
    lines = ["", json.dumps({"MESSAGE": "real"}), "  "]
    assert _parse_journalctl_failed("\n".join(lines)) == ["real"]


# ============================================================
# _parse_reverse_deps
# ============================================================


# systemctl list-dependencies --reverse uses Unicode box-drawing characters
# in its tree output (U+251C, U+2500, U+2502, U+2514). CLAUDE.md mandates
# ASCII-only source files, so the runtime string is built from \u escapes.
REVERSE_DEPS_OUTPUT = (
    "nginx.service\n"
    "\u251c\u2500multi-user.target\n"
    "\u2502 \u2514\u2500graphical.target\n"
    "\u2514\u2500cloudflare-tunnel.service\n"
)


def test_parse_reverse_deps_happy():
    deps = _parse_reverse_deps(REVERSE_DEPS_OUTPUT)
    assert "multi-user.target" in deps
    assert "graphical.target" in deps
    assert "cloudflare-tunnel.service" in deps
    # First line is the queried unit, must NOT be in deps
    assert "nginx.service" not in deps


def test_parse_reverse_deps_empty():
    assert _parse_reverse_deps("") == []


def test_parse_reverse_deps_none():
    assert _parse_reverse_deps(None) == []


def test_parse_reverse_deps_only_root_unit():
    """Just the queried unit, no deps."""
    assert _parse_reverse_deps("nginx.service\n") == []


def test_parse_reverse_deps_dedup():
    output = (
        "nginx.service\n"
        "\u251c\u2500multi-user.target\n"
        "\u2502 \u2514\u2500multi-user.target\n"
    )
    deps = _parse_reverse_deps(output)
    assert deps == ["multi-user.target"]


def test_parse_reverse_deps_skip_blank_branch_lines():
    output = "nginx.service\n  \n\u2514\u2500multi-user.target\n"
    assert _parse_reverse_deps(output) == ["multi-user.target"]


# ============================================================
# Exec record extraction
# ============================================================


def test_extract_exec_record_happy():
    rec = _extract_exec_record(
        " path=/usr/bin/nginx ; argv[]=/usr/bin/nginx -g daemon off ; "
        "ignore_errors=no ; start_time=[Mon 2024-01-15] ; pid=1234 "
    )
    assert rec["path"] == "/usr/bin/nginx"
    assert rec["argv"] == "/usr/bin/nginx -g daemon off"
    assert rec["ignore_errors"] == "no"
    assert "start_time" not in rec
    assert "pid" not in rec


def test_extract_exec_record_no_path_returns_none():
    """Without path, the record is malformed."""
    assert _extract_exec_record("argv[]=foo ; ignore_errors=no") is None


def test_extract_exec_record_only_path():
    """argv and ignore_errors are optional in the regex."""
    rec = _extract_exec_record("path=/bin/true")
    assert rec == {"path": "/bin/true"}


def test_parse_exec_property_single_record():
    value = "{ path=/usr/bin/foo ; argv[]=foo ; ignore_errors=no }"
    result = _parse_exec_property(value)
    assert result == [{"path": "/usr/bin/foo", "argv": "foo", "ignore_errors": "no"}]


def test_parse_exec_property_multi_records():
    value = (
        "{ path=/usr/bin/pre ; argv[]=pre ; ignore_errors=yes } "
        "{ path=/usr/bin/main ; argv[]=main arg ; ignore_errors=no }"
    )
    result = _parse_exec_property(value)
    assert len(result) == 2
    assert result[0]["path"] == "/usr/bin/pre"
    assert result[1]["path"] == "/usr/bin/main"


def test_parse_exec_property_empty_string():
    assert _parse_exec_property("") == []


def test_parse_exec_property_none():
    assert _parse_exec_property(None) == []


def test_parse_exec_property_no_braces():
    """Malformed value with no braces returns empty list."""
    assert _parse_exec_property("path=/bin/foo argv[]=foo") == []


def test_parse_exec_property_record_without_path_skipped():
    value = "{ argv[]=foo ; ignore_errors=no }"
    assert _parse_exec_property(value) == []


def test_exec_argv_re_terminates_at_semicolon():
    """argv[]=value ; next-field -- value should not include the semicolon."""
    m = EXEC_ARGV_RE.search("argv[]=foo bar ; next=x")
    assert m
    assert m.group(1) == "foo bar"


# ============================================================
# Hash canonicalization
# ============================================================


def test_normalize_property_for_hash_exec():
    val = "{ path=/bin/foo ; argv[]=foo arg ; ignore_errors=no }"
    result = _normalize_property_for_hash("ExecStart", val)
    assert result == [{"path": "/bin/foo", "argv": "foo arg", "ignore_errors": "no"}]


def test_normalize_property_for_hash_list_sorted():
    val = "zeta.target alpha.target middle.target"
    assert _normalize_property_for_hash("After", val) == [
        "alpha.target",
        "middle.target",
        "zeta.target",
    ]


def test_normalize_property_for_hash_scalar():
    assert _normalize_property_for_hash("FragmentPath", "  /etc/foo  ") == "/etc/foo"


def test_normalize_property_for_hash_empty_list():
    assert _normalize_property_for_hash("After", "") == []


def test_normalize_property_for_hash_empty_scalar():
    assert _normalize_property_for_hash("FragmentPath", None) == ""


def test_canonicalize_unit_strips_runtime_fields():
    props = {
        "Id": "nginx.service",
        "MainPID": "1234",
        "ExecMainStartTimestamp": "Mon 2024-01-15",
        "InvocationID": "abc-def",
        "FragmentPath": "/etc/systemd/system/nginx.service",
        # Volatile state fields: must NOT survive into the canonical form.
        "ActiveState": "active",
        "NRestarts": "7",
        "ActiveEnterTimestamp": "Mon 2024-01-15 10:00:00",
        "SubState": "running",
    }
    canon = _canonicalize_unit(props)
    assert "MainPID" not in canon
    assert "ExecMainStartTimestamp" not in canon
    assert "InvocationID" not in canon
    assert "ActiveState" not in canon
    assert "NRestarts" not in canon
    assert "ActiveEnterTimestamp" not in canon
    assert "SubState" not in canon
    assert canon["FragmentPath"] == "/etc/systemd/system/nginx.service"
    assert canon["Id"] == "nginx.service"


def test_canonical_inventory_hash_stable():
    """Same inventory in different insertion orders produces same hash."""
    a = {
        "nginx.service": {"Id": "nginx.service", "FragmentPath": "/etc/foo"},
        "cron.service": {"Id": "cron.service", "FragmentPath": "/etc/bar"},
    }
    b = {
        "cron.service": {"Id": "cron.service", "FragmentPath": "/etc/bar"},
        "nginx.service": {"Id": "nginx.service", "FragmentPath": "/etc/foo"},
    }
    assert _canonical_inventory_hash(a) == _canonical_inventory_hash(b)


def test_canonical_inventory_hash_stable_across_restarts():
    """CRITICAL regression test: hash is identical pre and post restart.

    Strip-list correctness is the contract that prevents inventory churn.
    """
    pre_restart = {
        "nginx.service": {
            "Id": "nginx.service",
            "FragmentPath": "/etc/systemd/system/nginx.service",
            "ExecStart": "{ path=/usr/sbin/nginx ; argv[]=nginx ; ignore_errors=no }",
            "MainPID": "1234",
            "ExecMainStartTimestamp": "Mon 2024-01-15 10:00:00",
            "ExecMainStartTimestampMonotonic": "1000000",
            "ExecMainPID": "1234",
            "InvocationID": "old-invocation-id",
            "StateChangeTimestamp": "Mon 2024-01-15 10:00:00",
            "ActiveEnterTimestampMonotonic": "1000000",
            # Volatile health state -- a real restart bumps these. They must
            # NOT affect the hash. (This pair is what the original test missed.)
            "ActiveState": "active",
            "SubState": "running",
            "Result": "success",
            "NRestarts": "0",
            "ActiveEnterTimestamp": "Mon 2024-01-15 10:00:00",
            "InactiveEnterTimestamp": "",
            "After": "network.target multi-user.target",
        },
    }
    post_restart = {
        "nginx.service": {
            "Id": "nginx.service",
            "FragmentPath": "/etc/systemd/system/nginx.service",
            "ExecStart": "{ path=/usr/sbin/nginx ; argv[]=nginx ; ignore_errors=no }",
            "MainPID": "5678",  # different PID
            "ExecMainStartTimestamp": "Mon 2024-01-15 11:00:00",  # different time
            "ExecMainStartTimestampMonotonic": "2000000",
            "ExecMainPID": "5678",
            "InvocationID": "new-invocation-id",  # different invocation
            "StateChangeTimestamp": "Mon 2024-01-15 11:00:00",
            "ActiveEnterTimestampMonotonic": "2000000",
            # Restart bumped NRestarts and the wall-clock enter timestamp, and
            # the unit briefly went inactive. None of this is a config change.
            "ActiveState": "active",
            "SubState": "running",
            "Result": "success",
            "NRestarts": "1",
            "ActiveEnterTimestamp": "Mon 2024-01-15 11:00:00",
            "InactiveEnterTimestamp": "Mon 2024-01-15 10:59:59",
            "After": "network.target multi-user.target",
        },
    }
    assert _canonical_inventory_hash(pre_restart) == _canonical_inventory_hash(
        post_restart
    )


def test_canonical_inventory_hash_changes_on_static_field_change():
    """If FragmentPath changes (admin edit), hash must change."""
    base = {
        "nginx.service": {
            "Id": "nginx.service",
            "FragmentPath": "/etc/systemd/system/nginx.service",
        },
    }
    mutated = {
        "nginx.service": {
            "Id": "nginx.service",
            "FragmentPath": "/usr/lib/systemd/system/nginx.service",
        },
    }
    assert _canonical_inventory_hash(base) != _canonical_inventory_hash(mutated)


def test_canonical_inventory_hash_after_list_reorder_stable():
    """Reordering the After= list does not flap the hash."""
    a = {"foo.service": {"Id": "foo.service", "After": "a.target b.target c.target"}}
    b = {"foo.service": {"Id": "foo.service", "After": "c.target a.target b.target"}}
    assert _canonical_inventory_hash(a) == _canonical_inventory_hash(b)


def test_canonical_inventory_hash_empty_input():
    """Empty inventory still produces a stable hash."""
    assert _canonical_inventory_hash({}) == _canonical_inventory_hash({})


# ============================================================
# SystemdCollector.collect
# ============================================================


def _make_collector():
    """Construct a collector with version and hierarchy pre-set so __init__
    does not call the real subprocess/filesystem."""
    SystemdCollector._version = 252
    SystemdCollector._hierarchy = "v2"
    return SystemdCollector()


def test_collect_happy_path():
    coll = _make_collector()

    def fake_run(args, timeout=None):
        if args[0] == "list-units":
            return LIST_UNITS_OUTPUT, None
        if args[0] == "show":
            return SHOW_BULK_TWO_UNITS, None
        return "", None

    with patch.object(coll, "_list_units", wraps=coll._list_units) as _:
        with patch("fivenines_agent.systemd._run_systemctl", side_effect=fake_run):
            with patch(
                "fivenines_agent.systemd.read_unit_resources",
                return_value={
                    "memory_current": 1000,
                    "cpu_usec": 500,
                    "oom_kill_count": 0,
                    "inception_id": 7,
                },
            ):
                # Drilldown-running units would call _drilldown internally; bypass
                # by mocking the drilldown method to a no-op for THIS test.
                with patch.object(coll, "_drilldown_failed_units", return_value={}):
                    result = coll.collect()
    assert result["version"] == 252
    assert result["cgroup"] == "v2"
    # SHOW_BULK_TWO_UNITS only has nginx + fail2ban; the other 3 list-units
    # names are absent from the show output and are skipped (not blanked).
    names = {u["name"] for u in result["units"]}
    assert names == {"nginx.service", "fail2ban.service"}
    assert "broken.service" not in names
    nginx = next(u for u in result["units"] if u["name"] == "nginx.service")
    assert nginx["active_state"] == "active"
    assert nginx["memory_current"] == 1000


def test_collect_list_units_error_returns_empty_with_error():
    coll = _make_collector()
    with patch(
        "fivenines_agent.systemd._run_systemctl",
        return_value=(None, {"type": "timeout", "message": "x"}),
    ):
        result = coll.collect()
    assert result["units"] == []
    assert result["drilldowns"] == {}
    assert any(e["step"] == "list_units" for e in result["errors"])


def test_collect_no_units_returns_empty():
    coll = _make_collector()

    def fake_run(args, timeout=None):
        if args[0] == "list-units":
            return "", None
        return "", None

    with patch("fivenines_agent.systemd._run_systemctl", side_effect=fake_run):
        result = coll.collect()
    assert result["units"] == []
    assert result["errors"] == []


def test_collect_show_bulk_error_returns_empty_not_blanks():
    """A transient show failure must early-return (no blanked units), so failed
    units are not misreported as empty state."""
    coll = _make_collector()

    def fake_run(args, timeout=None):
        if args[0] == "list-units":
            return LIST_UNITS_OUTPUT, None
        if args[0] == "show":
            return None, {"type": "timeout", "message": "show timed out"}
        return "", None

    with patch("fivenines_agent.systemd._run_systemctl", side_effect=fake_run):
        with patch("fivenines_agent.systemd.read_unit_resources", return_value={}):
            result = coll.collect()
    assert any(e["step"] == "show_bulk" for e in result["errors"])
    assert result["units"] == []
    assert result["drilldowns"] == {}


def test_collect_show_bulk_error_preserves_failure_cache():
    """A show timeout must NOT wipe the failure-signature debounce cache (which
    would re-drill every failed unit next tick)."""
    coll = _make_collector()
    # Seed a known failed-unit signature.
    SystemdCollector._last_failure_signatures["fail2ban.service"] = ("3", "T1")

    def fake_run(args, timeout=None):
        if args[0] == "list-units":
            return LIST_UNITS_OUTPUT, None
        if args[0] == "show":
            return None, {"type": "timeout", "message": "show timed out"}
        return "", None

    with patch("fivenines_agent.systemd._run_systemctl", side_effect=fake_run):
        coll.collect()
    assert SystemdCollector._last_failure_signatures.get("fail2ban.service") == (
        "3",
        "T1",
    )


def test_collect_malformed_control_group_does_not_crash():
    """A malformed ControlGroup from systemctl triggers the cgroup-path
    defense, which logs and continues rather than crashing collect()."""
    coll = _make_collector()
    # ControlGroup with a traversal segment -> read_unit_resources raises,
    # _build_health_entry catches and logs.
    bad_props = {
        "Id": "nginx.service",
        "ControlGroup": "/system.slice/../../etc",
    }
    with patch.object(coll, "_list_units", return_value=(["nginx.service"], None)):
        with patch.object(
            coll, "_show_bulk", return_value=({"nginx.service": bad_props}, None)
        ):
            with patch("fivenines_agent.systemd.log") as mock_log:
                result = coll.collect()
    assert result["units"][0]["name"] == "nginx.service"
    assert result["units"][0]["memory_current"] is None
    assert any("invalid control group" in str(c) for c in mock_log.call_args_list)


def test_collect_no_cgroup_skips_resource_read():
    """When hierarchy is None, skip cgroup reads and return units with null cgroup fields."""
    SystemdCollector._version = 252
    SystemdCollector._hierarchy = None
    coll = SystemdCollector()
    with patch.object(coll, "_list_units", return_value=(["nginx.service"], None)):
        with patch.object(
            coll,
            "_show_bulk",
            return_value=(
                {"nginx.service": {"Id": "nginx.service", "ActiveState": "active"}},
                None,
            ),
        ):
            with patch("fivenines_agent.systemd.read_unit_resources") as mock_read:
                result = coll.collect()
    mock_read.assert_not_called()
    assert result["units"][0]["memory_current"] is None


def test_collect_n_restarts_invalid_value():
    """NRestarts that's not an int defaults to 0 without crashing."""
    coll = _make_collector()
    with patch.object(coll, "_list_units", return_value=(["x.service"], None)):
        with patch.object(
            coll,
            "_show_bulk",
            return_value=(
                {"x.service": {"Id": "x.service", "NRestarts": "garbage"}},
                None,
            ),
        ):
            with patch("fivenines_agent.systemd.read_unit_resources", return_value={}):
                result = coll.collect()
    assert result["units"][0]["n_restarts"] == 0


# ============================================================
# Failure debounce (_is_newly_failed)
# ============================================================


def test_is_newly_failed_triggers_on_first_failure():
    coll = _make_collector()
    props = {"ActiveState": "failed", "NRestarts": "1", "ActiveEnterTimestamp": "T1"}
    assert coll._is_newly_failed("foo.service", props) is True


def test_is_newly_failed_suppresses_repeat_with_same_signature():
    coll = _make_collector()
    props = {"ActiveState": "failed", "NRestarts": "1", "ActiveEnterTimestamp": "T1"}
    coll._is_newly_failed("foo.service", props)
    # Second call with same signature should NOT trigger drilldown
    assert coll._is_newly_failed("foo.service", props) is False


def test_is_newly_failed_re_triggers_when_signature_changes():
    coll = _make_collector()
    coll._is_newly_failed(
        "foo.service",
        {"ActiveState": "failed", "NRestarts": "1", "ActiveEnterTimestamp": "T1"},
    )
    # NRestarts incremented = new failure
    assert (
        coll._is_newly_failed(
            "foo.service",
            {
                "ActiveState": "failed",
                "NRestarts": "2",
                "ActiveEnterTimestamp": "T2",
            },
        )
        is True
    )


def test_is_newly_failed_clears_cache_on_recovery():
    coll = _make_collector()
    coll._is_newly_failed(
        "foo.service",
        {"ActiveState": "failed", "NRestarts": "1", "ActiveEnterTimestamp": "T1"},
    )
    assert "foo.service" in SystemdCollector._last_failure_signatures
    # Recovery
    coll._is_newly_failed(
        "foo.service",
        {"ActiveState": "active", "NRestarts": "1", "ActiveEnterTimestamp": "T1"},
    )
    assert "foo.service" not in SystemdCollector._last_failure_signatures


def test_is_newly_failed_lru_bound():
    """Cache is bounded; FAILURE_SIG_MAX entries max."""
    coll = _make_collector()
    # Fill cache with FAILURE_SIG_MAX + 5 entries
    for i in range(systemd.FAILURE_SIG_MAX + 5):
        coll._is_newly_failed(
            f"unit_{i}.service",
            {
                "ActiveState": "failed",
                "NRestarts": "1",
                "ActiveEnterTimestamp": f"T{i}",
            },
        )
    assert len(SystemdCollector._last_failure_signatures) <= systemd.FAILURE_SIG_MAX


# ============================================================
# Drilldown
# ============================================================


def test_drilldown_one_combines_journal_and_deps():
    coll = _make_collector()
    with patch.object(coll, "_journal_tail", return_value=["error line"]):
        with patch.object(coll, "_reverse_deps", return_value=["dep1"]):
            result = coll._drilldown_one("nginx.service")
    assert result == {"journal_tail": ["error line"], "reverse_deps": ["dep1"]}


def test_drilldown_failed_units_runs_in_parallel():
    coll = _make_collector()
    units = ["a.service", "b.service", "c.service"]

    def fake_drill(name):
        return {"journal_tail": [name], "reverse_deps": []}

    with patch.object(coll, "_drilldown_one", side_effect=fake_drill):
        result = coll._drilldown_failed_units(units)
    assert set(result.keys()) == set(units)
    assert result["a.service"]["journal_tail"] == ["a.service"]


def test_drilldown_failed_units_handles_thread_exception():
    coll = _make_collector()

    def fake_drill(name):
        if name == "bad.service":
            raise RuntimeError("blew up")
        return {"journal_tail": [], "reverse_deps": []}

    with patch.object(coll, "_drilldown_one", side_effect=fake_drill):
        with patch("fivenines_agent.systemd.log"):
            result = coll._drilldown_failed_units(["good.service", "bad.service"])
    assert "error" in result["bad.service"]
    assert result["bad.service"]["journal_tail"] == []
    assert "error" not in result["good.service"]


def test_drilldown_max_workers_capped():
    """Worker count caps at MAX_DRILLDOWN_WORKERS for huge failure batches."""
    coll = _make_collector()
    units = [f"u{i}.service" for i in range(MAX_DRILLDOWN_WORKERS + 5)]
    with patch(
        "fivenines_agent.systemd.concurrent.futures.ThreadPoolExecutor"
    ) as mock_exec:
        mock_ctx = mock_exec.return_value.__enter__.return_value
        mock_ctx.submit.return_value = MagicMock()
        # as_completed iterates over submitted futures; emulate with empty
        with patch(
            "fivenines_agent.systemd.concurrent.futures.as_completed",
            return_value=iter([]),
        ):
            coll._drilldown_failed_units(units)
    args, kwargs = mock_exec.call_args
    assert kwargs.get("max_workers") == MAX_DRILLDOWN_WORKERS


# ============================================================
# Journal tail + reverse deps
# ============================================================


def test_journal_tail_happy():
    coll = _make_collector()
    with patch(
        "fivenines_agent.systemd._run_journalctl",
        return_value=(json.dumps({"MESSAGE": "boom"}), None),
    ):
        result = coll._journal_tail("foo.service")
    assert result == ["boom"]


def test_journal_tail_error_returns_empty():
    coll = _make_collector()
    with patch(
        "fivenines_agent.systemd._run_journalctl",
        return_value=(None, {"type": "timeout", "message": "x"}),
    ):
        assert coll._journal_tail("foo.service") == []


def test_reverse_deps_modern_systemd():
    SystemdCollector._version = 252
    SystemdCollector._hierarchy = "v2"
    coll = SystemdCollector()
    with patch(
        "fivenines_agent.systemd._run_systemctl",
        return_value=(REVERSE_DEPS_OUTPUT, None),
    ):
        deps = coll._reverse_deps("nginx.service")
    assert "multi-user.target" in deps


def test_reverse_deps_centos_7_returns_none():
    """systemd 219 < 230, capability gated off."""
    SystemdCollector._version = 219
    SystemdCollector._hierarchy = "v1"
    coll = SystemdCollector()
    assert coll._reverse_deps("nginx.service") is None


def test_reverse_deps_no_systemd_version():
    SystemdCollector._version = None
    SystemdCollector._hierarchy = None
    coll = SystemdCollector()
    assert coll._reverse_deps("nginx.service") is None


def test_reverse_deps_subprocess_error():
    SystemdCollector._version = 252
    SystemdCollector._hierarchy = "v2"
    coll = SystemdCollector()
    with patch(
        "fivenines_agent.systemd._run_systemctl",
        return_value=(None, {"type": "timeout", "message": "x"}),
    ):
        assert coll._reverse_deps("nginx.service") is None


def test_reverse_deps_min_version_constant():
    assert MIN_SYSTEMD_VERSION_REVERSE_DEPS == 230


# ============================================================
# Inventory snapshot + sync
# ============================================================


def test_snapshot_inventory_happy():
    coll = _make_collector()
    bulk = (
        "Id=nginx.service\n"
        "FragmentPath=/etc/systemd/system/nginx.service\n"
        "ExecStart={ path=/usr/sbin/nginx ; argv[]=nginx ; ignore_errors=no }\n"
        "After=network.target\n"
    )
    with patch.object(coll, "_list_units", return_value=(["nginx.service"], None)):
        with patch.object(
            coll, "_show_bulk", return_value=(_parse_show_bulk(bulk), None)
        ):
            units, h, errors = coll.snapshot_inventory()
    assert "nginx.service" in units
    assert h is not None
    assert errors == []


def test_snapshot_inventory_list_units_error():
    coll = _make_collector()
    with patch.object(
        coll,
        "_list_units",
        return_value=([], {"type": "cli_error", "message": "x"}),
    ):
        units, h, errors = coll.snapshot_inventory()
    assert units == {}
    assert h is None
    assert any(e["step"] == "list_units" for e in errors)


def test_snapshot_inventory_no_units():
    coll = _make_collector()
    with patch.object(coll, "_list_units", return_value=([], None)):
        units, h, errors = coll.snapshot_inventory()
    assert units == {}
    assert h is not None  # Empty inventory still has a stable hash
    assert errors == []


def test_snapshot_inventory_show_bulk_partial_error():
    coll = _make_collector()
    with patch.object(coll, "_list_units", return_value=(["x.service"], None)):
        with patch.object(
            coll,
            "_show_bulk",
            return_value=({}, {"type": "timeout", "message": "x"}),
        ):
            units, h, errors = coll.snapshot_inventory()
    assert any(e["step"] == "show_bulk_inventory" for e in errors)
    # Still produces a (empty) hash so caller can compare
    assert h is not None


def test_inventory_sync_no_scan_does_nothing():
    coll = _make_collector()
    send_fn = MagicMock()
    coll.inventory_sync({}, send_fn)
    send_fn.assert_not_called()


def test_inventory_sync_scan_false_does_nothing():
    coll = _make_collector()
    send_fn = MagicMock()
    coll.inventory_sync({"systemd": {"scan": False}}, send_fn)
    send_fn.assert_not_called()


def test_inventory_sync_scan_not_dict_does_nothing():
    coll = _make_collector()
    send_fn = MagicMock()
    coll.inventory_sync({"systemd": True}, send_fn)
    send_fn.assert_not_called()


def test_inventory_sync_snapshot_failure_skips_send():
    coll = _make_collector()
    send_fn = MagicMock()
    with patch.object(coll, "snapshot_inventory", return_value=({}, None, [])):
        coll.inventory_sync({"systemd": {"scan": True}}, send_fn)
    send_fn.assert_not_called()


def test_inventory_sync_unchanged_skips_send():
    """When local hash, server hash, and current hash all agree, no send."""
    coll = _make_collector()
    send_fn = MagicMock()
    SystemdCollector._last_local_inventory_hash = "deadbeef"
    with patch.object(coll, "snapshot_inventory", return_value=({}, "deadbeef", [])):
        coll.inventory_sync(
            {"systemd": {"scan": True, "last_inventory_hash": "deadbeef"}},
            send_fn,
        )
    send_fn.assert_not_called()


def test_inventory_sync_changed_sends():
    coll = _make_collector()
    send_fn = MagicMock(return_value={"ok": True})
    with patch.object(
        coll,
        "snapshot_inventory",
        return_value=({"x.service": {}}, "newhash", []),
    ):
        coll.inventory_sync(
            {"systemd": {"scan": True, "last_inventory_hash": "oldhash"}},
            send_fn,
        )
    send_fn.assert_called_once()
    payload = send_fn.call_args[0][0]
    assert payload["inventory_hash"] == "newhash"
    assert "x.service" in payload["units"]
    assert SystemdCollector._last_local_inventory_hash == "newhash"


def test_inventory_sync_local_hash_only_suppresses_send():
    """OR-gate (fix): a confirmed local send suppresses the next resend even
    before the backend echoes the hash back (server_hash still None)."""
    coll = _make_collector()
    send_fn = MagicMock()
    SystemdCollector._last_local_inventory_hash = "abc123"
    with patch.object(coll, "snapshot_inventory", return_value=({}, "abc123", [])):
        # server has not echoed the hash yet (last_inventory_hash absent)
        coll.inventory_sync({"systemd": {"scan": True}}, send_fn)
    send_fn.assert_not_called()


def test_inventory_sync_server_hash_only_suppresses_send():
    """OR-gate: server-echoed hash alone also suppresses, even if local was
    cleared (e.g. by force_inventory_resend on a prior tick that then sent)."""
    coll = _make_collector()
    send_fn = MagicMock()
    SystemdCollector._last_local_inventory_hash = None
    with patch.object(coll, "snapshot_inventory", return_value=({}, "srv", [])):
        coll.inventory_sync(
            {"systemd": {"scan": True, "last_inventory_hash": "srv"}}, send_fn
        )
    send_fn.assert_not_called()


def test_inventory_sync_includes_errors():
    coll = _make_collector()
    send_fn = MagicMock(return_value={"ok": True})
    with patch.object(
        coll,
        "snapshot_inventory",
        return_value=({}, "h", [{"step": "x", "type": "timeout", "message": "m"}]),
    ):
        coll.inventory_sync({"systemd": {"scan": True}}, send_fn)
    send_fn.assert_called_once()
    payload = send_fn.call_args[0][0]
    assert "errors" in payload


def test_inventory_sync_dry_run_does_not_send():
    coll = _make_collector()
    send_fn = MagicMock()
    with patch.object(
        coll,
        "snapshot_inventory",
        return_value=({"x.service": {}}, "h", []),
    ):
        with patch("fivenines_agent.systemd.dry_run", return_value=True):
            coll.inventory_sync({"systemd": {"scan": True}}, send_fn)
    send_fn.assert_not_called()


def test_inventory_sync_send_failure_does_not_update_local_hash():
    coll = _make_collector()
    send_fn = MagicMock(return_value=None)  # send failed
    with patch.object(
        coll,
        "snapshot_inventory",
        return_value=({"x.service": {}}, "h", []),
    ):
        coll.inventory_sync({"systemd": {"scan": True}}, send_fn)
    assert SystemdCollector._last_local_inventory_hash is None


def test_inventory_sync_force_resend_sends_even_if_unchanged():
    coll = _make_collector()
    send_fn = MagicMock(return_value={"ok": True})
    SystemdCollector._last_local_inventory_hash = "deadbeef"
    with patch.object(coll, "snapshot_inventory", return_value=({}, "deadbeef", [])):
        coll.inventory_sync(
            {"systemd": {"scan": True, "last_inventory_hash": "deadbeef"}},
            send_fn,
            force_resend=True,
        )
    send_fn.assert_called_once()


# ============================================================
# Public API
# ============================================================


def test_systemd_metrics_no_systemctl():
    with patch("fivenines_agent.systemd.shutil.which", return_value=None):
        assert systemd_metrics() is None


def test_systemd_metrics_calls_collect():
    SystemdCollector._version = 252
    SystemdCollector._hierarchy = "v2"
    fake_collector = MagicMock()
    fake_collector.collect.return_value = {"units": [], "drilldowns": {}}
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch(
            "fivenines_agent.systemd._get_collector", return_value=fake_collector
        ):
            result = systemd_metrics()
    fake_collector.collect.assert_called_once()
    assert result == {"units": [], "drilldowns": {}}


def test_systemd_metrics_accepts_extra_kwargs():
    """Future-proofing: extra kwargs from server config must not error."""
    fake_collector = MagicMock()
    fake_collector.collect.return_value = {}
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch(
            "fivenines_agent.systemd._get_collector", return_value=fake_collector
        ):
            systemd_metrics(unit_types="service", future_field=True)


def test_systemd_metrics_unit_types_recreates_collector():
    """Changing unit_types triggers a fresh SystemdCollector instance."""
    fake_collector_1 = MagicMock(unit_types="service,timer,socket")
    fake_collector_1.collect.return_value = {}
    fake_collector_2 = MagicMock(unit_types="service")
    fake_collector_2.collect.return_value = {}
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch(
            "fivenines_agent.systemd.SystemdCollector",
            side_effect=[fake_collector_1, fake_collector_2],
        ):
            systemd_metrics(unit_types=DEFAULT_UNIT_TYPES)
            systemd_metrics(unit_types="service")
    fake_collector_1.collect.assert_called_once()
    fake_collector_2.collect.assert_called_once()


def test_systemd_inventory_sync_no_systemctl():
    send_fn = MagicMock()
    with patch("fivenines_agent.systemd.shutil.which", return_value=None):
        systemd_inventory_sync({"systemd": {"scan": True}}, send_fn)
    send_fn.assert_not_called()


def test_systemd_inventory_sync_delegates_to_collector():
    fake_collector = MagicMock()
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch(
            "fivenines_agent.systemd._get_collector", return_value=fake_collector
        ) as mock_get:
            systemd_inventory_sync(
                {"systemd": {"scan": True}}, "send_fn", force_resend=True
            )
    mock_get.assert_called_once_with(unit_types=DEFAULT_UNIT_TYPES)
    fake_collector.inventory_sync.assert_called_once_with(
        {"systemd": {"scan": True}}, "send_fn", force_resend=True
    )


def test_systemd_inventory_sync_passes_unit_types_from_config():
    """Inventory sync must use the same unit_types as the metrics path so the
    module-level singleton does not get recreated every tick when config
    overrides the default scope."""
    fake_collector = MagicMock()
    config = {"systemd": {"scan": True, "unit_types": "service"}}
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch(
            "fivenines_agent.systemd._get_collector", return_value=fake_collector
        ) as mock_get:
            systemd_inventory_sync(config, "send_fn")
    mock_get.assert_called_once_with(unit_types="service")


def test_systemd_inventory_sync_falls_back_to_default_when_config_not_dict():
    """Bool / truthy non-dict config still works via DEFAULT_UNIT_TYPES."""
    fake_collector = MagicMock()
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch(
            "fivenines_agent.systemd._get_collector", return_value=fake_collector
        ) as mock_get:
            systemd_inventory_sync({"systemd": True}, "send_fn")
    mock_get.assert_called_once_with(unit_types=DEFAULT_UNIT_TYPES)


def test_force_inventory_resend_clears_local_hash():
    SystemdCollector._last_local_inventory_hash = "abc"
    force_inventory_resend()
    assert SystemdCollector._last_local_inventory_hash is None


def test_reset_collector_clears_singleton_and_class_state():
    SystemdCollector._version = 252
    SystemdCollector._hierarchy = "v2"
    SystemdCollector._last_local_inventory_hash = "h"
    SystemdCollector._last_failure_signatures["foo"] = "sig"
    # Force the module-level singleton to be set
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch.object(SystemdCollector, "collect", return_value={}):
            systemd_metrics()
    assert systemd._collector is not None
    reset_collector()
    assert systemd._collector is None
    assert SystemdCollector._version is None
    assert SystemdCollector._hierarchy is None
    assert SystemdCollector._last_local_inventory_hash is None
    assert SystemdCollector._last_failure_signatures == {}


# ============================================================
# Fixes: shared fetch, coercion, runtime refresh, LRU, decode
# ============================================================


SHOW_BULK_CONFIG = (
    "Id=nginx.service\n"
    "LoadState=loaded\n"
    "ActiveState=active\n"
    "SubState=running\n"
    "NRestarts=0\n"
    "UnitFileState=enabled\n"
    "FragmentPath=/etc/systemd/system/nginx.service\n"
)


def test_collect_scan_stashes_for_inventory_reuse():
    """collect(scan=True) fetches ALL_PROPERTIES once and stashes the raw output
    so snapshot_inventory reuses it -- one list-units + one show for the tick."""
    coll = _make_collector()
    calls = []

    def fake_run(args, timeout=None):
        calls.append(args[0])
        if args[0] == "list-units":
            return "nginx.service loaded active running Web\n", None
        if args[0] == "show":
            return SHOW_BULK_CONFIG, None
        return "", None

    with patch("fivenines_agent.systemd._run_systemctl", side_effect=fake_run):
        with patch("fivenines_agent.systemd.read_unit_resources", return_value={}):
            with patch.object(coll, "_drilldown_failed_units", return_value={}):
                health = coll.collect(scan=True)
                # The show must have requested the superset.
                show_call = [c for c in calls if c == "show"]
                assert len(show_call) == 1
                # Inventory in the same tick reuses the stash: no new subprocess.
                calls_before = len(calls)
                units, h, errors = coll.snapshot_inventory()
    assert health["units"][0]["name"] == "nginx.service"
    assert "nginx.service" in units
    assert h is not None
    assert errors == []
    # snapshot_inventory ran zero additional systemctl calls (reused the stash).
    assert len(calls) == calls_before


def test_collect_scan_uses_all_properties():
    """When scan is on, the show fetches ALL_PROPERTIES (health+config union)."""
    coll = _make_collector()
    captured = {}

    def fake_show(unit_names, properties):
        captured["properties"] = properties
        return ({"nginx.service": {"Id": "nginx.service"}}, None)

    with patch.object(coll, "_list_units", return_value=(["nginx.service"], None)):
        with patch.object(coll, "_show_bulk", side_effect=fake_show):
            with patch("fivenines_agent.systemd.read_unit_resources", return_value={}):
                coll.collect(scan=True)
    assert captured["properties"] == ALL_PROPERTIES


def test_collect_no_scan_uses_health_properties_only():
    """Health-only hosts must not pay the heavier inventory show."""
    coll = _make_collector()
    captured = {}

    def fake_show(unit_names, properties):
        captured["properties"] = properties
        return ({"nginx.service": {"Id": "nginx.service"}}, None)

    with patch.object(coll, "_list_units", return_value=(["nginx.service"], None)):
        with patch.object(coll, "_show_bulk", side_effect=fake_show):
            with patch("fivenines_agent.systemd.read_unit_resources", return_value={}):
                coll.collect(scan=False)
    assert captured["properties"] == HEALTH_PROPERTIES
    assert coll._pending_inventory is None


def test_snapshot_inventory_fetches_fresh_without_stash():
    """When no shared fetch is pending, snapshot_inventory fetches its own
    config-only show."""
    coll = _make_collector()
    captured = {}

    def fake_show(unit_names, properties):
        captured["properties"] = properties
        return ({"nginx.service": {"Id": "nginx.service"}}, None)

    with patch.object(coll, "_list_units", return_value=(["nginx.service"], None)):
        with patch.object(coll, "_show_bulk", side_effect=fake_show):
            units, h, errors = coll.snapshot_inventory()
    assert captured["properties"] == INVENTORY_PROPERTIES
    assert "nginx.service" in units


def test_shared_and_fresh_inventory_hash_match():
    """The hash from a reused ALL_PROPERTIES fetch equals the hash from a fresh
    config-only fetch (volatile fields stripped either way)."""
    raw_all = {
        "nginx.service": {
            "Id": "nginx.service",
            "LoadState": "loaded",
            "UnitFileState": "enabled",
            "ActiveState": "active",
            "NRestarts": "3",
            "ActiveEnterTimestamp": "now",
            "FragmentPath": "/etc/systemd/system/nginx.service",
        }
    }
    raw_config = {
        "nginx.service": {
            "Id": "nginx.service",
            "LoadState": "loaded",
            "UnitFileState": "enabled",
            "FragmentPath": "/etc/systemd/system/nginx.service",
        }
    }
    assert _canonical_inventory_hash(raw_all) == _canonical_inventory_hash(raw_config)


# ---- _normalize_unit_types / coercion (fix #7) ----


def test_normalize_unit_types_string_passthrough():
    assert _normalize_unit_types("service,timer") == "service,timer"


def test_normalize_unit_types_list_joined():
    assert _normalize_unit_types(["service", "timer", "socket"]) == (
        "service,timer,socket"
    )


def test_normalize_unit_types_tuple_joined():
    assert _normalize_unit_types(("service", "timer")) == "service,timer"


def test_config_unit_types_coerces_list():
    cfg = {"systemd": {"scan": True, "unit_types": ["service", "timer"]}}
    assert _config_unit_types(cfg) == "service,timer"


def test_config_unit_types_default_when_absent():
    assert _config_unit_types({"systemd": {"scan": True}}) == DEFAULT_UNIT_TYPES
    assert _config_unit_types({"systemd": True}) == DEFAULT_UNIT_TYPES


def test_collector_init_normalizes_list_unit_types():
    SystemdCollector._version = 252
    SystemdCollector._hierarchy = "v2"
    coll = SystemdCollector(unit_types=["service", "timer"])
    assert coll.unit_types == "service,timer"


def test_list_units_builds_valid_type_arg_from_list():
    """A list unit_types must produce --type=service,timer, not a Python repr."""
    SystemdCollector._version = 252
    SystemdCollector._hierarchy = "v2"
    coll = SystemdCollector(unit_types=["service", "timer"])
    captured = {}

    def fake_run(args, timeout=None):
        captured["args"] = args
        return "", None

    with patch("fivenines_agent.systemd._run_systemctl", side_effect=fake_run):
        coll._list_units()
    assert "--type=service,timer" in captured["args"]


# ---- unit_types change clears failure signatures (fix #11) ----


def test_unit_types_change_clears_failure_signatures():
    SystemdCollector._version = 252
    SystemdCollector._hierarchy = "v2"
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch.object(SystemdCollector, "collect", return_value={}):
            systemd_metrics(unit_types="service,timer,socket")
            SystemdCollector._last_failure_signatures["old.timer"] = ("1", "T1")
            # Narrow the unit set -> new collector instance, stale sigs cleared.
            systemd_metrics(unit_types="service")
    assert "old.timer" not in SystemdCollector._last_failure_signatures


# ---- refresh_runtime_caches (fix #9) ----


def test_refresh_runtime_caches_redetects_hierarchy_and_version():
    SystemdCollector._hierarchy = None
    SystemdCollector._version = None
    with patch("fivenines_agent.systemd.cgroup_reset_cache") as mock_reset:
        with patch("fivenines_agent.systemd.detect_hierarchy", return_value="v2"):
            with patch("fivenines_agent.systemd._systemd_version", return_value=252):
                refresh_runtime_caches()
    mock_reset.assert_called_once()
    assert SystemdCollector._hierarchy == "v2"
    assert SystemdCollector._version == 252


# ---- LRU touch-on-access (fix #8) ----


def test_failure_cache_lru_evicts_least_recently_seen():
    """After the cache fills, re-confirming an old unit each tick keeps it; a
    unit not seen for a while is the one evicted."""
    coll = _make_collector()
    sigs = SystemdCollector._last_failure_signatures
    # Fill to the cap with distinct failed units.
    for i in range(systemd.FAILURE_SIG_MAX):
        coll._is_newly_failed(
            f"u{i}.service",
            {"ActiveState": "failed", "NRestarts": "1", "ActiveEnterTimestamp": "T"},
        )
    assert len(sigs) == systemd.FAILURE_SIG_MAX
    # Touch u0 (re-confirm, unchanged) so it becomes most-recently-seen.
    coll._is_newly_failed(
        "u0.service",
        {"ActiveState": "failed", "NRestarts": "1", "ActiveEnterTimestamp": "T"},
    )
    # Insert one new failure -> eviction of the least-recently-seen (u1, not u0).
    coll._is_newly_failed(
        "new.service",
        {"ActiveState": "failed", "NRestarts": "1", "ActiveEnterTimestamp": "T"},
    )
    assert "u0.service" in sigs
    assert "u1.service" not in sigs
    assert "new.service" in sigs
    assert len(sigs) == systemd.FAILURE_SIG_MAX


def test_failure_cache_reconfirm_does_not_grow():
    coll = _make_collector()
    sigs = SystemdCollector._last_failure_signatures
    props = {"ActiveState": "failed", "NRestarts": "1", "ActiveEnterTimestamp": "T"}
    assert coll._is_newly_failed("a.service", props) is True
    # Re-confirm same signature: no re-drill, no growth.
    assert coll._is_newly_failed("a.service", props) is False
    assert len(sigs) == 1


# ---- UnicodeDecodeError handling (fix #2) ----


def test_run_subprocess_unicode_decode_error_returns_error_dict():
    """Non-UTF-8 child output must degrade to an error dict, not propagate."""
    with patch("fivenines_agent.systemd.shutil.which", return_value="/bin/foo"):
        with patch(
            "fivenines_agent.systemd.subprocess.run",
            side_effect=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid"),
        ):
            stdout, error = _run_subprocess("foo", [], 5)
    assert stdout is None
    assert error["type"] == "unknown"


# ---- whitespace-only version output (fix #6) ----


def test_systemd_version_whitespace_only_stdout_returns_none():
    """A wrapper systemctl returning whitespace must yield None, not IndexError."""
    fake = MagicMock(returncode=0, stdout="\n   \n")
    with patch(
        "fivenines_agent.systemd.shutil.which", return_value="/usr/bin/systemctl"
    ):
        with patch("fivenines_agent.systemd.subprocess.run", return_value=fake):
            assert _systemd_version() is None
