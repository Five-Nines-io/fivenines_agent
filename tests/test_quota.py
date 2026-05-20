"""Tests for the disk quota metrics collector."""

import subprocess
import sys
from unittest.mock import MagicMock, patch

# Mock libvirt before any fivenines_agent imports that transitively need it
sys.modules.setdefault("libvirt", MagicMock())

from fivenines_agent.quota import (  # noqa: E402
    _fetch_primary_group_quota,
    _parse_filesystem_row,
    _parse_quota_output,
    _quota_env,
    _strip_asterisk,
    quota_metrics,
)


# ---------------------------------------------------------------------------
# _quota_env
# ---------------------------------------------------------------------------


def test_quota_env_has_lc_all_c():
    """_quota_env sets LC_ALL=C on top of the clean env."""
    with patch("fivenines_agent.subprocess_utils.get_clean_env", return_value={"PATH": "/usr/bin"}):
        env = _quota_env()
    assert env["LC_ALL"] == "C"
    assert env["PATH"] == "/usr/bin"


# ---------------------------------------------------------------------------
# _strip_asterisk / integer parsing
# ---------------------------------------------------------------------------


def test_parse_value_with_asterisk():
    """Trailing asterisk is stripped before int conversion."""
    assert _strip_asterisk("65*") == 65


def test_parse_value_without_asterisk():
    """Plain integer string is converted normally."""
    assert _strip_asterisk("65") == 65


def test_parse_value_zero():
    """Zero (meaning 'no limit') is parsed correctly."""
    assert _strip_asterisk("0") == 0


# ---------------------------------------------------------------------------
# Exceeded-flag semantics
# ---------------------------------------------------------------------------


def _make_row(space_used, space_soft, space_hard, files_used=0, files_soft=0, files_hard=0):
    """Build a minimal quota output line for testing exceeded flags."""
    line = "/dev/sda1  {}  {}  {}  {}  {}  {}".format(
        space_used, space_soft, space_hard, files_used, files_soft, files_hard
    )
    return _parse_filesystem_row(line)


def test_exceeded_soft_nonzero_used_greater():
    """soft=50000, used=50001 -> soft_exceeded=True."""
    row = _make_row(50001, 50000, 60000)
    assert row["soft_exceeded"] is True


def test_exceeded_soft_nonzero_used_equal():
    """soft=50000, used=50000 -> soft_exceeded=False (strictly greater-than)."""
    row = _make_row(50000, 50000, 60000)
    assert row["soft_exceeded"] is False


def test_exceeded_soft_zero_unlimited():
    """soft=0, used=99999 -> soft_exceeded=False (0 means no limit)."""
    row = _make_row(99999, 0, 60000)
    assert row["soft_exceeded"] is False


def test_exceeded_hard_nonzero_used_equal():
    """hard=60000, used=60000 -> hard_exceeded=True (greater-or-equal)."""
    row = _make_row(60000, 50000, 60000)
    assert row["hard_exceeded"] is True


def test_exceeded_hard_nonzero_used_less():
    """hard=60000, used=59999 -> hard_exceeded=False."""
    row = _make_row(59999, 50000, 60000)
    assert row["hard_exceeded"] is False


def test_exceeded_hard_zero_unlimited():
    """hard=0, used=99999 -> hard_exceeded=False."""
    row = _make_row(99999, 50000, 0)
    assert row["hard_exceeded"] is False


def test_exceeded_files_soft():
    """File soft limit exceeded triggers soft_exceeded."""
    row = _make_row(100, 50000, 60000, files_used=10001, files_soft=10000, files_hard=12000)
    assert row["soft_exceeded"] is True


def test_exceeded_files_hard():
    """File hard limit at-limit triggers hard_exceeded."""
    row = _make_row(100, 50000, 60000, files_used=12000, files_soft=10000, files_hard=12000)
    assert row["hard_exceeded"] is True


# ---------------------------------------------------------------------------
# User-section parsing
# ---------------------------------------------------------------------------


def test_parse_user_none():
    """'none' trailer produces user with empty filesystems list."""
    stdout = "Disk quotas for user alice (uid 1000): none\n"
    user, groups = _parse_quota_output(stdout)
    assert user is not None
    assert user["name"] == "alice"
    assert user["id"] == 1000
    assert user["filesystems"] == []


def test_parse_user_no_limited_resources():
    """'no limited resources used' produces user with empty filesystems."""
    stdout = "Disk quotas for user bob (uid 1001): no limited resources used\n"
    user, groups = _parse_quota_output(stdout)
    assert user is not None
    assert user["name"] == "bob"
    assert user["id"] == 1001
    assert user["filesystems"] == []


def test_parse_user_single_filesystem_under_quota():
    """Single filesystem under quota, both flags False."""
    stdout = (
        "Disk quotas for user spuyet (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   12345   50000   60000           1234   10000   12000\n"
    )
    user, groups = _parse_quota_output(stdout)
    assert user["name"] == "spuyet"
    assert user["id"] == 1000
    assert len(user["filesystems"]) == 1
    fs = user["filesystems"][0]
    assert fs["filesystem"] == "/dev/sda1"
    assert fs["space"]["used_kib"] == 12345
    assert fs["space"]["soft_kib"] == 50000
    assert fs["space"]["hard_kib"] == 60000
    assert fs["space"]["grace"] is None
    assert fs["files"]["used"] == 1234
    assert fs["files"]["soft"] == 10000
    assert fs["files"]["hard"] == 12000
    assert fs["files"]["grace"] is None
    assert fs["soft_exceeded"] is False
    assert fs["hard_exceeded"] is False


def test_parse_user_multiple_filesystems():
    """User with local + NFS filesystems."""
    stdout = (
        "Disk quotas for user spuyet (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   12345   50000   60000           1234   10000   12000\n"
        "       host:/nfs  98765* 100000  120000  6days   5000    8000   10000\n"
    )
    user, groups = _parse_quota_output(stdout)
    assert len(user["filesystems"]) == 2

    fs0 = user["filesystems"][0]
    assert fs0["filesystem"] == "/dev/sda1"

    fs1 = user["filesystems"][1]
    assert fs1["filesystem"] == "host:/nfs"
    assert fs1["space"]["used_kib"] == 98765
    assert fs1["space"]["soft_kib"] == 100000
    assert fs1["space"]["hard_kib"] == 120000
    assert fs1["space"]["grace"] == "6days"
    assert fs1["soft_exceeded"] is False  # 98765 <= 100000


def test_parse_user_soft_limit_exceeded_with_asterisk():
    """Asterisk on blocks value, grace populated, soft_exceeded True."""
    stdout = (
        "Disk quotas for user alice (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1  100001*  100000  120000  6days   5000    8000   10000\n"
    )
    user, _ = _parse_quota_output(stdout)
    fs = user["filesystems"][0]
    assert fs["space"]["used_kib"] == 100001
    assert fs["space"]["grace"] == "6days"
    assert fs["soft_exceeded"] is True
    assert fs["hard_exceeded"] is False


def test_parse_user_hard_limit_exceeded():
    """used >= hard triggers hard_exceeded=True."""
    stdout = (
        "Disk quotas for user alice (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1  120000*  100000  120000  6days   5000    8000   10000\n"
    )
    user, _ = _parse_quota_output(stdout)
    fs = user["filesystems"][0]
    assert fs["hard_exceeded"] is True
    assert fs["soft_exceeded"] is True


def test_parse_user_grace_period_formats():
    """Various grace string formats are captured as-is."""
    lines = [
        "      /dev/sda1  100001*  100000  120000  6days   5000    8000   10000",
        "      /dev/sdb1  100001*  100000  120000  5:32    5000    8000   10000",
        "      /dev/sdc1  100001*  100000  120000  none    5000    8000   10000",
    ]
    for line in lines:
        row = _parse_filesystem_row(line.strip())
        assert row is not None
        assert row["space"]["grace"] is not None


# ---------------------------------------------------------------------------
# Group-section parsing
# ---------------------------------------------------------------------------


def test_parse_groups_empty():
    """No group sections in output produces empty groups list."""
    stdout = (
        "Disk quotas for user spuyet (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   12345   50000   60000           1234   10000   12000\n"
    )
    _, groups = _parse_quota_output(stdout)
    assert groups == []


def test_parse_groups_single():
    """Single group section parsed correctly."""
    stdout = (
        "Disk quotas for group dev (gid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   45678   90000  100000          5678   20000   25000\n"
    )
    _, groups = _parse_quota_output(stdout)
    assert len(groups) == 1
    assert groups[0]["name"] == "dev"
    assert groups[0]["id"] == 1000
    assert len(groups[0]["filesystems"]) == 1
    assert groups[0]["filesystems"][0]["space"]["used_kib"] == 45678


def test_parse_groups_multiple():
    """User in 3+ groups, each with its own section."""
    stdout = (
        "Disk quotas for group dev (gid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   45678   90000  100000          5678   20000   25000\n"
        "Disk quotas for group docker (gid 999): none\n"
        "Disk quotas for group www-data (gid 33):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   10000   80000   90000          2000   15000   20000\n"
    )
    _, groups = _parse_quota_output(stdout)
    assert len(groups) == 3
    assert groups[0]["name"] == "dev"
    assert groups[1]["name"] == "docker"
    assert groups[1]["filesystems"] == []
    assert groups[2]["name"] == "www-data"
    assert groups[2]["id"] == 33


def test_parse_group_none():
    """'none' trailer for group produces group with empty filesystems."""
    stdout = "Disk quotas for group docker (gid 999): none\n"
    _, groups = _parse_quota_output(stdout)
    assert len(groups) == 1
    assert groups[0]["name"] == "docker"
    assert groups[0]["id"] == 999
    assert groups[0]["filesystems"] == []


def test_parse_group_no_limited_resources():
    """'no limited resources used' variant for groups."""
    stdout = "Disk quotas for group docker (gid 999): no limited resources used\n"
    _, groups = _parse_quota_output(stdout)
    assert len(groups) == 1
    assert groups[0]["filesystems"] == []


def test_parse_group_id_extraction():
    """(gid N) is parsed from the header."""
    stdout = "Disk quotas for group staff (gid 50): none\n"
    _, groups = _parse_quota_output(stdout)
    assert groups[0]["id"] == 50


def test_uid_extraction():
    """(uid N) is parsed from the user header."""
    stdout = "Disk quotas for user testuser (uid 5001): none\n"
    user, _ = _parse_quota_output(stdout)
    assert user["id"] == 5001


# ---------------------------------------------------------------------------
# Full output with both user and group sections
# ---------------------------------------------------------------------------


def test_parse_full_output():
    """Full realistic output with user and multiple groups."""
    stdout = (
        "Disk quotas for user spuyet (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   12345   50000   60000           1234   10000   12000\n"
        "       host:/nfs  98765* 100000  120000  6days   5000    8000   10000\n"
        "Disk quotas for group dev (gid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   45678   90000  100000          5678   20000   25000\n"
        "Disk quotas for group docker (gid 999): none\n"
    )
    user, groups = _parse_quota_output(stdout)
    assert user["name"] == "spuyet"
    assert len(user["filesystems"]) == 2
    assert len(groups) == 2
    assert groups[0]["name"] == "dev"
    assert groups[1]["name"] == "docker"
    assert groups[1]["filesystems"] == []


# ---------------------------------------------------------------------------
# Filesystem row edge cases
# ---------------------------------------------------------------------------


def test_parse_filesystem_row_too_few_columns():
    """Row with fewer than 7 columns returns None."""
    assert _parse_filesystem_row("/dev/sda1 100 200") is None


def test_parse_filesystem_row_malformed_values():
    """Non-numeric values in expected numeric columns return None."""
    assert _parse_filesystem_row("/dev/sda1 abc def ghi jkl mno pqr") is None


# ---------------------------------------------------------------------------
# Primary group fallback
# ---------------------------------------------------------------------------


def test_primary_group_present_in_output():
    """When primary group is already in output, no fallback subprocess call."""
    stdout = (
        "Disk quotas for user spuyet (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   12345   50000   60000           1234   10000   12000\n"
        "Disk quotas for group dev (gid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   45678   90000  100000          5678   20000   25000\n"
    )
    main_result = MagicMock()
    main_result.returncode = 0
    main_result.stdout = stdout
    main_result.stderr = ""

    with patch("fivenines_agent.quota.subprocess.run", return_value=main_result) as mock_run, \
         patch("fivenines_agent.quota.os.getegid", return_value=1000):
        result = quota_metrics()

    # Only one subprocess call (the main quota -ugw)
    assert mock_run.call_count == 1
    assert len(result["groups"]) == 1
    assert result["groups"][0]["id"] == 1000


def test_primary_group_missing_triggers_fallback():
    """When primary group is not in parsed groups, fallback call fires."""
    main_stdout = (
        "Disk quotas for user spuyet (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   12345   50000   60000           1234   10000   12000\n"
        "Disk quotas for group docker (gid 999): none\n"
    )
    fallback_stdout = (
        "Disk quotas for group staff (gid 50):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   5000   80000   90000          2000   15000   20000\n"
    )

    main_result = MagicMock()
    main_result.returncode = 0
    main_result.stdout = main_stdout
    main_result.stderr = ""

    fallback_result = MagicMock()
    fallback_result.returncode = 0
    fallback_result.stdout = fallback_stdout
    fallback_result.stderr = ""

    mock_grp = MagicMock()
    mock_grp.gr_name = "staff"

    with patch("fivenines_agent.quota.subprocess.run", side_effect=[main_result, fallback_result]) as mock_run, \
         patch("fivenines_agent.quota.os.getegid", return_value=50), \
         patch("fivenines_agent.quota.grp.getgrgid", return_value=mock_grp):
        result = quota_metrics()

    assert mock_run.call_count == 2
    # Second call passes group name as positional arg, not --group=GID
    assert "staff" in mock_run.call_args_list[1][0][0]
    assert len(result["groups"]) == 2
    group_ids = [g["id"] for g in result["groups"]]
    assert 50 in group_ids


def test_primary_group_fallback_timeout():
    """Fallback timeout is non-fatal -- group is simply omitted."""
    main_stdout = (
        "Disk quotas for user spuyet (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   12345   50000   60000           1234   10000   12000\n"
    )
    main_result = MagicMock()
    main_result.returncode = 0
    main_result.stdout = main_stdout
    main_result.stderr = ""

    mock_grp = MagicMock()
    mock_grp.gr_name = "staff"

    def run_side_effect(cmd, **kwargs):
        if "staff" in cmd:
            raise subprocess.TimeoutExpired(cmd, 10)
        return main_result

    with patch("fivenines_agent.quota.subprocess.run", side_effect=run_side_effect), \
         patch("fivenines_agent.quota.os.getegid", return_value=50), \
         patch("fivenines_agent.quota.grp.getgrgid", return_value=mock_grp):
        result = quota_metrics()

    # Result is valid despite fallback timeout
    assert result is not None
    assert result["user"]["name"] == "spuyet"
    assert result["groups"] == []


# ---------------------------------------------------------------------------
# Collector behavior -- exit codes and error handling
# ---------------------------------------------------------------------------


def test_collector_exit_0_parses():
    """Exit 0 with valid stdout is parsed normally."""
    stdout = (
        "Disk quotas for user alice (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   12345   50000   60000           1234   10000   12000\n"
    )
    result = MagicMock()
    result.returncode = 0
    result.stdout = stdout
    result.stderr = ""

    with patch("fivenines_agent.quota.subprocess.run", return_value=result), \
         patch("fivenines_agent.quota.os.getegid", return_value=1000):
        data = quota_metrics()

    assert data is not None
    assert data["command"] == "quota -ugw"
    assert data["space_unit"] == "kib"
    assert data["user"]["name"] == "alice"


def test_collector_exit_nonzero_valid_stdout_parses():
    """Exit 1 with valid stdout (exceeded) is parsed, not treated as error."""
    stdout = (
        "Disk quotas for user alice (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1  100001* 100000  120000  6days   5000    8000   10000\n"
    )
    result = MagicMock()
    result.returncode = 1
    result.stdout = stdout
    result.stderr = ""

    with patch("fivenines_agent.quota.subprocess.run", return_value=result), \
         patch("fivenines_agent.quota.os.getegid", return_value=1000):
        data = quota_metrics()

    assert data is not None
    assert data["user"]["filesystems"][0]["soft_exceeded"] is True


def test_collector_exit_nonzero_empty_stdout():
    """Exit 1 with empty stdout -> returns None and logs error."""
    result = MagicMock()
    result.returncode = 1
    result.stdout = ""
    result.stderr = "quota: Cannot open quotafile"

    with patch("fivenines_agent.quota.subprocess.run", return_value=result), \
         patch("fivenines_agent.quota.log") as mock_log:
        data = quota_metrics()

    assert data is None
    error_calls = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert len(error_calls) >= 1


def test_collector_exit_0_empty_stdout():
    """Exit 0 with empty stdout -> returns {} (no quotas configured)."""
    result = MagicMock()
    result.returncode = 0
    result.stdout = ""
    result.stderr = ""

    with patch("fivenines_agent.quota.subprocess.run", return_value=result):
        data = quota_metrics()

    assert data == {}


def test_collector_timeout():
    """Subprocess timeout returns None and logs error."""
    with patch("fivenines_agent.quota.subprocess.run", side_effect=subprocess.TimeoutExpired(["quota"], 10)), \
         patch("fivenines_agent.quota.log") as mock_log:
        data = quota_metrics()

    assert data is None
    error_calls = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert any("timed out" in c.args[0] for c in error_calls)


def test_collector_generic_exception():
    """Generic exception returns None and logs error."""
    with patch("fivenines_agent.quota.subprocess.run", side_effect=OSError("no such file")), \
         patch("fivenines_agent.quota.log") as mock_log:
        data = quota_metrics()

    assert data is None
    error_calls = [c for c in mock_log.call_args_list if c.args[1] == "error"]
    assert len(error_calls) >= 1


def test_collector_malformed_output():
    """Garbage stdout that produces no sections -> returns {}."""
    result = MagicMock()
    result.returncode = 0
    result.stdout = "this is not quota output at all\nrandom garbage\n"
    result.stderr = ""

    with patch("fivenines_agent.quota.subprocess.run", return_value=result):
        data = quota_metrics()

    assert data == {}


def test_collector_uses_clean_env_with_lc_all():
    """Verify subprocess is called with _quota_env (LC_ALL=C + clean env)."""
    result = MagicMock()
    result.returncode = 0
    result.stdout = "Disk quotas for user alice (uid 1000): none\n"
    result.stderr = ""

    with patch("fivenines_agent.quota.subprocess.run", return_value=result) as mock_run, \
         patch("fivenines_agent.quota.os.getegid", return_value=1000):
        quota_metrics()

    call_kwargs = mock_run.call_args
    env = call_kwargs.kwargs.get("env") or call_kwargs[1].get("env")
    assert env is not None
    assert env["LC_ALL"] == "C"


def test_lc_all_c_forced():
    """_quota_env explicitly sets LC_ALL=C regardless of system locale."""
    with patch("fivenines_agent.subprocess_utils.get_clean_env", return_value={"LC_ALL": "fr_FR.UTF-8", "PATH": "/usr/bin"}):
        env = _quota_env()
    assert env["LC_ALL"] == "C"


def test_partial_stdout_with_stderr():
    """stderr 'Cannot stat()' with partial stdout -> parse what we can, log stderr at debug."""
    stdout = (
        "Disk quotas for user alice (uid 1000):\n"
        "     Filesystem  blocks   quota   limit   grace   files   quota   limit   grace\n"
        "      /dev/sda1   12345   50000   60000           1234   10000   12000\n"
    )
    result = MagicMock()
    result.returncode = 1
    result.stdout = stdout
    result.stderr = "quota: Cannot stat() mounted device /dev/sdb1: No such file or directory"

    with patch("fivenines_agent.quota.subprocess.run", return_value=result), \
         patch("fivenines_agent.quota.os.getegid", return_value=1000), \
         patch("fivenines_agent.quota.log") as mock_log:
        data = quota_metrics()

    # Data is still returned despite stderr
    assert data is not None
    assert data["user"]["name"] == "alice"
    # stderr is logged at debug level
    debug_calls = [c for c in mock_log.call_args_list if c.args[1] == "debug"]
    assert any("Cannot stat()" in c.args[0] for c in debug_calls)


# ---------------------------------------------------------------------------
# _fetch_primary_group_quota edge cases
# ---------------------------------------------------------------------------


def test_fetch_primary_group_quota_gid_resolve_fails():
    """GID that doesn't map to a group name returns None."""
    with patch("fivenines_agent.quota.grp.getgrgid", side_effect=KeyError("getgrgid(): gid not found: 99999")):
        assert _fetch_primary_group_quota(99999) is None


def test_fetch_primary_group_quota_empty_stdout():
    """Empty stdout from fallback returns None."""
    result = MagicMock()
    result.returncode = 0
    result.stdout = ""
    result.stderr = ""

    mock_grp = MagicMock()
    mock_grp.gr_name = "staff"

    with patch("fivenines_agent.quota.grp.getgrgid", return_value=mock_grp), \
         patch("fivenines_agent.quota.subprocess.run", return_value=result):
        assert _fetch_primary_group_quota(50) is None


def test_fetch_primary_group_quota_gid_not_in_output():
    """Fallback output that does not contain the requested GID returns None."""
    result = MagicMock()
    result.returncode = 0
    result.stdout = "Disk quotas for group other (gid 99): none\n"
    result.stderr = ""

    mock_grp = MagicMock()
    mock_grp.gr_name = "staff"

    with patch("fivenines_agent.quota.grp.getgrgid", return_value=mock_grp), \
         patch("fivenines_agent.quota.subprocess.run", return_value=result):
        assert _fetch_primary_group_quota(50) is None


def test_fetch_primary_group_quota_exception():
    """Generic exception in fallback returns None."""
    mock_grp = MagicMock()
    mock_grp.gr_name = "staff"

    with patch("fivenines_agent.quota.grp.getgrgid", return_value=mock_grp), \
         patch("fivenines_agent.quota.subprocess.run", side_effect=OSError("boom")):
        assert _fetch_primary_group_quota(50) is None


# ---------------------------------------------------------------------------
# Permissions probe tests (_can_run_quota)
# ---------------------------------------------------------------------------


def test_can_run_quota_binary_missing():
    """which returns None -> False, reason set."""
    from fivenines_agent.permissions import PermissionProbe

    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    probe._capability_reasons = {}
    probe._current_reason = None

    with patch("fivenines_agent.permissions.shutil.which", return_value=None):
        result = probe._can_run_quota()

    assert result is False
    assert probe._current_reason == "quota not found in PATH"


def test_can_run_quota_exit_0_stdout_present():
    """Exit 0 with stdout -> True."""
    from fivenines_agent.permissions import PermissionProbe

    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    probe._capability_reasons = {}
    probe._current_reason = None

    result_obj = MagicMock()
    result_obj.returncode = 0
    result_obj.stdout = b"Disk quotas for user alice (uid 1000): none\n"
    result_obj.stderr = b""

    with patch("fivenines_agent.permissions.shutil.which", return_value="/usr/bin/quota"), \
         patch("fivenines_agent.permissions.subprocess.run", return_value=result_obj):
        result = probe._can_run_quota()

    assert result is True


def test_can_run_quota_exit_nonzero_stdout_present():
    """Exit nonzero with valid stdout (exceeded) -> True."""
    from fivenines_agent.permissions import PermissionProbe

    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    probe._capability_reasons = {}
    probe._current_reason = None

    result_obj = MagicMock()
    result_obj.returncode = 1
    result_obj.stdout = b"Disk quotas for user alice (uid 1000):\n"
    result_obj.stderr = b""

    with patch("fivenines_agent.permissions.shutil.which", return_value="/usr/bin/quota"), \
         patch("fivenines_agent.permissions.subprocess.run", return_value=result_obj):
        result = probe._can_run_quota()

    assert result is True


def test_can_run_quota_exit_0_empty_stdout():
    """Exit 0 with empty stdout -> True (no quotas but binary works)."""
    from fivenines_agent.permissions import PermissionProbe

    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    probe._capability_reasons = {}
    probe._current_reason = None

    result_obj = MagicMock()
    result_obj.returncode = 0
    result_obj.stdout = b""
    result_obj.stderr = b""

    with patch("fivenines_agent.permissions.shutil.which", return_value="/usr/bin/quota"), \
         patch("fivenines_agent.permissions.subprocess.run", return_value=result_obj):
        result = probe._can_run_quota()

    assert result is True


def test_can_run_quota_exit_nonzero_empty_stdout():
    """Exit nonzero with empty stdout -> False, reason populated."""
    from fivenines_agent.permissions import PermissionProbe

    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    probe._capability_reasons = {}
    probe._current_reason = None

    result_obj = MagicMock()
    result_obj.returncode = 1
    result_obj.stdout = b""
    result_obj.stderr = b"quota: Cannot open quotafile\n"

    with patch("fivenines_agent.permissions.shutil.which", return_value="/usr/bin/quota"), \
         patch("fivenines_agent.permissions.subprocess.run", return_value=result_obj):
        result = probe._can_run_quota()

    assert result is False
    assert "Cannot open quotafile" in probe._current_reason


def test_can_run_quota_exit_nonzero_empty_stdout_no_stderr():
    """Exit nonzero with empty stdout and empty stderr -> False, reason has returncode."""
    from fivenines_agent.permissions import PermissionProbe

    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    probe._capability_reasons = {}
    probe._current_reason = None

    result_obj = MagicMock()
    result_obj.returncode = 2
    result_obj.stdout = b""
    result_obj.stderr = b""

    with patch("fivenines_agent.permissions.shutil.which", return_value="/usr/bin/quota"), \
         patch("fivenines_agent.permissions.subprocess.run", return_value=result_obj):
        result = probe._can_run_quota()

    assert result is False
    assert "returncode 2" in probe._current_reason


def test_can_run_quota_timeout():
    """Subprocess timeout -> False, reason mentions timeout."""
    from fivenines_agent.permissions import PermissionProbe

    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    probe._capability_reasons = {}
    probe._current_reason = None

    with patch("fivenines_agent.permissions.shutil.which", return_value="/usr/bin/quota"), \
         patch("fivenines_agent.permissions.subprocess.run", side_effect=subprocess.TimeoutExpired(["quota"], 5)):
        result = probe._can_run_quota()

    assert result is False
    assert "timed out" in probe._current_reason


def test_can_run_quota_generic_exception():
    """Generic exception -> False, reason includes exception type."""
    from fivenines_agent.permissions import PermissionProbe

    probe = PermissionProbe.__new__(PermissionProbe)
    probe.capabilities = {}
    probe._capability_reasons = {}
    probe._current_reason = None

    with patch("fivenines_agent.permissions.shutil.which", return_value="/usr/bin/quota"), \
         patch("fivenines_agent.permissions.subprocess.run", side_effect=OSError("permission denied")):
        result = probe._can_run_quota()

    assert result is False
    assert "OSError" in probe._current_reason
