"""Tests for env module functions including get_user_context."""

import os
import sys
from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest

from fivenines_agent import cli
from fivenines_agent.env import (
    api_url,
    config_dir,
    dry_run,
    get_user_context,
    is_windows,
    log_level,
    os_family,
    restrict_to_owner,
)


@pytest.fixture(autouse=True)
def _default_to_linux_env_path():
    """Force is_windows=False by default so existing Linux-shape tests for
    get_user_context (and similar) run identically on Windows CI. Tests that
    exercise the Windows branch explicitly override via @patch (decorator
    wins inside the test body). Tests that exercise the is_windows function
    itself should test os_family() directly, which is not patched here."""
    with patch("fivenines_agent.env.is_windows", return_value=False):
        yield


# Tests asserting the Linux/POSIX get_user_context shape (uid/euid/gid,
# pwd.getpwuid, grp.getgrgid). Cannot run on Windows because os.getuid
# itself does not exist there - the Windows branch (_windows_user_context)
# is exercised by the explicit Windows test functions below.
linux_user_context_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Test asserts Linux/POSIX get_user_context shape; Windows uses _windows_user_context",
)


@linux_user_context_only
def test_get_user_context_returns_dict():
    result = get_user_context("/opt/fivenines")
    assert isinstance(result, dict)
    assert "username" in result
    assert "uid" in result
    assert "euid" in result
    assert "gid" in result
    assert "groupname" in result
    assert "groups" in result
    assert "is_root" in result
    assert "is_user_install" in result
    assert "config_dir" in result
    assert "home_dir" in result


@linux_user_context_only
def test_get_user_context_system_install():
    result = get_user_context("/opt/fivenines")
    assert result["config_dir"] == "/opt/fivenines"
    assert result["is_user_install"] is False


@linux_user_context_only
def test_get_user_context_user_install():
    home = os.path.expanduser("~")
    cfg_dir = os.path.join(home, ".local/fivenines")
    result = get_user_context(cfg_dir)
    assert result["is_user_install"] is True


@linux_user_context_only
def test_get_user_context_current_user():
    result = get_user_context("/opt/fivenines")
    assert result["uid"] == os.getuid()
    assert result["euid"] == os.geteuid()
    assert result["gid"] == os.getgid()
    assert result["is_root"] == (os.getuid() == 0)


@linux_user_context_only
@patch("fivenines_agent.env.os.getuid", side_effect=OSError("mocked"))
def test_get_user_context_error_fallback(mock_uid):
    result = get_user_context("/opt/fivenines")
    assert result == {
        "username": "unknown",
        "is_root": False,
        "is_user_install": False,
    }


@linux_user_context_only
@patch("fivenines_agent.env.pwd.getpwuid", side_effect=KeyError("no user"))
def test_get_user_context_unknown_username(mock_pw):
    result = get_user_context("/opt/fivenines")
    assert result["username"] == str(os.getuid())


@linux_user_context_only
@patch("fivenines_agent.env.grp.getgrgid", side_effect=KeyError("no group"))
def test_get_user_context_unknown_group(mock_grp):
    result = get_user_context("/opt/fivenines")
    assert result["groupname"] == str(os.getgid())
    # groups list should also fall back to numeric strings
    assert all(isinstance(g, str) for g in result["groups"])


# ----- T1: OS helpers, OS-aware config_dir, Windows user context -----


def test_os_family_is_lowercase():
    result = os_family()
    assert result == result.lower()
    assert isinstance(result, str) and result


@patch("fivenines_agent.env.platform.system", return_value="Windows")
def test_os_family_returns_windows_when_platform_is_windows(mock_sys):
    # is_windows() is autouse-patched in this file, so test the underlying
    # os_family() directly. is_windows() is defined as `os_family() == 'windows'`
    # so this is the meaningful check.
    assert os_family() == "windows"


def test_config_dir_linux_default():
    with patch.dict(os.environ, {}, clear=False), \
         patch("fivenines_agent.env.is_windows", return_value=False):
        os.environ.pop("CONFIG_DIR", None)
        assert config_dir() == "/etc/fivenines_agent"


def test_config_dir_env_override_wins():
    with patch.dict(os.environ, {"CONFIG_DIR": "/custom/path"}):
        assert config_dir() == "/custom/path"


def test_config_dir_windows_default():
    with patch.dict(os.environ, {"ProgramData": r"C:\ProgramData"}, clear=False), \
         patch("fivenines_agent.env.is_windows", return_value=True):
        os.environ.pop("CONFIG_DIR", None)
        result = config_dir()
    assert "fivenines_agent" in result
    assert "ProgramData" in result


def test_config_dir_windows_missing_programdata():
    with patch.dict(os.environ, {}, clear=False), \
         patch("fivenines_agent.env.is_windows", return_value=True):
        os.environ.pop("CONFIG_DIR", None)
        os.environ.pop("ProgramData", None)
        result = config_dir()
    assert "fivenines_agent" in result
    assert "ProgramData" in result  # falls back to C:\\ProgramData


def test_get_user_context_windows_admin_check_unavailable():
    """When ctypes.windll IsUserAnAdmin raises, is_admin is False.

    Mock ctypes to raise deterministically so the test exercises the failure
    path on both non-Windows hosts (where ctypes.windll genuinely doesn't
    exist) and on Windows CI (where it does and the runner is admin)."""
    fake_ctypes = MagicMock()
    fake_ctypes.windll.shell32.IsUserAnAdmin.side_effect = AttributeError("windll unavailable")
    with patch("fivenines_agent.env.is_windows", return_value=True), \
         patch("getpass.getuser", return_value="Administrator"), \
         patch.dict("sys.modules", {"ctypes": fake_ctypes}):
        result = get_user_context(r"C:\ProgramData\fivenines_agent")
    assert result["username"] == "Administrator"
    assert result["os_family"] == "windows"
    assert result["is_admin"] is False
    assert result["is_root"] is False
    assert result["is_user_install"] is False
    assert result["config_dir"] == r"C:\ProgramData\fivenines_agent"


def test_get_user_context_windows_admin_check_succeeds():
    fake_ctypes = MagicMock()
    fake_ctypes.windll.shell32.IsUserAnAdmin.return_value = 1
    with patch("fivenines_agent.env.is_windows", return_value=True), \
         patch("getpass.getuser", return_value="admin"), \
         patch.dict("sys.modules", {"ctypes": fake_ctypes}):
        result = get_user_context(r"C:\ProgramData\fivenines_agent")
    assert result["is_admin"] is True
    assert result["is_root"] is True


def test_get_user_context_windows_getuser_fallback():
    with patch("fivenines_agent.env.is_windows", return_value=True), \
         patch("getpass.getuser", side_effect=OSError("no user")), \
         patch.dict(os.environ, {"USERNAME": "envuser"}, clear=False):
        result = get_user_context(r"C:\x")
    assert result["username"] == "envuser"


# --- restrict_to_owner -----------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32", reason="os.fchmod does not exist on Windows"
)
def test_restrict_to_owner_sets_0600_on_posix(tmp_path):
    path = tmp_path / "state"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT, 0o666)
    try:
        restrict_to_owner(fd)
    finally:
        os.close(fd)
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_restrict_to_owner_is_a_noop_without_fchmod(tmp_path, monkeypatch):
    """The Windows path: os.fchmod does not exist, so the helper must do
    nothing rather than raise -- every caller is mid-write on a file it has
    already truncated, and an exception there loses the file's contents."""
    monkeypatch.delattr(os, "fchmod", raising=False)
    path = tmp_path / "state"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        restrict_to_owner(fd)  # must not raise
        os.write(fd, b"still written")
    finally:
        os.close(fd)
    assert path.read_bytes() == b"still written"


# --- api_url / dry_run / log_level -----------------------------------------


@pytest.fixture
def no_run_mode(monkeypatch):
    """Neither DRY_RUN nor a parsed --dry-run; cli._args goes through
    monkeypatch so whatever another test parsed is put back afterwards."""
    monkeypatch.delenv("DRY_RUN", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.setattr(cli, "_args", None)


def test_api_url_default(monkeypatch):
    monkeypatch.delenv("API_URL", raising=False)
    assert api_url() == "api.fivenines.io"


def test_api_url_env_override(monkeypatch):
    monkeypatch.setenv("API_URL", "staging.example.test")
    assert api_url() == "staging.example.test"


def test_dry_run_false_by_default(no_run_mode):
    assert dry_run() is False


def test_dry_run_env_true(no_run_mode, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")
    assert dry_run() is True


@pytest.mark.parametrize("value", ["1", "yes", "True", "TRUE", ""])
def test_dry_run_env_only_accepts_lowercase_true(no_run_mode, monkeypatch, value):
    monkeypatch.setenv("DRY_RUN", value)
    assert dry_run() is False


def test_dry_run_from_parsed_args(no_run_mode, monkeypatch):
    monkeypatch.setattr(cli, "_args", Namespace(dry_run=True))
    assert dry_run() is True
    monkeypatch.setattr(cli, "_args", Namespace(dry_run=False))
    assert dry_run() is False


def test_log_level_defaults_to_info(no_run_mode):
    assert log_level() == "info"


def test_log_level_from_env(no_run_mode, monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "error")
    assert log_level() == "error"


def test_log_level_is_debug_under_dry_run_whatever_log_level_says(
    no_run_mode, monkeypatch
):
    monkeypatch.setenv("LOG_LEVEL", "error")
    monkeypatch.setenv("DRY_RUN", "true")
    assert log_level() == "debug"


def test_log_level_is_debug_under_the_dry_run_flag(no_run_mode, monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "error")
    monkeypatch.setattr(cli, "_args", Namespace(dry_run=True))
    assert log_level() == "debug"
