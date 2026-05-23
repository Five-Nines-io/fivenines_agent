"""Tests for env module functions including get_user_context."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from fivenines_agent.env import (
    config_dir,
    get_user_context,
    is_windows,
    os_family,
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
