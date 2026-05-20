"""Tests for env module functions including get_user_context."""

import os
from unittest.mock import MagicMock, patch

from fivenines_agent.env import (
    config_dir,
    get_user_context,
    is_windows,
    os_family,
)


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


def test_get_user_context_system_install():
    result = get_user_context("/opt/fivenines")
    assert result["config_dir"] == "/opt/fivenines"
    assert result["is_user_install"] is False


def test_get_user_context_user_install():
    home = os.path.expanduser("~")
    cfg_dir = os.path.join(home, ".local/fivenines")
    result = get_user_context(cfg_dir)
    assert result["is_user_install"] is True


def test_get_user_context_current_user():
    result = get_user_context("/opt/fivenines")
    assert result["uid"] == os.getuid()
    assert result["euid"] == os.geteuid()
    assert result["gid"] == os.getgid()
    assert result["is_root"] == (os.getuid() == 0)


@patch("fivenines_agent.env.os.getuid", side_effect=OSError("mocked"))
def test_get_user_context_error_fallback(mock_uid):
    result = get_user_context("/opt/fivenines")
    assert result == {
        "username": "unknown",
        "is_root": False,
        "is_user_install": False,
    }


@patch("fivenines_agent.env.pwd.getpwuid", side_effect=KeyError("no user"))
def test_get_user_context_unknown_username(mock_pw):
    result = get_user_context("/opt/fivenines")
    assert result["username"] == str(os.getuid())


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


def test_is_windows_false_on_this_host():
    # Test host is macOS or a Linux CI runner, never Windows.
    assert is_windows() is False


@patch("fivenines_agent.env.platform.system", return_value="Windows")
def test_is_windows_true_when_platform_is_windows(mock_sys):
    assert is_windows() is True
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
    # On a non-Windows host, ctypes.windll raises AttributeError -> is_admin False.
    with patch("fivenines_agent.env.is_windows", return_value=True), \
         patch("getpass.getuser", return_value="Administrator"):
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
