"""Tests for env module functions including get_user_context."""

import os
from unittest.mock import patch

from fivenines_agent.env import get_user_context


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
