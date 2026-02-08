"""Tests for fivenines_agent.packages module."""

import hashlib
import subprocess
from unittest.mock import MagicMock, mock_open, patch

from fivenines_agent.packages import (
    _get_packages_apk,
    _get_packages_dpkg,
    _get_packages_rpm,
    get_distro,
    get_installed_packages,
    get_packages_hash,
    packages_available,
)


# --- packages_available ---


@patch("fivenines_agent.packages.shutil.which")
def test_packages_available_dpkg(mock_which):
    mock_which.side_effect = lambda cmd: (
        "/usr/bin/dpkg-query" if cmd == "dpkg-query" else None
    )
    assert packages_available() is True


@patch("fivenines_agent.packages.shutil.which")
def test_packages_available_rpm(mock_which):
    mock_which.side_effect = lambda cmd: "/usr/bin/rpm" if cmd == "rpm" else None
    assert packages_available() is True


@patch("fivenines_agent.packages.shutil.which")
def test_packages_available_apk(mock_which):
    mock_which.side_effect = lambda cmd: "/sbin/apk" if cmd == "apk" else None
    assert packages_available() is True


@patch("fivenines_agent.packages.shutil.which", return_value=None)
def test_packages_available_none(mock_which):
    assert packages_available() is False


# --- get_distro ---


def test_get_distro_debian():
    content = 'PRETTY_NAME="Debian GNU/Linux 12"\nID=debian\nVERSION_ID="12"\n'
    with patch("builtins.open", mock_open(read_data=content)):
        assert get_distro() == "debian:12"


def test_get_distro_ubuntu():
    content = 'ID=ubuntu\nVERSION_ID="22.04"\n'
    with patch("builtins.open", mock_open(read_data=content)):
        assert get_distro() == "ubuntu:22.04"


def test_get_distro_quoted():
    content = 'ID="alpine"\nVERSION_ID="3.19"\n'
    with patch("builtins.open", mock_open(read_data=content)):
        assert get_distro() == "alpine:3.19"


def test_get_distro_no_version():
    content = 'ID="alpine"\n'
    with patch("builtins.open", mock_open(read_data=content)):
        assert get_distro() == "alpine"


def test_get_distro_file_not_found():
    with patch("builtins.open", side_effect=FileNotFoundError):
        assert get_distro() == "unknown"


def test_get_distro_no_id_line():
    content = "PRETTY_NAME=Foo\nVERSION=1\n"
    with patch("builtins.open", mock_open(read_data=content)):
        assert get_distro() == "unknown"


# --- _get_packages_dpkg ---


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_dpkg_success(mock_run, mock_env):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="openssl\t3.0.11-1\nzlib\t1.2.13\n",
    )
    result = _get_packages_dpkg()
    assert result == [
        {"name": "openssl", "version": "3.0.11-1"},
        {"name": "zlib", "version": "1.2.13"},
    ]
    mock_run.assert_called_once()
    args = mock_run.call_args
    assert args[0][0] == ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"]
    assert args[1]["timeout"] == 30


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_dpkg_failure(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=1, stderr="error")
    result = _get_packages_dpkg()
    assert result == []


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_dpkg_empty_lines(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=0, stdout="")
    result = _get_packages_dpkg()
    assert result == []


# --- _get_packages_rpm ---


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_success(mock_run, mock_env):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="openssl\t3.0.11-1.el9\nbash\t5.2.15-3.el9\n",
    )
    result = _get_packages_rpm()
    assert result == [
        {"name": "openssl", "version": "3.0.11-1.el9"},
        {"name": "bash", "version": "5.2.15-3.el9"},
    ]


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_failure(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=1, stderr="error")
    result = _get_packages_rpm()
    assert result == []


# --- _get_packages_apk ---


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_apk_success(mock_run, mock_env):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="musl-1.2.4-r2 x86_64 {musl} (MIT)\nbusybox-1.36.1-r5 x86_64 {busybox} (GPL-2.0)\n",
    )
    result = _get_packages_apk()
    assert result == [
        {"name": "musl", "version": "1.2.4-r2"},
        {"name": "busybox", "version": "1.36.1-r5"},
    ]


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_apk_failure(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=1, stderr="error")
    result = _get_packages_apk()
    assert result == []


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_apk_two_segment(mock_run, mock_env):
    """Package with only one hyphen separator (name-version)."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="foo-1.0 x86_64 {foo} (MIT)\n",
    )
    result = _get_packages_apk()
    assert result == [{"name": "foo", "version": "1.0"}]


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_apk_empty_lines(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=0, stdout="\n\n")
    result = _get_packages_apk()
    assert result == []


# --- get_installed_packages ---


@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages._get_packages_dpkg")
def test_get_installed_packages_dpkg(mock_dpkg, mock_which):
    mock_which.side_effect = lambda cmd: (
        "/usr/bin/dpkg-query" if cmd == "dpkg-query" else None
    )
    mock_dpkg.return_value = [
        {"name": "zlib", "version": "1.0"},
        {"name": "openssl", "version": "3.0"},
    ]
    result = get_installed_packages()
    assert result == [
        {"name": "openssl", "version": "3.0"},
        {"name": "zlib", "version": "1.0"},
    ]


@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages._get_packages_rpm")
def test_get_installed_packages_rpm(mock_rpm, mock_which):
    mock_which.side_effect = lambda cmd: "/usr/bin/rpm" if cmd == "rpm" else None
    mock_rpm.return_value = [{"name": "bash", "version": "5.0"}]
    result = get_installed_packages()
    assert result == [{"name": "bash", "version": "5.0"}]


@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages._get_packages_apk")
def test_get_installed_packages_apk(mock_apk, mock_which):
    mock_which.side_effect = lambda cmd: "/sbin/apk" if cmd == "apk" else None
    mock_apk.return_value = [{"name": "musl", "version": "1.2"}]
    result = get_installed_packages()
    assert result == [{"name": "musl", "version": "1.2"}]


@patch("fivenines_agent.packages.shutil.which", return_value=None)
def test_get_installed_packages_none(mock_which):
    result = get_installed_packages()
    assert result == []


@patch("fivenines_agent.packages.shutil.which", return_value="/usr/bin/dpkg-query")
@patch(
    "fivenines_agent.packages._get_packages_dpkg",
    side_effect=subprocess.TimeoutExpired("cmd", 30),
)
def test_get_installed_packages_timeout(mock_dpkg, mock_which):
    result = get_installed_packages()
    assert result == []


@patch("fivenines_agent.packages.shutil.which", return_value="/usr/bin/dpkg-query")
@patch(
    "fivenines_agent.packages._get_packages_dpkg",
    side_effect=RuntimeError("boom"),
)
def test_get_installed_packages_exception(mock_dpkg, mock_which):
    result = get_installed_packages()
    assert result == []


# --- get_packages_hash ---


def test_get_packages_hash():
    packages = [
        {"name": "openssl", "version": "3.0.11-1"},
        {"name": "zlib", "version": "1.2.13"},
    ]
    expected = hashlib.sha256(b"openssl=3.0.11-1\nzlib=1.2.13\n").hexdigest()
    assert get_packages_hash(packages) == expected


def test_get_packages_hash_empty():
    assert get_packages_hash([]) == hashlib.sha256(b"").hexdigest()


def test_get_packages_hash_deterministic():
    packages = [{"name": "a", "version": "1"}, {"name": "b", "version": "2"}]
    assert get_packages_hash(packages) == get_packages_hash(packages)
