"""Tests for fivenines_agent.packages module."""

import hashlib
import subprocess
from unittest.mock import MagicMock, mock_open, patch

import pytest

from fivenines_agent.debug import start_log_capture, stop_log_capture
from fivenines_agent.packages import (
    _get_packages_apk,
    _get_packages_dpkg,
    _get_packages_pacman,
    _get_packages_rpm,
    _get_packages_synopkg,
    _get_packages_windows_registry,
    get_distro,
    get_installed_packages,
    get_packages_hash,
    packages_available,
)


@pytest.fixture(autouse=True)
def _default_to_linux_packages_path():
    """Existing tests exercise the Linux package-manager dispatch; force
    is_windows=False by default so they run identically on Windows CI.
    Windows-specific tests explicitly override via @patch decorator (decorator
    wins inside the test body)."""
    with patch("fivenines_agent.packages.is_windows", return_value=False):
        yield


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


@patch("fivenines_agent.packages.shutil.which")
def test_packages_available_pacman(mock_which):
    mock_which.side_effect = lambda cmd: (
        "/usr/bin/pacman" if cmd == "pacman" else None
    )
    assert packages_available() is True


@patch("fivenines_agent.packages.shutil.which")
def test_packages_available_synopkg(mock_which):
    mock_which.side_effect = lambda cmd: (
        "/usr/syno/bin/synopkg" if cmd == "synopkg" else None
    )
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
        stdout="openssl\t1\t3.0.7-24.el9\nbash\t(none)\t5.2.15-3.el9\n",
    )
    result = _get_packages_rpm()
    assert result == [
        {"name": "openssl", "version": "1:3.0.7-24.el9"},
        {"name": "bash", "version": "5.2.15-3.el9"},
    ]
    mock_run.assert_called_once()
    args = mock_run.call_args
    assert args[0][0] == [
        "rpm",
        "-qa",
        "--queryformat",
        "%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\n",
    ]
    assert args[1]["timeout"] == 30


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_pins_the_locale(mock_run, mock_env):
    """The parser matches rpm's "(none)" byte-for-byte and get_clean_env passes
    the host's LANG/LC_* through, so the locale is pinned at the call site. A
    localized sentinel would fail every no-epoch line -- i.e. every package."""
    mock_run.return_value = MagicMock(returncode=0, stdout="bash\t(none)\t5.2.15-3.el9\n")
    _get_packages_rpm()
    assert mock_run.call_args[1]["env"]["LC_ALL"] == "C"


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_keeps_epoch(mock_run, mock_env):
    """An epoch-carrying package MUST ship its epoch: the RHEL advisory feeds
    quote fix versions as '2:8.2.2637-21.el9' and the server compares a missing
    epoch as 0, so dropping it pins the package below every fix forever."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="vim-enhanced\t2\t8.2.2637-21.el9\n",
    )
    assert _get_packages_rpm() == [
        {"name": "vim-enhanced", "version": "2:8.2.2637-21.el9"}
    ]


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_omits_zero_epoch(mock_run, mock_env):
    """'(none)' and an explicit '0' are the same version to RPM and to the
    server, so both send the short form -- one canonical spelling per package."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="zlib\t0\t1.2.11-40.el9\nglibc\t(none)\t2.34-125.el9\n",
    )
    assert _get_packages_rpm() == [
        {"name": "zlib", "version": "1.2.11-40.el9"},
        {"name": "glibc", "version": "2.34-125.el9"},
    ]


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_skips_gpg_pubkey(mock_run, mock_env):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=(
            "gpg-pubkey\t(none)\t3228467c-613798eb\n"
            "gpg-pubkey\t(none)\tfd431d51-4ae0493b\n"
            "bash\t(none)\t5.2.15-3.el9\n"
        ),
    )
    assert _get_packages_rpm() == [{"name": "bash", "version": "5.2.15-3.el9"}]


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_collapses_multiarch_duplicates(mock_run, mock_env):
    """glibc.i686 + glibc.x86_64 at the same NEVR are one package once arch is
    dropped; a partially-updated pair keeps both rows."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=(
            "glibc\t(none)\t2.34-125.el9\n"
            "glibc\t(none)\t2.34-125.el9\n"
            "libstdc++\t(none)\t11.4.1-3.el9\n"
            "libstdc++\t(none)\t11.4.1-2.el9\n"
        ),
    )
    assert _get_packages_rpm() == [
        {"name": "glibc", "version": "2.34-125.el9"},
        {"name": "libstdc++", "version": "11.4.1-3.el9"},
        {"name": "libstdc++", "version": "11.4.1-2.el9"},
    ]


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_keeps_multiple_kernels(mock_run, mock_env):
    """An old kernel that is still installed is still a finding."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="kernel\t(none)\t5.14.0-284.el9\nkernel\t(none)\t5.14.0-362.el9\n",
    )
    assert _get_packages_rpm() == [
        {"name": "kernel", "version": "5.14.0-284.el9"},
        {"name": "kernel", "version": "5.14.0-362.el9"},
    ]


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_blank_lines_are_tolerated(mock_run, mock_env):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="\nbash\t(none)\t5.2.15-3.el9\n\n",
    )
    assert _get_packages_rpm() == [{"name": "bash", "version": "5.2.15-3.el9"}]


@pytest.mark.parametrize(
    "stdout",
    [
        # A dropped field (a format change, or a truncated read).
        "bash\t5.2.15-3.el9\nopenssl\t1\t3.0.7-24.el9\n",
        # An extra field.
        "bash\t(none)\t5.2.15-3.el9\tx86_64\nopenssl\t1\t3.0.7-24.el9\n",
        # An epoch that is not a plain integer.
        "bash\tnot-an-epoch\t5.2.15-3.el9\n",
        # Non-ASCII digits (superscript two): str.isdigit() alone accepts these.
        # Spelled with chr() to keep this file ASCII-only, as the repo requires.
        "bash\t" + chr(0xB2) + "\t5.2.15-3.el9\n",
        # An empty name or version.
        "\t(none)\t5.2.15-3.el9\n",
        "bash\t(none)\t\n",
        # A broken header printing rpm's unset sentinel where a version belongs.
        "bash\t(none)\t(none)-(none)\n",
    ],
)
@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_discards_whole_read_on_malformed_line(
    mock_run, mock_env, stdout
):
    """One unparseable line fails the whole read. The server replaces a host's
    package set with whatever arrives, so shipping the lines we did understand
    would auto-resolve the vulnerabilities of the ones we did not."""
    mock_run.return_value = MagicMock(returncode=0, stdout=stdout)
    assert _get_packages_rpm() == []


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_failure(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=1, stderr="error")
    result = _get_packages_rpm()
    assert result == []


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_bounds_the_stderr_it_logs(mock_run, mock_env):
    """rpm against a corrupt Berkeley DB prints one error line per package, and
    this message rides the telemetry payload like the parse rejection above."""
    mock_run.return_value = MagicMock(returncode=1, stderr="boom\n" * 20_000)
    start_log_capture()
    try:
        assert _get_packages_rpm() == []
        errors = stop_log_capture()
    finally:
        stop_log_capture()
    assert len(errors) == 1
    assert len(errors[0]) < 300


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_empty(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=0, stdout="")
    assert _get_packages_rpm() == []


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_bounds_the_rejected_line_it_logs(mock_run, mock_env):
    """The rejection message is captured into _telemetry["packages_sync"]
    ["errors"] and shipped in the next tick's payload, so a corrupt rpmdb
    emitting a huge line must not inflate the metrics POST."""
    mock_run.return_value = MagicMock(returncode=0, stdout="x" * 100_000 + "\n")
    start_log_capture()
    try:
        assert _get_packages_rpm() == []
        errors = stop_log_capture()
    finally:
        stop_log_capture()
    assert len(errors) == 1
    # 200 chars of payload + repr quotes + the fixed prefix, nowhere near 100k.
    assert len(errors[0]) < 300


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_rpm_trusts_a_read_that_warned_on_stderr(mock_run, mock_env):
    """Deliberately NOT the wireguard rule (there, any stderr means a partial
    dump). rpm routinely warns on stderr while exiting 0 with a complete list
    -- 'found bdb Packages database while attempting sqlite backend' being the
    common one -- and discarding those reads would blind whole distro
    generations. Exit code and the parse are the gates, not stderr."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="bash\t(none)\t5.2.15-3.el9\n",
        stderr="warning: Found bdb Packages database while attempting sqlite backend\n",
    )
    assert _get_packages_rpm() == [{"name": "bash", "version": "5.2.15-3.el9"}]


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


# --- _get_packages_pacman ---


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_pacman_success(mock_run, mock_env):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="linux 6.7.4.arch1-1\nopenssl 3.2.1-1\nzlib 1.3.1-1\n",
    )
    result = _get_packages_pacman()
    assert result == [
        {"name": "linux", "version": "6.7.4.arch1-1"},
        {"name": "openssl", "version": "3.2.1-1"},
        {"name": "zlib", "version": "1.3.1-1"},
    ]
    mock_run.assert_called_once()
    args = mock_run.call_args
    assert args[0][0] == ["pacman", "-Q"]
    assert args[1]["timeout"] == 30


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_pacman_failure(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=1, stderr="error")
    result = _get_packages_pacman()
    assert result == []


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_pacman_empty(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=0, stdout="")
    result = _get_packages_pacman()
    assert result == []


# --- _get_packages_synopkg ---


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_synopkg_success(mock_run, mock_env):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="ContainerManager 20.10.0-1001\nTextEditor 3.2.0-0001\n",
    )
    result = _get_packages_synopkg()
    assert result == [
        {"name": "ContainerManager", "version": "20.10.0-1001"},
        {"name": "TextEditor", "version": "3.2.0-0001"},
    ]
    mock_run.assert_called_once()
    args = mock_run.call_args
    assert args[0][0] == ["synopkg", "list"]
    assert args[1]["timeout"] == 30


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_synopkg_failure(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=1, stderr="error")
    result = _get_packages_synopkg()
    assert result == []


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_synopkg_empty_lines(mock_run, mock_env):
    mock_run.return_value = MagicMock(returncode=0, stdout="\n\n")
    result = _get_packages_synopkg()
    assert result == []


@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_get_packages_synopkg_short_line(mock_run, mock_env):
    """Lines with fewer than 2 fields should be skipped."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="OnlyName\nContainerManager 20.10.0-1001\n",
    )
    result = _get_packages_synopkg()
    assert result == [{"name": "ContainerManager", "version": "20.10.0-1001"}]


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


@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages._get_packages_pacman")
def test_get_installed_packages_pacman(mock_pacman, mock_which):
    mock_which.side_effect = lambda cmd: (
        "/usr/bin/pacman" if cmd == "pacman" else None
    )
    mock_pacman.return_value = [{"name": "linux", "version": "6.7"}]
    result = get_installed_packages()
    assert result == [{"name": "linux", "version": "6.7"}]


@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages._get_packages_synopkg")
def test_get_installed_packages_synopkg(mock_synopkg, mock_which):
    mock_which.side_effect = lambda cmd: (
        "/usr/syno/bin/synopkg" if cmd == "synopkg" else None
    )
    mock_synopkg.return_value = [{"name": "ContainerManager", "version": "20.10.0-1001"}]
    result = get_installed_packages()
    assert result == [{"name": "ContainerManager", "version": "20.10.0-1001"}]


@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages._get_packages_rpm")
def test_get_installed_packages_sorts_same_name_by_version(mock_rpm, mock_which):
    """rpm -qa does not order its output, so a repeated name (several kernels)
    must be ordered by version too or the delta hash flaps between ticks."""
    mock_which.side_effect = lambda cmd: "/usr/bin/rpm" if cmd == "rpm" else None
    mock_rpm.return_value = [
        {"name": "kernel", "version": "5.14.0-362.el9"},
        {"name": "bash", "version": "5.2.15-3.el9"},
        {"name": "kernel", "version": "5.14.0-284.el9"},
    ]
    assert get_installed_packages() == [
        {"name": "bash", "version": "5.2.15-3.el9"},
        {"name": "kernel", "version": "5.14.0-284.el9"},
        {"name": "kernel", "version": "5.14.0-362.el9"},
    ]


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


# --- T9: Windows registry-based software inventory ---


@patch("fivenines_agent.packages.is_windows", return_value=True)
def test_packages_available_windows_returns_true(mock_iw):
    assert packages_available() is True


@patch("fivenines_agent.packages.is_windows", return_value=True)
def test_get_distro_windows_returns_release(mock_iw):
    with patch("platform.release", return_value="10"):
        assert get_distro() == "windows:10"


@patch("fivenines_agent.packages.is_windows", return_value=True)
def test_get_distro_windows_empty_release_returns_plain_windows(mock_iw):
    with patch("platform.release", return_value=""):
        assert get_distro() == "windows"


@patch("fivenines_agent.packages.is_windows", return_value=True)
def test_get_distro_windows_handles_release_exception(mock_iw):
    with patch("platform.release", side_effect=OSError("nope")):
        assert get_distro() == "windows"


def _make_fake_winreg(roots_to_entries):
    """Build a fake winreg module.

    *roots_to_entries* is a dict from subkey-path-substring to list of
    (subkey_name, {value_name: value}) tuples. None as the value list means
    'opening this root raises OSError'.
    """
    fake = MagicMock()
    fake.HKEY_LOCAL_MACHINE = "HKLM"

    def open_key(arg1, arg2):
        if arg1 == "HKLM":
            for key_sub, entries in roots_to_entries.items():
                if key_sub in arg2:
                    if entries is None:
                        raise OSError(f"cannot open {arg2}")
                    h = MagicMock(name=f"root:{arg2}")
                    h._entries = entries
                    return h
            # Default: opening unknown root path raises
            raise OSError(f"unknown path {arg2}")
        # Sub-key open: arg1 is a root, arg2 is a sub-key name
        if arg2 == "__BROKEN_SUB__":
            raise OSError("broken sub")
        for name, vals in arg1._entries:
            if name == arg2:
                sub = MagicMock(name=f"sub:{arg2}")
                sub._values = vals
                return sub
        raise OSError(f"sub missing: {arg2}")

    def enum_key(handle, index):
        if index >= len(handle._entries):
            raise OSError("no more entries")
        return handle._entries[index][0]

    def query_value(handle, value_name):
        if value_name not in handle._values:
            raise OSError(f"missing value {value_name}")
        return (handle._values[value_name], 1)

    fake.OpenKey.side_effect = open_key
    fake.EnumKey.side_effect = enum_key
    fake.QueryValueEx.side_effect = query_value
    fake.CloseKey = MagicMock()
    return fake


def test_get_packages_windows_registry_reads_both_views():
    """Both the 64-bit and 32-bit registry views contribute."""
    fake = _make_fake_winreg({
        "WOW6432Node": [("OldApp", {"DisplayName": "Legacy 32-bit App", "DisplayVersion": "1.0"})],
        "Microsoft\\Windows\\CurrentVersion\\Uninstall": [
            ("Firefox", {"DisplayName": "Mozilla Firefox", "DisplayVersion": "123.0"}),
            ("Chrome", {"DisplayName": "Google Chrome", "DisplayVersion": "120.0"}),
        ],
    })
    with patch.dict("sys.modules", {"winreg": fake}):
        packages = _get_packages_windows_registry()
    names = sorted(p["name"] for p in packages)
    assert names == ["Google Chrome", "Legacy 32-bit App", "Mozilla Firefox"]


def test_get_packages_windows_registry_skips_entries_without_displayname():
    fake = _make_fake_winreg({
        "WOW6432Node": [],
        "Microsoft\\Windows\\CurrentVersion\\Uninstall": [
            ("Real", {"DisplayName": "Real App", "DisplayVersion": "1.0"}),
            ("Update_KB123", {}),
        ],
    })
    with patch.dict("sys.modules", {"winreg": fake}):
        packages = _get_packages_windows_registry()
    assert [p["name"] for p in packages] == ["Real App"]


def test_get_packages_windows_registry_skips_entries_with_empty_displayname():
    """DisplayName present but empty string (some installer-leftover entries do this)."""
    fake = _make_fake_winreg({
        "WOW6432Node": [],
        "Microsoft\\Windows\\CurrentVersion\\Uninstall": [
            ("Real", {"DisplayName": "Real App", "DisplayVersion": "1.0"}),
            ("Empty", {"DisplayName": "", "DisplayVersion": "1.0"}),
        ],
    })
    with patch.dict("sys.modules", {"winreg": fake}):
        packages = _get_packages_windows_registry()
    assert [p["name"] for p in packages] == ["Real App"]


def test_get_packages_windows_registry_missing_displayversion_returns_empty_string():
    fake = _make_fake_winreg({
        "WOW6432Node": [],
        "Microsoft\\Windows\\CurrentVersion\\Uninstall": [
            ("NoVersion", {"DisplayName": "Versionless App"}),
        ],
    })
    with patch.dict("sys.modules", {"winreg": fake}):
        packages = _get_packages_windows_registry()
    assert packages == [{"name": "Versionless App", "version": ""}]


def test_get_packages_windows_registry_returns_empty_when_winreg_missing():
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "winreg":
            raise ImportError("not on this OS")
        return real_import(name, *args, **kwargs)

    with patch.object(builtins, "__import__", fake_import):
        assert _get_packages_windows_registry() == []


def test_get_packages_windows_registry_one_root_unreachable():
    """If WOW6432Node fails to open, the 64-bit view still contributes."""
    fake = _make_fake_winreg({
        "WOW6432Node": None,  # raises on open
        "Microsoft\\Windows\\CurrentVersion\\Uninstall": [
            ("Firefox", {"DisplayName": "Mozilla Firefox", "DisplayVersion": "123.0"}),
        ],
    })
    with patch.dict("sys.modules", {"winreg": fake}):
        packages = _get_packages_windows_registry()
    assert packages == [{"name": "Mozilla Firefox", "version": "123.0"}]


def test_get_packages_windows_registry_unreadable_subkey_does_not_abort():
    fake = _make_fake_winreg({
        "WOW6432Node": [],
        "Microsoft\\Windows\\CurrentVersion\\Uninstall": [
            ("__BROKEN_SUB__", {}),  # OpenKey raises OSError
            ("Good", {"DisplayName": "Good Entry", "DisplayVersion": "2.0"}),
        ],
    })
    with patch.dict("sys.modules", {"winreg": fake}):
        packages = _get_packages_windows_registry()
    assert [p["name"] for p in packages] == ["Good Entry"]


@patch("fivenines_agent.packages.is_windows", return_value=True)
def test_get_installed_packages_windows_dispatches_to_registry(mock_iw):
    with patch(
        "fivenines_agent.packages._get_packages_windows_registry",
        return_value=[{"name": "B App", "version": "1"}, {"name": "A App", "version": "2"}],
    ):
        result = get_installed_packages()
    # Sorted by name.
    assert [p["name"] for p in result] == ["A App", "B App"]
