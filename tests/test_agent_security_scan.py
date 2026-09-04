"""Tests for packages_sync() standalone function."""

from unittest.mock import MagicMock, mock_open, patch

from fivenines_agent.packages import get_packages_hash, packages_sync


PACKAGES_CONFIG = {"scan": True, "last_scan_at": None, "last_package_hash": None}

# A trimmed but shape-accurate `rpm -qa --queryformat` capture from a RHEL 9
# host: two epoch-carrying packages, a multiarch pair listed twice, two
# installed kernels, and the gpg-pubkey pseudo-packages rpm always lists.
# Deliberately unordered -- rpm -qa returns rpmdb order, not sorted output.
RHEL_RPM_QA_OUTPUT = (
    "gpg-pubkey\t(none)\t5a6340b3-6229229e\n"
    "glibc\t(none)\t2.34-100.el9_4.2\n"
    "vim-enhanced\t2\t8.2.2637-20.el9_1\n"
    "kernel\t(none)\t5.14.0-427.16.1.el9_4\n"
    "glibc\t(none)\t2.34-100.el9_4.2\n"
    "openssl\t1\t3.0.7-27.el9\n"
    "kernel\t(none)\t5.14.0-427.13.1.el9_4\n"
)


# --- packages_sync ---


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_no_packages_key(mock_hash, mock_distro, mock_pkgs):
    config = {"enabled": True}
    send_fn = MagicMock()

    packages_sync(config, send_fn)

    mock_distro.assert_not_called()
    mock_pkgs.assert_not_called()


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_packages_none(mock_hash, mock_distro, mock_pkgs):
    config = {"enabled": True, "packages": None}
    send_fn = MagicMock()

    packages_sync(config, send_fn)

    mock_distro.assert_not_called()


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_scan_false(mock_hash, mock_distro, mock_pkgs):
    config = {"enabled": True, "packages": {"scan": False}}
    send_fn = MagicMock()

    packages_sync(config, send_fn)

    mock_distro.assert_not_called()


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_no_packages_found(mock_hash, mock_distro, mock_pkgs):
    config = {"enabled": True, "packages": PACKAGES_CONFIG}
    send_fn = MagicMock()
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = []

    packages_sync(config, send_fn)

    mock_distro.assert_called_once()
    mock_pkgs.assert_called_once()
    mock_hash.assert_not_called()
    send_fn.assert_not_called()


@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_hash_matches_server(mock_hash, mock_distro, mock_pkgs):
    config = {
        "enabled": True,
        "packages": {"scan": True, "last_package_hash": "abc123"},
    }
    send_fn = MagicMock()
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "abc123"

    packages_sync(config, send_fn)

    send_fn.assert_not_called()


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_sends_on_hash_change(mock_hash, mock_distro, mock_pkgs, mock_dry):
    config = {
        "enabled": True,
        "packages": {"scan": True, "last_package_hash": "old_hash"},
    }
    send_fn = MagicMock(return_value={"status": "queued"})
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"

    packages_sync(config, send_fn)

    send_fn.assert_called_once_with(
        {
            "distro": "debian:12",
            "packages_hash": "new_hash",
            "packages": [{"name": "openssl", "version": "3.0"}],
        }
    )


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_sends_when_server_hash_is_none(mock_hash, mock_distro, mock_pkgs, mock_dry):
    """First scan ever: server has no hash yet."""
    config = {"enabled": True, "packages": PACKAGES_CONFIG}
    send_fn = MagicMock(return_value={"status": "queued"})
    mock_distro.return_value = "ubuntu:22.04"
    mock_pkgs.return_value = [{"name": "bash", "version": "5.0"}]
    mock_hash.return_value = "hash1"

    packages_sync(config, send_fn)

    send_fn.assert_called_once()


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_failure_logs_error(mock_hash, mock_distro, mock_pkgs, mock_dry):
    config = {"enabled": True, "packages": PACKAGES_CONFIG}
    send_fn = MagicMock(return_value=None)
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"

    packages_sync(config, send_fn)

    send_fn.assert_called_once()


@patch("fivenines_agent.packages.dry_run", return_value=True)
@patch("fivenines_agent.packages.get_installed_packages")
@patch("fivenines_agent.packages.get_distro")
@patch("fivenines_agent.packages.get_packages_hash")
def test_dry_run_skips_send(mock_hash, mock_distro, mock_pkgs, mock_dry):
    config = {"enabled": True, "packages": PACKAGES_CONFIG}
    send_fn = MagicMock()
    mock_distro.return_value = "debian:12"
    mock_pkgs.return_value = [{"name": "openssl", "version": "3.0"}]
    mock_hash.return_value = "new_hash"

    packages_sync(config, send_fn)

    send_fn.assert_not_called()


# --- RHEL family, end to end (#123) ---


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.is_windows", return_value=False)
@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_rhel_host_posts_epoch_qualified_packages(
    mock_run, mock_env, mock_which, mock_is_windows, mock_dry
):
    """The exact body a RHEL 9 host POSTs to /packages. Only the two OS
    boundaries are mocked (rpm's stdout and /etc/os-release); everything
    between them is the real path, so this pins the server-facing envelope:
    'rhel:9.4' as-is (the server collapses 9.4 -> 9), epochs kept, no
    gpg-pubkey rows, multiarch collapsed, both kernels kept, sorted."""
    mock_which.side_effect = lambda cmd: "/usr/bin/rpm" if cmd == "rpm" else None
    mock_run.return_value = MagicMock(returncode=0, stdout=RHEL_RPM_QA_OUTPUT)
    os_release = 'NAME="Red Hat Enterprise Linux"\nID="rhel"\nVERSION_ID="9.4"\n'
    send_fn = MagicMock(return_value={"status": "ok", "changed": True})

    with patch("builtins.open", mock_open(read_data=os_release)):
        packages_sync({"enabled": True, "packages": PACKAGES_CONFIG}, send_fn)

    packages = [
        {"name": "glibc", "version": "2.34-100.el9_4.2"},
        {"name": "kernel", "version": "5.14.0-427.13.1.el9_4"},
        {"name": "kernel", "version": "5.14.0-427.16.1.el9_4"},
        {"name": "openssl", "version": "1:3.0.7-27.el9"},
        {"name": "vim-enhanced", "version": "2:8.2.2637-20.el9_1"},
    ]
    send_fn.assert_called_once_with(
        {
            "distro": "rhel:9.4",
            "packages_hash": get_packages_hash(packages),
            "packages": packages,
        }
    )


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.is_windows", return_value=False)
@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_rhel_host_sends_nothing_when_rpm_output_is_untrustworthy(
    mock_run, mock_env, mock_which, mock_is_windows, mock_dry
):
    """A read the parser cannot fully account for sends NOTHING. /packages
    replaces the host's package set and deletes the findings that no longer
    match it, so a partial list would auto-resolve live vulnerabilities."""
    mock_which.side_effect = lambda cmd: "/usr/bin/rpm" if cmd == "rpm" else None
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="glibc\t(none)\t2.34-100.el9_4.2\nopenssl\t3.0.7-27.el9\n",
    )
    os_release = 'ID="almalinux"\nVERSION_ID="9.3"\n'
    send_fn = MagicMock()

    with patch("builtins.open", mock_open(read_data=os_release)):
        packages_sync({"enabled": True, "packages": PACKAGES_CONFIG}, send_fn)

    send_fn.assert_not_called()


# The Debian-family half of the RHEL pair above. Shape-accurate
# `dpkg-query -W -f '${db:Status-Status}\t${Package}\t${Version}\n'` output from
# an Ubuntu 24.04 host: two live kernel ABIs, a removed-but-not-purged third
# one, a config-files row from an `apt remove nginx-common`, and a package
# caught mid-apt-run in triggers-pending.
UBUNTU_DPKG_QUERY_OUTPUT = (
    "installed\tbash\t5.2.21-2ubuntu4\n"
    "config-files\tlinux-image-6.8.0-31-generic\t6.8.0-31.31\n"
    "installed\tlinux-image-6.8.0-51-generic\t6.8.0-51.52\n"
    "config-files\tnginx-common\t1.24.0-2ubuntu7\n"
    "triggers-pending\tman-db\t2.12.0-4build2\n"
    "installed\tlinux-image-6.8.0-45-generic\t6.8.0-45.45\n"
    "installed\topenssl\t3.0.13-0ubuntu3.4\n"
)


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.is_windows", return_value=False)
@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_debian_host_posts_only_packages_whose_files_are_on_disk(
    mock_run, mock_env, mock_which, mock_is_windows, mock_dry
):
    """The exact body an Ubuntu host POSTs to /packages. Only the two OS
    boundaries are mocked (dpkg-query's stdout and /etc/os-release); everything
    between them is the real path. The two config-files rows are gone -- they
    are the bug this filter exists for -- while man-db, caught in
    triggers-pending, is kept: its files are on disk and it is still
    scannable."""
    mock_which.side_effect = lambda cmd: (
        "/usr/bin/dpkg-query" if cmd == "dpkg-query" else None
    )
    mock_run.return_value = MagicMock(
        returncode=0, stdout=UBUNTU_DPKG_QUERY_OUTPUT
    )
    os_release = 'NAME="Ubuntu"\nID="ubuntu"\nVERSION_ID="24.04"\n'
    send_fn = MagicMock(return_value={"status": "ok", "changed": True})

    with patch("builtins.open", mock_open(read_data=os_release)):
        packages_sync({"enabled": True, "packages": PACKAGES_CONFIG}, send_fn)

    packages = [
        {"name": "bash", "version": "5.2.21-2ubuntu4"},
        {"name": "linux-image-6.8.0-45-generic", "version": "6.8.0-45.45"},
        {"name": "linux-image-6.8.0-51-generic", "version": "6.8.0-51.52"},
        {"name": "man-db", "version": "2.12.0-4build2"},
        {"name": "openssl", "version": "3.0.13-0ubuntu3.4"},
    ]
    send_fn.assert_called_once_with(
        {
            "distro": "ubuntu:24.04",
            "packages_hash": get_packages_hash(packages),
            "packages": packages,
        }
    )


@patch("fivenines_agent.packages.dry_run", return_value=False)
@patch("fivenines_agent.packages.is_windows", return_value=False)
@patch("fivenines_agent.packages.shutil.which")
@patch("fivenines_agent.packages.get_clean_env", return_value={})
@patch("fivenines_agent.packages.subprocess.run")
def test_debian_host_sends_nothing_when_dpkg_output_is_untrustworthy(
    mock_run, mock_env, mock_which, mock_is_windows, mock_dry
):
    """Same rule as the RHEL twin, pinned at the seam for the family that
    motivated the filter. A read the parser cannot fully account for sends
    NOTHING: /packages replaces the host's package set and deletes the findings
    that no longer match it, so a partial list would auto-resolve live
    vulnerabilities."""
    mock_which.side_effect = lambda cmd: (
        "/usr/bin/dpkg-query" if cmd == "dpkg-query" else None
    )
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="installed\tbash\t5.2.21-2\nreinstreq\topenssl\t3.0.13-0ubuntu3.4\n",
    )
    send_fn = MagicMock()

    with patch("builtins.open", mock_open(read_data='ID="ubuntu"\n')):
        packages_sync({"enabled": True, "packages": PACKAGES_CONFIG}, send_fn)

    send_fn.assert_not_called()
