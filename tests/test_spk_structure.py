"""Tests for Synology SPK package structure validation."""

import os
import subprocess
import tarfile
import tempfile

import pytest


SYNOLOGY_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "synology"
)
BUILD_SPK = os.path.join(SYNOLOGY_DIR, "build_spk.sh")

REQUIRED_SPK_ENTRIES = [
    "INFO",
    "package.tgz",
    "scripts/start-stop-status",
    "scripts/postinst",
    "conf/privilege",
    "WIZARD_UIFILES/install_uifile",
    "PACKAGE_ICON.PNG",
    "PACKAGE_ICON_256.PNG",
]


@pytest.fixture
def fake_binary(tmp_path):
    """Create fake binary directories mimicking py2exe.sh output for both arches."""
    for arch in ("amd64", "arm64"):
        binary_dir = tmp_path / "dist" / "linux" / f"fivenines-agent-synology-{arch}"
        binary_dir.mkdir(parents=True)
        binary = binary_dir / "fivenines-agent"
        binary.write_text("#!/bin/sh\necho fake-agent")
        binary.chmod(0o755)
        # Simulate a shared library alongside the binary
        (binary_dir / "libpython3.9.so").write_text("fake-lib")
    return tmp_path


def test_build_spk_produces_valid_structure(fake_binary):
    """build_spk.sh produces an SPK with all required entries."""
    env = os.environ.copy()
    env["REPO_ROOT"] = str(fake_binary)
    result = subprocess.run(
        ["bash", BUILD_SPK, "1.0.0", "x86_64"],
        cwd=str(fake_binary),
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, f"build_spk.sh failed: {result.stderr}"

    spk_path = fake_binary / "dist" / "synology" / "fivenines-agent-1.0.0-x86_64.spk"
    assert spk_path.exists(), f"SPK not found at {spk_path}"

    with tarfile.open(str(spk_path), "r") as spk:
        members = [m.name for m in spk.getmembers()]

    for entry in REQUIRED_SPK_ENTRIES:
        assert entry in members, f"Missing required SPK entry: {entry}"


def test_build_spk_info_has_correct_metadata(fake_binary):
    """INFO file contains correct version and architecture."""
    env = os.environ.copy()
    env["REPO_ROOT"] = str(fake_binary)
    subprocess.run(
        ["bash", BUILD_SPK, "2.3.4", "aarch64"],
        cwd=str(fake_binary),
        capture_output=True,
        text=True,
        env=env,
    )

    spk_path = fake_binary / "dist" / "synology" / "fivenines-agent-2.3.4-aarch64.spk"
    with tarfile.open(str(spk_path), "r") as spk:
        info = spk.extractfile("INFO")
        assert info is not None
        content = info.read().decode("utf-8")

    assert 'version="2.3.4-0001"' in content
    assert 'arch="aarch64"' in content
    assert 'package="fivenines-agent"' in content


def test_build_spk_package_tgz_contains_binary(fake_binary):
    """package.tgz inside the SPK contains the agent binary."""
    env = os.environ.copy()
    env["REPO_ROOT"] = str(fake_binary)
    subprocess.run(
        ["bash", BUILD_SPK, "1.0.0", "x86_64"],
        cwd=str(fake_binary),
        capture_output=True,
        text=True,
        env=env,
    )

    spk_path = fake_binary / "dist" / "synology" / "fivenines-agent-1.0.0-x86_64.spk"
    with tarfile.open(str(spk_path), "r") as spk:
        pkg_tgz = spk.extractfile("package.tgz")
        assert pkg_tgz is not None
        # Write to a temp file so tarfile can read it
        with tempfile.NamedTemporaryFile(suffix=".tgz", delete=False) as tmp:
            tmp.write(pkg_tgz.read())
            tmp_path = tmp.name

    try:
        with tarfile.open(tmp_path, "r:gz") as pkg:
            members = [m.name for m in pkg.getmembers()]
        assert "./bin/fivenines-agent" in members
        # Shared libs should also be included
        assert "./bin/libpython3.9.so" in members
        # Logrotate config must be inside package.tgz (target/conf/)
        assert "./conf/logrotate.conf" in members
    finally:
        os.unlink(tmp_path)


def test_build_spk_missing_binary(tmp_path):
    """build_spk.sh fails gracefully when binary is missing."""
    env = os.environ.copy()
    env["REPO_ROOT"] = str(tmp_path)
    result = subprocess.run(
        ["bash", BUILD_SPK, "1.0.0", "x86_64"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode != 0
    assert "Binary not found" in result.stderr or "Binary not found" in result.stdout


def test_build_spk_unsupported_arch(fake_binary):
    """build_spk.sh rejects unsupported architectures."""
    env = os.environ.copy()
    env["REPO_ROOT"] = str(fake_binary)
    result = subprocess.run(
        ["bash", BUILD_SPK, "1.0.0", "mips"],
        cwd=str(fake_binary),
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode != 0
    assert "Unsupported arch" in result.stderr or "Unsupported arch" in result.stdout
