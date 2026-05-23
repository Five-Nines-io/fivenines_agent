"""Package collection for fivenines agent security scanning."""

import hashlib
import json
import shutil
import subprocess

from fivenines_agent.debug import debug, log
from fivenines_agent.env import dry_run, is_windows
from fivenines_agent.subprocess_utils import get_clean_env


def packages_available():
    """Check if a supported package source is available.

    On Windows the Uninstall registry is always reachable in principle (the
    permissions probe verifies actual read access at startup), so we treat
    the source as available here.
    """
    if is_windows():
        return True
    for cmd in ("dpkg-query", "rpm", "apk", "pacman", "synopkg"):
        if shutil.which(cmd):
            return True
    return False


def get_distro():
    """Return a short OS identifier suitable for the packages payload.

    Linux/Synology: reads /etc/os-release and returns 'id:version_id'
    (e.g. 'debian:13'). Windows: returns 'windows:<release>' using
    platform.release() (e.g. 'windows:10', 'windows:2022server').
    """
    if is_windows():
        try:
            import platform
            release = platform.release() or ""
            release = release.lower().strip()
            return f"windows:{release}" if release else "windows"
        except Exception as e:
            log(f"Error reading Windows release: {e}", "error")
            return "windows"
    try:
        fields = {}
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("ID="):
                    fields["id"] = line.strip().split("=", 1)[1].strip('"').lower()
                elif line.startswith("VERSION_ID="):
                    fields["version_id"] = (
                        line.strip().split("=", 1)[1].strip('"').lower()
                    )
        distro_id = fields.get("id")
        if not distro_id:
            return "unknown"
        version_id = fields.get("version_id")
        if version_id:
            return f"{distro_id}:{version_id}"
        return distro_id
    except Exception as e:
        log(f"Error reading /etc/os-release: {e}", "error")
    return "unknown"


def _get_packages_dpkg():
    """Get installed packages via dpkg-query."""
    result = subprocess.run(
        ["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"],
        capture_output=True,
        text=True,
        timeout=30,
        env=get_clean_env(),
    )
    if result.returncode != 0:
        log(f"dpkg-query failed: {result.stderr}", "error")
        return []
    packages = []
    for line in result.stdout.strip().split("\n"):
        if "\t" in line:
            name, version = line.split("\t", 1)
            packages.append({"name": name, "version": version})
    return packages


def _get_packages_rpm():
    """Get installed packages via rpm."""
    result = subprocess.run(
        ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
        capture_output=True,
        text=True,
        timeout=30,
        env=get_clean_env(),
    )
    if result.returncode != 0:
        log(f"rpm failed: {result.stderr}", "error")
        return []
    packages = []
    for line in result.stdout.strip().split("\n"):
        if "\t" in line:
            name, version = line.split("\t", 1)
            packages.append({"name": name, "version": version})
    return packages


def _get_packages_apk():
    """Get installed packages via apk."""
    result = subprocess.run(
        ["apk", "list", "--installed"],
        capture_output=True,
        text=True,
        timeout=30,
        env=get_clean_env(),
    )
    if result.returncode != 0:
        log(f"apk list failed: {result.stderr}", "error")
        return []
    packages = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        # Format: name-version-release arch {origin} (license)
        # e.g. "musl-1.2.4-r2 x86_64 {musl} (MIT)"
        parts = line.split(" ", 1)
        pkg_str = parts[0]
        # Split name from version: last two hyphens separate version-release
        # e.g. "musl-1.2.4-r2" -> name="musl", version="1.2.4-r2"
        segments = pkg_str.rsplit("-", 2)
        if len(segments) == 3:
            name = segments[0]
            version = segments[1] + "-" + segments[2]
            packages.append({"name": name, "version": version})
        elif len(segments) == 2:
            packages.append({"name": segments[0], "version": segments[1]})
    return packages


def _get_packages_pacman():
    """Get installed packages via pacman."""
    result = subprocess.run(
        ["pacman", "-Q"],
        capture_output=True,
        text=True,
        timeout=30,
        env=get_clean_env(),
    )
    if result.returncode != 0:
        log(f"pacman failed: {result.stderr}", "error")
        return []
    packages = []
    for line in result.stdout.strip().split("\n"):
        if " " in line:
            name, version = line.split(" ", 1)
            packages.append({"name": name, "version": version})
    return packages


def _get_packages_synopkg():
    """Get installed packages via Synology synopkg."""
    result = subprocess.run(
        ["synopkg", "list"],
        capture_output=True,
        text=True,
        timeout=30,
        env=get_clean_env(),
    )
    if result.returncode != 0:
        log(f"synopkg list failed: {result.stderr}", "error")
        return []
    packages = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            packages.append({"name": parts[0], "version": parts[1]})
    return packages


def _get_packages_windows_registry():
    """Read installed programs from the Windows Uninstall registry keys.

    Reads both the 64-bit view (HKLM\\SOFTWARE\\...) and the 32-bit redirect
    view (HKLM\\SOFTWARE\\WOW6432Node\\...) so 32-bit apps on 64-bit Windows
    are not missed. Entries with no DisplayName (typically system updates and
    hidden components) are skipped.
    """
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return []

    packages = []
    uninstall_paths = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    )
    for subkey_path in uninstall_paths:
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path)  # type: ignore[attr-defined]
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(root, i)  # type: ignore[attr-defined]
                except OSError:
                    break
                i += 1
                try:
                    sub = winreg.OpenKey(root, sub_name)  # type: ignore[attr-defined]
                except OSError:
                    continue
                try:
                    try:
                        name = winreg.QueryValueEx(sub, "DisplayName")[0]  # type: ignore[attr-defined]
                    except OSError:
                        continue
                    if not name:
                        continue
                    try:
                        version = winreg.QueryValueEx(sub, "DisplayVersion")[0]  # type: ignore[attr-defined]
                    except OSError:
                        version = ""
                    packages.append({"name": str(name), "version": str(version or "")})
                finally:
                    winreg.CloseKey(sub)  # type: ignore[attr-defined]
        finally:
            winreg.CloseKey(root)  # type: ignore[attr-defined]
    return packages


@debug("get_installed_packages")
def get_installed_packages():
    """Detect the package source and return a sorted list of installed packages."""
    try:
        if is_windows():
            packages = _get_packages_windows_registry()
        elif shutil.which("dpkg-query"):
            packages = _get_packages_dpkg()
        elif shutil.which("rpm"):
            packages = _get_packages_rpm()
        elif shutil.which("apk"):
            packages = _get_packages_apk()
        elif shutil.which("pacman"):
            packages = _get_packages_pacman()
        elif shutil.which("synopkg"):
            packages = _get_packages_synopkg()
        else:
            log("No supported package manager found", "debug")
            return []
        return sorted(packages, key=lambda p: p["name"])
    except subprocess.TimeoutExpired:
        log("Package collection timed out", "error")
        return []
    except Exception as e:
        log(f"Error collecting packages: {e}", "error")
        return []


def get_packages_hash(packages):
    """Compute SHA256 hash of package list for delta optimization."""
    content = "".join(f"{p['name']}={p['version']}\n" for p in packages)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def packages_sync(config, send_packages_fn):
    """Sync installed packages if backend requests it via packages.scan."""
    packages_config = config.get("packages")
    if not isinstance(packages_config, dict):
        return
    if not packages_config.get("scan"):
        return

    distro = get_distro()
    packages = get_installed_packages()
    if not packages:
        log("Packages synchronization: no packages found", "debug")
        return

    packages_hash = get_packages_hash(packages)
    if packages_hash == packages_config.get("last_package_hash"):
        log("Packages synchronization: packages unchanged, skipping", "debug")
        return

    packages_data = {
        "distro": distro,
        "packages_hash": packages_hash,
        "packages": packages,
    }

    if dry_run():
        log(
            f"Packages synchronization (dry-run): {json.dumps(packages_data, indent=2)}",
            "debug",
        )
        return

    response = send_packages_fn(packages_data)
    if response is not None:
        log("Packages synchronization sent successfully", "info")
    else:
        log("Packages synchronization failed, will retry", "error")
