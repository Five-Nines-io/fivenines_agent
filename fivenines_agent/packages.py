"""Package collection for fivenines agent security scanning."""

import hashlib
import shutil
import subprocess

from fivenines_agent.debug import debug, log
from fivenines_agent.subprocess_utils import get_clean_env


def packages_available():
    """Check if a supported package manager is available."""
    for cmd in ("dpkg-query", "rpm", "apk"):
        if shutil.which(cmd):
            return True
    return False


def get_distro():
    """Read /etc/os-release and return the lowercase distribution ID."""
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.strip().split("=", 1)[1].strip('"').lower()
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


@debug("get_installed_packages")
def get_installed_packages():
    """Detect package manager and return sorted list of installed packages."""
    try:
        if shutil.which("dpkg-query"):
            packages = _get_packages_dpkg()
        elif shutil.which("rpm"):
            packages = _get_packages_rpm()
        elif shutil.which("apk"):
            packages = _get_packages_apk()
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
