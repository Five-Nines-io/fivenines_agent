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


def parse_os_release(lines):
    """Parse an os-release ID + VERSION_ID into a short distro identifier.

    Returns 'id:version_id' (e.g. 'debian:13'), just 'id' when VERSION_ID is
    absent, or 'unknown' when there is no ID. Same lowercase / strip-quotes
    rules the host path has always used. Shared with the Docker image inventory
    path (docker_image_inventory.py), which extracts /etc/os-release from an
    image via the archive API -- one parser, one set of rules, so the host and
    image distro strings can never diverge. *lines* is any iterable of raw
    os-release lines (an open file, or a list from a decoded blob)."""
    fields = {}
    for line in lines:
        if line.startswith("ID="):
            fields["id"] = line.strip().split("=", 1)[1].strip('"').lower()
        elif line.startswith("VERSION_ID="):
            fields["version_id"] = line.strip().split("=", 1)[1].strip('"').lower()
    distro_id = fields.get("id")
    if not distro_id:
        return "unknown"
    version_id = fields.get("version_id")
    if version_id:
        return f"{distro_id}:{version_id}"
    return distro_id


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
        with open("/etc/os-release", "r") as f:
            return parse_os_release(f)
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


# rpm's own spelling for a tag the package does not declare. RPM semantics --
# and the server's version comparison, which splits on /\A(\d+):/ and defaults a
# missing epoch to 0 -- make "(none)" and "0" the same thing as no epoch at all,
# so both are sent as the short form. One canonical spelling per package also
# keeps the delta hash still when a rebuild starts declaring an explicit Epoch: 0.
_RPM_EPOCH_NONE = "(none)"

# Epoch is asked for as its OWN tab-separated field instead of being folded in
# with rpm's conditional query syntax (%|EPOCH?{%{EPOCH}:}:{}|): that syntax is
# not worth depending on across the rpm 4.11 (CentOS 7) -> 4.20 range this
# binary ships to, while normalizing "(none)" here is one branch with a test.
_RPM_QUERYFORMAT = "%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\n"

# rpm -qa lists the trusted GPG keys as pseudo-packages whose "version" is a
# keyid-timestamp pair ("gpg-pubkey (none) 3228467c-613798eb"). They are keys,
# not software, no advisory feed carries them, and the /packages inventory is a
# CVE-scanning surface -- so they are dropped rather than shipped as noise.
_RPM_PSEUDO_PACKAGES = frozenset({"gpg-pubkey"})

# How much of a rejected line the error log quotes. Long enough to diagnose a
# format change, short enough that a corrupt rpmdb cannot inflate the telemetry
# payload the message rides in (see _get_packages_rpm).
_RPM_LOG_LINE_CHARS = 200


def _parse_rpm_line(line):
    """NAME<TAB>EPOCH<TAB>VERSION-RELEASE -> (name, '[epoch:]version-release').

    Returns None when the line is not exactly that shape. The caller then
    discards the WHOLE read, so this deliberately has no lenient path: see
    _get_packages_rpm for why a skipped line is worse than a missing scan.
    """
    fields = line.split("\t")
    if len(fields) != 3:
        return None
    name, epoch, version = (field.strip() for field in fields)
    if not name or not version:
        return None
    # VERSION and RELEASE are mandatory on an installed package and cannot
    # contain parentheses, so "(none)" here is a broken header, not a version.
    if _RPM_EPOCH_NONE in version:
        return None
    if epoch in (_RPM_EPOCH_NONE, "0"):
        return name, version
    # isdigit() alone accepts superscripts and non-ASCII digits; an epoch that
    # is not a plain integer means the output is not what we asked for.
    if not (epoch.isascii() and epoch.isdigit()):
        return None
    return name, f"{epoch}:{version}"


def _get_packages_rpm():
    """Get installed packages via rpm, as canonical '[epoch:]version-release'.

    The epoch is not cosmetic. The advisory feeds for the RHEL family carry
    epoch-prefixed fix versions ("2:8.2.2637-21.el9") and the server compares a
    missing epoch as 0, so an epoch-carrying package sent WITHOUT its epoch
    sorts below every fix version forever: fully patched vim/nginx/postgresql
    hosts would report as vulnerable and never clear.

    An unparseable line fails the whole read (returns []) instead of being
    skipped. The server replaces a host's package set with whatever arrives and
    deletes the findings that no longer match, so a silently short list resolves
    live vulnerabilities; an empty return is read by packages_sync as "no data"
    and skips the send, which costs a scan but never a false all-clear.

    The cost of that choice, stated plainly: ONE broken header freezes this
    host's inventory at its last good state until the read parses again. That
    is deliberate -- stale-but-honest beats a manufactured all-clear -- but it
    is only safe while someone can SEE the host went quiet. The server stores
    last_packages_received_at; surfacing it is tracked in TODOS.md.
    """
    # LC_ALL=C: the parser matches rpm's "(none)" sentinel byte-for-byte, and
    # get_clean_env() passes the host's LANG/LC_* through untouched. Pinning the
    # locale keeps any localized formatting out of a machine-parsed surface --
    # a translated sentinel would fail EVERY no-epoch line, i.e. every package.
    env = get_clean_env()
    env["LC_ALL"] = "C"
    result = subprocess.run(
        ["rpm", "-qa", "--queryformat", _RPM_QUERYFORMAT],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    if result.returncode != 0:
        # Bounded for the same reason as the unparseable-line message below:
        # rpm against a corrupt Berkeley DB can print one error line PER
        # package, and this string rides the next tick's telemetry payload.
        log(f"rpm failed: {result.stderr[:_RPM_LOG_LINE_CHARS]}", "error")
        return []
    packages = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parsed = _parse_rpm_line(line)
        if parsed is None:
            # Truncated, and !r-quoted: this message is captured by
            # debug.start_log_capture into _telemetry["packages_sync"]["errors"]
            # and SHIPPED in the next tick's payload, so an unbounded line from
            # a corrupt rpmdb would bloat the metrics POST, and a crafted
            # package name could smuggle control characters into the logs.
            log(
                "rpm returned an unparseable line, discarding read: "
                f"{line[:_RPM_LOG_LINE_CHARS]!r}",
                "error",
            )
            return []
        name, version = parsed
        if name in _RPM_PSEUDO_PACKAGES:
            continue
        # The same NEVR twice is a multiarch install (glibc.i686 + glibc.x86_64)
        # and the payload carries no arch, so the two rows are one package.
        # Genuinely different versions of one name (several kernels) keep their
        # own rows -- an old vulnerable kernel still installed is still a finding.
        packages[(name, version)] = {"name": name, "version": version}
    return list(packages.values())


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
        # Sort on (name, version), not name alone: rpm -qa does not order its
        # output, so a name that appears more than once (several kernels) would
        # otherwise keep rpm's order and flap the delta hash after a dnf
        # transaction reorders the db, re-sending an unchanged package set.
        return sorted(packages, key=lambda p: (p["name"], p["version"]))
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
