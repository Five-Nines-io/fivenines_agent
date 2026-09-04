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


# How much of a rejected line (or a stderr blob) the error log quotes. Long
# enough to diagnose a format change, short enough that a damaged package
# database cannot inflate the telemetry payload the message rides in. Shared by
# the dpkg and rpm readers, which both fail a read by logging what broke it.
_LOG_LINE_CHARS = 200

# dpkg's COMPLETE package-status vocabulary: the third word of the Status
# field, and exactly what ${db:Status-Status} renders. Spellings are dpkg's own,
# verified against statusinfos[] in lib/dpkg/pkg-namevalue.c. The set is closed
# -- dpkg has not added a state in two decades -- and it is enumerated in full
# rather than implied, so a status the agent has never seen fails the read
# LOUDLY instead of being guessed at in whichever direction happens to be wrong.
_DPKG_STATUS_KNOWN = frozenset(
    {
        "not-installed",
        "config-files",
        "half-installed",
        "unpacked",
        "half-configured",
        "triggers-awaited",
        "triggers-pending",
        "installed",
    }
)

# The two states in which dpkg GUARANTEES none of the package's program files
# are on the machine: never installed, and removed-but-not-purged, where dpkg
# keeps the stanza (name AND version) forever while the software itself is gone.
# Those are dropped. Every other state is inventoried.
#
# Not because the other six guarantee the opposite -- half-installed does not.
# It is dpkg's state for "indeterminate", reached both by a failed unpack and
# midway through a REMOVAL (installed -> half-configured -> half-installed, and
# only then are the files deleted), so an interrupted `apt remove` can park a
# package there with nothing left on disk. It is inventoried anyway, because
# the two directions of error are not equal here: over-reporting a package
# costs a false finding an operator can dismiss, under-reporting one deletes a
# real finding for software that is still there.
#
# That asymmetry is the whole argument. Filtering harder -- keeping only
# `installed` -- would also drop the trigger and half-done states, whose files
# ARE unpacked and executable: `triggers-pending` occurs on every
# unattended-upgrades run and persists while a `dpkg --configure -a` is
# outstanding, and `half-configured` is dpkg's postinst-failed state, which
# persists until a human intervenes. /packages replaces the host's set and
# deletes what no longer matches, so dropping those is a false all-clear -- the
# one direction this inventory must never fail in (see _get_packages_rpm), and
# the one the issue behind this filter (#138) rules out in as many words:
# "false positives, never false negatives".
#
# Dropping a KNOWN state is deliberate, so unlike an unknown status it must not
# fail the read.
_DPKG_STATUS_ABSENT = frozenset({"not-installed", "config-files"})

# ${db:Status-Status} is the field dpkg exposes for this (since dpkg 1.17.11,
# 2014 -- Debian 8 and Ubuntu 16.04 already carry it, and the oldest
# Debian-family image the release matrix tests, Ubuntu 20.04, ships 1.19.7).
# A dpkg too old to know the field does not fail loudly: its format printer
# misses in fieldinfos[], then virtinfos[], then the arbitrary-field table, and
# substitutes nothing at all -- so the line arrives with an EMPTY status rather
# than an error. _parse_dpkg_line rejects that and the read fails, which is why
# the empty-status case below is a hard error and not a skip.
_DPKG_QUERYFORMAT = "${db:Status-Status}\t${Package}\t${Version}\n"

# Stands in for a status field that rendered empty, so the rejection can name
# the cause. Deliberately not a member of _DPKG_STATUS_KNOWN: it still fails the
# read, it just fails it legibly.
_DPKG_STATUS_MISSING = "<empty>"


def _parse_dpkg_line(line):
    """STATUS<TAB>NAME<TAB>VERSION -> (status, name, version).

    Returns None when the line is not exactly that shape; the caller then
    discards the WHOLE read, so this has no lenient path -- see
    _get_packages_dpkg. An empty VERSION is accepted here and judged by the
    caller instead: dpkg prints no version for a package it only knows about,
    and only the status says whether that is legal.
    """
    fields = line.split("\t")
    if len(fields) != 3:
        return None
    status, name, version = (field.strip() for field in fields)
    if not name:
        return None
    if not status:
        # Distinguished from the other rejections because it has ONE likely
        # cause and an actionable name: a dpkg older than 1.17.11 does not know
        # ${db:Status-Status} and substitutes nothing for it, so every line on
        # that host arrives shaped correctly with an empty first field. Telling
        # that operator "malformed line" would send them hunting a corrupt
        # database instead of an unsupported dpkg.
        return _DPKG_STATUS_MISSING, name, version
    return status, name, version


def _log_rejected_dpkg_line(reason, line):
    """Report a line that fails the read, naming the rule that rejected it.

    *reason* matters for diagnosis: two of the three rejections below are
    perfectly well-SHAPED lines (an unrecognized status, an on-disk package
    with no version), and an operator staring at a fleet-wide read failure
    should not have to guess which rule fired.

    Bounded and !r-quoted for the same reason as the rpm reader: this message is
    captured by debug.start_log_capture into _telemetry["packages_sync"]
    ["errors"] and SHIPPED in the next tick's payload, so an unbounded line from
    a damaged dpkg database would bloat the metrics POST, and a crafted package
    name could smuggle control characters into the logs.
    """
    log(
        f"dpkg-query line rejected ({reason}), discarding read: "
        f"{line[:_LOG_LINE_CHARS]!r}",
        "error",
    )


def _get_packages_dpkg():
    """Get installed packages via dpkg-query, filtered on install status.

    `dpkg-query -W` reports every package the dpkg database knows about, not
    only the installed ones. A package removed with `apt remove` rather than
    `apt purge` stays in the `config-files` state with its name and a real
    version string intact, forever, and nothing downstream can tell it apart
    from an installed package -- so the backend scans it and attributes CVEs to
    software that is not on the machine. It shows up worst on kernels, which a
    Debian-family upgrade installs alongside rather than replacing: on one
    observed Ubuntu 24.04 host, 11 removed kernel ABIs produced roughly 90k
    findings, about 94% of everything reported for that host. The operator
    cannot clear them -- `apt autoremove --purge` correctly reports nothing to
    remove, because nothing is left to remove.

    So ask dpkg for the status and drop the two states whose files are gone.
    The image path applies the SAME rule when it parses /var/lib/dpkg/status
    directly (docker_image_inventory._parse_dpkg_status), and imports
    _DPKG_STATUS_ABSENT from here rather than restating it -- the two had
    drifted onto different rules once already, which is how held packages ended
    up dropped from image inventories.

    Like the rpm reader, an unparseable line fails the WHOLE read (returns [])
    instead of being skipped. /packages replaces the host's package set and the
    server deletes the findings that no longer match, so a silently short list
    resolves live vulnerabilities, while an empty return is read by
    packages_sync as "no data" and skips the send -- stale, but never a
    manufactured all-clear.
    """
    # LC_ALL=C for the same reason as the rpm reader: get_clean_env() passes the
    # host's LANG/LC_* through untouched, and this parser matches dpkg's status
    # words byte-for-byte. Those words are bare C literals in statusinfos[] with
    # no gettext wrapper, so this is belt-and-braces rather than load-bearing --
    # but it is one line, and the failure it forecloses would fire fleet-wide on
    # a single day. It also keeps the stderr quoted below readable.
    env = get_clean_env()
    env["LC_ALL"] = "C"
    result = subprocess.run(
        ["dpkg-query", "-W", "-f", _DPKG_QUERYFORMAT],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    if result.returncode != 0:
        # !r for the same reason as the rejected-line message: dpkg-query quotes
        # content from /var/lib/dpkg/status in its own errors, so a newline or
        # an escape sequence in a package field would otherwise reach an
        # operator's terminal verbatim and forge extra lines in the telemetry
        # buffer this rides in. Truncation bounds the size, repr bounds content.
        log(f"dpkg-query failed: {result.stderr[:_LOG_LINE_CHARS]!r}", "error")
        return []
    packages = {}
    for line in result.stdout.splitlines():
        # `not line`, NOT `not line.strip()`. splitlines() never yields a line
        # containing its own terminator, so the only genuinely blank line is the
        # empty string. strip() would also swallow "\t\t" -- a row that carries
        # its separators but rendered every field empty -- and that is a broken
        # read, not a blank line: skipping it silently would ship the surviving
        # lines as a short list, which is the one failure /packages turns into
        # deleted findings. Let the parser judge anything with content in it.
        if not line:
            continue
        parsed = _parse_dpkg_line(line)
        if parsed is None:
            _log_rejected_dpkg_line("malformed line", line)
            return []
        status, name, version = parsed
        # A status outside dpkg's closed vocabulary means dpkg is not answering
        # the question we asked. Keeping the line would put a package of unknown
        # provenance on the CVE surface and dropping it would delete findings,
        # so neither guess is made and the read fails like any other drift.
        if status not in _DPKG_STATUS_KNOWN:
            _log_rejected_dpkg_line(
                "dpkg too old for ${db:Status-Status}"
                if status == _DPKG_STATUS_MISSING
                else "unrecognized status",
                line,
            )
            return []
        if status in _DPKG_STATUS_ABSENT:
            continue
        # Only reached for a package whose files are on disk. dpkg prints no
        # version for one it merely knows about, and those are already gone.
        if not version:
            _log_rejected_dpkg_line("on-disk package with no version", line)
            return []
        # Keyed, not appended: ${Package} renders the name WITHOUT its
        # architecture, so a multiarch install (libc6:amd64 + libc6:i386) is
        # listed twice under one name, and the payload carries no arch to tell
        # the two rows apart -- they are one package. Same rule, same reason as
        # _get_packages_rpm. Genuinely different versions of one name (several
        # kernels) keep their own rows: an old vulnerable kernel still installed
        # is still a finding.
        packages[(name, version)] = {"name": name, "version": version}
    return list(packages.values())


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
        # !r for the same reason as its dpkg twin: truncation bounds the size,
        # repr bounds the CONTENT, and rpm quotes package names back in its
        # own error text.
        log(f"rpm failed: {result.stderr[:_LOG_LINE_CHARS]!r}", "error")
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
                f"{line[:_LOG_LINE_CHARS]!r}",
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
