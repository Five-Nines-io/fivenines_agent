"""Disk quota metrics collector for fivenines agent.

Collects per-user and per-group disk quota information using Linux
quota-tools (``quota -ugw``).  This collector is most useful in
**user-install mode** on shared hosting, where the running user's own
quota is what matters.  In a system install the data is still valid but
describes the ``fivenines`` service user rather than the customer.

Platform scope: Linux quota-tools only.  FreeBSD uses different flags
(no ``-w``) and is out of scope.
"""

import grp
import os
import re
import subprocess

from fivenines_agent.debug import debug, log
from fivenines_agent.subprocess_utils import get_clean_env_c_locale as _quota_env


# Regex for section headers produced by ``quota -ugw`` with LC_ALL=C.
# Examples:
#   Disk quotas for user spuyet (uid 1000): none
#   Disk quotas for group dev (gid 1000): no limited resources used
#   Disk quotas for user spuyet (uid 1000):
_SECTION_RE = re.compile(
    r"^Disk quotas for (user|group) (\S+) "
    r"\((uid|gid) (\d+)\):\s*(.*?)\s*$"
)


def _strip_asterisk(value):
    """Strip trailing ``*`` from a quota value and convert to int."""
    return int(value.rstrip("*"))


def _parse_filesystem_row(line):
    """Parse a single filesystem data row into a dict.

    Expected columns (wide format, ``-w``):
        Filesystem  blocks  quota  limit  grace  files  quota  limit  grace
    """
    cols = line.split()
    if len(cols) < 7:
        return None

    try:
        filesystem = cols[0]
        space_used = _strip_asterisk(cols[1])
        space_soft = _strip_asterisk(cols[2])
        space_hard = _strip_asterisk(cols[3])

        # Grace column may be absent (empty) -- detect by checking whether
        # column 4 looks like an integer (files-used) or a grace string.
        idx = 4
        space_grace = None
        if len(cols) > 8 or (len(cols) > 4 and not cols[4].rstrip("*").isdigit()):
            space_grace = cols[4] if cols[4] != "" else None
            idx = 5

        files_used = _strip_asterisk(cols[idx])
        files_soft = _strip_asterisk(cols[idx + 1])
        files_hard = _strip_asterisk(cols[idx + 2])

        files_grace = None
        if idx + 3 < len(cols):
            files_grace = cols[idx + 3]

        soft_exceeded = (
            (space_soft != 0 and space_used > space_soft)
            or (files_soft != 0 and files_used > files_soft)
        )
        hard_exceeded = (
            (space_hard != 0 and space_used >= space_hard)
            or (files_hard != 0 and files_used >= files_hard)
        )

        return {
            "filesystem": filesystem,
            "space": {
                "used_kib": space_used,
                "soft_kib": space_soft,
                "hard_kib": space_hard,
                "grace": space_grace,
            },
            "files": {
                "used": files_used,
                "soft": files_soft,
                "hard": files_hard,
                "grace": files_grace,
            },
            "soft_exceeded": soft_exceeded,
            "hard_exceeded": hard_exceeded,
        }
    except (ValueError, IndexError):
        return None


def _parse_quota_output(stdout):
    """Parse the full stdout of ``quota -ugw`` into structured data.

    Returns ``(user_dict_or_none, groups_list)``.
    """
    user = None
    groups = []
    current_section = None  # ("user"|"group", name, id)
    current_filesystems = []
    header_line_seen = False

    def _flush_section():
        nonlocal user, current_section, current_filesystems, header_line_seen
        if current_section is None:
            return
        kind, name, identity = current_section
        entry = {
            "name": name,
            "id": identity,
            "filesystems": current_filesystems,
        }
        if kind == "user":
            user = entry
        else:
            groups.append(entry)
        current_section = None
        current_filesystems = []
        header_line_seen = False

    for line in stdout.splitlines():
        line_stripped = line.strip()
        if not line_stripped:
            continue

        # Check for section header
        match = _SECTION_RE.match(line_stripped)
        if match:
            _flush_section()
            kind = match.group(1)  # "user" or "group"
            name = match.group(2)
            identity = int(match.group(4))
            trailer = match.group(5).lower()

            current_section = (kind, name, identity)
            current_filesystems = []
            header_line_seen = False

            # "none" or "no limited resources used" => empty filesystems
            if trailer in ("none", "no limited resources used"):
                _flush_section()
            continue

        # Skip the column-header line (Filesystem  blocks  quota ...)
        if current_section and not header_line_seen:
            if line_stripped.startswith("Filesystem"):
                header_line_seen = True
                continue

        # Data row
        if current_section and header_line_seen:
            row = _parse_filesystem_row(line_stripped)
            if row is not None:
                current_filesystems.append(row)

    _flush_section()
    return user, groups


def _fetch_primary_group_quota(primary_gid):
    """Fetch quota for a single group by GID.

    Resolves the GID to a group name via ``grp.getgrgid`` and passes it
    as a positional argument to ``quota -gw``.  The ``--group`` long
    option is a boolean mode flag (equivalent to ``-g``) and does NOT
    accept a GID value.

    Returns a group dict or None on failure.
    """
    try:
        group_name = grp.getgrgid(primary_gid).gr_name
    except KeyError:
        log("quota: cannot resolve gid {} to group name".format(primary_gid), "debug")
        return None
    try:
        result = subprocess.run(
            ["quota", "-gw", group_name],
            env=_quota_env(),
            timeout=10,
            capture_output=True,
            text=True,
        )
        stdout = result.stdout.strip()
        if not stdout:
            return None
        _, groups = _parse_quota_output(stdout)
        for g in groups:
            if g["id"] == primary_gid:
                return g
        return None
    except subprocess.TimeoutExpired:
        log(
            "quota -gw {} timed out after 10s".format(group_name),
            "debug",
        )
        return None
    except Exception as e:
        log(
            "quota -gw {}: {}: {}".format(group_name, type(e).__name__, e),
            "debug",
        )
        return None


@debug("quota")
def quota_metrics():
    """Collect per-user and per-group disk quota metrics.

    Runs ``quota -ugw`` with ``LC_ALL=C`` and parses the output.
    Returns a dict with ``command``, ``space_unit``, ``user``, ``groups``
    keys.  Returns ``{}`` when quota is available but the user/groups
    have no quotas configured.  Returns ``None`` on error.
    """
    try:
        result = subprocess.run(
            ["quota", "-ugw"],
            env=_quota_env(),
            timeout=10,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired:
        log("quota -ugw timed out after 10s", "error")
        return None
    except Exception as e:
        log("quota -ugw: {}: {}".format(type(e).__name__, e), "error")
        return None

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    # Log stderr at debug (e.g. "Cannot stat() mounted device") but do
    # not treat it as fatal when stdout has data.
    if stderr:
        log("quota stderr: {}".format(stderr), "debug")

    # Empty stdout handling
    if not stdout:
        if result.returncode == 0:
            # No quotas configured -- valid empty result
            return {}
        # Nonzero exit with no stdout is an error
        detail = stderr.splitlines()[0] if stderr else "returncode {}".format(
            result.returncode
        )
        log("quota -ugw failed: {}".format(detail), "error")
        return None

    # Parse stdout regardless of exit code (nonzero + valid stdout =
    # exceeded, not error).
    try:
        user, groups = _parse_quota_output(stdout)
    except Exception as e:
        log("quota output parse error: {}: {}".format(type(e).__name__, e), "error")
        return None

    # If parsing produced nothing at all, treat as empty
    if user is None and not groups:
        return {}

    # Primary group fallback: if os.getegid() is not among the parsed
    # groups, explicitly fetch it.
    primary_gid = os.getegid()
    if not any(g["id"] == primary_gid for g in groups):
        fallback = _fetch_primary_group_quota(primary_gid)
        if fallback is not None:
            groups.append(fallback)

    return {
        "command": "quota -ugw",
        "space_unit": "kib",
        "user": user,
        "groups": groups,
    }
