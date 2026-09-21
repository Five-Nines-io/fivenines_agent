"""Operator-controlled allowlist of units whose journal the agent may read.

The backend already sends a `logs.units` allowlist, but that is the SERVER's
policy: a host owner who wants a hard local bound on which journals can leave
the box had no way to express one. This module reads one optional file in the
config dir -- `journal_units.allow` -- and turns it into a local veto that
every journal read passes through:

    logs.collect_log_signals              continuous per-unit signals
    log_capture.evaluate_and_enqueue      backend-pulled incident capture
    logs._capture_entries                 the choke point both run through
    systemd.SystemdCollector._journal_tail failure drilldown

The veto can only ever REMOVE access: it is intersected with what the server
asked for, never unioned. Semantics:

    file absent       -> no local policy, the server allowlist decides (the
                         default, so an install that never creates the file
                         behaves exactly as before)
    file present      -> only units matching a listed pattern may be read
    present but empty -> nothing may be read (the "logs off, but keep the
                         feature configured" statement)
    unreadable        -> nothing may be read, loudly. A policy that exists but
                         cannot be applied must never read as "no policy".

Patterns are shell globs matched against the unit name (`nginx.service`,
`postgresql@*.service`, `*.socket`). A name with no unit suffix gets systemd's
own implicit `.service` on BOTH sides of the match, so `nginx` in the file and
`nginx` from the server both match `nginx.service`.

For hosts that need no log monitoring at all, the stronger move is to take the
journal group away from the agent entirely (README: "Removing journal
access"); this file is for hosts that keep the feature but want to bound it.
"""

import fnmatch
import os
import stat as stat_module
import threading

from fivenines_agent.debug import log
from fivenines_agent.env import config_dir

ALLOWLIST_FILENAME = "journal_units.allow"

# Bounds on an operator-written file. Not a security boundary (the file is
# owned by whoever can already reconfigure the agent) -- just a guard against
# a truncated/garbage file turning every journal read into a 100k-pattern
# fnmatch sweep on the watchdog-bounded collection loop.
MAX_PATTERNS = 200
MAX_PATTERN_CHARS = 200
# Byte cap on the file itself, checked against the stat _policy() already did
# (and again on the read, since the file can grow in between). The per-line
# and per-pattern caps do NOT bound the read: iterating a file object
# materializes a whole line before its length can be rejected, so a file of
# one 50 MB line was read to EOF on the watchdog-bounded collection loop.
# 64 KiB is 200 patterns x 200 chars with room for comments.
#
# An oversized file is REFUSED, never truncated-and-parsed: cutting the blob
# at a byte offset can leave a partial last line, and a `*.service` cut to
# `*` WIDENS the policy to every unit -- the one direction a security control
# must never fail in.
MAX_FILE_BYTES = 64 * 1024
# Bound on a single server-supplied unit name. MAX_FILTER_UNITS bounds the
# count and MAX_PATTERN_CHARS bounds the operator's patterns; without this a
# 5 MB "unit name" would be strip()ed, scanned for metacharacters and then
# fnmatch'd against up to MAX_PATTERNS patterns, on the collection loop.
# Same per-field posture as MAX_PING_FIELD_CHARS.
MAX_UNIT_CHARS = 256
# Cap on how much of the SERVER's unit list is matched per call. The server
# sends the list, nothing in the agent bounds it, and each entry costs up to
# MAX_PATTERNS fnmatch calls. Same posture as MAX_PING_TARGETS and
# MAX_RESCAN_SCANNED: bound the untrusted input, do not trust it to be small.
MAX_FILTER_UNITS = 200

# Deny-everything, as distinct from None (no policy at all).
_DENY_ALL = ()

_UNIT_SUFFIXES = (
    ".service",
    ".socket",
    ".timer",
    ".target",
    ".mount",
    ".automount",
    ".path",
    ".slice",
    ".scope",
    ".swap",
    ".device",
)
_GLOB_CHARS = "*?["
# systemd unit names are drawn from ASCII alphanumerics plus ":-_.\@", so a
# glob metacharacter in a name the SERVER sent is never a real unit -- and
# `journalctl -u` expands globs itself. Matching such a name literally against
# an operator pattern lets a compromised backend walk straight through the
# veto: policy `app-?.service` accepts the literal `app-*.service` (the `?`
# matches the `*`), and journalctl then reads every app-* unit on the box.
# Under an active policy these are refused outright.
_SERVER_GLOB_CHARS = "*?[]"

_lock = threading.Lock()
# key: the stat identity the cached value was derived from. value: always a
# tuple of patterns (possibly _DENY_ALL); an absent file is never cached,
# because the stat that detects it runs before any cache lookup (see _policy).
_cache = {"key": None, "value": None}
_last_denied = None
_last_warning = None


def allowlist_path():
    return os.path.join(config_dir(), ALLOWLIST_FILENAME)


def reset_cache():
    """Drop the cached policy. Called on SIGHUP with the other host-state
    re-probes, and by tests."""
    global _last_denied, _last_warning
    with _lock:
        _cache["key"] = None
        _cache["value"] = None
        _last_denied = None
        _last_warning = None


def _normalize(name):
    """Apply systemd's implicit `.service` so both sides of a match agree.

    A glob is left alone: `nginx*` already matches `nginx.service`, and
    appending a suffix to a pattern would break `*` entirely.
    """
    name = name.strip()
    if any(char in name for char in _GLOB_CHARS):
        return name
    if name.endswith(_UNIT_SUFFIXES):
        return name
    return name + ".service"


def _warn_once(key, message):
    """Log an operator-facing notice once per distinct condition.

    These conditions persist for as long as the file does, and this runs on
    the per-tick collection path, so an unguarded log() would be a line every
    interval forever.
    """
    global _last_warning
    with _lock:
        if _last_warning == key:
            return
        _last_warning = key
    log(message, "error")


class OversizedPolicy(Exception):
    """The allowlist file is larger than MAX_FILE_BYTES."""


def _read_patterns(path):
    patterns = []
    skipped = 0
    total = 0
    # errors="replace" rather than a strict decode: an undecodable byte must
    # not take log monitoring down, and it cannot widen the policy either --
    # a pattern carrying U+FFFD matches nothing rather than matching more.
    # One bounded read (not line iteration) so no single line can be larger
    # than the cap. Over the cap is a refusal, not a truncation: see
    # MAX_FILE_BYTES.
    with open(path, "r", errors="replace") as f:
        blob = f.read(MAX_FILE_BYTES + 1)
    if len(blob) > MAX_FILE_BYTES:
        raise OversizedPolicy(f"larger than {MAX_FILE_BYTES} bytes")
    for line in blob.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) > MAX_PATTERN_CHARS:
            skipped += 1
            continue
        total += 1
        if len(patterns) < MAX_PATTERNS:
            patterns.append(_normalize(line))
    if skipped:
        log(
            f"journal allowlist: ignored {skipped} over-long line(s) in {path}",
            "error",
        )
    if total > MAX_PATTERNS:
        # Never silent: everything past the cap is DENIED, so an operator
        # whose file is too long loses those units' journals and has to be
        # able to see why. Reported on the real overflow only -- a file of
        # exactly MAX_PATTERNS entries is complete, not truncated.
        log(
            f"journal allowlist: {path} lists {total} patterns; only the first "
            f"{MAX_PATTERNS} are applied and the rest are refused",
            "error",
        )
    return tuple(patterns)


def _policy():
    """The active pattern tuple, or None when there is no local policy.

    Re-read only when the file's stat identity changes, so the common case
    (no file, or an unchanged file) costs one stat per call.
    """
    global _last_denied, _last_warning

    path = allowlist_path()

    try:
        st = os.stat(path)
    except FileNotFoundError:
        # A DANGLING SYMLINK is not "no policy": the operator pointed the
        # allowlist at something -- a managed config, a mounted secret -- that
        # is missing right now. Reading that as "allow everything" would open
        # every journal at exactly the moment a deployment broke.
        if os.path.islink(path):
            _warn_once(
                ("dangling", path),
                f"journal allowlist {path} is a symlink with no target; "
                "refusing every journal read until it resolves",
            )
            return _DENY_ALL
        # No local policy. Nothing to cache: the stat above IS the check, and
        # it runs before any cache lookup, so a cached "absent" marker would
        # never be read.
        return None
    except OSError as e:
        # The file is there but we cannot even stat it: deny, do not guess.
        # Not cacheable -- there is no stat identity to key on -- so this is
        # the one path that repeats its syscall per call.
        _warn_once(
            ("stat", path, str(e)),
            f"journal allowlist {path} cannot be read ({e}); "
            "refusing every journal read until it can",
        )
        return _DENY_ALL

    if not stat_module.S_ISREG(st.st_mode):
        # A FIFO -- or a symlink to one -- blocks open() forever when nothing
        # is writing, and on the single-threaded collection loop that is a
        # watchdog kill, not a slow read. Only a regular file can be a policy.
        _warn_once(
            ("not-regular", path),
            f"journal allowlist {path} is not a regular file; "
            "refusing every journal read until it is",
        )
        return _DENY_ALL

    # st_mode and st_ctime_ns are in the key because chmod changes NEITHER
    # mtime, size nor inode: without them, fixing a root-owned 0600 policy to
    # 0644 would leave the cached refusal in place indefinitely, and making a
    # readable policy unreadable would keep serving the cached patterns.
    key = (path, st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino, st.st_mode)
    with _lock:
        if _cache["key"] == key:
            return _cache["value"]

    try:
        patterns = _read_patterns(path)
    except OversizedPolicy as e:
        # Refused, not truncated: a blob cut at a byte offset can end in a
        # partial pattern, and `*.service` cut to `*` would WIDEN the policy
        # to every unit.
        _warn_once(
            ("oversized", path, str(e)),
            f"journal allowlist {path} is {e}; refusing every journal read "
            "until it is smaller",
        )
        with _lock:
            _cache["key"] = key
            _cache["value"] = _DENY_ALL
        return _DENY_ALL
    except Exception as e:
        # Deliberately broad: whatever went wrong with an operator-written
        # file, the answer is "this policy could not be applied", never an
        # exception escaping into the collection loop.
        _warn_once(
            ("read", path, str(e)),
            f"journal allowlist {path} cannot be read ({e}); "
            "refusing every journal read until it can",
        )
        # Cache the refusal under the same stat identity: a root-owned 0600
        # file the agent cannot open would otherwise re-open once per unit per
        # tick forever. Fixing the mode changes the stat identity, so recovery
        # still happens on the next tick.
        with _lock:
            _cache["key"] = key
            _cache["value"] = _DENY_ALL
        return _DENY_ALL

    with _lock:
        _cache["key"] = key
        _cache["value"] = patterns
        # A file that reads cleanly re-arms BOTH latches, so a later
        # permission regression or a re-introduced denial is reported again
        # instead of being swallowed. An operator edit is exactly the event
        # after which the next refusal should be worth a line.
        _last_warning = None
        _last_denied = None

    # Reached only when the file changed, so this is once per edit, not per
    # tick. Operators need to see that a local policy took effect, and that an
    # empty file means "nothing", not "everything".
    if patterns:
        log(
            f"journal allowlist active: {len(patterns)} pattern(s) from {path}",
            "info",
        )
    else:
        log(
            f"journal allowlist {path} lists no unit: no journal will be read",
            "info",
        )
    return patterns


def unit_allowed(unit):
    """True when this host permits reading `unit`'s journal."""
    patterns = _policy()
    if patterns is None:
        return True  # no local policy: the server allowlist decides
    if not isinstance(unit, str) or not unit.strip():
        return False
    if len(unit) > MAX_UNIT_CHARS:
        return False
    if any(char in unit for char in _SERVER_GLOB_CHARS):
        # The name the server sent is not a unit name, it is a pattern --
        # and journalctl would expand it. Refuse rather than match it
        # literally against the operator's patterns (see _SERVER_GLOB_CHARS).
        return False
    candidate = _normalize(unit)
    return any(fnmatch.fnmatchcase(candidate, pattern) for pattern in patterns)


def filter_units(units):
    """Intersect a server-supplied unit list with the local allowlist.

    Returns (allowed, refused). The caller is expected to SURFACE the refused
    half: a unit that was never read must not be reported as a unit with no
    errors -- that is the same false-clean the packages collector's
    errors[] contract exists to prevent.
    """
    global _last_denied
    if _policy() is None:
        # No local policy: a genuine pass-through. Returning early also keeps
        # the cap below from reporting "the journal allowlist refused N
        # units" on a host that has no allowlist at all.
        return list(units or []), []
    allowed = []
    denied = []
    requested = units or []
    for unit in requested[:MAX_FILTER_UNITS]:
        if unit_allowed(unit):
            allowed.append(unit)
        else:
            denied.append(unit)
    # Everything past the cap is refused too, so it is reported as refused
    # rather than vanishing: a server list long enough to hit the cap would
    # otherwise drop the operator's actually-allowed units with no line.
    denied.extend(requested[MAX_FILTER_UNITS:])

    if denied:
        # frozenset, not a sorted tuple: this runs every tick in the steady
        # state and only ever decides "same set as last time?". The sorted
        # display string is built on the branch that actually logs.
        key = frozenset(str(u) for u in denied)
        with _lock:
            already = _last_denied == key
            _last_denied = key
        if not already:
            names = sorted(key)
            shown = ", ".join(names[:5])
            more = "" if len(names) <= 5 else f" (+{len(names) - 5} more)"
            log(
                f"journal allowlist: refusing {len(names)} unit(s) requested by "
                f"the server: {shown}{more}",
                "error",
            )
    else:
        # Nothing refused this tick: re-arm, so a denial that comes back is
        # reported again rather than matching a stale key forever.
        with _lock:
            _last_denied = None
    return allowed, denied
