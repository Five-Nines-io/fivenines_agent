"""Run the agent's `sudo -n` probes without making sudo mail root.

Debian and Ubuntu ship `Defaults mail_badpass` in their stock /etc/sudoers.
With it, every `sudo -n` that sudo refuses for a user it knows -- one with any
sudoers rule, or a member of the sudo group -- mails root a
"*** SECURITY information ***" message ("a password is required"), as soon as
the host can send mail. The capability probes re-ran each refused call every
one to five minutes, so a host missing one sudoers rule mailed its
administrator 288 to ~1150 times a day per command, whether or not the feature
was enabled.

run_checked() does two things about it:

- It asks `sudo -n -l <command>` first, and runs the command only when sudo
  lists it as allowed. Listing needs no password when the user has at least
  one NOPASSWD rule (sudoers' default `listpw=any`), the README's setup, so a
  command without a rule costs no authentication failure and no mail. A user
  whose rules all need a password (an install run by a member of the sudo
  group) still fails the listing, and sudo mails that too (measured on
  1.8.31 to 1.9.16p2: 1.9.16p1 stopped mailing a bare `-nl`, not
  `-l <command>`), so the memory below is what bounds it.
- It remembers what sudo refused, and does not ask again until one of these
  happens:
    * a file a sudoers rule or a group membership is read from changes
      (/etc/sudoers, /etc/sudoers.d and its entries, /etc/group): an operator
      who adds the missing rule sees it at the next probe;
    * reset() (SIGHUP, or the dashboard's permission recheck);
    * retry_interval has passed (REFUSAL_RETRY_INTERVAL for an enabled
      feature, None -- never -- for one that is not), for rules this cannot see
      change (LDAP, sssd, a group managed outside /etc/group);
    * the agent restarts (the memory is per process).

A command that sudo allowed and that then failed on its own (fail2ban-client
while fail2ban is stopped) is not a refusal and is retried as before: sudo
mails nothing about it.
"""

import os
import subprocess
import threading
import time

from fivenines_agent.subprocess_utils import get_clean_env, run_privileged

# Retry a refusal once a day anyway, for the rules no file here reflects.
REFUSAL_RETRY_INTERVAL = 24 * 3600

# Files a sudoers rule, or a group membership granting one, is read from. Each
# is stat'ed, never read (/etc/sudoers is root-only).
POLICY_FILES = ("/etc/sudoers", "/etc/group")

# Its entries are stat'ed too when it can be listed (0755 on Debian/Ubuntu).
# Where it cannot (0750 on RHEL), the directory's own times still move when a
# file is added, removed or saved by visudo (which renames a temp file).
POLICY_DIR = "/etc/sudoers.d"

# sudo's own words for a call it refuses under -n. get_clean_env() pins
# LC_ALL=C, so they are never translated.
REFUSAL_MESSAGE = "a password is required"

_SUDO_PREFIX = "sudo:"


def _decode(output):
    return (output or b"").decode("utf-8", errors="replace").strip()


def refusal_line(returncode, stderr):
    """sudo's own line refusing the call, or None if sudo did not refuse it.

    None for a command that sudo ran and that failed on its own. The line is
    looked for, not taken first: sudo can warn before it refuses ("sudo:
    unable to resolve host ..." on a host whose name does not resolve).
    """
    if returncode == 0:
        return None
    for line in stderr.splitlines():
        line = line.strip()
        if line.startswith(_SUDO_PREFIX) and REFUSAL_MESSAGE in line:
            return line
    return None


def _stat_key(path):
    try:
        st = os.stat(path)
    except OSError as e:
        return (path, e.errno)
    return (path, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def policy_fingerprint():
    """What the sudo policy files look like now: changes when any of them does."""
    keys = [_stat_key(path) for path in POLICY_FILES + (POLICY_DIR,)]
    try:
        names = sorted(os.listdir(POLICY_DIR))
    except OSError:
        names = []
    keys.extend(_stat_key(os.path.join(POLICY_DIR, name)) for name in names)
    return tuple(keys)


class SudoRefusals:
    """The calls sudo refused in this process, keyed by the argv after `sudo -n`."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        # key -> (policy fingerprint, refused at, reason)
        self._refused = {}
        # key -> policy fingerprint read just before the call recall() allowed
        self._before_call = {}

    def recall(self, key, retry_interval):
        """The reason sudo refused *key*, while that refusal still holds.

        None means: make the call, then report it with remember(). The policy
        is read BEFORE the call, so a rule saved while it runs is still seen as
        a change by the next recall(). retry_interval None never retries on
        time alone.
        """
        fingerprint = policy_fingerprint()
        with self._lock:
            entry = self._refused.pop(key, None)
            if entry is not None:
                refused_fingerprint, refused_at, reason = entry
                expired = (
                    retry_interval is not None
                    and self._clock() - refused_at >= retry_interval
                )
                if refused_fingerprint == fingerprint and not expired:
                    self._refused[key] = entry
                    return reason
            self._before_call[key] = fingerprint
            return None

    def remember(self, key, reason):
        """Report the call recall() allowed: *reason* if sudo refused it, else None."""
        with self._lock:
            fingerprint = self._before_call.pop(key, None)
            if reason is None:
                return
            if fingerprint is None:
                fingerprint = policy_fingerprint()
            self._refused[key] = (fingerprint, self._clock(), reason)

    def reset(self):
        """Forget every refusal: the next call of each is sent again."""
        with self._lock:
            self._refused.clear()
            self._before_call.clear()


_refusals = SudoRefusals()


def reset():
    """Forget every refusal of this process (SIGHUP, the dashboard's recheck)."""
    _refusals.reset()


def run_checked(args, timeout, retry_interval=REFUSAL_RETRY_INTERVAL, stdout=None):
    """Run `sudo -n *args` unless sudo refuses it, without asking twice.

    Returns (result, refusal). When sudo refuses the call -- its listing now,
    or an earlier refusal nothing has changed since -- result is None and
    refusal says why, in the `sudo -n <command>: <detail>` form the capability
    reasons use. Otherwise refusal is None and result is the command's
    CompletedProcess (bytes; stdout piped unless *stdout* says otherwise), which
    may have failed on its own; a run sudo itself refused (a rule that needs a
    password) is remembered too. Raises what run_privileged raises; nothing is
    remembered then.
    """
    key = tuple(args)
    refusal = _refusals.recall(key, retry_interval)
    if refusal is not None:
        return None, refusal
    listed = run_privileged(
        ["sudo", "-n", "-l", *args],
        timeout=timeout,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=get_clean_env(),
    )
    if listed.returncode != 0:
        # The last line: a warning sudo prints first (unable to resolve host)
        # is not why it said no.
        lines = _decode(listed.stderr).splitlines()
        detail = lines[-1].strip() if lines else "not allowed by sudoers"
        refusal = f"sudo -n {args[0]}: {detail}"
        _refusals.remember(key, refusal)
        return None, refusal
    result = run_privileged(
        ["sudo", "-n", *args],
        timeout=timeout,
        stdout=subprocess.PIPE if stdout is None else stdout,
        stderr=subprocess.PIPE,
        env=get_clean_env(),
    )
    line = refusal_line(result.returncode, _decode(result.stderr))
    _refusals.remember(key, None if line is None else f"sudo -n {args[0]}: {line}")
    return result, None
