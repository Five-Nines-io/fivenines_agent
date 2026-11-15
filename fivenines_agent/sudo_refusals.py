"""Run the agent's `sudo -n` probes without making sudo mail root.

Debian and Ubuntu ship `Defaults mail_badpass` in their stock /etc/sudoers.
With it, every `sudo -n` that sudo refuses for a user it knows -- one with any
sudoers rule, or a member of the sudo group -- mails root a
"*** SECURITY information ***" message ("a password is required"), as soon as
the host can send mail. The capability probes re-ran each refused call every
one to five minutes, so a host missing one sudoers rule mailed its
administrator 288 to ~1150 times a day per command, whether or not the feature
was enabled.

run_checked() asks sudo only what costs no mail where anything can, and never
asks twice:

- `sudo -n -l` with no command first, once per policy: may this account use
  sudo without a password at all? Refused, no command is tried. It mails
  nothing for an account sudoers does not know, nor since sudo 1.9.16p1 (and
  never under sudo-rs); an older sudo mails a refusal once, for an account
  whose rules all need a password (an install run by a member of the sudo
  group). Nothing an unprivileged process can ask sudo avoids that one:
  /etc/sudoers is root-only, and every other question is refused the same way.
- `sudo -n -l <command>` next: the command runs only once sudo lists it.
  Listing needs no password when the account has at least one NOPASSWD rule
  (sudoers' default `listpw=any`, the README setup), so a command without a
  rule mails nothing.
- every refusal is remembered, in the config directory so a restart (an
  update, a reboot) does not ask again, and asked again only when one of these
  happens:
    * a file a sudoers rule or a group membership is read from changes
      (/etc/sudoers, /etc/sudoers.d and its entries, /etc/group): an operator
      who adds the missing rule sees it at the next probe;
    * reset() (SIGHUP, or the dashboard's permission recheck);
    * retry_interval has passed (REFUSAL_RETRY_INTERVAL for an enabled
      feature, None -- never -- for one that is not), for rules this cannot see
      change (LDAP, sssd, a group managed outside /etc/group).

A command that sudo allowed and that then failed on its own (fail2ban-client
while fail2ban is stopped) is not a refusal and is retried as before: sudo
mails nothing about it.
"""

import json
import os
import stat
import subprocess
import threading
import time

from fivenines_agent.debug import log
from fivenines_agent.env import config_dir, restrict_to_owner
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

# The refusals, in the config directory, written owner-only.
STATE_FILE = "sudo_refusals"

# The file holds a handful of entries, far under this: a larger one is not
# the agent's, and is ignored rather than read.
MAX_STATE_BYTES = 64 * 1024

# The key of `sudo -n -l` with no command.
GATE = ()


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


def _state_path():
    return os.path.join(config_dir(), STATE_FILE)


def _load_state():
    """The refusals an earlier run left: {key: (fingerprint, refused at, detail)}.

    {} when there are none, or when the file cannot be read as the agent wrote
    it: the worst a lost refusal costs is one more question to sudo.
    """
    path = _state_path()
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return {}
    except OSError as e:
        log(f"sudo_refusals: cannot open {path}: {e}", "debug")
        return {}
    try:
        # open() did not block on a FIFO (O_NONBLOCK), read() would.
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            log(f"sudo_refusals: {path} is not a regular file", "debug")
            return {}
        raw = os.read(fd, MAX_STATE_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_STATE_BYTES:
        log(f"sudo_refusals: {path} is over {MAX_STATE_BYTES} bytes", "debug")
        return {}
    try:
        return {
            tuple(entry["argv"]): (
                tuple(tuple(part) for part in entry["fingerprint"]),
                float(entry["refused_at"]),
                str(entry["detail"]),
            )
            for entry in json.loads(raw)
        }
    except (ValueError, TypeError, KeyError) as e:
        log(f"sudo_refusals: ignoring {path}: {e}", "debug")
        return {}


def _save_state(entries):
    """Write the refusals owner-only: a temp file, then os.replace (no torn file)."""
    path = _state_path()
    tmp_path = path + ".tmp"
    data = json.dumps(
        [
            {
                "argv": list(key),
                "fingerprint": [list(part) for part in fingerprint],
                "refused_at": refused_at,
                "detail": detail,
            }
            for key, (fingerprint, refused_at, detail) in entries.items()
        ]
    )
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        restrict_to_owner(fd)
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp_path, path)
    except OSError as e:
        log(f"sudo_refusals: cannot save {path}: {e}", "debug")


class SudoRefusals:
    """What sudo refused, keyed by the argv after `sudo -n` (GATE for none).

    The refusals are read from the state file on first use and written back
    whenever they change. Wall-clock times, since they outlive the process.
    """

    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.Lock()
        # key -> (policy fingerprint, refused at, what sudo said); None until read
        self._refused = None
        # key -> the policy fingerprint sudo last allowed it under (this process)
        self._passed = {}

    def _entries(self):
        if self._refused is None:
            self._refused = _load_state()
        return self._refused

    def recall(self, key, retry_interval, fingerprint):
        """What sudo said when it refused *key*, while that refusal holds.

        None: no refusal holds, ask sudo. One made under another policy, or
        longer ago than retry_interval (None: never on time alone; a clock that
        went back counts as passed), is dropped.
        """
        with self._lock:
            entries = self._entries()
            entry = entries.get(key)
            if entry is None:
                return None
            refused_fingerprint, refused_at, detail = entry
            elapsed = self._clock() - refused_at
            expired = retry_interval is not None and not 0 <= elapsed < retry_interval
            if refused_fingerprint == fingerprint and not expired:
                return detail
            del entries[key]
            _save_state(entries)
            return None

    def remember(self, key, detail, fingerprint):
        """Record what sudo answered under *fingerprint*: *detail* if it refused, else None."""
        with self._lock:
            entries = self._entries()
            if detail is None:
                self._passed[key] = fingerprint
                if entries.pop(key, None) is not None:
                    _save_state(entries)
                return
            self._passed.pop(key, None)
            entries[key] = (fingerprint, self._clock(), detail)
            _save_state(entries)

    def passed(self, key, fingerprint):
        """Whether sudo allowed *key* under this same policy, in this process."""
        with self._lock:
            return self._passed.get(key) == fingerprint

    def reset(self):
        """Forget every answer: each call is asked again."""
        with self._lock:
            self._passed.clear()
            self._refused = {}
            _save_state(self._refused)


_refusals = SudoRefusals()


def reset():
    """Forget every refusal (SIGHUP, the dashboard's recheck)."""
    _refusals.reset()


def _listing_refusal(args, timeout):
    """None when `sudo -n -l [args]` lists it, else what sudo said."""
    listed = run_privileged(
        ["sudo", "-n", "-l", *args],
        timeout=timeout,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=get_clean_env(),
    )
    if listed.returncode == 0:
        return None
    # The last line: a warning sudo prints first (unable to resolve host) is
    # not why it said no.
    lines = _decode(listed.stderr).splitlines()
    return lines[-1].strip() if lines else "not allowed by sudoers"


def run_checked(args, timeout, retry_interval=REFUSAL_RETRY_INTERVAL, stdout=None):
    """Run `sudo -n *args` unless sudo refuses it, without asking twice.

    Returns (result, refusal). When sudo refuses the call -- the account
    (`sudo -n -l`), the command (`sudo -n -l *args`) or the run itself (a rule
    that needs a password), now or earlier under the same policy -- result is
    None and refusal says why, in the `sudo -n <command>: <detail>` form the
    capability reasons use. Otherwise refusal is None and result is the
    command's CompletedProcess (bytes; stdout piped unless *stdout* says
    otherwise), which may have failed on its own. Raises what run_privileged
    raises; nothing is remembered then.
    """
    key = tuple(args)
    fingerprint = policy_fingerprint()
    for asked in (GATE, key):
        detail = _refusals.recall(asked, retry_interval, fingerprint)
        if detail is not None:
            return None, f"sudo -n {args[0]}: {detail}"
    if not _refusals.passed(GATE, fingerprint):
        detail = _listing_refusal([], timeout)
        _refusals.remember(GATE, detail, fingerprint)
        if detail is not None:
            return None, f"sudo -n {args[0]}: {detail}"
    detail = _listing_refusal(args, timeout)
    if detail is not None:
        _refusals.remember(key, detail, fingerprint)
        return None, f"sudo -n {args[0]}: {detail}"
    result = run_privileged(
        ["sudo", "-n", *args],
        timeout=timeout,
        stdout=subprocess.PIPE if stdout is None else stdout,
        stderr=subprocess.PIPE,
        env=get_clean_env(),
    )
    _refusals.remember(
        key, refusal_line(result.returncode, _decode(result.stderr)), fingerprint
    )
    return result, None
