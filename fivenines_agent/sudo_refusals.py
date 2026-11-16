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
asks twice. What each question costs, per kind of account, is measured on the
real sudo of each CI image (ci/test-sudo-mail.sh); on a sudo older than
1.9.16p1 with mail_badpass, in mails:

    account                          run  -l  -l <command>  -v
    a NOPASSWD rule (README)          1    0       0         0
    no sudoers rule (default)         0    1       1         0
    every rule needs a password       1    1       1         1

- once per policy, whether the account may use sudo without a password at
  all, by the question that is free for the account it most likely is (see
  _account_refusal): `sudo -n -v` (free unless a rule needs a password; sudo
  then names an account it does not know, "may not run sudo"), or for a
  member of an admin group, or an account whose -v needed a password before,
  `sudo -n -l` (free once any rule is NOPASSWD, the README's user
  installation). Refused, no command is tried. An account whose rules all
  need a password costs that one mail on a sudo older than 1.9.16p1 (two,
  -v then -l, outside an admin group), again once a day while a sudo feature
  is enabled (the retry below); nothing an unprivileged process can ask sudo
  avoids it: /etc/sudoers is root-only, and every question is refused the
  same way. From 1.9.16p1 on, and under sudo-rs, nothing mails.
- `sudo -n -l <command>` next, once per policy: the command runs only once
  sudo lists it. Listing needs no password when the account has at least one
  NOPASSWD rule (sudoers' default `listpw=any`, the README setup), so a
  command without a rule mails nothing; under another listpw a listing
  refused for a password leaves the decision to the run. It also lists a
  command a rule allows WITH a password (an admin group's `ALL`), whose run
  would then mail: for an account with such a rule, a command the account's
  own `sudo -n -l` shows under no NOPASSWD rule is not run
  (_needs_a_password, which never guesses).
- every answer is remembered, a refusal in the config directory so a restart
  (an update, a reboot) does not ask again (not for a --dry-run, which asks
  afresh and leaves the service's file alone), and asked again only when one
  of these happens:
    * the policy fingerprint changes: a file a sudoers rule or a group
      membership is read from (/etc/sudoers, /etc/sudoers.d and its entries
      where it can be listed, /etc/group), or the process's own uid and groups
      (sudo matches %group rules against those, and they change only at a
      restart): an operator who adds the missing rule sees it at the next
      probe (on RHEL, whose /etc/sudoers.d cannot be listed, only a file added,
      removed or saved by visudo shows);
    * reset() (SIGHUP, or the dashboard's permission recheck);
    * retry_interval has passed (REFUSAL_RETRY_INTERVAL for an enabled
      feature, None -- never -- for one that is not), for rules this cannot see
      change (LDAP, sssd, a group managed outside /etc/group). Known limit: a
      host whose sudo rules come from LDAP and whose agent asked before sssd
      answered keeps that refusal until then, or until a recheck.

A command that sudo allowed and that then failed on its own (fail2ban-client
while fail2ban is stopped) is not a refusal and is retried as before: sudo
mails nothing about it.
"""

import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time

from fivenines_agent.debug import log
from fivenines_agent.env import config_dir, dry_run, restrict_to_owner
from fivenines_agent.subprocess_utils import get_clean_env, run_privileged

# Retry a refusal once a day anyway, for the rules no file here reflects.
REFUSAL_RETRY_INTERVAL = 24 * 3600

# A question about the policy (-v, -l) answers at once: it gets at most this
# long, whatever the command itself is given, so the questions chained before
# a run stay short of the watchdog-bounded loop's budget.
QUESTION_TIMEOUT = 5

# Files a sudoers rule, or a group membership granting one, is read from. Each
# is stat'ed, never read (/etc/sudoers is root-only).
POLICY_FILES = ("/etc/sudoers", "/etc/group")

# Its entries are stat'ed too when it can be listed (0755 on Debian/Ubuntu).
# Where it cannot (0750 on RHEL), the directory's own times still move when a
# file is added, removed or saved by visudo (which renames a temp file).
POLICY_DIR = "/etc/sudoers.d"

# sudo's own words for a call it refuses under -n (sudo-rs has its own).
# get_clean_env() pins LC_ALL=C, so they are never translated.
REFUSAL_MESSAGES = ("a password is required", "interactive authentication is required")

_SUDO_PREFIX = "sudo:"

# The refusals, in the config directory, written owner-only.
STATE_FILE = "sudo_refusals"

# The file holds a handful of entries, far under this: a larger one is not
# the agent's, and is ignored rather than read.
MAX_STATE_BYTES = 64 * 1024

# The key of the question about the account itself (_account_refusal), and
# the one kept when that account's -v needs a password, so it is asked -l
# directly from then on: its -v would mail at every start.
GATE = ()
_VALIDATE = ("-v",)

# Groups the stock sudoers lets use sudo with a password: sudo (Debian,
# Ubuntu), admin (Ubuntu before 12.04), wheel (RHEL family).
ADMIN_GROUPS = frozenset({"sudo", "admin", "wheel"})

# How classic sudo refuses an account sudoers does not know (LC_ALL=C).
NOT_IN_SUDOERS = ("may not run sudo", "is not in the sudoers file")

# The header `sudo -l` prints before an account's rules, and the tags it
# prints before an entry's commands ("NOPASSWD: NOLOG_OUTPUT: /usr/bin/wg").
_RULES_HEADER = "may run the following commands"
_TAGS = re.compile(r"(?:[A-Z_]+:\s*)+")
# The options sudo prints before an entry's tags ("CWD=/ TIMEOUT=60 ").
_OPTIONS = re.compile(r"(?:[A-Z_]+=\S*\s+)*")

# Why a listed command is not run (see _needs_a_password).
NEEDS_AUTHENTICATION = "needs a password (sudo -l shows no NOPASSWD rule for it)"


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
        if line.startswith(_SUDO_PREFIX) and any(
            message in line for message in REFUSAL_MESSAGES
        ):
            return line
    return None


def _stat_key(path):
    try:
        st = os.stat(path)
    except OSError as e:
        return (path, e.errno)
    return (path, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _policy_stats():
    """What the sudo policy files look like now."""
    keys = [_stat_key(path) for path in POLICY_FILES + (POLICY_DIR,)]
    try:
        names = sorted(os.listdir(POLICY_DIR))
    except OSError:
        names = []
    keys.extend(_stat_key(os.path.join(POLICY_DIR, name)) for name in names)
    return tuple(keys)


def _identity():
    """Who asks sudo: the effective uid and the process's groups.

    sudo matches %group rules against the process's groups, which change only
    when the agent restarts, so a group granted at runtime counts only then.
    () where there are none (Windows, which never runs sudo).
    """
    if not hasattr(os, "getgroups"):
        return ()
    return (os.geteuid(), tuple(sorted(os.getgroups())))


def _is_root():
    """Whether the agent runs as root, whom sudo never asks a password."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def policy_fingerprint():
    """A digest of the sudo policy and of who asks: changes when either does.

    A digest, so each state file entry stays small however many files
    /etc/sudoers.d holds.
    """
    data = repr((_identity(), _policy_stats())).encode()
    return hashlib.sha256(data).hexdigest()


def _state_path():
    """Where the refusals are kept, or None for a --dry-run: it asks sudo
    afresh, and leaves the service's refusals alone."""
    if dry_run():
        return None
    return os.path.join(config_dir(), STATE_FILE)


def _load_state():
    """The refusals an earlier run left: {key: (fingerprint, refused at, detail)}.

    {} when there are none, or when the file cannot be read as the agent wrote
    it: the worst a lost refusal costs is one more question to sudo.
    """
    path = _state_path()
    if path is None:
        return {}
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
                str(entry["fingerprint"]),
                float(entry["refused_at"]),
                str(entry["detail"]),
            )
            for entry in json.loads(raw)
        }
    except (ValueError, TypeError, KeyError, RecursionError) as e:
        log(f"sudo_refusals: ignoring {path}: {e}", "debug")
        return {}


def _save_state(entries):
    """Write the refusals owner-only, through a temp file of this write's own
    then os.replace: no torn file, even with a --dry-run writing beside."""
    path = _state_path()
    if path is None:
        return
    data = json.dumps(
        [
            {
                "argv": list(key),
                "fingerprint": fingerprint,
                "refused_at": refused_at,
                "detail": detail,
            }
            for key, (fingerprint, refused_at, detail) in entries.items()
        ]
    )
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix=STATE_FILE + ".", dir=os.path.dirname(path)
        )
        restrict_to_owner(fd)
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp_path, path)
    except OSError as e:
        log(f"sudo_refusals: cannot save {path}: {e}", "debug")
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)


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
        # key -> (policy fingerprint, allowed at, what it printed) of the last
        # call sudo allowed (this process only)
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
            if refused_fingerprint == fingerprint and not self._expired(
                refused_at, retry_interval
            ):
                return detail
            del entries[key]
            _save_state(entries)
            return None

    def _expired(self, at, retry_interval):
        """Whether an answer given at *at* is due again (None: never on time;
        a clock that went back counts as due)."""
        elapsed = self._clock() - at
        return retry_interval is not None and not 0 <= elapsed < retry_interval

    def remember(self, key, detail, fingerprint, listing=""):
        """Record what sudo answered under *fingerprint*: *detail* if it refused, else None.

        *listing* is what an allowed call printed, kept for passed().
        """
        with self._lock:
            entries = self._entries()
            if detail is None:
                self._passed[key] = (fingerprint, self._clock(), listing)
                if entries.pop(key, None) is not None:
                    _save_state(entries)
                return
            self._passed.pop(key, None)
            entries[key] = (fingerprint, self._clock(), detail)
            _save_state(entries)

    def passed(self, key, fingerprint, retry_interval=None):
        """What sudo printed when it allowed *key* under this same policy, in
        this process ("" for nothing), or None if it did not, or if that pass
        is due again under the same retry_interval as a refusal: a rule
        withdrawn, or given, where no file shows it counts then too."""
        with self._lock:
            entry = self._passed.get(key)
            if entry is None:
                return None
            passed_fingerprint, passed_at, listing = entry
            if passed_fingerprint != fingerprint or self._expired(
                passed_at, retry_interval
            ):
                return None
            return listing

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


def _ask(options, timeout):
    """Ask `sudo -n *options`: (None, what it printed) when it exits 0, else
    (the last line sudo wrote, "")."""
    answer = run_privileged(
        ["sudo", "-n", *options],
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=get_clean_env(),
    )
    if answer.returncode == 0:
        return None, _decode(answer.stdout)
    # The last line: a warning sudo prints first (unable to resolve host) is
    # not why it said no.
    lines = _decode(answer.stderr).splitlines()
    return (lines[-1].strip() if lines else "not allowed by sudoers"), ""


def _in_admin_group():
    """Whether this process belongs to a group the stock sudoers names."""
    import grp  # Unix only, like every caller of run_checked

    for gid in set(os.getgroups()) | {os.getegid()}:
        try:
            if grp.getgrgid(gid).gr_name in ADMIN_GROUPS:
                return True
        except KeyError:
            continue
    return False


def _account_refusal(timeout, fingerprint):
    """Whether this account may use sudo without a password for something.

    (None, listing) when it may, else (what sudo said, ""). *listing* is the
    account's `sudo -n -l` when that answered, i.e. when some rule of the
    account needs a password ("" when none does). The first question is the
    one that mails nothing for the account it most likely is (the table in the
    module docstring):

    - a member of an admin group has a rule that needs a password: `sudo -n
      -l`, free once any of its rules is NOPASSWD (the README's user
      installation), where `-v` would mail;
    - any other account: `sudo -n -v`, free for one whose rules are all
      NOPASSWD (the README's system installation) and for one sudoers does not
      know (the default installation), which sudo then names. Refused for
      another reason (a rule of its own that needs a password, or sudo-rs's
      wording), `sudo -n -l` decides, and is asked first from then on under
      this policy, across restarts: that -v mails.
    """
    if not _in_admin_group() and _refusals.recall(_VALIDATE, None, fingerprint) is None:
        detail, _ = _ask(["-v"], timeout)
        if detail is None:
            return None, ""
        if any(marker in detail for marker in NOT_IN_SUDOERS):
            return detail, ""
        _refusals.remember(_VALIDATE, detail, fingerprint)
    return _ask(["-l"], timeout)


def _nopasswd_commands(listing):
    """The commands an account's `sudo -l` shows under NOPASSWD.

    None when it cannot tell: no rules header (another format),
    `!authenticate` (no rule needs a password) or `exempt_group` (sudo never
    authenticates that group's members) among its Defaults.
    """
    if "!authenticate" in listing or "exempt_group" in listing:
        return None
    lines = listing.splitlines()
    for start, line in enumerate(lines):
        if _RULES_HEADER in line:
            break
    else:
        return None
    commands = []
    first = start + 1
    for line in lines[first:]:
        entry = line.strip()
        if entry.startswith("("):
            entry = entry.partition(")")[2]
        nopasswd = False
        for item in entry.split(","):
            item = item.strip()
            skip = _OPTIONS.match(item).end()
            item = item[skip:]
            tags = _TAGS.match(item)
            if tags:
                for tag in tags.group(0).split(":"):
                    if tag.strip() == "NOPASSWD":
                        nopasswd = True
                    elif tag.strip() == "PASSWD":
                        nopasswd = False
                end = tags.end()
                item = item[end:]
            if nopasswd and item:
                commands.append(item)
    return commands


def _resolved(listed, command):
    """The program sudo runs for *command*: the path `sudo -n -l <command>`
    printed (sudo resolves it with its own secure_path), else the agent's PATH."""
    words = listed.split()
    if words and words[0].startswith("/"):
        return words[0]
    return shutil.which(command)


def _needs_a_password(path, listing):
    """Whether the account's listing proves sudo would ask a password to run
    the program at *path*.

    `sudo -n -l <command>` lists a command a rule allows WITH a password too
    (an admin group's `ALL`), and running it then mails. True only when that
    is certain: the listing shows NOPASSWD entries, every one an absolute path
    to a program, and none is *path*. `ALL`, an alias, a wildcard, a negation
    or a directory (`/usr/sbin/` allows every program in it), which this does
    not expand, no NOPASSWD entry at all (an account sudo does not
    authenticate: root, an exempt group), or a listing it cannot read: False,
    the command is run as before.
    """
    commands = _nopasswd_commands(listing)
    if not commands or path is None:
        return False
    target = os.path.realpath(path)
    for item in commands:
        word = item.split()[0]
        if (
            not word.startswith("/")
            or word.endswith("/")
            or any(ch in word for ch in "*?[\\")
        ):
            return False
        if os.path.realpath(word) == target:
            return False
    return True


def run_checked(args, timeout, retry_interval=REFUSAL_RETRY_INTERVAL, stdout=None):
    """Run `sudo -n *args` unless sudo refuses it, without asking twice.

    Returns (result, refusal). When sudo refuses the call -- the account
    (_account_refusal), the command (`sudo -n -l *args`, or a listing that
    shows it needs a password, _needs_a_password) or the run itself (a rule
    that needs a password), now or earlier under the same policy -- result is
    None and refusal says why, in the `sudo -n <command>: <detail>` form the
    capability reasons use. Otherwise refusal is None and result is the
    command's CompletedProcess (bytes; stdout piped unless *stdout* says
    otherwise), which may have failed on its own. Raises what run_privileged
    raises; nothing is remembered then.
    """
    key = tuple(args)
    fingerprint = policy_fingerprint()
    question_timeout = min(timeout, QUESTION_TIMEOUT)
    for asked in (GATE, key):
        detail = _refusals.recall(asked, retry_interval, fingerprint)
        if detail is not None:
            return None, f"sudo -n {args[0]}: {detail}"
    listing = _refusals.passed(GATE, fingerprint, retry_interval)
    if listing is None:
        detail, listing = _account_refusal(question_timeout, fingerprint)
        _refusals.remember(GATE, detail, fingerprint, listing)
        if detail is not None:
            return None, f"sudo -n {args[0]}: {detail}"
    detail = None
    # A pass is reused until it is due again; only a listing renews it, so a
    # command run every few minutes is still listed again once a day.
    listing_due = _refusals.passed(key, fingerprint, retry_interval) is None
    if listing_due:
        detail, listed = _ask(["-l", *args], question_timeout)
        if detail is not None and any(m in detail for m in REFUSAL_MESSAGES):
            # A listpw other than the default: listing asks a password even for
            # a NOPASSWD command. The run decides (its refusal is kept too).
            detail = None
        if (
            detail is None
            and listing
            and not _is_root()
            and _needs_a_password(_resolved(listed, args[0]), listing)
        ):
            detail = NEEDS_AUTHENTICATION
    if detail is None:
        result = run_privileged(
            ["sudo", "-n", *args],
            timeout=timeout,
            stdout=subprocess.PIPE if stdout is None else stdout,
            stderr=subprocess.PIPE,
            env=get_clean_env(),
        )
        detail = refusal_line(result.returncode, _decode(result.stderr))
    if listing_due or detail is not None:
        _refusals.remember(key, detail, fingerprint)
    if detail is not None:
        return None, f"sudo -n {args[0]}: {detail}"
    return result, None
