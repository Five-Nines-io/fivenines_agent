"""Tests for sudo_refusals: ask sudo only what mails nothing, and never twice.

On Debian/Ubuntu (stock `Defaults mail_badpass`) every `sudo -n` that sudo
refuses mails root, and the capability probes used to repeat each refused call
every one to five minutes. These tests pin the fix: `sudo -n -l` with no
command decides first whether the account can use sudo without a password at
all, a command sudoers does not list is never run, and a refusal -- kept in
the config directory across restarts -- is asked again only once the sudo
policy files change, a recheck resets it, or its retry interval has passed.
"""

import json
import os
import stat
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from fivenines_agent import sudo_refusals
from fivenines_agent.sudo_refusals import GATE, SudoRefusals
from fivenines_agent.sudo_refusals import _in_admin_group as real_in_admin_group

REFUSED = "sudo: a password is required"
NOT_KNOWN = "Sorry, user norule may not run sudo on box."
FP = (("/etc/sudoers", 1, 2, 3, 4),)
OTHER_FP = (("/etc/sudoers", 1, 2, 3, 5),)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes/FIFOs")


class _Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def policy(tmp_path, monkeypatch):
    """A sudoers file, a group file and a sudoers.d directory of our own."""
    sudoers = tmp_path / "sudoers"
    group = tmp_path / "group"
    sudoers_d = tmp_path / "sudoers.d"
    sudoers.write_text("root ALL=(ALL) ALL\n")
    group.write_text("sudo:x:27:\n")
    sudoers_d.mkdir()
    (sudoers_d / "README").write_text("#\n")
    monkeypatch.setattr(sudo_refusals, "POLICY_FILES", (str(sudoers), str(group)))
    monkeypatch.setattr(sudo_refusals, "POLICY_DIR", str(sudoers_d))
    return tmp_path


def _state_file():
    return os.path.join(os.environ["CONFIG_DIR"], sudo_refusals.STATE_FILE)


def _completed(returncode=0, stdout=b"", stderr=b""):
    result = MagicMock(returncode=returncode)
    result.stdout = stdout
    result.stderr = stderr
    return result


# --- refusal_line ---


def test_refusal_line_none_on_success():
    assert sudo_refusals.refusal_line(0, REFUSED) is None


def test_refusal_line_is_the_refusal_not_the_warning_before_it():
    """sudo warns first on a host whose name does not resolve."""
    stderr = "sudo: unable to resolve host box: Name or service not known\n" + REFUSED
    assert sudo_refusals.refusal_line(1, stderr) == REFUSED


def test_refusal_line_none_when_the_command_failed_on_its_own():
    """fail2ban-client with fail2ban stopped: sudo ran it, it failed."""
    assert sudo_refusals.refusal_line(255, "Failed to access socket path") is None


def test_refusal_line_needs_sudo_to_say_it():
    """The command quoting the words is not sudo refusing it."""
    assert sudo_refusals.refusal_line(1, "error: a password is required") is None
    assert sudo_refusals.refusal_line(1, "sudo: unable to resolve host box") is None


# --- policy_fingerprint ---


def test_fingerprint_stable_while_nothing_changes(policy):
    assert sudo_refusals.policy_fingerprint() == sudo_refusals.policy_fingerprint()


@pytest.mark.parametrize(
    "change",
    [
        "add_rule_file",
        "edit_rule_file",
        "touch_rule_file",
        "edit_sudoers",
        "edit_group",
        "remove_rule_file",
    ],
)
def test_fingerprint_changes_with_the_policy(policy, change):
    rule = policy / "sudoers.d" / "fivenines"
    if change != "add_rule_file":
        rule.write_text("fivenines ALL=(ALL) NOPASSWD: /usr/sbin/smartctl\n")
    before = sudo_refusals.policy_fingerprint()
    if change == "add_rule_file":
        rule.write_text("fivenines ALL=(ALL) NOPASSWD: /usr/sbin/smartctl\n")
    elif change == "edit_rule_file":
        rule.write_text("fivenines ALL=(ALL) NOPASSWD: /sbin/mdadm\n")
    elif change == "touch_rule_file":
        # Same content, later modification time.
        st = rule.stat()
        os.utime(rule, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    elif change == "edit_sudoers":
        (policy / "sudoers").write_text("root ALL=(ALL) ALL\n#includedir x\n")
    elif change == "edit_group":
        (policy / "group").write_text("sudo:x:27:fivenines\n")
    else:
        rule.unlink()
    assert sudo_refusals.policy_fingerprint() != before


def test_fingerprint_counts_the_change_time():
    """chmod moves only the change time: a 0640 rule sudo ignored, then fixed
    to 0440, must read as a policy change."""
    stat_before = MagicMock(st_ino=1, st_size=10, st_mtime_ns=5, st_ctime_ns=5)
    chmodded = MagicMock(st_ino=1, st_size=10, st_mtime_ns=5, st_ctime_ns=6)
    with patch.object(sudo_refusals.os, "stat", side_effect=[stat_before, chmodded]):
        assert sudo_refusals._stat_key("/etc/sudoers.d/x") != sudo_refusals._stat_key(
            "/etc/sudoers.d/x"
        )


def test_fingerprint_unreadable_directory_still_fingerprints(monkeypatch, tmp_path):
    """RHEL's 0750 sudoers.d cannot be listed: its own stat still counts."""
    sudoers_d = tmp_path / "sudoers.d"
    sudoers_d.mkdir()
    monkeypatch.setattr(sudo_refusals, "POLICY_FILES", ())
    monkeypatch.setattr(sudo_refusals, "POLICY_DIR", str(sudoers_d))
    with patch.object(sudo_refusals.os, "listdir", side_effect=PermissionError):
        fingerprint = sudo_refusals.policy_fingerprint()
    assert len(fingerprint) == 1
    assert fingerprint[0][0] == str(sudoers_d)
    assert len(fingerprint[0]) == 5


def test_fingerprint_missing_file_is_its_errno(monkeypatch, tmp_path):
    missing = str(tmp_path / "nope")
    monkeypatch.setattr(sudo_refusals, "POLICY_FILES", (missing,))
    monkeypatch.setattr(sudo_refusals, "POLICY_DIR", str(tmp_path / "nodir"))
    fingerprint = sudo_refusals.policy_fingerprint()
    assert fingerprint[0] == (missing, 2)


# --- SudoRefusals ---


def test_recall_none_until_a_refusal_is_remembered():
    refusals = SudoRefusals(clock=_Clock())
    assert refusals.recall(("wg",), 60, FP) is None
    refusals.remember(("wg",), None, FP)
    assert refusals.recall(("wg",), 60, FP) is None


def test_a_refusal_holds_while_nothing_changes():
    clock = _Clock()
    refusals = SudoRefusals(clock=clock)
    refusals.remember(("smartctl", "--version"), REFUSED, FP)
    clock.now += 3599
    assert refusals.recall(("smartctl", "--version"), 3600, FP) == REFUSED
    # Another command is its own key.
    assert refusals.recall(("mdadm", "--version"), 3600, FP) is None


def test_a_refusal_ends_when_its_retry_interval_has_passed():
    clock = _Clock()
    refusals = SudoRefusals(clock=clock)
    refusals.remember(("smartctl",), "refused", FP)
    clock.now += 3600
    assert refusals.recall(("smartctl",), 3600, FP) is None
    # Dropped: it does not come back on the next call either.
    assert refusals.recall(("smartctl",), 3600, FP) is None


def test_a_clock_that_went_back_retries():
    """Wall-clock times outlive the process; a clock stepped back must not
    hold a refusal until it catches up."""
    clock = _Clock()
    refusals = SudoRefusals(clock=clock)
    refusals.remember(("smartctl",), "refused", FP)
    clock.now -= 60
    assert refusals.recall(("smartctl",), 3600, FP) is None


def test_no_retry_interval_never_retries_on_time_alone():
    """A feature that is not enabled: no daily retry, only a policy change."""
    clock = _Clock()
    refusals = SudoRefusals(clock=clock)
    refusals.remember(("fail2ban-client", "status"), "refused", FP)
    clock.now += 10 * 365 * 86400
    assert refusals.recall(("fail2ban-client", "status"), None, FP) == "refused"


def test_a_refusal_ends_when_the_policy_changes():
    refusals = SudoRefusals(clock=_Clock())
    refusals.remember(("smartctl",), "refused", FP)
    assert refusals.recall(("smartctl",), None, OTHER_FP) is None
    assert refusals.recall(("smartctl",), None, FP) is None


def test_passed_holds_under_the_same_policy_only():
    refusals = SudoRefusals(clock=_Clock())
    assert refusals.passed(GATE, FP) is None
    refusals.remember(GATE, None, FP)
    assert refusals.passed(GATE, FP) == ""
    refusals.remember(GATE, None, FP, "User x may run the following commands")
    assert refusals.passed(GATE, FP) == "User x may run the following commands"
    assert refusals.passed(GATE, OTHER_FP) is None
    # A refusal ends the pass.
    refusals.remember(GATE, REFUSED, FP)
    assert refusals.passed(GATE, FP) is None


def test_allowed_after_a_refusal_drops_it():
    refusals = SudoRefusals(clock=_Clock())
    refusals.remember(("smartctl",), "refused", FP)
    refusals.remember(("smartctl",), None, OTHER_FP)
    assert refusals.recall(("smartctl",), None, FP) is None
    with open(_state_file()) as f:
        assert json.load(f) == []


def test_reset_forgets_every_answer():
    refusals = SudoRefusals(clock=_Clock())
    refusals.remember(("smartctl",), "refused", FP)
    refusals.remember(GATE, None, FP)
    refusals.reset()
    assert refusals.recall(("smartctl",), None, FP) is None
    assert refusals.passed(GATE, FP) is None
    # Persisted too: a restart after a recheck does not bring it back.
    assert SudoRefusals().recall(("smartctl",), None, FP) is None


def test_module_reset_resets_the_process_memory():
    sudo_refusals._refusals.remember(("smartctl",), "refused", FP)
    sudo_refusals.reset()
    assert sudo_refusals._refusals.recall(("smartctl",), None, FP) is None


# --- the state file ---


def test_a_restart_remembers_the_refusals():
    """An update or a reboot restarts the agent: on a sudo older than
    1.9.16p1 asking again would mail root again."""
    clock = _Clock()
    SudoRefusals(clock=clock).remember(("smartctl", "--version"), REFUSED, FP)
    clock.now += 60
    restarted = SudoRefusals(clock=clock)
    assert restarted.recall(("smartctl", "--version"), 3600, FP) == REFUSED
    assert restarted.recall(("smartctl", "--version"), 3600, OTHER_FP) is None
    # The drop is persisted as well.
    again = SudoRefusals(clock=clock)
    assert again.recall(("smartctl", "--version"), 3600, FP) is None


def test_a_pass_is_not_persisted():
    SudoRefusals().remember(GATE, None, FP)
    assert SudoRefusals().passed(GATE, FP) is None


def test_the_state_file_round_trips_a_real_fingerprint(policy):
    SudoRefusals().remember(GATE, REFUSED, sudo_refusals.policy_fingerprint())
    restarted = SudoRefusals()
    assert restarted.recall(GATE, None, sudo_refusals.policy_fingerprint()) == REFUSED


@posix_only
def test_the_state_file_is_owner_only():
    path = _state_file()
    with open(path, "w") as f:
        f.write("[]")
    os.chmod(path, 0o644)
    SudoRefusals().remember(("smartctl",), REFUSED, FP)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b'{"argv": ["smartctl"]}',
        b'[{"argv": ["smartctl"]}]',
        b'[{"argv": 5, "fingerprint": [], "refused_at": 1, "detail": "x"}]',
        b'[{"argv": ["x"], "fingerprint": [], "refused_at": "soon", "detail": "x"}]',
    ],
    ids=["not-json", "not-a-list", "missing-keys", "bad-argv", "bad-time"],
)
def test_an_unreadable_state_file_is_no_refusal(content):
    with open(_state_file(), "wb") as f:
        f.write(content)
    assert SudoRefusals().recall(("smartctl",), None, FP) is None


def test_an_oversized_state_file_is_not_read():
    entry = {"argv": ["smartctl"], "fingerprint": [], "refused_at": 1, "detail": "x"}
    with open(_state_file(), "w") as f:
        json.dump([entry], f)
        f.write(" " * sudo_refusals.MAX_STATE_BYTES)
    assert SudoRefusals().recall(("smartctl",), None, ()) is None


def test_a_state_path_that_is_not_a_file_is_not_read():
    os.mkdir(_state_file())
    assert SudoRefusals().recall(("smartctl",), None, FP) is None


@posix_only
def test_a_fifo_state_file_never_blocks():
    """open() on a FIFO blocks without O_NONBLOCK, and read() would after it:
    the probes run on the watchdog-bounded collection loop."""
    os.mkfifo(_state_file())
    assert SudoRefusals().recall(("smartctl",), None, FP) is None


def test_a_state_file_that_cannot_be_opened_is_no_refusal():
    with patch.object(sudo_refusals.os, "open", side_effect=PermissionError("denied")):
        assert SudoRefusals().recall(("smartctl",), None, FP) is None


def test_a_state_file_that_cannot_be_written_keeps_the_memory(monkeypatch, tmp_path):
    monkeypatch.setenv("CONFIG_DIR", str(tmp_path / "missing"))
    refusals = SudoRefusals()
    with patch("fivenines_agent.sudo_refusals.log") as log:
        refusals.remember(("smartctl",), REFUSED, FP)
    assert refusals.recall(("smartctl",), None, FP) == REFUSED
    assert "cannot save" in log.call_args.args[0]


# --- run_checked ---


def test_run_checked_asks_the_account_then_the_command_then_runs(policy):
    calls = []

    def fake(argv, **kwargs):
        calls.append((argv, kwargs))
        return _completed(0, b"smartctl 7.4\n")

    with patch.object(sudo_refusals, "run_privileged", side_effect=fake):
        result, refusal = sudo_refusals.run_checked(
            ["smartctl", "--version"], timeout=7
        )

    assert refusal is None
    assert result.stdout == b"smartctl 7.4\n"
    assert [argv for argv, _ in calls] == [
        ["sudo", "-n", "-v"],
        ["sudo", "-n", "-l", "smartctl", "--version"],
        ["sudo", "-n", "smartctl", "--version"],
    ]
    for _, kwargs in calls:
        assert kwargs["timeout"] == 7
        assert kwargs["stderr"] == subprocess.PIPE
        assert kwargs["env"]["LC_ALL"] == "C"
    assert calls[0][1]["stdout"] == subprocess.PIPE
    assert calls[1][1]["stdout"] == subprocess.PIPE
    assert calls[2][1]["stdout"] == subprocess.PIPE


def test_run_checked_asks_the_account_once_per_policy(policy):
    with patch.object(
        sudo_refusals, "run_privileged", return_value=_completed(0)
    ) as run:
        sudo_refusals.run_checked(["smartctl", "--version"], timeout=5)
        sudo_refusals.run_checked(["mdadm", "--version"], timeout=5)
        (policy / "sudoers.d" / "fivenines").write_text("rule\n")
        sudo_refusals.run_checked(["mdadm", "--version"], timeout=5)
    asked = [call.args[0] for call in run.call_args_list]
    assert asked.count(["sudo", "-n", "-v"]) == 2
    assert len(asked) == 3 + 2 + 3


def test_run_checked_an_account_with_password_rules_asks_no_command(policy):
    """Rules that all need a password: -v is refused for a password, so the
    listing decides; refused too, no command is asked, until the policy
    changes."""
    refused = _completed(1, stderr=REFUSED.encode())
    with patch.object(sudo_refusals, "run_privileged", return_value=refused) as run:
        first = sudo_refusals.run_checked(["smartctl", "--version"], timeout=5)
        others = [
            sudo_refusals.run_checked(argv, timeout=5)
            for argv in (["mdadm", "--version"], ["fail2ban-client", "status"])
        ]

    assert first == (None, "sudo -n smartctl: " + REFUSED)
    assert others == [
        (None, "sudo -n mdadm: " + REFUSED),
        (None, "sudo -n fail2ban-client: " + REFUSED),
    ]
    assert [call.args[0] for call in run.call_args_list] == [
        ["sudo", "-n", "-v"],
        ["sudo", "-n", "-l"],
    ]


def test_run_checked_an_account_sudoers_does_not_know_asks_only_v(policy):
    """The default install: `sudo -n -v` mails nothing for it and names it,
    while `sudo -n -l` would mail on a sudo older than 1.9.16p1."""
    not_known = _completed(1, stderr=NOT_KNOWN.encode())
    with patch.object(sudo_refusals, "run_privileged", return_value=not_known) as run:
        assert sudo_refusals.run_checked(["smartctl", "--version"], timeout=5) == (
            None,
            "sudo -n smartctl: " + NOT_KNOWN,
        )
        sudo_refusals.run_checked(["mdadm", "--version"], timeout=5)
    assert [call.args[0] for call in run.call_args_list] == [["sudo", "-n", "-v"]]


def test_run_checked_an_admin_group_member_is_asked_l_first(policy, monkeypatch):
    """A member of sudo or wheel has a rule that needs a password: -v would
    mail; the listing is free once one of its rules is NOPASSWD (the README's
    user installation)."""
    monkeypatch.setattr(sudo_refusals, "_in_admin_group", lambda: True)
    with patch.object(
        sudo_refusals, "run_privileged", return_value=_completed(0)
    ) as run:
        sudo_refusals.run_checked(["smartctl", "--version"], timeout=5)
    assert [call.args[0] for call in run.call_args_list] == [
        ["sudo", "-n", "-l"],
        ["sudo", "-n", "-l", "smartctl", "--version"],
        ["sudo", "-n", "smartctl", "--version"],
    ]


def test_run_checked_never_runs_what_sudoers_does_not_list(policy):
    """The README case: a NOPASSWD rule for smartctl, none for fail2ban. The
    listings need no password, so no authentication fails and nothing mails;
    the command itself is never run, and the next probe asks nothing."""
    not_listed = _completed(
        1,
        stderr=b"sudo: unable to resolve host box\nSorry, user fivenines is not allowed\n",
    )
    with patch.object(
        sudo_refusals, "run_privileged", side_effect=[_completed(0), not_listed]
    ) as run:
        first = sudo_refusals.run_checked(["fail2ban-client", "status"], timeout=5)
        second = sudo_refusals.run_checked(["fail2ban-client", "status"], timeout=5)

    reason = "sudo -n fail2ban-client: Sorry, user fivenines is not allowed"
    assert first == (None, reason)
    assert second == (None, reason)
    assert run.call_count == 2
    assert run.call_args.args[0] == ["sudo", "-n", "-l", "fail2ban-client", "status"]


def test_run_checked_silent_listing_refusal_has_a_reason(policy):
    with patch.object(
        sudo_refusals, "run_privileged", side_effect=[_completed(0), _completed(1)]
    ):
        assert sudo_refusals.run_checked(["mdadm", "--version"], timeout=5) == (
            None,
            "sudo -n mdadm: not allowed by sudoers",
        )


def test_run_checked_remembers_a_run_sudo_refused(policy):
    """Listed, but the rule needs a password: the run itself is refused (and
    mails on Debian). It is a refusal, and it is not sent again."""
    responses = [_completed(0), _completed(0), _completed(1, stderr=REFUSED.encode())]
    with patch.object(sudo_refusals, "run_privileged", side_effect=responses) as run:
        first = sudo_refusals.run_checked(["fail2ban-client", "status"], 5)
        again = sudo_refusals.run_checked(["fail2ban-client", "status"], 5)

    assert first == again == (None, "sudo -n fail2ban-client: " + REFUSED)
    assert run.call_count == 3


def test_run_checked_remembers_a_run_sudo_rs_refused(policy):
    """sudo-rs words it its own way."""
    refused = b"sudo: interactive authentication is required"
    responses = [_completed(0), _completed(0), _completed(1, stderr=refused)]
    with patch.object(sudo_refusals, "run_privileged", side_effect=responses):
        assert sudo_refusals.run_checked(["fail2ban-client", "status"], 5) == (
            None,
            "sudo -n fail2ban-client: sudo: interactive authentication is required",
        )


def test_run_checked_retries_a_command_that_failed_on_its_own(policy):
    """fail2ban stopped: sudo ran the command, so the next probe runs it again."""
    failed = _completed(255, stderr=b"Failed to access socket path")
    responses = [_completed(0), _completed(0), failed, _completed(0), failed]
    with patch.object(sudo_refusals, "run_privileged", side_effect=responses) as run:
        sudo_refusals.run_checked(["fail2ban-client", "status"], 5)
        result, refusal = sudo_refusals.run_checked(["fail2ban-client", "status"], 5)
    assert refusal is None
    assert result is failed
    assert run.call_count == 5


def test_run_checked_passes_stdout_through(policy):
    """wg's dump is key material: the probe sends it to DEVNULL."""
    with patch.object(
        sudo_refusals, "run_privileged", return_value=_completed(0)
    ) as run:
        sudo_refusals.run_checked(
            ["wg", "show", "all", "dump"], timeout=10, stdout=subprocess.DEVNULL
        )
    assert run.call_args_list[-1].kwargs["stdout"] == subprocess.DEVNULL


def test_run_checked_retry_interval_reaches_recall(policy):
    with patch.object(sudo_refusals._refusals, "recall", return_value="held") as recall:
        assert sudo_refusals.run_checked(["smartctl"], 5, retry_interval=None) == (
            None,
            "sudo -n smartctl: held",
        )
    assert recall.call_args.args[:2] == (GATE, None)
    with patch.object(sudo_refusals._refusals, "recall", return_value="held") as recall:
        sudo_refusals.run_checked(["smartctl"], 5)
    assert recall.call_args.args[:2] == (GATE, sudo_refusals.REFUSAL_RETRY_INTERVAL)


def test_run_checked_remembers_nothing_when_sudo_times_out(policy):
    with patch.object(
        sudo_refusals,
        "run_privileged",
        side_effect=subprocess.TimeoutExpired(["sudo"], 5),
    ):
        with pytest.raises(subprocess.TimeoutExpired):
            sudo_refusals.run_checked(["smartctl"], 5)
    with patch.object(
        sudo_refusals, "run_privileged", return_value=_completed(0)
    ) as run:
        sudo_refusals.run_checked(["smartctl"], 5)
    assert run.call_count == 3


# --- _in_admin_group ---


class _Group:
    def __init__(self, name):
        self.gr_name = name


@pytest.mark.skipif(sys.platform == "win32", reason="grp is Unix-only")
@pytest.mark.parametrize(
    "groups, expected",
    [
        ({1000: "paseo", 27: "sudo"}, True),
        ({1000: "paseo", 10: "wheel"}, True),
        ({1000: "paseo", 4: "adm"}, False),
        ({1000: "paseo"}, False),
    ],
)
def test_in_admin_group_reads_the_process_groups(groups, expected):
    import grp

    def getgrgid(gid):
        if gid not in groups:
            raise KeyError(gid)
        return _Group(groups[gid])

    with patch.object(
        sudo_refusals.os, "getgroups", return_value=[*groups, 999]
    ), patch.object(sudo_refusals.os, "getegid", return_value=1000), patch.object(
        grp, "getgrgid", side_effect=getgrgid
    ):
        assert real_in_admin_group() is expected


# --- an account with rules that need a password (_needs_a_password) ---

ALICE = """Matching Defaults entries for alice on box:
    env_reset, mail_badpass, secure_path=/usr/sbin\\:/usr/bin, use_pty

User alice may run the following commands on box:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /usr/sbin/smartctl, /sbin/mdadm
    (root) NOPASSWD: NOLOG_OUTPUT: /usr/bin/wg show all dump
    (root) /usr/bin/journalctl, NOPASSWD: /usr/bin/uptime, PASSWD: /usr/bin/id
"""


@pytest.fixture
def tools(monkeypatch, tmp_path):
    """Each probed tool at a path of its own; /sbin/mdadm resolves to one."""
    paths = {}
    for name in ("smartctl", "mdadm", "wg", "fail2ban-client", "nvme", "uptime", "id"):
        path = tmp_path / name
        path.write_text("")
        paths[name] = str(path)
    real = {
        "/usr/sbin/smartctl": paths["smartctl"],
        "/sbin/mdadm": paths["mdadm"],
        "/usr/bin/wg": paths["wg"],
        "/usr/bin/uptime": paths["uptime"],
        "/usr/bin/id": paths["id"],
    }
    monkeypatch.setattr(sudo_refusals.shutil, "which", paths.get)
    real_realpath = os.path.realpath
    monkeypatch.setattr(
        sudo_refusals.os.path, "realpath", lambda p: real_realpath(real.get(p, p))
    )
    return paths


def test_nopasswd_commands_reads_tags_per_item():
    assert sudo_refusals._nopasswd_commands(ALICE) == [
        "/usr/sbin/smartctl",
        "/sbin/mdadm",
        "/usr/bin/wg show all dump",
        "/usr/bin/uptime",
    ]


@pytest.mark.parametrize(
    "listing",
    [
        "Matching Defaults entries for alice on box:\n    !authenticate\n" + ALICE,
        "alice may do things:\n    NOPASSWD: /usr/sbin/smartctl\n",
    ],
    ids=["no-authenticate", "unknown-format"],
)
def test_nopasswd_commands_none_when_it_cannot_tell(listing):
    assert sudo_refusals._nopasswd_commands(listing) is None


@pytest.mark.parametrize(
    "command, needs",
    [
        ("smartctl", False),
        ("mdadm", False),  # /sbin/mdadm resolves to the same file
        ("wg", False),
        ("uptime", False),
        ("fail2ban-client", True),
        ("nvme", True),
        ("id", True),  # PASSWD: undoes the NOPASSWD before it
    ],
)
def test_needs_a_password_only_when_no_nopasswd_rule_names_it(tools, command, needs):
    assert sudo_refusals._needs_a_password(command, ALICE) is needs


@pytest.mark.parametrize(
    "rule",
    [
        "(ALL) NOPASSWD: ALL",
        "(ALL) NOPASSWD: SMART_TOOLS",
        "(ALL) NOPASSWD: /usr/sbin/*",
        "(ALL) NOPASSWD: !/usr/bin/su",
    ],
    ids=["all", "alias", "wildcard", "negation"],
)
def test_needs_a_password_never_guesses(tools, rule):
    """ALL, an alias, a wildcard or a negation could cover the command: run
    it, as before, rather than call a working tool unavailable."""
    listing = "User alice may run the following commands on box:\n    " + rule + "\n"
    assert sudo_refusals._needs_a_password("fail2ban-client", listing) is False


def test_needs_a_password_never_guesses_a_command_not_on_path(tools, monkeypatch):
    monkeypatch.setattr(sudo_refusals.shutil, "which", lambda _name: None)
    assert sudo_refusals._needs_a_password("fail2ban-client", ALICE) is False


def test_run_checked_an_admin_group_member_with_a_nopasswd_rule(
    policy, tools, monkeypatch
):
    """The README's user installation: a sudo-group member with a NOPASSWD
    rule for smartctl. `sudo -n -l fail2ban-client status` says yes (the
    group's ALL, with a password), and running it would mail: the listing
    shows no NOPASSWD rule for it, so it is refused without asking."""
    monkeypatch.setattr(sudo_refusals, "_in_admin_group", lambda: True)
    with patch.object(
        sudo_refusals, "run_privileged", return_value=_completed(0, ALICE.encode())
    ) as run:
        assert sudo_refusals.run_checked(["fail2ban-client", "status"], timeout=5) == (
            None,
            "sudo -n fail2ban-client: " + sudo_refusals.NEEDS_AUTHENTICATION,
        )
        result, refusal = sudo_refusals.run_checked(
            ["smartctl", "--version"], timeout=5
        )
        assert (
            sudo_refusals.run_checked(["fail2ban-client", "status"], timeout=5)[0]
            is None
        )

    assert refusal is None
    assert [call.args[0] for call in run.call_args_list] == [
        ["sudo", "-n", "-l"],
        ["sudo", "-n", "-l", "smartctl", "--version"],
        ["sudo", "-n", "smartctl", "--version"],
    ]
