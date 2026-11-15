"""Tests for sudo_refusals: ask `sudo -n -l` first, and never repeat a refusal.

On Debian/Ubuntu (stock `Defaults mail_badpass`) every `sudo -n` that sudo
refuses mails root, and the capability probes used to repeat each refused call
every one to five minutes. These tests pin the two halves of the fix: a
command sudoers does not list is never run, and a refusal is sent again only
once the sudo policy files change, a recheck resets it, or its retry interval
has passed.
"""

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from fivenines_agent import sudo_refusals
from fivenines_agent.sudo_refusals import SudoRefusals

REFUSED = "sudo: a password is required"


class _Clock:
    def __init__(self):
        self.now = 1000.0

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
    stat = MagicMock(st_ino=1, st_size=10, st_mtime_ns=5, st_ctime_ns=5)
    chmodded = MagicMock(st_ino=1, st_size=10, st_mtime_ns=5, st_ctime_ns=6)
    with patch.object(sudo_refusals.os, "stat", side_effect=[stat, chmodded]):
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


def test_recall_none_until_a_refusal_is_remembered(policy):
    refusals = SudoRefusals(clock=_Clock())
    assert refusals.recall(("wg",), 60) is None
    refusals.remember(("wg",), None)
    assert refusals.recall(("wg",), 60) is None


def test_a_refusal_holds_while_nothing_changes(policy):
    clock = _Clock()
    refusals = SudoRefusals(clock=clock)
    assert refusals.recall(("smartctl", "--version"), 3600) is None
    refusals.remember(("smartctl", "--version"), "sudo -n smartctl: " + REFUSED)
    clock.now += 3599
    assert refusals.recall(("smartctl", "--version"), 3600) == (
        "sudo -n smartctl: " + REFUSED
    )
    # Another command is its own key.
    assert refusals.recall(("mdadm", "--version"), 3600) is None


def test_a_refusal_ends_when_its_retry_interval_has_passed(policy):
    clock = _Clock()
    refusals = SudoRefusals(clock=clock)
    refusals.recall(("smartctl",), 3600)
    refusals.remember(("smartctl",), "refused")
    clock.now += 3600
    assert refusals.recall(("smartctl",), 3600) is None
    # Dropped: it does not come back on the next call either.
    assert refusals.recall(("smartctl",), 3600) is None


def test_no_retry_interval_never_retries_on_time_alone(policy):
    """A feature that is not enabled: no daily retry, only a policy change."""
    clock = _Clock()
    refusals = SudoRefusals(clock=clock)
    refusals.recall(("fail2ban-client", "status"), None)
    refusals.remember(("fail2ban-client", "status"), "refused")
    clock.now += 10 * 365 * 86400
    assert refusals.recall(("fail2ban-client", "status"), None) == "refused"


def test_a_refusal_ends_when_the_policy_changes(policy):
    refusals = SudoRefusals(clock=_Clock())
    refusals.recall(("smartctl",), None)
    refusals.remember(("smartctl",), "refused")
    (policy / "sudoers.d" / "fivenines").write_text("rule\n")
    assert refusals.recall(("smartctl",), None) is None


def test_a_rule_saved_during_the_call_is_still_a_change(policy):
    """The policy is read before the call, so a rule saved while sudo was
    refusing still makes the next recall retry."""
    refusals = SudoRefusals(clock=_Clock())
    assert refusals.recall(("smartctl",), None) is None
    (policy / "sudoers.d" / "fivenines").write_text("rule\n")  # mid-call
    refusals.remember(("smartctl",), "refused")
    assert refusals.recall(("smartctl",), None) is None


def test_remember_without_recall_reads_the_policy_now(policy):
    refusals = SudoRefusals(clock=_Clock())
    refusals.remember(("smartctl",), "refused")
    assert refusals.recall(("smartctl",), None) == "refused"


def test_reset_forgets_every_refusal(policy):
    refusals = SudoRefusals(clock=_Clock())
    refusals.recall(("smartctl",), None)
    refusals.remember(("smartctl",), "refused")
    refusals.reset()
    assert refusals.recall(("smartctl",), None) is None


def test_module_reset_resets_the_process_memory(policy):
    sudo_refusals._refusals.remember(("smartctl",), "refused")
    sudo_refusals.reset()
    assert sudo_refusals._refusals.recall(("smartctl",), None) is None


# --- run_checked ---


def test_run_checked_lists_then_runs(policy):
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
        ["sudo", "-n", "-l", "smartctl", "--version"],
        ["sudo", "-n", "smartctl", "--version"],
    ]
    for _, kwargs in calls:
        assert kwargs["timeout"] == 7
        assert kwargs["stderr"] == subprocess.PIPE
        assert kwargs["env"]["LC_ALL"] == "C"
    assert calls[0][1]["stdout"] == subprocess.DEVNULL
    assert calls[1][1]["stdout"] == subprocess.PIPE


def test_run_checked_passes_stdout_through(policy):
    """wg's dump is key material: the probe sends it to DEVNULL."""
    with patch.object(
        sudo_refusals, "run_privileged", return_value=_completed(0)
    ) as run:
        sudo_refusals.run_checked(
            ["wg", "show", "all", "dump"], timeout=10, stdout=subprocess.DEVNULL
        )
    assert run.call_args_list[1].kwargs["stdout"] == subprocess.DEVNULL


def test_run_checked_never_runs_what_sudoers_does_not_list(policy):
    """The README case: a NOPASSWD rule for smartctl, none for fail2ban. The
    listing needs no password, so no authentication fails and nothing mails;
    the command itself is never run, and the next probe asks nothing."""
    listed = _completed(
        1,
        stderr=b"sudo: unable to resolve host box\nSorry, user fivenines is not allowed\n",
    )
    with patch.object(sudo_refusals, "run_privileged", return_value=listed) as run:
        first = sudo_refusals.run_checked(["fail2ban-client", "status"], timeout=5)
        second = sudo_refusals.run_checked(["fail2ban-client", "status"], timeout=5)

    reason = "sudo -n fail2ban-client: Sorry, user fivenines is not allowed"
    assert first == (None, reason)
    assert second == (None, reason)
    assert run.call_count == 1
    assert run.call_args.args[0] == ["sudo", "-n", "-l", "fail2ban-client", "status"]


def test_run_checked_silent_listing_refusal_has_a_reason(policy):
    with patch.object(sudo_refusals, "run_privileged", return_value=_completed(1)):
        assert sudo_refusals.run_checked(["mdadm", "--version"], timeout=5) == (
            None,
            "sudo -n mdadm: not allowed by sudoers",
        )


def test_run_checked_remembers_a_run_sudo_refused(policy):
    """Listed, but the rule needs a password: the run itself is refused (and
    mails on Debian). It is not sent again."""
    responses = [_completed(0), _completed(1, stderr=REFUSED.encode())]
    with patch.object(sudo_refusals, "run_privileged", side_effect=responses) as run:
        result, refusal = sudo_refusals.run_checked(["fail2ban-client", "status"], 5)
        again = sudo_refusals.run_checked(["fail2ban-client", "status"], 5)

    assert refusal is None
    assert result.returncode == 1
    assert again == (None, "sudo -n fail2ban-client: " + REFUSED)
    assert run.call_count == 2


def test_run_checked_retries_a_command_that_failed_on_its_own(policy):
    """fail2ban stopped: sudo ran the command, so the next probe runs it again."""
    failed = _completed(255, stderr=b"Failed to access socket path")
    responses = [_completed(0), failed, _completed(0), failed]
    with patch.object(sudo_refusals, "run_privileged", side_effect=responses) as run:
        sudo_refusals.run_checked(["fail2ban-client", "status"], 5)
        result, refusal = sudo_refusals.run_checked(["fail2ban-client", "status"], 5)
    assert refusal is None
    assert result is failed
    assert run.call_count == 4


def test_run_checked_retry_interval_reaches_recall(policy):
    with patch.object(sudo_refusals._refusals, "recall", return_value="held") as recall:
        assert sudo_refusals.run_checked(["smartctl"], 5, retry_interval=None) == (
            None,
            "held",
        )
    recall.assert_called_once_with(("smartctl",), None)
    with patch.object(sudo_refusals._refusals, "recall", return_value="held") as recall:
        sudo_refusals.run_checked(["smartctl"], 5)
    recall.assert_called_once_with(("smartctl",), sudo_refusals.REFUSAL_RETRY_INTERVAL)


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
    assert run.call_count == 2
