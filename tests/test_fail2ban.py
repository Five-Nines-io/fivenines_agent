"""Tests for the fail2ban collector.

Pins the payload contract around the None/[] split in get_jail_list:
{} = fail2ban unavailable, {"version":..., "jails": []} = zero jails --
without a separate availability probe (which used to run the exact same
`fail2ban-client status` command a second time every tick).
"""

from unittest.mock import MagicMock, patch

import fivenines_agent.fail2ban as fail2ban_module
from fivenines_agent.fail2ban import (
    fail2ban_metrics,
    get_fail2ban_version,
    get_jail_list,
    get_jail_status,
)

STATUS_OUT = (
    "Status\n"
    "|- Number of jail:      2\n"
    "`- Jail list:   sshd, apache-auth\n"
)

JAIL_OUT = (
    "Status for the jail: sshd\n"
    "|- Filter\n"
    "|  |- Currently failed: 3\n"
    "|  |- Total failed:     147\n"
    "|  `- File list:        /var/log/auth.log\n"
    "`- Actions\n"
    "   |- Currently banned: 2\n"
    "   |- Total banned:     45\n"
    "   `- Banned IP list:   1.2.3.4 5.6.7.8\n"
)


def _proc(returncode=0, stdout="", stderr=""):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def _reset_cache():
    fail2ban_module._fail2ban_cache["timestamp"] = 0
    fail2ban_module._fail2ban_cache["data"] = {}
    fail2ban_module._version_cache = None


# --- get_jail_list: the None/[]/list contract ------------------------------


def test_jail_list_none_when_client_fails():
    with patch.object(
        fail2ban_module.subprocess, "run", return_value=_proc(1, "", "denied")
    ):
        assert get_jail_list() is None


def test_jail_list_none_on_exception():
    with patch.object(
        fail2ban_module.subprocess, "run", side_effect=OSError("no fork")
    ):
        assert get_jail_list() is None


def test_jail_list_empty_when_no_jails():
    with patch.object(
        fail2ban_module.subprocess,
        "run",
        return_value=_proc(0, "Status\n`- Jail list:\n"),
    ):
        assert get_jail_list() == []


def test_jail_list_parses_names():
    with patch.object(
        fail2ban_module.subprocess, "run", return_value=_proc(0, STATUS_OUT)
    ):
        assert get_jail_list() == ["sshd", "apache-auth"]


# --- get_fail2ban_version: process cache -----------------------------------


def test_version_is_cached_after_first_success():
    _reset_cache()
    with patch.object(
        fail2ban_module.subprocess, "run", return_value=_proc(0, "Fail2Ban v0.11.2")
    ) as run:
        assert get_fail2ban_version() == "0.11.2"
        assert get_fail2ban_version() == "0.11.2"
    run.assert_called_once()  # second read served from the process cache


def test_version_unparseable_output_kept_verbatim():
    _reset_cache()
    with patch.object(
        fail2ban_module.subprocess, "run", return_value=_proc(0, "weird")
    ):
        assert get_fail2ban_version() == "weird"


def test_version_failure_not_cached():
    _reset_cache()
    with patch.object(
        fail2ban_module.subprocess, "run", side_effect=OSError("boom")
    ):
        assert get_fail2ban_version() == "unknown"
    with patch.object(
        fail2ban_module.subprocess, "run", return_value=_proc(0, "Fail2Ban v1.0.2")
    ):
        assert get_fail2ban_version() == "1.0.2"  # retried, not stuck on unknown


# --- get_jail_status --------------------------------------------------------


def test_jail_status_parses_counters_and_ips():
    with patch.object(
        fail2ban_module.subprocess, "run", return_value=_proc(0, JAIL_OUT)
    ):
        status = get_jail_status("sshd")
    assert status == {
        "name": "sshd",
        "currently_failed": 3,
        "total_failed": 147,
        "currently_banned": 2,
        "total_banned": 45,
        "banned_ips": ["1.2.3.4", "5.6.7.8"],
    }


def test_jail_status_none_on_failure():
    with patch.object(
        fail2ban_module.subprocess, "run", return_value=_proc(1, "", "denied")
    ):
        assert get_jail_status("sshd") is None


# --- fail2ban_metrics: payload contract ------------------------------------


def test_metrics_unavailable_is_empty_dict():
    _reset_cache()
    with patch.object(fail2ban_module, "get_jail_list", return_value=None):
        assert fail2ban_metrics() == {}


def test_metrics_zero_jails_keeps_version_and_empty_list():
    _reset_cache()
    with patch.object(fail2ban_module, "get_jail_list", return_value=[]), patch.object(
        fail2ban_module, "get_fail2ban_version", return_value="0.11.2"
    ):
        assert fail2ban_metrics() == {"version": "0.11.2", "jails": []}


def test_metrics_collects_each_jail_and_skips_failures():
    _reset_cache()
    statuses = {"sshd": {"name": "sshd"}, "broken": None}
    with patch.object(
        fail2ban_module, "get_jail_list", return_value=["sshd", "broken"]
    ), patch.object(
        fail2ban_module, "get_jail_status", side_effect=lambda j: statuses[j]
    ), patch.object(
        fail2ban_module, "get_fail2ban_version", return_value="0.11.2"
    ):
        assert fail2ban_metrics() == {
            "version": "0.11.2",
            "jails": [{"name": "sshd"}],
        }


def test_metrics_cached_within_ttl():
    _reset_cache()
    with patch.object(
        fail2ban_module, "get_jail_list", return_value=None
    ) as jail_list:
        fail2ban_metrics()
        fail2ban_metrics()
    jail_list.assert_called_once()  # second call inside the 60s TTL


# --- get_jail_status: malformed counters and a failed call -----------------


def test_jail_status_unparseable_counters_keep_zero_and_parse_the_rest():
    """A counter that is not an integer keeps its 0 default instead of
    failing the jail: the other counters and the banned IPs still ship.

    The 0 pins TODAY's behaviour, not the contract: an unparseable counter is
    unknown, and 0 reads as "nothing banned" (TODOS.md). A fix that ships
    None for it must change this test."""
    garbled = (
        "Status for the jail: sshd\n"
        "|- Filter\n"
        "|  |- Currently failed: n/a\n"
        "|  |- Total failed:     lots\n"
        "|  `- File list:        /var/log/auth.log\n"
        "`- Actions\n"
        "   |- Currently banned: ?\n"
        "   |- Total banned:     12x\n"
        "   `- Banned IP list:   203.0.113.7\n"
    )
    with patch.object(
        fail2ban_module, "run_privileged", return_value=_proc(0, garbled)
    ) as run:
        status = get_jail_status("sshd")
    assert status == {
        "name": "sshd",
        "currently_failed": 0,
        "total_failed": 0,
        "currently_banned": 0,
        "total_banned": 0,
        "banned_ips": ["203.0.113.7"],
    }
    # Non-interactive sudo, the jail name as its own argv element.
    assert run.call_args.args[0] == [
        "sudo",
        "-n",
        "fail2ban-client",
        "status",
        "sshd",
    ]


def test_jail_status_empty_banned_list_stays_empty():
    """`Banned IP list:` with nothing after it is zero bans, not a [""] entry."""
    out = JAIL_OUT.replace("1.2.3.4 5.6.7.8", "")
    with patch.object(fail2ban_module, "run_privileged", return_value=_proc(0, out)):
        status = get_jail_status("sshd")
    assert status["banned_ips"] == []
    assert status["total_banned"] == 45


def test_jail_status_none_and_logged_when_call_raises():
    """A sudo call that raises (here: run_privileged's TimeoutExpired for a
    wedged sudoers backend) is a per-jail None with an error line, never an
    exception out of the collector."""
    timeout = fail2ban_module.subprocess.TimeoutExpired(
        cmd=["sudo", "-n", "fail2ban-client", "status", "sshd"], timeout=12
    )
    with patch.object(
        fail2ban_module, "run_privileged", side_effect=timeout
    ), patch.object(fail2ban_module, "log") as log:
        assert get_jail_status("sshd") is None
    log.assert_called_once()
    message, level = log.call_args.args
    assert level == "error"
    assert "sshd" in message
