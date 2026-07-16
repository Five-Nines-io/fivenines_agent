"""Tests for the journald read-access capability probe (_can_read_journal).

Mirrors how the log collector reads the journal: a trivial `journalctl -n 0`.
Constructed via __new__ so we exercise only the probe, not the full _probe_all.
"""

import subprocess
from unittest.mock import MagicMock, patch

from fivenines_agent import permissions
from fivenines_agent.permissions import PermissionProbe


def _probe():
    p = PermissionProbe.__new__(PermissionProbe)
    p._current_reason = None
    return p


def test_journald_false_when_journalctl_missing():
    with patch.object(permissions.shutil, "which", return_value=None):
        p = _probe()
        assert p._can_read_journal() is False
        assert "not found" in p._current_reason


def test_journald_true_when_readable():
    with patch.object(
        permissions.shutil, "which", return_value="/usr/bin/journalctl"
    ), patch.object(
        permissions.subprocess, "run", return_value=MagicMock(returncode=0)
    ) as run:
        assert _probe()._can_read_journal() is True
    # bounded subprocess: clean env + timeout (the two learnings).
    _, kwargs = run.call_args
    assert kwargs["timeout"] == 5
    assert "env" in kwargs


def test_journald_false_on_nonzero_exit():
    with patch.object(
        permissions.shutil, "which", return_value="/usr/bin/journalctl"
    ), patch.object(
        permissions.subprocess, "run", return_value=MagicMock(returncode=1)
    ):
        p = _probe()
        assert p._can_read_journal() is False
        assert "systemd-journal" in p._current_reason


def test_journald_false_on_timeout():
    with patch.object(
        permissions.shutil, "which", return_value="/usr/bin/journalctl"
    ), patch.object(
        permissions.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired("journalctl", 5),
    ):
        assert _probe()._can_read_journal() is False


def test_journald_false_on_generic_exception():
    with patch.object(
        permissions.shutil, "which", return_value="/usr/bin/journalctl"
    ), patch.object(permissions.subprocess, "run", side_effect=OSError("boom")):
        assert _probe()._can_read_journal() is False
