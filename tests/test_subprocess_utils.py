"""Tests for the privileged subprocess runner (#144).

`run_privileged` exists because `subprocess.run(timeout=...)` does NOT bound a
sudo child: sudo switches to full root before its sudoers lookup, so the kill
CPython issues after the timeout comes back EPERM, the PermissionError escapes
the TimeoutExpired handler, and `Popen.__exit__` waits with no timeout at all.
On the single-threaded collection loop that is a watchdog SIGABRT and, with
Restart=always, a restart loop.
"""

import subprocess
import sys
import threading
import time

import pytest

from fivenines_agent.subprocess_utils import run_command, run_privileged


def test_returns_the_completed_process_on_the_normal_path():
    # sys.executable, not /bin/echo: the Windows job runs this whole suite.
    result = run_privileged(
        [sys.executable, "-c", "print('hello')"],
        timeout=30,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_supplies_a_clean_env_by_default(monkeypatch):
    """Callers must not have to remember: a PyInstaller LD_LIBRARY_PATH leaking
    into a sudo child is the documented breaker for every sudo collector."""
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/fivenines/_internal")
    run_privileged(["sudo", "-n", "wg", "show", "all", "dump"], timeout=3)
    assert "LD_LIBRARY_PATH" not in seen["env"]
    assert seen["timeout"] == 3


def test_an_explicit_env_is_not_overwritten(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    run_privileged(["sudo", "-n", "true"], timeout=1, env={"PATH": "/usr/bin"})
    assert seen["env"] == {"PATH": "/usr/bin"}


def test_a_normal_timeout_still_reaches_the_caller(monkeypatch):
    """A killable child times out the ordinary way; the caller's existing
    TimeoutExpired handling must keep working unchanged."""

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(subprocess.TimeoutExpired):
        run_privileged(["sudo", "-n", "true"], timeout=1)


def test_other_exceptions_are_re_raised_on_the_callers_thread(monkeypatch):
    """A worker thread that swallowed OSError would turn "sudo is not
    installed" into a silent success."""

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError(2, "No such file or directory: 'sudo'")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(FileNotFoundError):
        run_privileged(["sudo", "-n", "true"], timeout=1)


def test_an_unkillable_child_is_abandoned_instead_of_blocking(monkeypatch):
    """THE reason this helper exists.

    The stand-in models a wedged sudo: `subprocess.run` does not return when
    its own timeout expires, because the root-owned child cannot be killed.
    The caller must still be freed, and must see the timeout it was promised.
    """
    released = threading.Event()

    def wedged_run(cmd, **kwargs):
        released.wait(30)  # far past the caller's deadline
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", wedged_run)
    started = time.monotonic()
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_privileged(["sudo", "-n", "wg", "show", "all", "dump"], timeout=1)
        waited = time.monotonic() - started
        # timeout + the 2s abandon grace, not the 30s the child would take.
        assert waited < 10
    finally:
        released.set()


def test_the_abandoned_worker_is_a_daemon(monkeypatch):
    """An abandoned worker must never keep the process alive at shutdown: the
    agent has to be able to exit while a wedged sudo is still out there."""
    released = threading.Event()
    captured = {}
    real_thread = threading.Thread

    def recording_thread(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        captured["thread"] = thread
        return thread

    def wedged_run(cmd, **kwargs):
        released.wait(30)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", wedged_run)
    monkeypatch.setattr(threading, "Thread", recording_thread)
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_privileged(["sudo", "-n", "true"], timeout=1)
        assert captured["thread"].daemon is True
        assert captured["thread"].is_alive()
    finally:
        released.set()


# --- run_command (the non-privileged wrapper) ------------------------------


def test_run_command_defaults_to_a_clean_env(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("LD_PRELOAD", "/opt/fivenines/_internal/libz.so")
    run_command(["true"], timeout=2)
    assert "LD_PRELOAD" not in seen["env"]
    assert seen["timeout"] == 2


def test_run_command_keeps_an_explicit_env(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    run_command(["true"], env={"PATH": "/bin"})
    assert seen["env"] == {"PATH": "/bin"}
