"""
Subprocess utilities for fivenines agent.
Provides helpers for running system commands safely from PyInstaller bundles.
"""

import os
import subprocess
from typing import List

from fivenines_agent.bounded import WorkerTimeout, call_bounded
from fivenines_agent.debug import log

# Environment variables that can interfere with system commands when running
# from a PyInstaller bundle. These are set by PyInstaller to point to bundled
# libraries (e.g., libselinux.so.1) which can conflict with system utilities
# like sudo that expect system versions.
SANITIZE_ENV_VARS = [
    'LD_LIBRARY_PATH',
    'LD_PRELOAD',
    'LIBPATH',
    'DYLD_LIBRARY_PATH',
    'DYLD_FALLBACK_LIBRARY_PATH',
]


def get_clean_env() -> dict:
    """
    Return a sanitized copy of the environment for subprocess calls.

    Removes PyInstaller-injected library paths that can interfere with
    system commands like sudo, smartctl, mdadm, etc.

    This is necessary because PyInstaller bundles libraries (like libselinux.so.1
    from libvirt) that can conflict with system utilities when they inherit
    LD_LIBRARY_PATH from the parent process.
    """
    env = os.environ.copy()
    for var in SANITIZE_ENV_VARS:
        env.pop(var, None)
    return env


# Extra seconds the caller waits past a privileged command's own timeout before
# abandoning it. Only covers the interpreter's own teardown; the deadline that
# matters is the command's.
_ABANDON_GRACE = 2


def run_privileged(cmd: List[str], timeout: int, **kwargs):
    """Run a sudo-wrapped command without ever blocking the caller past the deadline.

    `subprocess.run(timeout=...)` does NOT bound a `sudo` child. sudo switches
    to full root before its sudoers lookup, so the kill() CPython issues after
    the timeout comes back EPERM for an unprivileged parent; that
    PermissionError escapes the TimeoutExpired handler into Popen.__exit__,
    which then waits with NO timeout at all. A wedged sudoers backend (sudo-ldap
    and sssd default to bind timeouts of tens of seconds) pins the
    single-threaded collection loop between two watchdog pings until systemd
    SIGABRTs the agent -- and Restart=always makes that a loop.

    Killing the process group instead does not help: the group is root-owned
    too, so the kill fails the same way. What protects the loop is not waiting:
    bounded.call_bounded (shared with the libvirt probe and io_topology) runs it
    in a daemon worker, gives up at the deadline, and lets the wedged child and
    its thread finish in the background whenever sudo returns.

    Returns the CompletedProcess. When the deadline passes it raises
    subprocess.TimeoutExpired -- the same exception the caller would have seen
    from a bounded command, so every existing handler treats it correctly
    without a None check at ten call sites. The difference from a normal
    timeout is only that the child is still out there.
    """
    kwargs.setdefault("env", get_clean_env())
    try:
        return call_bounded(
            lambda: subprocess.run(cmd, timeout=timeout, **kwargs),
            timeout + _ABANDON_GRACE,
        )
    except WorkerTimeout:
        # The command outlived its own timeout AND the interpreter's teardown,
        # which in practice means sudo is wedged and unkillable. Abandon it:
        # the worker is a daemon, so it dies with the process, and the caller
        # gets the timeout it was promised.
        log(
            f"run_privileged: abandoning '{' '.join(cmd[:3])}' after "
            f"{timeout + _ABANDON_GRACE}s (unkillable sudo child)",
            "error",
        )
        raise subprocess.TimeoutExpired(cmd, timeout + _ABANDON_GRACE) from None
