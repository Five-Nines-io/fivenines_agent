"""
Subprocess utilities for fivenines agent.
Provides helpers for running system commands safely from PyInstaller bundles.
"""

import os
import subprocess
from typing import List, Optional

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


def run_command(
    cmd: List[str],
    timeout: Optional[int] = None,
    capture_output: bool = True,
    check: bool = False,
    shell: bool = False,
    **kwargs
) -> subprocess.CompletedProcess:
    """
    Run a system command with a sanitized environment.

    This is a thin wrapper around subprocess.run() that automatically
    uses get_clean_env() to prevent PyInstaller library conflicts.

    Args:
        cmd: Command and arguments as a list
        timeout: Timeout in seconds (optional)
        capture_output: Capture stdout/stderr (default: True)
        check: Raise exception on non-zero exit (default: False)
        shell: Run through shell (default: False)
        **kwargs: Additional arguments passed to subprocess.run()

    Returns:
        subprocess.CompletedProcess instance
    """
    # Use clean env unless caller explicitly provides one
    if 'env' not in kwargs:
        kwargs['env'] = get_clean_env()

    return subprocess.run(
        cmd,
        timeout=timeout,
        capture_output=capture_output,
        check=check,
        shell=shell,
        **kwargs
    )
