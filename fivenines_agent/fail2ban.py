"""Fail2ban metrics collector for fivenines agent."""

import subprocess
import time
import re
from fivenines_agent.debug import debug, log
from fivenines_agent.subprocess_utils import get_clean_env, run_privileged

_fail2ban_cache = {
    "timestamp": 0,
    "data": {}
}

CACHE_TTL = 60  # seconds


# fail2ban version, cached for the process lifetime once read successfully:
# it only changes on a package upgrade, and every fetch is a sudo spawn of a
# full Python CLI (~150-400ms).
_version_cache = None


def get_fail2ban_version() -> str:
    """Get fail2ban version string (cached per process)."""
    global _version_cache
    if _version_cache is not None:
        return _version_cache
    try:
        result = run_privileged(
            ["sudo", "-n", "fail2ban-client", "version"],
            capture_output=True,
            text=True,
            timeout=5,
            env=get_clean_env()
        )
        if result.returncode == 0:
            # Output is like "Fail2Ban v0.11.2" (or just "0.11.2"). Require at
            # least one dot: the old r'v?([\d.]+)' matched the lone "2" inside
            # the word "Fail2Ban" first and reported version "2" -- worth
            # fixing now that the value is cached for the process lifetime.
            version = result.stdout.strip()
            match = re.search(r'v?(\d+(?:\.\d+)+)', version)
            if match:
                _version_cache = match.group(1)
            else:
                _version_cache = version
            return _version_cache
    except Exception as e:
        log(f"Error getting fail2ban version: {e}", 'debug')
    # Not cached: a transient failure retries on the next fetch.
    return "unknown"


def get_jail_list():
    """Get the list of active jails.

    Returns a list ([] when fail2ban runs with zero jails) or None when
    fail2ban-client itself is unusable (not installed, no sudo, daemon down).
    The None/[] split lets the caller keep the payload contract ({} =
    unavailable vs {"jails": []} = zero jails) WITHOUT a separate
    fail2ban_available() probe -- that probe ran the exact same
    `fail2ban-client status` command, doubling the sudo + CLI startup cost of
    every tick for no information this call does not already return.
    """
    try:
        result = run_privileged(
            ["sudo", "-n", "fail2ban-client", "status"],
            capture_output=True,
            text=True,
            timeout=10,
            env=get_clean_env()
        )
        if result.returncode != 0:
            log(f"fail2ban-client status failed: {result.stderr}", 'error')
            return None

        # Parse output like:
        # Status
        # |- Number of jail:      2
        # `- Jail list:   sshd, apache-auth
        for line in result.stdout.split('\n'):
            if 'Jail list:' in line:
                jails_str = line.split(':', 1)[1].strip()
                if jails_str:
                    return [j.strip() for j in jails_str.split(',')]
        return []
    except Exception as e:
        log(f"Error getting jail list: {e}", 'error')
        return None


def get_jail_status(jail_name: str):
    """Get detailed status for a specific jail."""
    try:
        result = run_privileged(
            ["sudo", "-n", "fail2ban-client", "status", jail_name],
            capture_output=True,
            text=True,
            timeout=10,
            env=get_clean_env()
        )
        if result.returncode != 0:
            log(f"fail2ban-client status {jail_name} failed: {result.stderr}", 'error')
            return None

        jail_info = {
            "name": jail_name,
            "currently_failed": 0,
            "total_failed": 0,
            "currently_banned": 0,
            "total_banned": 0,
            "banned_ips": []
        }

        # Parse output like:
        # Status for the jail: sshd
        # |- Filter
        # |  |- Currently failed: 3
        # |  |- Total failed:     147
        # |  `- File list:        /var/log/auth.log
        # `- Actions
        #    |- Currently banned: 2
        #    |- Total banned:     45
        #    `- Banned IP list:   1.2.3.4 5.6.7.8
        for line in result.stdout.split('\n'):
            line = line.strip()
            if 'Currently failed:' in line:
                try:
                    jail_info["currently_failed"] = int(line.split(':')[1].strip())
                except ValueError:
                    pass
            elif 'Total failed:' in line:
                try:
                    jail_info["total_failed"] = int(line.split(':')[1].strip())
                except ValueError:
                    pass
            elif 'Currently banned:' in line:
                try:
                    jail_info["currently_banned"] = int(line.split(':')[1].strip())
                except ValueError:
                    pass
            elif 'Total banned:' in line:
                try:
                    jail_info["total_banned"] = int(line.split(':')[1].strip())
                except ValueError:
                    pass
            elif 'Banned IP list:' in line:
                ips_str = line.split(':', 1)[1].strip()
                if ips_str:
                    jail_info["banned_ips"] = ips_str.split()

        return jail_info
    except Exception as e:
        log(f"Error getting jail status for {jail_name}: {e}", 'error')
        return None


@debug('fail2ban_metrics')
def fail2ban_metrics():
    """
    Collect fail2ban jail status and ban statistics.
    Cached for 60 seconds to avoid excessive subprocess calls.
    """
    global _fail2ban_cache
    now = time.time()

    # Return cached data if still valid
    if now - _fail2ban_cache["timestamp"] < CACHE_TTL:
        return _fail2ban_cache["data"]

    jails = get_jail_list()
    if jails is None:
        log("fail2ban unavailable (not installed or no sudo permissions)", 'debug')
        data = {}
    elif not jails:
        log("No fail2ban jails found", 'debug')
        data = {
            "version": get_fail2ban_version(),
            "jails": []
        }
    else:
        jail_data = []
        for jail in jails:
            status = get_jail_status(jail)
            if status:
                jail_data.append(status)

        data = {
            "version": get_fail2ban_version(),
            "jails": jail_data
        }

    _fail2ban_cache["timestamp"] = now
    _fail2ban_cache["data"] = data
    return data
