"""Fail2ban metrics collector for fivenines agent."""

import subprocess
import time
import re
from fivenines_agent.debug import debug, log

_fail2ban_cache = {
    "timestamp": 0,
    "data": {}
}

CACHE_TTL = 60  # seconds


def fail2ban_available() -> bool:
    """
    Check if fail2ban-client is available and we have permission to run it.
    Uses sudo -n (non-interactive) to detect if sudoers is configured.
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", "fail2ban-client", "status"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log("fail2ban-client availability check timed out", 'error')
        return False
    except Exception:
        return False


def get_fail2ban_version() -> str:
    """Get fail2ban version string."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "fail2ban-client", "version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Output is like "Fail2Ban v0.11.2"
            version = result.stdout.strip()
            match = re.search(r'v?([\d.]+)', version)
            if match:
                return match.group(1)
            return version
    except Exception as e:
        log(f"Error getting fail2ban version: {e}", 'debug')
    return "unknown"


def get_jail_list() -> list:
    """Get list of active jails."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "fail2ban-client", "status"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            log(f"fail2ban-client status failed: {result.stderr}", 'error')
            return []

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
        return []


def get_jail_status(jail_name: str) -> dict:
    """Get detailed status for a specific jail."""
    try:
        result = subprocess.run(
            ["sudo", "-n", "fail2ban-client", "status", jail_name],
            capture_output=True,
            text=True,
            timeout=10
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

    if not fail2ban_available():
        log("fail2ban unavailable (not installed or no sudo permissions)", 'debug')
        data = {}
    else:
        jails = get_jail_list()
        if not jails:
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
