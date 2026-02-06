#!/usr/bin/python

import grp
import json
import os
import platform
import pwd
import signal
import socket
import sys
import time
from threading import Event

import psutil
import systemd_watchdog
from dotenv import load_dotenv

from fivenines_agent.caddy import caddy_metrics
from fivenines_agent.cli import VERSION
from fivenines_agent.cpu import cpu_count, cpu_data, cpu_model, cpu_usage
from fivenines_agent.debug import debug, log
from fivenines_agent.docker import docker_metrics
from fivenines_agent.env import config_dir, dry_run, env_file
from fivenines_agent.fail2ban import fail2ban_metrics
from fivenines_agent.fans import fans
from fivenines_agent.files import file_handles_limit, file_handles_used
from fivenines_agent.io import io
from fivenines_agent.ip import get_ip
from fivenines_agent.load_average import load_average
from fivenines_agent.memory import memory, swap
from fivenines_agent.network import network
from fivenines_agent.nginx import nginx_metrics
from fivenines_agent.packages import (
    get_distro,
    get_installed_packages,
    get_packages_hash,
)
from fivenines_agent.partitions import partitions_metadata, partitions_usage
from fivenines_agent.permissions import get_permissions, print_capabilities_banner
from fivenines_agent.ports import listening_ports
from fivenines_agent.postgresql import postgresql_metrics
from fivenines_agent.processes import processes
from fivenines_agent.proxmox import proxmox_metrics
from fivenines_agent.qemu import qemu_metrics
from fivenines_agent.raid_storage import raid_storage_health
from fivenines_agent.redis import redis_metrics
from fivenines_agent.smart_storage import (
    smart_storage_health,
    smart_storage_identification,
)
from fivenines_agent.synchronization_queue import SynchronizationQueue
from fivenines_agent.synchronizer import Synchronizer
from fivenines_agent.temperatures import temperatures


CONFIG_DIR = config_dir()
load_dotenv(dotenv_path=env_file())


def get_user_context():
    """Get information about the user running the agent."""
    try:
        uid = os.getuid()
        euid = os.geteuid()
        gid = os.getgid()

        # Get username
        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            username = str(uid)

        # Get primary group name
        try:
            groupname = grp.getgrgid(gid).gr_name
        except KeyError:
            groupname = str(gid)

        # Get all groups the user belongs to
        try:
            groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        except Exception:
            groups = [str(g) for g in os.getgroups()]

        # Determine installation type based on config directory
        is_user_install = CONFIG_DIR.startswith(os.path.expanduser("~"))

        return {
            "username": username,
            "uid": uid,
            "euid": euid,
            "gid": gid,
            "groupname": groupname,
            "groups": groups,
            "is_root": uid == 0,
            "is_user_install": is_user_install,
            "config_dir": CONFIG_DIR,
            "home_dir": os.path.expanduser("~"),
        }
    except Exception as e:
        log(f"Error getting user context: {e}", "error")
        return {
            "username": "unknown",
            "is_root": False,
            "is_user_install": False,
        }


# Exit event for safe shutdown
exit_event = Event()
# Event to signal permission refresh needed
refresh_permissions_event = Event()


class Agent:
    def __init__(self):
        signal.signal(signal.SIGTERM, self._on_exit_signal)
        signal.signal(signal.SIGINT, self._on_exit_signal)
        signal.signal(signal.SIGHUP, self._on_sighup)

        log(f"fivenines agent v{VERSION}", "info")

        # Probe permissions and show capabilities banner
        self.permissions = get_permissions()
        print_capabilities_banner()

        # Load token
        self._load_file("TOKEN")

        self._last_packages_hash = ""

        self.queue = SynchronizationQueue(maxsize=100)
        self.synchronizer = Synchronizer(self.token, self.queue)
        self.synchronizer.start()

    def _on_exit_signal(self, signum, frame):
        # Only set the exit flag; defer cleanup to main loop
        exit_event.set()

    def _on_sighup(self, signum, frame):
        # SIGHUP triggers permission refresh instead of exit
        log("Received SIGHUP - will refresh capabilities", "info")
        refresh_permissions_event.set()

    def _load_file(self, filename):
        try:
            path = os.path.join(CONFIG_DIR, filename)
            with open(path, "r") as f:
                setattr(self, filename.lower(), f.read().strip())
        except FileNotFoundError:
            log(f"{filename} file is missing", "error")
            sys.exit(2)

    def run(self):
        # Notify systemd watchdog
        wd = systemd_watchdog.watchdog()
        wd.ready()

        # Static info
        static_data = {
            "version": VERSION,
            "uname": platform.uname()._asdict(),
            "boot_time": psutil.boot_time(),
            "capabilities": self.permissions.get_all(),
            "user_context": get_user_context(),
        }

        try:
            while not exit_event.is_set():
                wd.notify()

                # Check for permission refresh (SIGHUP or periodic)
                if refresh_permissions_event.is_set():
                    refresh_permissions_event.clear()
                    self.permissions.force_refresh()
                    static_data["capabilities"] = self.permissions.get_all()
                    print_capabilities_banner()
                elif self.permissions.refresh_if_needed():
                    static_data["capabilities"] = self.permissions.get_all()

                # Refresh config if disabled
                self.config = self.synchronizer.get_config()
                if not self.config.get("enabled", False):
                    self.queue.put({"get_config": True})
                    exit_event.wait(25)
                    continue

                data = static_data.copy()
                data["ts"] = time.time()
                start = time.monotonic()

                # Core metrics
                data["load_average"] = load_average()
                data["file_handles_used"] = file_handles_used()
                data["file_handles_limit"] = file_handles_limit()

                # Conditional metrics
                if self.config.get("ping"):
                    for region, host in self.config["ping"].items():
                        data[f"ping_{region}"] = self.tcp_ping(host)
                if self.config.get("cpu"):
                    data["cpu"] = cpu_data()
                    data["cpu_usage"] = cpu_usage()
                    data["cpu_model"] = cpu_model()
                    data["cpu_count"] = cpu_count()
                if self.config.get("memory"):
                    data["memory"] = memory()
                    data["swap"] = swap()
                if self.config.get("ipv4"):
                    data["ipv4"] = get_ip(ipv6=False)
                if self.config.get("ipv6"):
                    data["ipv6"] = get_ip(ipv6=True)
                if self.config.get("network"):
                    data["network"] = network()
                if self.config.get("partitions"):
                    data["partitions_metadata"] = partitions_metadata()
                    data["partitions_usage"] = partitions_usage()
                if self.config.get("io"):
                    data["io"] = io()
                if self.config.get("smart_storage_health"):
                    data["smart_storage_identification"] = (
                        smart_storage_identification()
                    )
                    data["smart_storage_health"] = smart_storage_health()
                if self.config.get("raid_storage_health"):
                    data["raid_storage_health"] = raid_storage_health()
                if self.config.get("processes"):
                    data["processes"] = processes()
                if self.config.get("ports"):
                    data["ports"] = listening_ports(**self.config["ports"])
                if self.config.get("temperatures"):
                    data["temperatures"] = temperatures()
                if self.config.get("fans"):
                    data["fans"] = fans()
                if self.config.get("redis"):
                    data["redis"] = redis_metrics(**self.config["redis"])
                if self.config.get("nginx"):
                    data["nginx"] = nginx_metrics(**self.config["nginx"])
                if self.config.get("docker"):
                    data["docker"] = docker_metrics(**self.config["docker"])
                if self.config.get("qemu"):
                    data["qemu"] = qemu_metrics(**self.config["qemu"])
                if self.config.get("fail2ban"):
                    data["fail2ban"] = fail2ban_metrics()
                if self.config.get("caddy"):
                    data["caddy"] = caddy_metrics(**self.config["caddy"])
                if self.config.get("postgresql"):
                    data["postgresql"] = postgresql_metrics(**self.config["postgresql"])
                if self.config.get("proxmox"):
                    data["proxmox"] = proxmox_metrics(**self.config["proxmox"])

                # Running time and enqueue
                running_time = time.monotonic() - start
                data["running_time"] = running_time

                self._maybe_run_security_scan()

                log(json.dumps(data, indent=2), "debug")
                # Exit immediately in dry-run
                if dry_run():
                    exit_event.set()
                else:
                    self.queue.put(data)
                    self._wait_interval(running_time)

        except Exception as e:
            # Log unexpected errors before exiting
            log(f"Error: {e}", "error")
        finally:
            self._cleanup()

    def _wait_interval(self, running_time):
        log(f"Running time: {running_time:.3f}s", "debug")
        interval = self.config.get("interval", 60)
        sleep_time = max(interval - running_time, 0.1)
        log(f"Sleeping time: {sleep_time * 1000:.0f} ms", "debug")
        exit_event.wait(sleep_time)

    def _maybe_run_security_scan(self):
        """Run security scan if configured by the backend."""
        security_scan_config = self.config.get("security_scan")
        if not isinstance(security_scan_config, dict):
            return

        distro = get_distro()
        packages = get_installed_packages()
        if not packages:
            log("Security scan: no packages found", "debug")
            return

        packages_hash = get_packages_hash(packages)
        if packages_hash == self._last_packages_hash:
            log("Security scan: packages unchanged, skipping", "debug")
            return

        scan_data = {
            "distro": distro,
            "packages_hash": packages_hash,
            "packages": packages,
        }

        if dry_run():
            log(f"Security scan (dry-run): {json.dumps(scan_data, indent=2)}", "debug")
            return

        response = self.synchronizer.send_security_scan(scan_data)
        if response is not None:
            self._last_packages_hash = packages_hash
            log("Security scan sent successfully", "info")
        else:
            log("Security scan failed, will retry", "error")

    @debug("tcp_ping")
    def tcp_ping(self, host, port=80, timeout=5):
        try:
            start = time.time()
            with socket.create_connection((host, port), timeout):
                return (time.time() - start) * 1000
        except Exception:
            return None

    def _cleanup(self):
        log("fivenines agent shutting down. Please wait...")
        self.queue.clear()
        self.synchronizer.stop()
        self.queue.put(None)
        self.synchronizer.join()
        sys.exit(0)
