#!/usr/bin/python

import json
import os
import platform
import signal
import sys
import time
from threading import Event

import psutil
from dotenv import load_dotenv

try:
    import systemd_watchdog
except ImportError:
    systemd_watchdog = None

from fivenines_agent.cli import VERSION
from fivenines_agent.collectors import collect_metrics
from fivenines_agent.debug import log, start_log_capture, stop_log_capture
from fivenines_agent.env import config_dir, dry_run, env_file, get_user_context
from fivenines_agent.files import file_handles_limit, file_handles_used
from fivenines_agent.ip import get_ip
from fivenines_agent.load_average import load_average
from fivenines_agent.packages import packages_sync
from fivenines_agent.permissions import get_permissions, print_capabilities_banner
from fivenines_agent.ping import tcp_ping
from fivenines_agent.synchronization_queue import SynchronizationQueue
from fivenines_agent.synchronizer import Synchronizer


CONFIG_DIR = config_dir()
load_dotenv(dotenv_path=env_file())

# Exit event for safe shutdown
exit_event = Event()
# Event to signal permission refresh needed
refresh_permissions_event = Event()


def _on_exit_signal(signum, frame):
    exit_event.set()


def _on_sighup(signum, frame):
    log("Received SIGHUP - will refresh capabilities", "info")
    refresh_permissions_event.set()


def setup_signals():
    signal.signal(signal.SIGTERM, _on_exit_signal)
    signal.signal(signal.SIGINT, _on_exit_signal)
    signal.signal(signal.SIGHUP, _on_sighup)


class Agent:
    def __init__(self):
        setup_signals()

        log(f"fivenines agent v{VERSION}", "info")

        # Probe permissions and show capabilities banner
        self.permissions = get_permissions()
        print_capabilities_banner()

        # Load token
        self._load_file("TOKEN")

        self.queue = SynchronizationQueue(maxsize=100)
        self.synchronizer = Synchronizer(self.token, self.queue)
        self.synchronizer.start()

    def _load_file(self, filename):
        try:
            path = os.path.join(CONFIG_DIR, filename)
            with open(path, "r") as f:
                setattr(self, filename.lower(), f.read().strip())
        except FileNotFoundError:
            log(f"{filename} file is missing", "error")
            sys.exit(2)

    def run(self):
        # Notify systemd watchdog (no-op on non-systemd systems like Alpine)
        if systemd_watchdog is not None:
            wd = systemd_watchdog.watchdog()
            wd.ready()
        else:
            wd = None

        # Static info
        static_data = {
            "version": VERSION,
            "uname": platform.uname()._asdict(),
            "boot_time": psutil.boot_time(),
            "capabilities": self.permissions.get_all(),
            "user_context": get_user_context(CONFIG_DIR),
        }

        try:
            while not exit_event.is_set():
                if wd is not None:
                    wd.notify()
                self._handle_permission_refresh(static_data)

                # Refresh config if disabled
                self.config = self.synchronizer.get_config()
                if not self.config.get("enabled", False):
                    self.queue.put({"get_config": True})
                    exit_event.wait(25)
                    continue

                data = static_data.copy()
                data["ts"] = time.time()
                start = time.monotonic()
                self._telemetry = {}

                self._collect_metrics(data)

                self._packages_sync_with_telemetry()
                data["_telemetry"] = self._telemetry

                # Running time and enqueue
                running_time = time.monotonic() - start
                data["running_time"] = running_time

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

    def _collect_metrics(self, data):
        # Core metrics (always enabled)
        data["load_average"] = self._collect("load_average", load_average)
        data["file_handles_used"] = self._collect("file_handles_used", file_handles_used)
        data["file_handles_limit"] = self._collect("file_handles_limit", file_handles_limit)

        # Conditional metrics via registry
        collect_metrics(self.config, data, self._telemetry)

        # Special-case collectors (unique dispatch patterns)
        if self.config.get("ping"):
            for region, host in self.config["ping"].items():
                data[f"ping_{region}"] = self._collect(f"ping_{region}", tcp_ping, host)
        if self.config.get("ipv4"):
            data["ipv4"] = self._collect("ipv4", get_ip, ipv6=False)
        if self.config.get("ipv6"):
            data["ipv6"] = self._collect("ipv6", get_ip, ipv6=True)

    def _collect(self, name, fn, *args, **kwargs):
        start = time.monotonic()
        start_log_capture()
        try:
            result = fn(*args, **kwargs)
            duration_ms = round((time.monotonic() - start) * 1000, 2)
            errors = stop_log_capture()
            entry = {"duration_ms": duration_ms}
            if errors:
                entry["errors"] = errors
            self._telemetry[name] = entry
            return result
        except Exception as e:
            errors = stop_log_capture()
            errors.append(str(e))
            duration_ms = round((time.monotonic() - start) * 1000, 2)
            self._telemetry[name] = {"duration_ms": duration_ms, "errors": errors}
            log(f"Error collecting {name}: {e}", "error")
            return None

    def _packages_sync_with_telemetry(self):
        ps_start = time.monotonic()
        start_log_capture()
        try:
            packages_sync(self.config, self.synchronizer.send_packages)
        except Exception as e:
            errors = stop_log_capture()
            errors.append(str(e))
            duration_ms = round((time.monotonic() - ps_start) * 1000, 2)
            self._telemetry["packages_sync"] = {"duration_ms": duration_ms, "errors": errors}
            log(f"Error in packages_sync: {e}", "error")
            return
        errors = stop_log_capture()
        duration_ms = round((time.monotonic() - ps_start) * 1000, 2)
        entry = {"duration_ms": duration_ms}
        if errors:
            entry["errors"] = errors
        self._telemetry["packages_sync"] = entry

    def _handle_permission_refresh(self, static_data):
        if refresh_permissions_event.is_set():
            refresh_permissions_event.clear()
            self.permissions.force_refresh()
            static_data["capabilities"] = self.permissions.get_all()
            print_capabilities_banner()
        elif self.permissions.refresh_if_needed():
            static_data["capabilities"] = self.permissions.get_all()

    def _wait_interval(self, running_time):
        log(f"Running time: {running_time:.3f}s", "debug")
        interval = self.config.get("interval", 60)
        sleep_time = max(interval - running_time, 0.1)
        log(f"Sleeping time: {sleep_time * 1000:.0f} ms", "debug")
        exit_event.wait(sleep_time)

    def _cleanup(self):
        log("fivenines agent shutting down. Please wait...")
        self.queue.clear()
        self.synchronizer.stop()
        self.queue.put(None)
        self.synchronizer.join()
        sys.exit(0)
