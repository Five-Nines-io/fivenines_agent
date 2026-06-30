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
from fivenines_agent.collectors import (
    COLLECTORS,
    _capability_key_for,
    _collect_with_telemetry,
    collect_metrics,
)
from fivenines_agent.debug import log
from fivenines_agent.env import config_dir, dry_run, env_file, get_user_context, is_windows
from fivenines_agent.files import file_handles_limit, file_handles_used, handle_count
from fivenines_agent.ip import get_ip
from fivenines_agent.load_average import load_average
from fivenines_agent.log_capture import CaptureCoordinator, evaluate_and_enqueue
from fivenines_agent.log_uploader import LogUploader
from fivenines_agent.logs import build_capture_bundle
from fivenines_agent.machine_id import get_machine_id
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

# Sentinel for "no permissions_recheck_token observed yet", so the first
# observation (including a real token already set when the agent restarts)
# only baselines and does not fire a spurious reprobe.
_RECHECK_UNSET = object()


# Permissive config used only in --dry-run so every collector that has the
# capability runs, without contacting the API. The keys mirror what the server
# would normally return for a fully-enabled install. Adding a new collector?
# Add its config_key here so dry-run actually exercises it.
_DRY_RUN_CONFIG = {
    "enabled": True,
    "interval": 60,
    "request_options": {"timeout": 5, "retry": 3, "retry_interval": 5},
    "cpu": True,
    "memory": True,
    "network": True,
    "partitions": True,
    "io": True,
    "logs": {"units": ["nginx.service", "ssh.service"]},
    "processes": True,
    "ports": True,
    "temperatures": True,
    "fans": True,
    "nvidia_gpu": True,
    "smart_storage_health": True,
    "raid_storage_health": True,
    "fail2ban": True,
    "disk_health": True,
}


def _on_exit_signal(signum, frame):
    exit_event.set()


def _on_sighup(signum, frame):
    log("Received SIGHUP - will refresh capabilities", "info")
    refresh_permissions_event.set()


def setup_signals():
    signal.signal(signal.SIGTERM, _on_exit_signal)
    signal.signal(signal.SIGINT, _on_exit_signal)
    # SIGHUP is Linux-only; on Windows the agent relies on the periodic
    # auto-reprobe in PermissionProbe.refresh_due (D9).
    if hasattr(signal, "SIGHUP"):
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

        # Last permissions_recheck_token acted on (see _recheck_token_changed).
        self._last_recheck_token = _RECHECK_UNSET

        # Static info sent with every request
        self.static_data = {
            "version": VERSION,
            "uname": platform.uname()._asdict(),
            "boot_time": psutil.boot_time(),
            "capabilities": self.permissions.get_all(),
            "capability_reasons": self.permissions.get_reasons(),
            "pending_capabilities": [],
            "user_context": get_user_context(CONFIG_DIR),
            "machine_id": get_machine_id(),
        }

        self.queue = SynchronizationQueue(maxsize=100)
        if dry_run():
            # Skip the synchronizer entirely. The synchronizer is a non-daemon
            # Thread that fetches config from the API at startup and would
            # otherwise block --dry-run on retries (especially with an invalid
            # token), preventing the main loop from ever reaching the
            # exit_event.set() at the end of the first collection tick. We use
            # _DRY_RUN_CONFIG so every collector that has the capability runs.
            self.synchronizer = None
        else:
            self.synchronizer = Synchronizer(self.token, self.queue, self.static_data)
            self.synchronizer.start()

        # Dedicated channel for incident log-capture bundles (Brique A), kept off
        # the metric path so a slow/large /logs upload never blocks collection or
        # /collect. The coordinator applies the capture_id nonce + disk persistence
        # so a backend command fires exactly once and never replays after a restart.
        self.log_queue = SynchronizationQueue(maxsize=20)
        self.capture_coordinator = CaptureCoordinator(
            os.path.join(CONFIG_DIR, "last_capture_id")
        )
        if self.synchronizer is None:
            self.log_uploader = None
        else:
            self.log_uploader = LogUploader(
                self.log_queue,
                build_capture_bundle,
                self.synchronizer.send_logs,
                on_success=self.capture_coordinator.mark_uploaded,
                on_failure=self.capture_coordinator.mark_failed,
            )
            self.log_uploader.start()

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

        try:
            while not exit_event.is_set():
                if wd is not None:
                    wd.notify()
                self._handle_sighup_refresh()

                # Refresh config if disabled. In --dry-run we use a static
                # permissive config so we never contact the API.
                if self.synchronizer is None:
                    self.config = _DRY_RUN_CONFIG
                    self._apply_config_driven_refresh(self.config)
                else:
                    self.config = self.synchronizer.get_config()
                    # Run config-driven permission refresh in BOTH the enabled
                    # and the disabled branch so the on-demand recheck token and
                    # fast gap detection work for not-yet-enabled onboarding
                    # hosts too.
                    self._apply_config_driven_refresh(self.config)
                    if not self.config.get("enabled", False):
                        self.queue.put({"get_config": True, **self.static_data})
                        exit_event.wait(25)
                        continue

                self._handle_capture_request(self.config)

                data = self.static_data.copy()
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
        # Core metrics (always enabled). load_average is Linux-only - psutil's
        # Windows emulation drops to zero on idle systems and resets on
        # process restart, so we omit the key entirely on Windows rather
        # than ship a value that's more misleading than informative.
        if not is_windows():
            data["load_average"] = self._collect("load_average", load_average)
        self._collect_file_handles(data)

        # Conditional metrics via registry, gated by capability where available
        collect_metrics(
            self.config, data, self._telemetry, self.permissions.get_all()
        )

        # Special-case collectors (unique dispatch patterns)
        if self.config.get("ping"):
            for region, host in self.config["ping"].items():
                data[f"ping_{region}"] = self._collect(f"ping_{region}", tcp_ping, host)
        if self.config.get("ipv4"):
            data["ipv4"] = self._collect("ipv4", get_ip, ipv6=False)
        if self.config.get("ipv6"):
            data["ipv6"] = self._collect("ipv6", get_ip, ipv6=True)
        snmp_targets = self.config.get("snmp_targets", [])
        if snmp_targets:
            from fivenines_agent.snmp import snmp_metrics

            data["snmp_metrics"] = self._collect(
                "snmp_metrics", snmp_metrics, snmp_targets
            )

    def _collect_file_handles(self, data):
        """Emit file-handle metrics under OS-appropriate keys (D2/D10).

        Linux reports used/limit pairs derived from /proc/sys/fs/file-nr.
        Windows has no equivalent; instead it reports the total kernel handle
        count under its own key so the backend does not conflate the two
        semantically distinct metrics.
        """
        if is_windows():
            data["handle_count"] = self._collect("handle_count", handle_count)
        else:
            data["file_handles_used"] = self._collect("file_handles_used", file_handles_used)
            data["file_handles_limit"] = self._collect("file_handles_limit", file_handles_limit)

    def _collect(self, name, fn, *args, **kwargs):
        return _collect_with_telemetry(name, fn, self._telemetry, *args, **kwargs)

    def _packages_sync_with_telemetry(self):
        # packages_sync POSTs to /packages, which we skip in --dry-run since
        # there's no synchronizer to dispatch through.
        if self.synchronizer is None:
            return
        self._collect(
            "packages_sync", packages_sync, self.config, self.synchronizer.send_packages
        )

    def _handle_capture_request(self, config):
        """Enqueue an incident log-capture job when the backend issues a new
        capture_logs command. The coordinator owns the nonce + allowlist + expiry;
        the LogUploader thread runs the actual journalctl capture off the loop.
        No-op when log uploading is disabled (dry-run / no synchronizer)."""
        if self.log_uploader is None:
            return
        evaluate_and_enqueue(self.capture_coordinator, self.log_queue, config)

    def _handle_sighup_refresh(self):
        """SIGHUP-triggered full reprobe. Kept at the top of the loop (needs no
        config) so it stays responsive even when the backend is unreachable."""
        if refresh_permissions_event.is_set():
            refresh_permissions_event.clear()
            self.permissions.force_refresh()
            # capabilities/reasons/pending are republished by
            # _apply_config_driven_refresh, which always runs later this same
            # tick (both loop branches), so we don't write static_data here.
            print_capabilities_banner()

    def _apply_config_driven_refresh(self, config):
        """Run config-driven permission refresh for this tick, then republish
        capability state for the next payload.

        - On-demand: a changed permissions_recheck_token forces a full reprobe.
        - Otherwise: full probe every REPROBE_INTERVAL plus a cheap selective
          gap re-probe (only enabled-but-missing capabilities) on the throttle
          cadence (default: every tick).
        """
        if self._recheck_token_changed(config.get("permissions_recheck_token")):
            self.permissions.force_refresh()
            pending = self._pending_capabilities(config)
        else:
            interval = self._collection_interval(config)
            gap_interval = self._gap_probe_interval(config, interval)
            pending = self._pending_capabilities(config)
            # Recompute only when the gap probe actually flipped a capability;
            # otherwise the pre-probe set is still current, avoiding a second
            # get_all() copy + COLLECTORS scan every tick.
            if self.permissions.refresh_due(pending, gap_interval):
                pending = self._pending_capabilities(config)
        self.static_data["capabilities"] = self.permissions.get_all()
        self.static_data["capability_reasons"] = self.permissions.get_reasons()
        self.static_data["pending_capabilities"] = pending

    def _recheck_token_changed(self, token):
        """Nonce state machine for the on-demand "re-detect now" button.

        The first observation only baselines (even a non-null token already set
        when the agent restarts), so a restart never triggers a spurious
        reprobe. A null/absent token resets the baseline. Only a transition to a
        different non-null value fires.
        """
        last = self._last_recheck_token
        if last is _RECHECK_UNSET:
            self._last_recheck_token = token
            return False
        if token is None:
            self._last_recheck_token = None
            return False
        if token != last:
            self._last_recheck_token = token
            return True
        return False

    def _collection_interval(self, config):
        """Collection interval, clamped: a low warmup value (e.g. 5s) is allowed,
        but 0/negative/non-numeric falls back to 60s to avoid a tight loop."""
        interval = config.get("interval", 60)
        if isinstance(interval, bool) or not isinstance(interval, (int, float)):
            return 60
        if interval <= 0:
            return 60
        return interval

    def _gap_probe_interval(self, config, interval):
        """Seconds between selective gap re-probes. Default 0 = every tick;
        permissions_recheck_interval can only THROTTLE (floored at the
        collection interval, since the probe runs once per tick) and is capped
        at 3600."""
        raw = config.get("permissions_recheck_interval")
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw <= 0:
            return 0
        return max(interval, min(raw, 3600))

    def _pending_capabilities(self, config):
        """Capabilities the operator enabled (config flag truthy) that are
        currently probed False. Drives the selective gap re-probe and is sent in
        the payload for the dashboard "pending + reason" view. Reuses the
        collectors config-key <-> capability-key mapping so the override
        (smart_storage_health -> smart_storage) lives in one place."""
        caps = self.permissions.get_all()
        pending = []
        for config_key, _collectors in COLLECTORS:
            if not config.get(config_key):
                continue
            cap_key = _capability_key_for(config_key)
            if cap_key in caps and not caps[cap_key]:
                pending.append(cap_key)
        # snmp and packages live outside COLLECTORS; use the same
        # present-and-falsy test as the COLLECTORS loop above (an absent cap on
        # this OS is not pending).
        if config.get("snmp_targets") and "snmp" in caps and not caps["snmp"]:
            pending.append("snmp")
        # packages.scan (nested dict, mirroring packages_sync's guard) reads a
        # package manager on Linux (the 'packages' cap) and the Uninstall
        # registry on Windows (the 'software_inventory' cap); surface whichever
        # gating cap is present-and-False on this host.
        pkg_cfg = config.get("packages")
        if isinstance(pkg_cfg, dict) and pkg_cfg.get("scan"):
            for pkg_cap in ("packages", "software_inventory"):
                if pkg_cap in caps and not caps[pkg_cap]:
                    pending.append(pkg_cap)
        return list(dict.fromkeys(pending))

    def _wait_interval(self, running_time):
        log(f"Running time: {running_time:.3f}s", "debug")
        interval = self._collection_interval(self.config)
        sleep_time = max(interval - running_time, 0.1)
        log(f"Sleeping time: {sleep_time * 1000:.0f} ms", "debug")
        exit_event.wait(sleep_time)

    def _cleanup(self):
        log("fivenines agent shutting down. Please wait...")
        self.queue.clear()
        if self.synchronizer is not None:
            self.synchronizer.stop()
            self.queue.put(None)
            self.synchronizer.join()
        if self.log_uploader is not None:
            self.log_uploader.stop()
            self.log_queue.put(None)
            self.log_uploader.join()
        sys.exit(0)
