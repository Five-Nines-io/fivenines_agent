"""
Permission probing for fivenines agent.
Detects what capabilities are available based on user permissions.
"""

import os
import shutil
import subprocess
import time

import psutil

from fivenines_agent.debug import log
from fivenines_agent.env import is_windows
from fivenines_agent.subprocess_utils import get_clean_env


# Re-probe interval in seconds (5 minutes)
REPROBE_INTERVAL = 300

# Max chars for stdout/stderr in debug logs
DEBUG_OUTPUT_LIMIT = 500

# Short, operator-friendly hint for each capability when it is unavailable.
# Used in both the startup banner and the info-level log emitted on initial
# probe / state flips. The deeper diagnostic (specific exception, missing
# binary, etc.) is in each probe method's debug-level log.
CAPABILITY_HINTS = {
    "smart_storage": "requires sudo smartctl",
    "raid_storage": "requires sudo mdadm",
    "ceph": "requires ceph CLI + client keyring",
    "docker": "requires docker group",
    "qemu": "requires libvirt group",
    "proxmox": "requires Proxmox VE host",
    "fail2ban": "requires sudo fail2ban-client",
    "packages": "requires dpkg-query, rpm, apk, pacman, or synopkg",
    "zfs": "requires zfs permissions",
    "nvidia_gpu": "requires NVIDIA driver",
    "temperatures": "no accessible sensors",
    "fans": "no accessible sensors",
    "snmp": "requires net-snmp",
    "disk_health": "requires WMI Storage namespace access",
    "software_inventory": "requires Uninstall registry key access",
}

# Banner group layout per OS. Each entry is (section title, [capability keys]).
LINUX_BANNER_GROUPS = [
    ("Core Metrics", ["cpu", "memory", "load_average", "io", "network",
                      "partitions", "file_handles", "ports", "processes"]),
    ("Hardware Sensors", ["temperatures", "fans", "nvidia_gpu"]),
    ("Storage", ["smart_storage", "raid_storage", "zfs", "ceph"]),
    ("Services", ["docker", "qemu", "proxmox"]),
    ("Security", ["fail2ban", "packages"]),
    ("Networking", ["snmp"]),
]

WINDOWS_BANNER_GROUPS = [
    # No load_average - Windows has no native equivalent and psutil's
    # CPU-sampling emulation drops to zero on idle systems, which is more
    # misleading than helpful. We omit the metric entirely on Windows.
    ("Core Metrics", ["cpu", "memory", "io", "network",
                      "partitions", "file_handles", "ports", "processes"]),
    ("Hardware Sensors", ["temperatures", "fans", "nvidia_gpu"]),
    ("Storage", ["disk_health"]),
    ("Inventory", ["software_inventory"]),
]


class PermissionProbe:
    """
    Probes system to detect available monitoring capabilities.
    Automatically re-probes periodically to detect permission changes.
    """

    def __init__(self):
        self.capabilities = {}
        # Maps capability name -> short reason string for the most recent
        # False result. Probe methods record their failure cause via
        # _set_reason(); _probe() captures it into this dict and clears it
        # when the capability flips back to True.
        self._capability_reasons = {}
        self._current_reason = None
        self._last_probe_time = 0
        self._probe_all()

    def _set_reason(self, msg):
        """Called by probe methods on a False-return path to record why."""
        self._current_reason = msg

    def _probe(self, cap_name, probe_callable, *args):
        """Run a probe method and capture its failure reason if any.

        Probes run sequentially in _probe_all, so the single-slot
        _current_reason register is safe.
        """
        self._current_reason = None
        result = probe_callable(*args)
        if result:
            self._capability_reasons.pop(cap_name, None)
        elif self._current_reason:
            self._capability_reasons[cap_name] = self._current_reason
        return result

    def _probe_all(self):
        """Probe all capabilities and cache results.

        Branches once on OS family. The Linux probe reports its existing
        capability set; the Windows probe reports a Windows-tailored set
        (D13 - the backend handles the different shape).
        """
        self._last_probe_time = time.time()
        old_capabilities = self.capabilities.copy()

        if is_windows():
            self.capabilities = self._build_windows_capabilities()
        else:
            self.capabilities = self._build_linux_capabilities()

        if not old_capabilities:
            # Initial probe: surface every unavailable capability at info level
            # so operators see WHY at default LOG_LEVEL. Format:
            #   Capability 'X' unavailable: <hint> (<probe-method reason>)
            for cap, available in self.capabilities.items():
                if available:
                    continue
                log(self._format_unavailable(cap, "unavailable"), "info")
        else:
            # Subsequent probes: log only state flips. Unavailability transitions
            # carry the same hint+reason payload as the initial probe.
            for cap, available in self.capabilities.items():
                old_value = old_capabilities.get(cap)
                if old_value is None or old_value == available:
                    continue
                if available:
                    log(f"Capability '{cap}' is now AVAILABLE", "info")
                else:
                    log(self._format_unavailable(cap, "is now UNAVAILABLE"), "info")

        return self.capabilities

    def _build_linux_capabilities(self):
        """Linux capability set: /proc, /sys, sudo, sockets, package managers."""
        return {
            # Core metrics - always available via /proc
            "cpu": self._probe("cpu", self._can_read, "/proc/stat"),
            "memory": self._probe("memory", self._can_read, "/proc/meminfo"),
            "load_average": self._probe("load_average", self._can_read, "/proc/loadavg"),
            "io": self._probe("io", self._can_read, "/proc/diskstats"),
            "network": self._probe("network", self._can_read, "/proc/net/dev"),
            "partitions": self._probe("partitions", self._can_read, "/proc/mounts"),
            "file_handles": self._probe("file_handles", self._can_read, "/proc/sys/fs/file-nr"),
            "ports": self._probe("ports", self._can_read, "/proc/net/tcp"),
            # Processes - works but may have limited visibility
            "processes": self._probe("processes", self._can_read, "/proc/self/stat"),
            # Hardware sensors - may or may not work without root
            "temperatures": self._probe("temperatures", self._can_access_hwmon),
            "fans": self._probe("fans", self._can_access_hwmon),
            # NVIDIA GPU
            "nvidia_gpu": self._probe("nvidia_gpu", self._can_access_gpu),
            # Storage requiring sudo
            "smart_storage": self._probe("smart_storage", self._can_run_sudo, "smartctl", "--version"),
            "raid_storage": self._probe("raid_storage", self._can_run_sudo, "mdadm", "--version"),
            # Ceph - light probe only (CLI present). Cluster reachability/auth is
            # reported per-cluster as runtime data by the collector, NOT gated
            # here: a cluster outage must show as a metric, not disable the
            # collector for the 5-minute reprobe window.
            "ceph": self._probe("ceph", self._can_run_ceph),
            # Security - requires sudo
            "fail2ban": self._probe("fail2ban", self._can_run_sudo, "fail2ban-client", "status"),
            # ZFS - doesn't need sudo but needs permissions or delegation
            "zfs": self._probe("zfs", self._can_run_zfs),
            # Docker - needs docker group membership
            "docker": self._probe("docker", self._can_access_docker),
            # QEMU/libvirt - needs libvirt group membership
            "qemu": self._probe("qemu", self._can_access_libvirt),
            # Proxmox VE - needs API access or local node
            "proxmox": self._probe("proxmox", self._can_access_proxmox),
            # Package listing - for security scanning
            "packages": self._probe("packages", self._can_list_packages),
            # SNMP polling - needs net-snmp CLI tools
            "snmp": self._probe("snmp", self._has_snmpget),
        }

    def _build_windows_capabilities(self):
        """Windows-tailored capability set (D13).

        Core metrics report True unconditionally - psutil works on Windows.
        Linux-only capabilities (raid_storage, zfs, fail2ban, proxmox, qemu,
        smart_storage via smartctl, packages via dpkg/rpm) are omitted: D13
        sends a Windows-shaped payload rather than Linux keys marked N/A.
        Windows-native entries: disk_health (WMI Storage), software_inventory
        (registry Uninstall key).
        """
        return {
            # Core metrics - psutil handles these cross-platform.
            # load_average is intentionally absent: Windows has no equivalent
            # (no D-state, no real load avg in the kernel), and psutil's
            # emulation samples CPU activity only and reads zero on idle
            # systems. Omit rather than ship misleading data (D13 - send a
            # Windows-shaped payload rather than Linux keys marked N/A).
            "cpu": True,
            "memory": True,
            "io": True,
            "network": True,
            "partitions": True,
            "file_handles": True,
            "ports": True,
            "processes": True,
            # Hardware sensors - psutil reports if any are exposed
            "temperatures": self._probe("temperatures", self._can_query_psutil_sensors, "temperatures"),
            "fans": self._probe("fans", self._can_query_psutil_sensors, "fans"),
            "nvidia_gpu": self._probe("nvidia_gpu", self._can_access_gpu),
            # Windows-native: WMI MSFT_PhysicalDisk + reliability counters
            "disk_health": self._probe("disk_health", self._can_query_wmi_storage),
            # Windows-native: registry Uninstall key (classic Win32 installed programs)
            "software_inventory": self._probe("software_inventory", self._can_read_uninstall_registry),
        }

    def _format_unavailable(self, cap, verb):
        """Build the operator-facing log line for an unavailable capability."""
        msg = f"Capability '{cap}' {verb}"
        hint = CAPABILITY_HINTS.get(cap)
        if hint:
            msg += f": {hint}"
        reason = self._capability_reasons.get(cap)
        if reason:
            msg += f" ({reason})"
        return msg

    def refresh_if_needed(self):
        """Re-probe capabilities if enough time has passed."""
        if time.time() - self._last_probe_time >= REPROBE_INTERVAL:
            log("Re-probing capabilities...", "debug")
            self._probe_all()
            return True
        return False

    def force_refresh(self):
        """Force an immediate re-probe of capabilities."""
        log("Force re-probing capabilities...", "info")
        self._probe_all()
        return self.capabilities

    def _can_read(self, path):
        """Check if a file/directory is readable."""
        try:
            exists = os.path.exists(path)
            if not exists:
                log(f"_can_read: '{path}' does not exist", "debug")
                self._set_reason(f"{path} does not exist")
                return False

            readable = os.access(path, os.R_OK)
            log(
                f"_can_read: '{path}' -> {'READABLE' if readable else 'NOT READABLE'}",
                "debug",
            )
            if not readable:
                self._set_reason(f"{path} is not readable")
            return readable
        except Exception as e:
            log(f"_can_read: '{path}' exception: {type(e).__name__}: {e}", "debug")
            self._set_reason(f"{path}: {type(e).__name__}: {e}")
            return False

    def _can_run_sudo(self, cmd, *args):
        """
        Check if we can run a command with sudo non-interactively.
        Uses sudo -n which fails immediately if password is required.
        """
        cmd_path = shutil.which(cmd)
        full_cmd = ["sudo", "-n", cmd, *args]
        full_cmd_str = " ".join(full_cmd)

        if not cmd_path:
            log(f"_can_run_sudo: '{cmd}' not found in PATH", "debug")
            self._set_reason(f"{cmd} not found in PATH")
            return False

        log(f"_can_run_sudo: '{cmd}' found at {cmd_path}", "debug")
        log(f"_can_run_sudo: running '{full_cmd_str}'", "debug")

        try:
            result = subprocess.run(
                full_cmd, capture_output=True, timeout=5, env=get_clean_env()
            )
            stdout = result.stdout.decode("utf-8", errors="ignore").strip()
            stderr = result.stderr.decode("utf-8", errors="ignore").strip()

            log(f"_can_run_sudo: '{cmd}' returned code {result.returncode}", "debug")
            if stdout:
                log(
                    f"_can_run_sudo: '{cmd}' stdout: {stdout[:DEBUG_OUTPUT_LIMIT]}",
                    "debug",
                )
            if stderr:
                log(
                    f"_can_run_sudo: '{cmd}' stderr: {stderr[:DEBUG_OUTPUT_LIMIT]}",
                    "debug",
                )

            success = result.returncode == 0
            log(
                f"_can_run_sudo: '{cmd}' -> {'AVAILABLE' if success else 'UNAVAILABLE'}",
                "debug",
            )
            if not success:
                detail = stderr.splitlines()[0] if stderr else f"returncode {result.returncode}"
                self._set_reason(f"sudo -n {cmd}: {detail}")
            return success
        except subprocess.TimeoutExpired:
            log(f"_can_run_sudo: '{cmd}' timed out after 5s", "debug")
            self._set_reason(f"sudo -n {cmd} timed out after 5s")
            return False
        except Exception as e:
            log(f"_can_run_sudo: '{cmd}' exception: {type(e).__name__}: {e}", "debug")
            self._set_reason(f"sudo -n {cmd}: {type(e).__name__}: {e}")
            return False

    def _can_run_ceph(self):
        """Light probe: is the ceph CLI present?

        Intentionally does NOT run `ceph status`. A capability that flips False
        on a transient cluster/auth/network failure would skip the whole
        collector for the reprobe window (collectors.py gates on it), blinding
        Ceph monitoring exactly when the cluster breaks. Per-cluster keyring
        readability and reachability are reported by the collector as runtime
        data instead.
        """
        if shutil.which("ceph"):
            log("_can_run_ceph: 'ceph' found in PATH", "debug")
            return True
        log("_can_run_ceph: 'ceph' not found in PATH", "debug")
        self._set_reason("ceph not found in PATH")
        return False

    def _can_access_hwmon(self):
        """Check if hardware monitoring sensors are readable."""
        hwmon_path = "/sys/class/hwmon"
        log(f"_can_access_hwmon: checking {hwmon_path}", "debug")

        if not os.path.exists(hwmon_path):
            log(f"_can_access_hwmon: {hwmon_path} does not exist", "debug")
            self._set_reason(f"{hwmon_path} does not exist")
            return False

        try:
            devices = os.listdir(hwmon_path)
            log(
                f"_can_access_hwmon: found {len(devices)} hwmon devices: {devices}",
                "debug",
            )

            # Check if we can read any hwmon device
            for device in devices:
                device_path = os.path.join(hwmon_path, device)
                try:
                    all_files = os.listdir(device_path)
                    temp_files = [
                        f
                        for f in all_files
                        if f.startswith("temp") and f.endswith("_input")
                    ]
                    log(
                        f"_can_access_hwmon: {device} has {len(temp_files)} temp files",
                        "debug",
                    )

                    for temp_file in temp_files:
                        temp_path = os.path.join(device_path, temp_file)
                        readable = os.access(temp_path, os.R_OK)
                        log(
                            f"_can_access_hwmon: {temp_path} -> {'READABLE' if readable else 'NOT READABLE'}",
                            "debug",
                        )
                        if readable:
                            log(
                                f"_can_access_hwmon: -> AVAILABLE (found readable sensor)",
                                "debug",
                            )
                            return True
                except Exception as e:
                    log(
                        f"_can_access_hwmon: error reading {device}: {type(e).__name__}: {e}",
                        "debug",
                    )
                    continue

            log(
                "_can_access_hwmon: -> UNAVAILABLE (no readable sensors found)", "debug"
            )
            self._set_reason(f"no readable sensors under {hwmon_path}")
            return False
        except Exception as e:
            log(f"_can_access_hwmon: exception: {type(e).__name__}: {e}", "debug")
            self._set_reason(f"{hwmon_path}: {type(e).__name__}: {e}")
            return False

    def _can_access_gpu(self):
        """Check if NVIDIA GPU is available via pynvml."""
        try:
            import pynvml
        except ImportError:
            log("_can_access_gpu: pynvml not installed", "debug")
            self._set_reason("pynvml not installed")
            return False

        try:
            pynvml.nvmlInit()
        except Exception as e:
            log(f"_can_access_gpu: nvmlInit failed: {e}", "debug")
            self._set_reason(f"nvmlInit failed: {e}")
            return False

        try:
            count = pynvml.nvmlDeviceGetCount()
            available = count > 0
            log(
                f"_can_access_gpu: found {count} GPU(s) -> "
                f"{'AVAILABLE' if available else 'UNAVAILABLE'}",
                "debug",
            )
            if not available:
                self._set_reason("0 GPUs detected")
            return available
        except Exception as e:
            log(f"_can_access_gpu: exception: {type(e).__name__}: {e}", "debug")
            self._set_reason(f"{type(e).__name__}: {e}")
            return False
        finally:
            pynvml.nvmlShutdown()

    def _can_run_zfs(self):
        """Check if zpool commands work."""
        zpool_path = shutil.which("zpool")
        if not zpool_path:
            log("_can_run_zfs: 'zpool' not found in PATH", "debug")
            self._set_reason("zpool not found in PATH")
            return False

        log(f"_can_run_zfs: 'zpool' found at {zpool_path}", "debug")
        log("_can_run_zfs: running 'zpool list -H'", "debug")

        try:
            # Try running zpool list - doesn't need sudo on properly configured systems
            result = subprocess.run(
                ["zpool", "list", "-H"],
                capture_output=True,
                timeout=5,
                env=get_clean_env(),
            )
            stdout = result.stdout.decode("utf-8", errors="ignore").strip()
            stderr = result.stderr.decode("utf-8", errors="ignore").strip()

            log(f"_can_run_zfs: returned code {result.returncode}", "debug")
            if stdout:
                log(f"_can_run_zfs: stdout: {stdout[:DEBUG_OUTPUT_LIMIT]}", "debug")
            if stderr:
                log(f"_can_run_zfs: stderr: {stderr[:DEBUG_OUTPUT_LIMIT]}", "debug")

            # Return code 0 means success, even if no pools exist
            # Return code 1 with "no pools available" is also OK (ZFS works, just no pools)
            if result.returncode == 0:
                log("_can_run_zfs: -> AVAILABLE (returncode 0)", "debug")
                return True
            if "no pools available" in stderr.lower():
                log("_can_run_zfs: -> AVAILABLE (no pools but ZFS works)", "debug")
                return True

            log("_can_run_zfs: -> UNAVAILABLE", "debug")
            detail = stderr.splitlines()[0] if stderr else f"returncode {result.returncode}"
            self._set_reason(f"zpool list: {detail}")
            return False
        except subprocess.TimeoutExpired:
            log("_can_run_zfs: timed out after 5s", "debug")
            self._set_reason("zpool list timed out after 5s")
            return False
        except Exception as e:
            log(f"_can_run_zfs: exception: {type(e).__name__}: {e}", "debug")
            self._set_reason(f"zpool list: {type(e).__name__}: {e}")
            return False

    def _can_access_docker(self):
        """Check if Docker socket is accessible."""
        docker_socket = "/var/run/docker.sock"
        log(f"_can_access_docker: checking {docker_socket}", "debug")

        if not os.path.exists(docker_socket):
            log(f"_can_access_docker: {docker_socket} does not exist", "debug")
            self._set_reason(f"{docker_socket} does not exist")
            return False

        readable = os.access(docker_socket, os.R_OK)
        writable = os.access(docker_socket, os.W_OK)
        accessible = readable and writable

        log(f"_can_access_docker: readable={readable}, writable={writable}", "debug")
        log(
            f"_can_access_docker: -> {'AVAILABLE' if accessible else 'UNAVAILABLE'}",
            "debug",
        )
        if not accessible:
            self._set_reason(
                f"{docker_socket} not accessible (readable={readable}, writable={writable})"
            )
        return accessible

    def _can_access_libvirt(self):
        """Check if libvirt socket is accessible."""
        # Common libvirt socket paths
        socket_paths = [
            "/var/run/libvirt/libvirt-sock-ro",
            "/var/run/libvirt/libvirt-sock",
        ]
        log(f"_can_access_libvirt: checking socket paths: {socket_paths}", "debug")

        for path in socket_paths:
            exists = os.path.exists(path)
            if not exists:
                log(f"_can_access_libvirt: {path} does not exist", "debug")
                continue

            readable = os.access(path, os.R_OK)
            log(f"_can_access_libvirt: {path} exists, readable={readable}", "debug")
            if readable:
                log(f"_can_access_libvirt: -> AVAILABLE (via {path})", "debug")
                return True

        log("_can_access_libvirt: -> UNAVAILABLE (no accessible sockets)", "debug")
        self._set_reason(f"no readable libvirt socket at {' or '.join(socket_paths)}")
        return False

    def _can_access_proxmox(self):
        """Check if Proxmox VE is accessible (local node detection)."""
        # Check if this is a Proxmox node by looking for /etc/pve
        # The API access will be configured separately via credentials
        if os.path.exists("/etc/pve") and os.path.isdir("/etc/pve"):
            return True
        # Also check for pvesh command (Proxmox shell)
        if shutil.which("pvesh"):
            return True
        self._set_reason("/etc/pve missing and pvesh not in PATH")
        return False

    def _has_snmpget(self):
        """Check if net-snmp CLI tools are available."""
        found = shutil.which("snmpget") is not None
        log(
            "_has_snmpget: {}".format("found" if found else "not found"),
            "debug",
        )
        if not found:
            self._set_reason("snmpget not found in PATH")
        return found

    def _can_list_packages(self):
        """Check if a supported package manager is available."""
        for cmd in ("dpkg-query", "rpm", "apk", "pacman", "synopkg"):
            if shutil.which(cmd):
                log(f"_can_list_packages: found '{cmd}'", "debug")
                return True
        log("_can_list_packages: no supported package manager found", "debug")
        self._set_reason("no supported package manager (dpkg-query, rpm, apk, pacman, synopkg)")
        return False

    def _can_query_psutil_sensors(self, kind):
        """Probe psutil hardware-sensor support on Windows.

        kind is 'temperatures' or 'fans'. psutil docs list these as Linux/FreeBSD
        only - on Windows the attribute typically does not exist or returns
        empty. Treat 'method exists and returns at least one sensor' as True.
        """
        attr = f"sensors_{kind}"
        try:
            method = getattr(psutil, attr)
        except AttributeError as e:
            self._set_reason(f"psutil.{attr} unavailable: {e}")
            return False
        try:
            data = method()
        except (OSError, NotImplementedError) as e:
            self._set_reason(f"psutil.{attr} call failed: {e}")
            return False
        if data:
            return True
        self._set_reason(f"psutil.{attr} reported no sensors")
        return False

    def _can_query_wmi_storage(self):
        """Probe whether WMI Storage namespace queries are likely to work.

        Light check: the wmi package must import (pywin32 + wmi installed).
        The actual disk-health collector runs subprocess-isolated and handles
        WMI runtime errors there (D11). Hung/wedged WMI is the collector's
        problem, not the probe's.
        """
        try:
            import wmi  # type: ignore[import-not-found]  # noqa: F401
        except ImportError as e:
            self._set_reason(f"wmi package not installed: {e}")
            return False
        return True

    def _can_read_uninstall_registry(self):
        """Probe whether the Windows Uninstall registry key opens read-only."""
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError as e:
            self._set_reason(f"winreg unavailable: {e}")
            return False
        try:
            key = winreg.OpenKey(  # type: ignore[attr-defined]
                winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined]
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            )
            winreg.CloseKey(key)  # type: ignore[attr-defined]
            return True
        except OSError as e:
            self._set_reason(f"Uninstall registry key unreadable: {e}")
            return False

    def get(self, capability, default=False):
        """Get a specific capability status."""
        return self.capabilities.get(capability, default)

    def get_all(self):
        """Get all capability statuses."""
        return self.capabilities.copy()

    def get_reasons(self):
        """Return {capability: reason} for capabilities currently unavailable.

        Reason is a short string captured by the probe method (e.g.,
        "nvmlInit failed: NVML Shared Library Not Found"). Sent to the
        backend in static_data so dashboards can show per-host failure
        reasons without an SSH session.
        """
        return self._capability_reasons.copy()

    def get_unavailable(self):
        """Get list of unavailable capabilities."""
        return [cap for cap, available in self.capabilities.items() if not available]

    def get_available(self):
        """Get list of available capabilities."""
        return [cap for cap, available in self.capabilities.items() if available]


# Global instance - initialized lazily
_probe = None


def get_permissions():
    """Get or create the global PermissionProbe instance."""
    global _probe
    if _probe is None:
        _probe = PermissionProbe()
    return _probe


def print_capabilities_banner():
    """Print a banner showing available and unavailable capabilities."""
    probe = get_permissions()
    caps = probe.get_all()

    groups = WINDOWS_BANNER_GROUPS if is_windows() else LINUX_BANNER_GROUPS
    core_metrics = groups[0][1]  # first group is always Core Metrics

    print("")
    print("=" * 60)
    print("  Fivenines Agent - Capabilities Detection")
    print("=" * 60)
    print("")

    def print_section(title, caps_list):
        print(f"  {title}:")
        for cap in caps_list:
            status = caps.get(cap, False)
            icon = "[+]" if status else "[-]"
            name = cap.replace("_", " ").title()

            hint = ""
            if not status and cap in CAPABILITY_HINTS:
                hint = f" ({CAPABILITY_HINTS[cap]})"

            print(f"    {icon} {name}{hint}")
        print("")

    for title, caps_list in groups:
        print_section(title, caps_list)

    unavailable = probe.get_unavailable()
    if unavailable:
        # Filter out core metrics that shouldn't fail
        important_unavailable = [c for c in unavailable if c not in core_metrics]
        if important_unavailable:
            print(
                "  [!] Some features unavailable. See: https://docs.fivenines.io/agent/permissions"
            )
    else:
        print("  [+] Full monitoring capabilities available")

    print("")
    print("=" * 60)
    print("")
