"""
Permission probing for fivenines agent.
Detects what capabilities are available based on user permissions.
"""

import os
import shutil
import subprocess
import time

from fivenines_agent.debug import log
from fivenines_agent.subprocess_utils import get_clean_env


# Re-probe interval in seconds (5 minutes)
REPROBE_INTERVAL = 300

# Max chars for stdout/stderr in debug logs
DEBUG_OUTPUT_LIMIT = 500


class PermissionProbe:
    """
    Probes system to detect available monitoring capabilities.
    Automatically re-probes periodically to detect permission changes.
    """

    def __init__(self):
        self.capabilities = {}
        self._last_probe_time = 0
        self._probe_all()

    def _probe_all(self):
        """Probe all capabilities and cache results."""
        self._last_probe_time = time.time()
        old_capabilities = self.capabilities.copy()

        self.capabilities = {
            # Core metrics - always available via /proc
            "cpu": self._can_read("/proc/stat"),
            "memory": self._can_read("/proc/meminfo"),
            "load_average": self._can_read("/proc/loadavg"),
            "io": self._can_read("/proc/diskstats"),
            "network": self._can_read("/proc/net/dev"),
            "partitions": self._can_read("/proc/mounts"),
            "file_handles": self._can_read("/proc/sys/fs/file-nr"),
            "ports": self._can_read("/proc/net/tcp"),
            # Processes - works but may have limited visibility
            "processes": self._can_read("/proc/self/stat"),
            # Hardware sensors - may or may not work without root
            "temperatures": self._can_access_hwmon(),
            "fans": self._can_access_hwmon(),
            # Storage requiring sudo
            "smart_storage": self._can_run_sudo("smartctl", "--version"),
            "raid_storage": self._can_run_sudo("mdadm", "--version"),
            # Security - requires sudo
            "fail2ban": self._can_run_sudo("fail2ban-client", "status"),
            # ZFS - doesn't need sudo but needs permissions or delegation
            "zfs": self._can_run_zfs(),
            # Docker - needs docker group membership
            "docker": self._can_access_docker(),
            # QEMU/libvirt - needs libvirt group membership
            "qemu": self._can_access_libvirt(),
            # Proxmox VE - needs API access or local node
            "proxmox": self._can_access_proxmox(),
            # Package listing - for security scanning
            "packages": self._can_list_packages(),
        }

        # Log any capability changes (only after first probe)
        if old_capabilities:
            for cap, available in self.capabilities.items():
                old_value = old_capabilities.get(cap)
                if old_value is not None and old_value != available:
                    if available:
                        log(f"Capability '{cap}' is now AVAILABLE", "info")
                    else:
                        log(f"Capability '{cap}' is now UNAVAILABLE", "info")

        return self.capabilities

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
                return False

            readable = os.access(path, os.R_OK)
            log(
                f"_can_read: '{path}' -> {'READABLE' if readable else 'NOT READABLE'}",
                "debug",
            )
            return readable
        except Exception as e:
            log(f"_can_read: '{path}' exception: {type(e).__name__}: {e}", "debug")
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
            return success
        except subprocess.TimeoutExpired:
            log(f"_can_run_sudo: '{cmd}' timed out after 5s", "debug")
            return False
        except Exception as e:
            log(f"_can_run_sudo: '{cmd}' exception: {type(e).__name__}: {e}", "debug")
            return False

    def _can_access_hwmon(self):
        """Check if hardware monitoring sensors are readable."""
        hwmon_path = "/sys/class/hwmon"
        log(f"_can_access_hwmon: checking {hwmon_path}", "debug")

        if not os.path.exists(hwmon_path):
            log(f"_can_access_hwmon: {hwmon_path} does not exist", "debug")
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
            return False
        except Exception as e:
            log(f"_can_access_hwmon: exception: {type(e).__name__}: {e}", "debug")
            return False

    def _can_run_zfs(self):
        """Check if zpool commands work."""
        zpool_path = shutil.which("zpool")
        if not zpool_path:
            log("_can_run_zfs: 'zpool' not found in PATH", "debug")
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
            return False
        except subprocess.TimeoutExpired:
            log("_can_run_zfs: timed out after 5s", "debug")
            return False
        except Exception as e:
            log(f"_can_run_zfs: exception: {type(e).__name__}: {e}", "debug")
            return False

    def _can_access_docker(self):
        """Check if Docker socket is accessible."""
        docker_socket = "/var/run/docker.sock"
        log(f"_can_access_docker: checking {docker_socket}", "debug")

        if not os.path.exists(docker_socket):
            log(f"_can_access_docker: {docker_socket} does not exist", "debug")
            return False

        readable = os.access(docker_socket, os.R_OK)
        writable = os.access(docker_socket, os.W_OK)
        accessible = readable and writable

        log(f"_can_access_docker: readable={readable}, writable={writable}", "debug")
        log(
            f"_can_access_docker: -> {'AVAILABLE' if accessible else 'UNAVAILABLE'}",
            "debug",
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
        return False

    def _can_list_packages(self):
        """Check if a supported package manager is available."""
        for cmd in ("dpkg-query", "rpm", "apk", "pacman", "synopkg"):
            if shutil.which(cmd):
                log(f"_can_list_packages: found '{cmd}'", "debug")
                return True
        log("_can_list_packages: no supported package manager found", "debug")
        return False

    def get(self, capability, default=False):
        """Get a specific capability status."""
        return self.capabilities.get(capability, default)

    def get_all(self):
        """Get all capability statuses."""
        return self.capabilities.copy()

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

    # Group capabilities for display
    core_metrics = [
        "cpu",
        "memory",
        "load_average",
        "io",
        "network",
        "partitions",
        "file_handles",
        "ports",
        "processes",
    ]
    hardware = ["temperatures", "fans"]
    storage = ["smart_storage", "raid_storage", "zfs"]
    services = ["docker", "qemu", "proxmox"]
    security = ["fail2ban", "packages"]

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

            # Add hints for unavailable features
            hint = ""
            if not status:
                if cap == "smart_storage":
                    hint = " (requires: sudo smartctl)"
                elif cap == "raid_storage":
                    hint = " (requires: sudo mdadm)"
                elif cap == "docker":
                    hint = " (requires: docker group)"
                elif cap == "qemu":
                    hint = " (requires: libvirt group)"
                elif cap == "proxmox":
                    hint = " (requires: Proxmox VE host)"
                elif cap == "fail2ban":
                    hint = " (requires: sudo fail2ban-client)"
                elif cap == "packages":
                    hint = " (requires: dpkg-query, rpm, apk, pacman, or synopkg)"
                elif cap == "zfs":
                    hint = " (requires: zfs permissions)"
                elif cap in ["temperatures", "fans"]:
                    hint = " (no accessible sensors)"

            print(f"    {icon} {name}{hint}")
        print("")

    print_section("Core Metrics", core_metrics)
    print_section("Hardware Sensors", hardware)
    print_section("Storage", storage)
    print_section("Services", services)
    print_section("Security", security)

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
