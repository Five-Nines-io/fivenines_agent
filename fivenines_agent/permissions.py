"""
Permission probing for fivenines agent.
Detects what capabilities are available based on user permissions.
"""

import os
import subprocess
import shutil
import time
from fivenines_agent.debug import log

# Re-probe interval in seconds (5 minutes)
REPROBE_INTERVAL = 300


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
            'cpu': self._can_read('/proc/stat'),
            'memory': self._can_read('/proc/meminfo'),
            'load_average': self._can_read('/proc/loadavg'),
            'io': self._can_read('/proc/diskstats'),
            'network': self._can_read('/proc/net/dev'),
            'partitions': self._can_read('/proc/mounts'),
            'file_handles': self._can_read('/proc/sys/fs/file-nr'),
            'ports': self._can_read('/proc/net/tcp'),

            # Processes - works but may have limited visibility
            'processes': self._can_read('/proc/self/stat'),

            # Hardware sensors - may or may not work without root
            'temperatures': self._can_access_hwmon(),
            'fans': self._can_access_hwmon(),

            # Storage requiring sudo
            'smart_storage': self._can_run_sudo('smartctl', '--version'),
            'raid_storage': self._can_run_sudo('mdadm', '--version'),

            # Security - requires sudo
            'fail2ban': self._can_run_sudo('fail2ban-client', 'status'),

            # ZFS - doesn't need sudo but needs permissions or delegation
            'zfs': self._can_run_zfs(),

            # Docker - needs docker group membership
            'docker': self._can_access_docker(),

            # QEMU/libvirt - needs libvirt group membership
            'qemu': self._can_access_libvirt(),
        }

        # Log any capability changes (only after first probe)
        if old_capabilities:
            for cap, available in self.capabilities.items():
                old_value = old_capabilities.get(cap)
                if old_value is not None and old_value != available:
                    if available:
                        log(f"Capability '{cap}' is now AVAILABLE", 'info')
                    else:
                        log(f"Capability '{cap}' is now UNAVAILABLE", 'info')

        return self.capabilities

    def refresh_if_needed(self):
        """Re-probe capabilities if enough time has passed."""
        if time.time() - self._last_probe_time >= REPROBE_INTERVAL:
            log("Re-probing capabilities...", 'debug')
            self._probe_all()
            return True
        return False

    def force_refresh(self):
        """Force an immediate re-probe of capabilities."""
        log("Force re-probing capabilities...", 'info')
        self._probe_all()
        return self.capabilities

    def _can_read(self, path):
        """Check if a file/directory is readable."""
        try:
            return os.access(path, os.R_OK)
        except Exception:
            return False

    def _can_run_sudo(self, cmd, *args):
        """
        Check if we can run a command with sudo non-interactively.
        Uses sudo -n which fails immediately if password is required.
        """
        if not shutil.which(cmd):
            return False

        try:
            result = subprocess.run(
                ['sudo', '-n', cmd, *args],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False

    def _can_access_hwmon(self):
        """Check if hardware monitoring sensors are readable."""
        hwmon_path = '/sys/class/hwmon'
        if not os.path.exists(hwmon_path):
            return False

        try:
            # Check if we can read any hwmon device
            for device in os.listdir(hwmon_path):
                device_path = os.path.join(hwmon_path, device)
                temp_files = [f for f in os.listdir(device_path) if f.startswith('temp') and f.endswith('_input')]
                for temp_file in temp_files:
                    temp_path = os.path.join(device_path, temp_file)
                    if os.access(temp_path, os.R_OK):
                        return True
            return False
        except Exception:
            return False

    def _can_run_zfs(self):
        """Check if zpool commands work."""
        if not shutil.which('zpool'):
            return False

        try:
            # Try running zpool list - doesn't need sudo on properly configured systems
            result = subprocess.run(
                ['zpool', 'list', '-H'],
                capture_output=True,
                timeout=5
            )
            # Return code 0 means success, even if no pools exist
            # Return code 1 with "no pools available" is also OK (ZFS works, just no pools)
            if result.returncode == 0:
                return True
            stderr = result.stderr.decode('utf-8', errors='ignore').lower()
            if 'no pools available' in stderr:
                return True
            return False
        except Exception:
            return False

    def _can_access_docker(self):
        """Check if Docker socket is accessible."""
        docker_socket = '/var/run/docker.sock'
        if not os.path.exists(docker_socket):
            return False
        return os.access(docker_socket, os.R_OK | os.W_OK)

    def _can_access_libvirt(self):
        """Check if libvirt socket is accessible."""
        # Common libvirt socket paths
        socket_paths = [
            '/var/run/libvirt/libvirt-sock-ro',
            '/var/run/libvirt/libvirt-sock',
        ]
        for path in socket_paths:
            if os.path.exists(path) and os.access(path, os.R_OK):
                return True
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
    core_metrics = ['cpu', 'memory', 'load_average', 'io', 'network', 'partitions', 'file_handles', 'ports', 'processes']
    hardware = ['temperatures', 'fans']
    storage = ['smart_storage', 'raid_storage', 'zfs']
    services = ['docker', 'qemu']
    security = ['fail2ban']

    print("")
    print("=" * 60)
    print("  Fivenines Agent - Capabilities Detection")
    print("=" * 60)
    print("")

    def print_section(title, caps_list):
        print(f"  {title}:")
        for cap in caps_list:
            status = caps.get(cap, False)
            icon = "[OK]" if status else "[X]"
            name = cap.replace('_', ' ').title()

            # Add hints for unavailable features
            hint = ""
            if not status:
                if cap == 'smart_storage':
                    hint = " (requires: sudo smartctl)"
                elif cap == 'raid_storage':
                    hint = " (requires: sudo mdadm)"
                elif cap == 'docker':
                    hint = " (requires: docker group)"
                elif cap == 'qemu':
                    hint = " (requires: libvirt group)"
                elif cap == 'fail2ban':
                    hint = " (requires: sudo fail2ban-client)"
                elif cap == 'zfs':
                    hint = " (requires: zfs permissions)"
                elif cap in ['temperatures', 'fans']:
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
            print("  [!] Some features unavailable. See: https://docs.fivenines.io/agent/permissions")
    else:
        print("  [OK] Full monitoring capabilities available")

    print("")
    print("=" * 60)
    print("")
