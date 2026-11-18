#!/bin/sh
# This script is used to uninstall the fivenines agent

# userdel, deluser, rc-update and the like live in the sbin directories,
# which a root shell reached through su without -, or a sudo that keeps the
# caller's PATH (sudo-rs reports no secure_path), may not search: each
# removal would then fail as "not found".
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
export PATH

# Check if running as root (use `id -u` for BusyBox/ash compatibility)
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root"
  exit 1
fi

detect_system() {
  if command -v rc-service >/dev/null 2>&1 && [ -d "/etc/init.d" ]; then
    echo "openrc"
  elif command -v systemctl >/dev/null 2>&1 && [ -d "/etc/systemd/system" ]; then
    echo "systemd"
  else
    echo "unknown"
  fi
}

cleanup_selinux_contexts() {
  # Detect SELinux using getenforce (same as setup script)
  if command -v getenforce >/dev/null 2>&1; then
    selinux_mode=$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')
  elif command -v sestatus >/dev/null 2>&1; then
    selinux_mode=$(sestatus 2>/dev/null | awk -F: '/^Current mode:/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print tolower($2)}')
  else
    echo "SELinux is not installed on this system."
    return 0
  fi

  if [ -z "$selinux_mode" ] || [ "$selinux_mode" = "disabled" ]; then
    echo "SELinux status: Disabled"
    return 0
  fi

  echo "Cleaning up SELinux policy module and contexts..."

  if command -v semodule >/dev/null 2>&1; then
    # Remove from multiple priorities to match setup behavior.
    # NOTE: keep in sync with setup_selinux_contexts() in fivenines_setup.sh
    semodule -X 400 -r fivenines_agent 2>/dev/null || true
    semodule -X 100 -r fivenines_agent 2>/dev/null || true
    semodule -r fivenines_agent 2>/dev/null || true
    # Remove optional modules
    semodule -r fivenines_agent_docker 2>/dev/null || true
    semodule -r fivenines_agent_libvirt 2>/dev/null || true
  fi

  if command -v semanage >/dev/null 2>&1; then
    # Remove potential custom fcontext rules from older/manual installs.
    semanage fcontext -d "/opt/fivenines(/.*)?" 2>/dev/null || true
    semanage fcontext -d "/etc/fivenines_agent(/.*)?" 2>/dev/null || true
    semanage fcontext -d "/boot/config/custom/fivenines_agent(/.*)?" 2>/dev/null || true
    semanage fcontext -d "/var/log/fivenines-agent.log" 2>/dev/null || true
  fi

  if command -v restorecon >/dev/null 2>&1; then
    if [ -d /opt/fivenines ]; then restorecon -Rv /opt/fivenines 2>/dev/null || true; fi
    if [ -d /etc/fivenines_agent ]; then restorecon -Rv /etc/fivenines_agent 2>/dev/null || true; fi
    if [ -d /boot/config/custom/fivenines_agent ]; then restorecon -Rv /boot/config/custom/fivenines_agent 2>/dev/null || true; fi
    if [ -f /var/log/fivenines-agent.log ]; then restorecon -v /var/log/fivenines-agent.log 2>/dev/null || true; fi
    if [ -f /etc/systemd/system/fivenines-agent.service ]; then restorecon -v /etc/systemd/system/fivenines-agent.service 2>/dev/null || true; fi
    if [ -f /etc/init.d/fivenines-agent ]; then restorecon -v /etc/init.d/fivenines-agent 2>/dev/null || true; fi
  fi
}

# Test mode: skip service management for CI testing
if [ "${FIVENINES_TEST_MODE:-}" = "1" ]; then
  echo "WARNING: Test mode enabled - skipping service management"
fi

SYSTEM_TYPE=$(detect_system)

# This script runs as root (checked above), so nothing below goes through
# sudo: on a host where root has no sudo (a minimal image, a container), every
# removal failed with "sudo: not found" and the script still ended with
# "complete" and exit 0, leaving the service, its TOKEN and the account (#302).
# Each failed step is said, and makes the exit status 1.
UNINSTALL_FAILED=0
step_failed() {
  echo "ERROR: $1"
  UNINSTALL_FAILED=1
}

# Clean up SELinux contexts before removing files
cleanup_selinux_contexts

# Service management (skip in test mode)
if [ "${FIVENINES_TEST_MODE:-}" != "1" ]; then
  if [ "$SYSTEM_TYPE" = "openrc" ]; then
    # OpenRC: Stop the service
    if rc-service fivenines-agent status >/dev/null 2>&1; then
      echo "Stopping fivenines-agent service..."
      rc-service fivenines-agent stop || step_failed "could not stop the fivenines-agent service."
    else
      echo "fivenines-agent service is not running."
    fi

    # OpenRC: Remove from default runlevel
    if rc-update show default | grep -q fivenines-agent; then
      echo "Removing fivenines-agent from default runlevel..."
      rc-update del fivenines-agent default || step_failed "could not remove fivenines-agent from the default runlevel."
    fi

    # OpenRC: Remove the init script
    if [ -f /etc/init.d/fivenines-agent ]; then
      echo "Removing fivenines-agent init script..."
      rm -f /etc/init.d/fivenines-agent || step_failed "could not remove /etc/init.d/fivenines-agent."
    fi
  else
    # systemd: Stop the service
    if systemctl is-active --quiet fivenines-agent.service; then
      echo "Stopping fivenines-agent service..."
      systemctl stop fivenines-agent.service || step_failed "could not stop the fivenines-agent service."
    else
      echo "fivenines-agent service is not running."
    fi

    # systemd: Disable the service
    if systemctl is-enabled --quiet fivenines-agent.service; then
      echo "Disabling fivenines-agent service..."
      systemctl disable fivenines-agent.service || step_failed "could not disable the fivenines-agent service."
    else
      echo "fivenines-agent service is not enabled."
    fi

    # systemd: Remove the service file
    if [ -f /etc/systemd/system/fivenines-agent.service ]; then
      echo "Removing fivenines-agent.service file..."
      rm -f /etc/systemd/system/fivenines-agent.service || step_failed "could not remove /etc/systemd/system/fivenines-agent.service."
    fi

    # systemd: Reload daemon
    echo "Reloading systemd daemon..."
    systemctl daemon-reload || true
  fi
else
  echo "Skipping service management (test mode)"
fi

# Uninstall fivenines_agent (legacy pipx)
if su - fivenines -s /bin/bash -c 'pipx list | grep -q fivenines_agent' 2>/dev/null; then
  echo "Uninstalling fivenines_agent..."
  su - fivenines -s /bin/bash -c 'pipx uninstall fivenines_agent' || true
else
  echo "fivenines_agent is not installed."
fi

# Remove the /etc/fivenines_agent directory
if [ -d /etc/fivenines_agent ]; then
  echo "Removing /etc/fivenines_agent directory..."
  rm -rf /etc/fivenines_agent || step_failed "could not remove /etc/fivenines_agent, which holds the agent's TOKEN."
else
  echo "/etc/fivenines_agent directory does not exist."
fi

# Remove the sudoers rules the installer wrote (--with-sudoers), recognised by
# their first line. A file without it was written by the operator: it is left,
# and said, since its rules name the user removed below.
SUDOERS_MARKER="# Managed by the fivenines agent installer (--with-sudoers)"
if [ -f /etc/sudoers.d/fivenines ]; then
  if head -n 1 /etc/sudoers.d/fivenines | grep -qxF "$SUDOERS_MARKER"; then
    echo "Removing /etc/sudoers.d/fivenines..."
    rm -f /etc/sudoers.d/fivenines || step_failed "could not remove /etc/sudoers.d/fivenines."
  else
    echo "/etc/sudoers.d/fivenines was not written by the installer: left in place (its rules name the fivenines user)."
  fi
fi

# Remove the system user for the agent
if id -u fivenines >/dev/null 2>&1; then
  echo "Removing system user fivenines..."
  if [ "$SYSTEM_TYPE" = "openrc" ]; then
    deluser --remove-home fivenines 2>/dev/null || userdel -r fivenines 2>/dev/null || true
    delgroup fivenines 2>/dev/null || true
  else
    userdel -r fivenines
  fi
  if id -u fivenines >/dev/null 2>&1; then
    step_failed "could not remove the system user fivenines."
  fi
else
  echo "System user fivenines does not exist."
fi

rm -f fivenines_uninstall.sh 2>/dev/null || true

if [ "$UNINSTALL_FAILED" != "0" ]; then
  echo "fivenines agent uninstallation finished with errors (see above)."
  exit 1
fi
echo "fivenines agent uninstallation complete."
