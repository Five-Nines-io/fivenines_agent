#!/bin/sh
# This script is used to uninstall the fivenines agent

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
  if ! command -v sestatus >/dev/null 2>&1; then
    echo "SELinux is not installed on this system."
    return 0
  fi

  selinux_mode=$(sestatus 2>/dev/null | awk -F: '/^Current mode:/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}')
  if [ -z "$selinux_mode" ] || [ "$selinux_mode" = "disabled" ] || [ "$selinux_mode" = "Disabled" ]; then
    echo "SELinux status: Disabled"
    return 0
  fi

  echo "Cleaning up SELinux policy module and contexts..."

  if command -v semodule >/dev/null 2>&1; then
    # Remove from multiple priorities to match setup behavior.
    semodule -X 400 -r fivenines_agent 2>/dev/null || true
    semodule -X 100 -r fivenines_agent 2>/dev/null || true
    semodule -r fivenines_agent 2>/dev/null || true
  fi

  if command -v semanage >/dev/null 2>&1; then
    # Remove potential custom fcontext rules from older/manual installs.
    semanage fcontext -d "/opt/fivenines(/.*)?" 2>/dev/null || true
    semanage fcontext -d "/etc/fivenines_agent(/.*)?" 2>/dev/null || true
    semanage fcontext -d "/boot/config/custom/fivenines_agent(/.*)?" 2>/dev/null || true
    semanage fcontext -d "/var/log/fivenines-agent.log" 2>/dev/null || true
  fi

  if command -v restorecon >/dev/null 2>&1; then
    restorecon -Rv /opt/fivenines /etc/fivenines_agent /boot/config/custom/fivenines_agent 2>/dev/null || true
    restorecon -v /var/log/fivenines-agent.log 2>/dev/null || true
    restorecon -v /etc/systemd/system/fivenines-agent.service 2>/dev/null || true
    restorecon -v /etc/init.d/fivenines-agent 2>/dev/null || true
  fi
}

SYSTEM_TYPE=$(detect_system)

cleanup_selinux_contexts

if [ "$SYSTEM_TYPE" = "openrc" ]; then
  # OpenRC: Stop the service
  if rc-service fivenines-agent status >/dev/null 2>&1; then
    echo "Stopping fivenines-agent service..."
    sudo rc-service fivenines-agent stop
  else
    echo "fivenines-agent service is not running."
  fi

  # OpenRC: Remove from default runlevel
  if rc-update show default | grep -q fivenines-agent; then
    echo "Removing fivenines-agent from default runlevel..."
    sudo rc-update del fivenines-agent default
  fi

  # OpenRC: Remove the init script
  if [ -f /etc/init.d/fivenines-agent ]; then
    echo "Removing fivenines-agent init script..."
    sudo rm /etc/init.d/fivenines-agent
  fi
else
  # systemd: Stop the service
  if systemctl is-active --quiet fivenines-agent.service; then
    echo "Stopping fivenines-agent service..."
    sudo systemctl stop fivenines-agent.service
  else
    echo "fivenines-agent service is not running."
  fi

  # systemd: Disable the service
  if systemctl is-enabled --quiet fivenines-agent.service; then
    echo "Disabling fivenines-agent service..."
    sudo systemctl disable fivenines-agent.service
  else
    echo "fivenines-agent service is not enabled."
  fi

  # systemd: Remove the service file
  if [ -f /etc/systemd/system/fivenines-agent.service ]; then
    echo "Removing fivenines-agent.service file..."
    sudo rm /etc/systemd/system/fivenines-agent.service
  fi

  # systemd: Reload daemon
  echo "Reloading systemd daemon..."
  sudo systemctl daemon-reload
fi

# Uninstall fivenines_agent (legacy pipx)
if su - fivenines -s /bin/bash -c 'pipx list | grep -q fivenines_agent' 2>/dev/null; then
  echo "Uninstalling fivenines_agent..."
  sudo su - fivenines -s /bin/bash -c 'pipx uninstall fivenines_agent'
else
  echo "fivenines_agent is not installed."
fi

# Remove the /etc/fivenines_agent directory
if [ -d /etc/fivenines_agent ]; then
  echo "Removing /etc/fivenines_agent directory..."
  sudo rm -rf /etc/fivenines_agent
else
  echo "/etc/fivenines_agent directory does not exist."
fi

# Remove the system user for the agent
if id -u fivenines >/dev/null 2>&1; then
  echo "Removing system user fivenines..."
  if [ "$SYSTEM_TYPE" = "openrc" ]; then
    sudo deluser --remove-home fivenines 2>/dev/null || sudo userdel -r fivenines 2>/dev/null || true
    sudo delgroup fivenines 2>/dev/null || true
  else
    sudo userdel -r fivenines
  fi
else
  echo "System user fivenines does not exist."
fi

rm fivenines_uninstall.sh

echo "fivenines agent uninstallation complete."
