#!/bin/bash
# This script is used to uninstall the fivenines agent

function detect_system() {
  if command -v rc-service >/dev/null 2>&1 && [ -d "/etc/init.d" ]; then
    echo "openrc"
  elif command -v systemctl >/dev/null 2>&1 && [ -d "/etc/systemd/system" ]; then
    echo "systemd"
  else
    echo "unknown"
  fi
}

SYSTEM_TYPE=$(detect_system)

if [ "$SYSTEM_TYPE" == "openrc" ]; then
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
  if [ "$SYSTEM_TYPE" == "openrc" ]; then
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
