#!/bin/bash
# This script is used to uninstall the fivenines agent

# Stop the fivenines-agent service
if systemctl is-active --quiet fivenines-agent.service; then
  echo "Stopping fivenines-agent service..."
  sudo systemctl stop fivenines-agent.service
else
  echo "fivenines-agent service is not running."
fi

# Disable the fivenines-agent service
if systemctl is-enabled --quiet fivenines-agent.service; then
  echo "Disabling fivenines-agent service..."
  sudo systemctl disable fivenines-agent.service
else
  echo "fivenines-agent service is not enabled."
fi

# Remove the fivenines-agent service file
if [ -f /etc/systemd/system/fivenines-agent.service ]; then
  echo "Removing fivenines-agent.service file..."
  sudo rm /etc/systemd/system/fivenines-agent.service
fi

# Reload systemd daemon
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Uninstall fivenines_agent
if su - fivenines -s /bin/bash -c 'pipx list | grep -q fivenines_agent'; then
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
  sudo userdel -r fivenines
else
  echo "System user fivenines does not exist."
fi

rm fivenines_uninstall.sh

echo "fivenines agent uninstallation complete."
