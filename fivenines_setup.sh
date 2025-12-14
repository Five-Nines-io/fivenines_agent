#!/bin/bash

# Fivenines Agent Setup Script
# Works on both standard Linux systems (systemd) and UNRAID

function exit_with_contact() {
  echo "Error: $1"
  echo "Please contact sebastien@fivenines.io for assistance."
  exit 1
}

function detect_system() {
  # Check if this is UNRAID
  if [ -f "/etc/unraid-version" ] || [ -d "/boot/config" ]; then
    echo "unraid"
    return
  fi

  # Check if systemd is available
  if command -v systemctl &> /dev/null && [ -d "/etc/systemd/system" ]; then
    echo "systemd"
    return
  fi

  # Fallback - check for other init systems
  if [ -f "/sbin/init" ]; then
    init_system=$(readlink -f /sbin/init)
    case "$init_system" in
      *systemd*)
        echo "systemd"
        ;;
      *)
        echo "other"
        ;;
    esac
  else
    echo "unknown"
  fi
}

function setup_systemd() {
  echo "Detected systemd system - using systemd service"

  # Download the service file
  wget --connect-timeout=3 https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines-agent.service -O fivenines-agent.service || exit_with_contact "Failed to download systemd service file"

  # Move the service file to the systemd directory
  mv fivenines-agent.service /etc/systemd/system/

  # Reload the service files to include the new fivenines-agent service
  systemctl daemon-reload

  # Enable fivenines-agent service on every reboot
  systemctl enable fivenines-agent.service

  # Start the fivenines-agent
  systemctl start fivenines-agent

  if [ $? -ne 0 ]; then
    exit_with_contact "Failed to start the fivenines-agent service. Check the system logs for more information."
  fi

  echo "Systemd service installed and started successfully"
}

function setup_unraid() {
  echo "Starting fivenines agent..."

  wget --connect-timeout=3 https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines_script.sh -O /boot/config/custom/fivenines_agent/fivenines_boot || exit_with_contact "Failed to download fivenines_script.sh"

  chmod 755 /boot/config/custom/fivenines_agent/fivenines_boot

  bash /boot/config/custom/fivenines_agent/fivenines_boot

  sleep 3

  if pgrep -f "fivenines_agent" > /dev/null; then
    echo "Fivenines agent is running (PID: $(pgrep -f "fivenines_agent"))"
    if ! grep -q "fivenines_boot" /boot/config/go; then
      echo "Adding fivenines agent to go startup"
      echo "# Start fivenines agent on boot" >> /boot/config/go
      echo "bash /boot/config/custom/fivenines_agent/fivenines_boot" >> /boot/config/go
    else
      echo "Fivenines agent is already in go startup"
    fi
  else
    exit_with_contact "Failed to start fivenines agent. Check /var/log/fivenines-agent.log for details."
  fi
}

# Main execution starts here

# Check that token parameter is present
if [ $# -eq 0 ] ; then
  echo 'Usage: ./setup.sh CLIENT_TOKEN'
  exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  exit_with_contact "This script must be run as root"
fi

# Detect system type
SYSTEM_TYPE=$(detect_system)
echo "Detected system type: $SYSTEM_TYPE"

# Check if SELinux is installed
if command -v getenforce &> /dev/null; then
  selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
  echo "SELinux status: $selinux_status"
  if [ "$selinux_status" == "Enforcing" ]; then
    exit_with_contact "SELinux is enabled in enforcing mode. fivenines agent will not work without disabling SELinux."
  fi
else
  echo "SELinux is not installed on this system."
fi

# Create a system user for the agent first
if ! id -u fivenines >/dev/null 2>&1; then
  echo "Creating system user fivenines"
  if [ "$SYSTEM_TYPE" == "unraid" ]; then
    useradd --system --user-group fivenines --shell /bin/false --create-home
  else
    useradd --system --user-group --key USERGROUPS_ENAB=yes fivenines --shell /bin/false --create-home -b /opt/
  fi
fi

# CloudLinux: add fivenines to clsupergid group for proper permissions
if [ -f "/etc/cloudlinux-release" ]; then
  echo "CloudLinux detected"
  if getent group clsupergid >/dev/null 2>&1; then
    echo "Adding fivenines user to clsupergid group"
    usermod -a -G clsupergid fivenines
  fi
fi

mkdir -p /etc/fivenines_agent
# Save the client token in appropriate location
if [ "$SYSTEM_TYPE" == "unraid" ]; then
  mkdir -p /boot/config/custom/fivenines_agent
  echo -n "$1" | tee /boot/config/custom/fivenines_agent/TOKEN > /dev/null
  chown fivenines:fivenines /boot/config/custom/fivenines_agent/TOKEN
  chmod 600 /boot/config/custom/fivenines_agent/TOKEN
else
  # Use standard location for other systems
  echo -n "$1" | tee /etc/fivenines_agent/TOKEN > /dev/null
  chown fivenines:fivenines /etc/fivenines_agent/TOKEN
  chmod 600 /etc/fivenines_agent/TOKEN
fi

CURRENT_ARCH=$(uname -m)

# Set install directory and binary name based on system type and architecture
if [ "$SYSTEM_TYPE" == "unraid" ]; then
  INSTALL_DIR="/boot/config/custom/fivenines_agent"
else
  INSTALL_DIR="/opt/fivenines"
fi

# Ensure install directory exists
mkdir -p "$INSTALL_DIR"

# Download the agent tarball based on the architecture
echo "Detected architecture: $CURRENT_ARCH"
if [ "$CURRENT_ARCH" == "aarch64" ]; then
  BINARY_NAME="fivenines-agent-linux-arm64"
  DOWNLOAD_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/latest/download/fivenines-agent-linux-arm64.tar.gz"
else
  BINARY_NAME="fivenines-agent-linux-amd64"
  DOWNLOAD_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/latest/download/fivenines-agent-linux-amd64.tar.gz"
fi

TARBALL_PATH="/tmp/${BINARY_NAME}.tar.gz"
AGENT_DIR="${INSTALL_DIR}/${BINARY_NAME}"
AGENT_EXECUTABLE="${AGENT_DIR}/${BINARY_NAME}"

echo "Downloading agent from $DOWNLOAD_URL..."
wget --connect-timeout=3 "$DOWNLOAD_URL" -O "$TARBALL_PATH" || exit_with_contact "Failed to download agent"

# Remove old installation if it exists
if [ -d "$AGENT_DIR" ]; then
  echo "Removing previous installation..."
  rm -rf "$AGENT_DIR"
fi

# Extract the tarball
echo "Extracting agent to $INSTALL_DIR..."
tar -xzf "$TARBALL_PATH" -C "$INSTALL_DIR" || exit_with_contact "Failed to extract agent"

# Clean up the tarball
rm -f "$TARBALL_PATH"

# Verify extraction was successful
if [ ! -f "$AGENT_EXECUTABLE" ]; then
  exit_with_contact "Agent executable not found after extraction at $AGENT_EXECUTABLE"
fi

# Handle different systems for file permissions and binary location
if [ "$SYSTEM_TYPE" == "unraid" ]; then
  # For UNRAID, create a symlink in /usr/local/bin for easy access
  chmod -R 755 "$AGENT_DIR"
  ln -sf "$AGENT_EXECUTABLE" /usr/local/bin/fivenines_agent
else
  # Create a symlink at a fixed path for the systemd service
  ln -sf "$AGENT_EXECUTABLE" "${INSTALL_DIR}/fivenines_agent"

  chown -R fivenines:fivenines "$INSTALL_DIR"
  chmod -R 755 "$AGENT_DIR"
fi

echo "Agent installed successfully at $AGENT_DIR"


# Test connectivity
hosts=("asia.fivenines.io" "eu.fivenines.io" "us.fivenines.io" "api.fivenines.io")

# Loop through each host and ping once
for host in "${hosts[@]}"; do
  echo "Pinging $host..."
  if ping -c 1 -W 5 "$host" &> /dev/null; then
    echo "Ping to $host successful!"
  else
    exit_with_contact "Ping to $host failed or timed out. Check your network connection."
  fi
done

# Setup based on system type
case "$SYSTEM_TYPE" in
  "unraid")
    setup_unraid "$1"
    ;;
  "systemd")
    setup_systemd
    ;;
  *)
    exit_with_contact "Unsupported system type: $SYSTEM_TYPE. This script supports systemd-based systems and UNRAID."
    ;;
esac

# Final output
echo ""
echo "=========================================="
echo "fivenines agent setup complete!"
echo "=========================================="
echo ""

if [ "$SYSTEM_TYPE" == "unraid" ]; then
  echo "The agent is now running and will automatically start when your UNRAID server boots."
  echo ""
  echo "Management options:"
  echo "- View/manage through: Settings -> User Scripts -> fivenines_agent"
  echo "- Log file: /var/log/fivenines-agent.log"
else
  echo "The agent is now running as a systemd service and will start automatically on boot."
  echo ""
  echo "Management commands:"
  echo "- Check status: systemctl status fivenines-agent"
  echo "- View logs: journalctl -u fivenines-agent -f"
  echo "- Stop/start: systemctl stop/start fivenines-agent"
fi

echo ""
echo "Happy monitoring!"

# Remove the setup script
rm -f "$0" 2>/dev/null || true
