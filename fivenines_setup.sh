#!/bin/bash

# Fivenines Agent Setup Script
# Works on both standard Linux systems (systemd) and UNRAID

# Mirror URLs (R2 is IPv6-compatible, GitHub is fallback)
R2_BASE_URL="https://releases.fivenines.io/latest"
GITHUB_RELEASES_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/latest/download"
GITHUB_RAW_URL="https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function print_banner() {
    echo ""
    echo -e "${BLUE}===============================================================${NC}"
    echo -e "${BLUE}  Fivenines Agent - System Installation${NC}"
    echo -e "${BLUE}===============================================================${NC}"
    echo ""
}

function print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

function print_error() {
    echo -e "${RED}[-]${NC} $1"
}

function download_with_fallback() {
  local filename="$1"
  local output="$2"
  local r2_url="${R2_BASE_URL}/${filename}"
  local github_url="$3"

  print_warning "Downloading ${filename}..."

  # Try R2 first (IPv6 compatible)
  if wget --connect-timeout=5 -q "$r2_url" -O "$output" 2>/dev/null; then
    print_success "Downloaded from releases.fivenines.io"
    return 0
  fi

  # Fallback to GitHub
  print_warning "R2 mirror unavailable, trying GitHub..."
  if wget --connect-timeout=5 -q "$github_url" -O "$output" 2>/dev/null; then
    print_success "Downloaded from GitHub"
    return 0
  fi

  return 1
}

function exit_with_contact() {
  print_error "$1"
  echo ""
  echo "For assistance, contact: sebastien@fivenines.io"
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
  print_success "Detected systemd system - using systemd service"

  # Download the service file
  download_with_fallback "fivenines-agent.service" "fivenines-agent.service" "${GITHUB_RAW_URL}/fivenines-agent.service" || exit_with_contact "Failed to download systemd service file"

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

  print_success "Systemd service installed and started successfully"
}

function setup_unraid() {
  print_warning "Starting fivenines agent..."

  download_with_fallback "fivenines_script.sh" "/boot/config/custom/fivenines_agent/fivenines_boot" "${GITHUB_RAW_URL}/fivenines_script.sh" || exit_with_contact "Failed to download fivenines_script.sh"

  chmod 755 /boot/config/custom/fivenines_agent/fivenines_boot

  bash /boot/config/custom/fivenines_agent/fivenines_boot

  sleep 3

  if pgrep -f "fivenines_agent" > /dev/null; then
    print_success "Fivenines agent is running (PID: $(pgrep -f "fivenines_agent"))"
    if ! grep -q "fivenines_boot" /boot/config/go; then
      print_success "Adding fivenines agent to go startup"
      echo "# Start fivenines agent on boot" >> /boot/config/go
      echo "bash /boot/config/custom/fivenines_agent/fivenines_boot" >> /boot/config/go
    else
      print_success "Fivenines agent is already in go startup"
    fi
  else
    exit_with_contact "Failed to start fivenines agent. Check /var/log/fivenines-agent.log for details."
  fi
}

# Main execution starts here
print_banner

# Check that token parameter is present
if [ $# -eq 0 ] ; then
  echo "Usage: ./setup.sh CLIENT_TOKEN"
  exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  exit_with_contact "This script must be run as root"
fi

# Detect system type
SYSTEM_TYPE=$(detect_system)
print_success "Detected system type: $SYSTEM_TYPE"

# Check if SELinux is installed
if command -v getenforce &> /dev/null; then
  selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
  print_success "SELinux status: $selinux_status"
  if [ "$selinux_status" == "Enforcing" ]; then
    exit_with_contact "SELinux is enabled in enforcing mode. fivenines agent will not work without disabling SELinux."
  fi
else
  print_success "SELinux is not installed on this system."
fi

# Create a system user for the agent first
if ! id -u fivenines >/dev/null 2>&1; then
  print_success "Creating system user fivenines"
  if [ "$SYSTEM_TYPE" == "unraid" ]; then
    useradd --system --user-group fivenines --shell /bin/false --create-home
  else
    useradd --system --user-group --key USERGROUPS_ENAB=yes fivenines --shell /bin/false --create-home -b /opt/
  fi
fi

# CloudLinux: add fivenines to clsupergid group for proper permissions
if [ -f "/etc/cloudlinux-release" ]; then
  print_success "CloudLinux detected"
  if getent group clsupergid >/dev/null 2>&1; then
    print_success "Adding fivenines user to clsupergid group"
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
print_success "Detected architecture: $CURRENT_ARCH"
if [ "$CURRENT_ARCH" == "aarch64" ]; then
  BINARY_NAME="fivenines-agent-linux-arm64"
else
  BINARY_NAME="fivenines-agent-linux-amd64"
fi

TARBALL_NAME="${BINARY_NAME}.tar.gz"
TARBALL_PATH="/tmp/${TARBALL_NAME}"
AGENT_DIR="${INSTALL_DIR}/${BINARY_NAME}"
AGENT_EXECUTABLE="${AGENT_DIR}/${BINARY_NAME}"

download_with_fallback "$TARBALL_NAME" "$TARBALL_PATH" "${GITHUB_RELEASES_URL}/${TARBALL_NAME}" || exit_with_contact "Failed to download agent"

# Remove old installation if it exists
if [ -d "$AGENT_DIR" ]; then
  print_warning "Removing previous installation..."
  rm -rf "$AGENT_DIR"
fi

# Extract the tarball
print_warning "Extracting agent to $INSTALL_DIR..."
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

print_success "Agent installed successfully at $AGENT_DIR"


# Test connectivity
echo "Testing connectivity..."
hosts=("asia.fivenines.io" "eu.fivenines.io" "us.fivenines.io" "api.fivenines.io")

# Loop through each host and ping once
for host in "${hosts[@]}"; do
  if ping -c 1 -W 5 "$host" &> /dev/null; then
    print_success "Connected to $host"
  else
    exit_with_contact "Ping to $host failed or timed out. Check your network connection."
  fi
done
echo ""

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
echo -e "${BLUE}===============================================================${NC}"
echo -e "${BLUE}  Installation Complete!${NC}"
echo -e "${BLUE}===============================================================${NC}"
echo ""

if [ "$SYSTEM_TYPE" == "unraid" ]; then
  echo "The agent is now running and will automatically start when your UNRAID server boots."
  echo ""
  echo "Management options:"
  echo "  Settings -> User Scripts -> fivenines_agent"
  echo "  Log file: /var/log/fivenines-agent.log"
else
  echo "The agent is now running as a systemd service and will start automatically on boot."
  echo ""
  echo "Management commands:"
  echo "  systemctl status fivenines-agent    - Check status"
  echo "  journalctl -u fivenines-agent -f    - View logs"
  echo "  systemctl stop/start fivenines-agent - Stop/start"
fi

echo ""
echo "Happy monitoring!"

# Remove the setup script
rm -f "$0" 2>/dev/null || true
