#!/bin/sh

# Fivenines Agent Setup Script
# Works on standard Linux systems (systemd), OpenRC (Alpine), and UNRAID
#
# Environment variables:
#   FIVENINES_AGENT_URL - Custom download URL for the agent tarball (e.g., pre-release builds)
#
# Example with custom build:
#   FIVENINES_AGENT_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/download/feature-branch-abc1234/fivenines-agent-linux-amd64.tar.gz" bash fivenines_setup.sh YOUR_TOKEN

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

print_banner() {
    echo ""
    printf '%b\n' "${BLUE}===============================================================${NC}"
    printf '%b\n' "${BLUE}  Fivenines Agent - System Installation${NC}"
    printf '%b\n' "${BLUE}===============================================================${NC}"
    echo ""
}

print_success() {
    printf '%b\n' "${GREEN}[+]${NC} $1"
}

print_warning() {
    printf '%b\n' "${YELLOW}[!]${NC} $1"
}

print_error() {
    printf '%b\n' "${RED}[-]${NC} $1"
}

download_with_fallback() {
  local filename="$1"
  local output="$2"
  local r2_url="${R2_BASE_URL}/${filename}"
  local github_url="$3"

  print_warning "Downloading ${filename}..."

  # Try R2 first (IPv6 compatible)
  # Use -T (BusyBox-compatible) instead of --connect-timeout (GNU wget only)
  if wget -T 5 -q "$r2_url" -O "$output" 2>/dev/null; then
    print_success "Downloaded from releases.fivenines.io"
    return 0
  fi

  # Fallback to GitHub
  print_warning "R2 mirror unavailable, trying GitHub..."
  if wget -T 5 -q "$github_url" -O "$output" 2>/dev/null; then
    print_success "Downloaded from GitHub"
    return 0
  fi

  return 1
}

exit_with_contact() {
  print_error "$1"
  echo ""
  echo "For assistance, contact: sebastien@fivenines.io"
  exit 1
}

detect_libc() {
  # Check ldd first - if it explicitly reports glibc or musl, trust that
  LDD_OUTPUT=$(ldd --version 2>&1 || true)
  if printf '%s' "$LDD_OUTPUT" | grep -qi glibc; then
    echo "glibc"
  elif printf '%s' "$LDD_OUTPUT" | grep -qi musl; then
    echo "musl"
  elif [ -f "/lib/ld-musl-x86_64.so.1" ] || [ -f "/lib/ld-musl-aarch64.so.1" ]; then
    echo "musl"
  else
    echo "glibc"
  fi
}

detect_system() {
  # Check if this is UNRAID
  if [ -f "/etc/unraid-version" ] || [ -d "/boot/config" ]; then
    echo "unraid"
    return
  fi

  # Check if OpenRC is available (Alpine Linux)
  if command -v rc-service >/dev/null 2>&1 && [ -d "/etc/init.d" ]; then
    echo "openrc"
    return
  fi

  # Check if systemd is available
  if command -v systemctl >/dev/null 2>&1 && [ -d "/etc/systemd/system" ]; then
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

setup_systemd() {
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

setup_unraid() {
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

setup_openrc() {
  print_success "Detected OpenRC system - using OpenRC service"

  # Download the OpenRC init script
  download_with_fallback "fivenines-agent.openrc" "/etc/init.d/fivenines-agent" "${GITHUB_RAW_URL}/fivenines-agent.openrc" || exit_with_contact "Failed to download OpenRC init script"

  # Make it executable
  chmod 755 /etc/init.d/fivenines-agent

  # Enable on boot
  rc-update add fivenines-agent default

  # Start the agent
  rc-service fivenines-agent start

  if [ $? -ne 0 ]; then
    exit_with_contact "Failed to start the fivenines-agent service. Check /var/log/fivenines-agent.log for details."
  fi

  print_success "OpenRC service installed and started successfully"
}

# Main execution starts here
print_banner

# Check that token parameter is present
if [ $# -eq 0 ] ; then
  echo "Usage: ./setup.sh CLIENT_TOKEN"
  exit 1
fi

# Check if running as root (use `id -u` for BusyBox/ash compatibility)
if [ "$(id -u)" -ne 0 ]; then
  exit_with_contact "This script must be run as root"
fi

# Detect system type
SYSTEM_TYPE=$(detect_system)
print_success "Detected system type: $SYSTEM_TYPE"

# Check if SELinux is installed
if command -v getenforce >/dev/null 2>&1; then
  selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
  print_success "SELinux status: $selinux_status"
  if [ "$selinux_status" = "Enforcing" ]; then
    exit_with_contact "SELinux is enabled in enforcing mode. fivenines agent will not work without disabling SELinux."
  fi
else
  print_success "SELinux is not installed on this system."
fi

# Create a system user for the agent first
if ! id -u fivenines >/dev/null 2>&1; then
  print_success "Creating system user fivenines"
  if [ "$SYSTEM_TYPE" = "unraid" ]; then
    useradd --system --user-group fivenines --shell /bin/false --create-home
  elif [ "$SYSTEM_TYPE" = "openrc" ]; then
    addgroup -S fivenines 2>/dev/null || true
    adduser -S -G fivenines -s /sbin/nologin -h /opt/fivenines fivenines 2>/dev/null || true
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
if [ "$SYSTEM_TYPE" = "unraid" ]; then
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
if [ "$SYSTEM_TYPE" = "unraid" ]; then
  INSTALL_DIR="/boot/config/custom/fivenines_agent"
else
  INSTALL_DIR="/opt/fivenines"
fi

# Ensure install directory exists
mkdir -p "$INSTALL_DIR"

# Download the agent tarball based on the architecture and libc
LIBC_TYPE=$(detect_libc)
print_success "Detected architecture: $CURRENT_ARCH"
print_success "Detected libc: $LIBC_TYPE"
if [ "$LIBC_TYPE" = "musl" ]; then
  if [ "$CURRENT_ARCH" = "aarch64" ]; then
    BINARY_NAME="fivenines-agent-alpine-arm64"
  else
    BINARY_NAME="fivenines-agent-alpine-amd64"
  fi
else
  if [ "$CURRENT_ARCH" = "aarch64" ]; then
    BINARY_NAME="fivenines-agent-linux-arm64"
  else
    BINARY_NAME="fivenines-agent-linux-amd64"
  fi
fi

TARBALL_NAME="${BINARY_NAME}.tar.gz"
TARBALL_PATH="/tmp/${TARBALL_NAME}"
AGENT_DIR="${INSTALL_DIR}/${BINARY_NAME}"
AGENT_EXECUTABLE="${AGENT_DIR}/${BINARY_NAME}"

if [ -n "${FIVENINES_AGENT_URL:-}" ]; then
  print_warning "Using custom agent URL: $FIVENINES_AGENT_URL"
  wget -T 10 -q "$FIVENINES_AGENT_URL" -O "$TARBALL_PATH" || exit_with_contact "Failed to download from custom URL"
  print_success "Downloaded from custom URL"
else
  download_with_fallback "$TARBALL_NAME" "$TARBALL_PATH" "${GITHUB_RELEASES_URL}/${TARBALL_NAME}" || exit_with_contact "Failed to download agent"
fi

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
if [ "$SYSTEM_TYPE" = "unraid" ]; then
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
for host in asia.fivenines.io eu.fivenines.io us.fivenines.io api.fivenines.io; do
  if ping -c 1 -W 5 "$host" >/dev/null 2>&1; then
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
  "openrc")
    setup_openrc
    ;;
  "systemd")
    setup_systemd
    ;;
  *)
    exit_with_contact "Unsupported system type: $SYSTEM_TYPE. This script supports systemd, OpenRC, and UNRAID systems."
    ;;
esac

# Final output
echo ""
printf '%b\n' "${BLUE}===============================================================${NC}"
printf '%b\n' "${BLUE}  Installation Complete!${NC}"
printf '%b\n' "${BLUE}===============================================================${NC}"
echo ""

if [ "$SYSTEM_TYPE" = "unraid" ]; then
  echo "The agent is now running and will automatically start when your UNRAID server boots."
  echo ""
  echo "Management options:"
  echo "  Settings -> User Scripts -> fivenines_agent"
  echo "  Log file: /var/log/fivenines-agent.log"
elif [ "$SYSTEM_TYPE" = "openrc" ]; then
  echo "The agent is now running as an OpenRC service and will start automatically on boot."
  echo ""
  echo "Management commands:"
  echo "  rc-service fivenines-agent status   - Check status"
  echo "  tail -f /var/log/fivenines-agent.log - View logs"
  echo "  rc-service fivenines-agent stop/start - Stop/start"
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
