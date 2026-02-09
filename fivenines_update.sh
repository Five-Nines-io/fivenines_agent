#!/bin/bash
# This script is used to update the fivenines agent
#
# Environment variables:
#   FIVENINES_AGENT_URL - Custom download URL for the agent tarball (e.g., pre-release builds)
#
# Example with custom build:
#   FIVENINES_AGENT_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/download/feature-branch-abc1234/fivenines-agent-linux-amd64.tar.gz" bash fivenines_update.sh

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

function print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

function print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

function print_error() {
    echo -e "${RED}[-]${NC} $1"
}

function exit_with_error() {
    print_error "$1"
    exit 1
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

# Print banner
echo ""
echo -e "${BLUE}===============================================================${NC}"
echo -e "${BLUE}  Fivenines Agent - System Update${NC}"
echo -e "${BLUE}===============================================================${NC}"
echo ""

# stop the agent
print_warning "Stopping fivenines-agent service..."
systemctl stop fivenines-agent.service
print_success "Agent stopped"

# if the home directory of user "fivenines" is /home/fivenines (which is the old location), migrate user's home directory to /opt/fivenines
if [ "$(getent passwd fivenines | cut -d: -f6)" == "/home/fivenines" ]; then
        print_warning "Migrating fivenines.io's working directory from /home/fivenines to /opt/fivenines"
        # if /opt/fivenines exists, or /home/fivenines not exists, exit
        if [ -d /opt/fivenines ] || [ ! -d /home/fivenines ]; then
                exit_with_error "/opt/fivenines already exists or /home/fivenines does not exist"
        fi
        usermod -m -d /opt/fivenines fivenines
        print_success "Working directory migrated to /opt/fivenines"
fi

# Check if the package is installed
su - fivenines -s /bin/bash -c 'pipx list | grep -q fivenines_agent'

# Get the exit status of the pipx command
if [ $? -ne 0 ]; then
        print_success "Agent is not installed with pipx. No need to clean the old package."
else
        print_warning "Uninstalling the old fivenines_agent package"
        su - fivenines -s /bin/bash -c 'python3 -m pipx uninstall fivenines_agent'
fi

CURRENT_ARCH=$(uname -m)
INSTALL_DIR="/opt/fivenines"

# Update the agent based on the architecture
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

if [ -n "${FIVENINES_AGENT_URL:-}" ]; then
    print_warning "Using custom agent URL: $FIVENINES_AGENT_URL"
    wget --connect-timeout=10 -q "$FIVENINES_AGENT_URL" -O "$TARBALL_PATH" || exit_with_error "Failed to download from custom URL"
    print_success "Downloaded from custom URL"
else
    download_with_fallback "$TARBALL_NAME" "$TARBALL_PATH" "${GITHUB_RELEASES_URL}/${TARBALL_NAME}" || exit_with_error "Failed to download agent"
fi

# Remove old installation if it exists
if [ -d "$AGENT_DIR" ]; then
        print_warning "Removing previous installation..."
        rm -rf "$AGENT_DIR"
fi

# Also remove old single-binary format if present
if [ -f "${INSTALL_DIR}/fivenines_agent" ]; then
        print_warning "Removing old single-binary installation..."
        rm -f "${INSTALL_DIR}/fivenines_agent"
fi

# Extract the tarball
print_warning "Extracting agent to $INSTALL_DIR..."
tar -xzf "$TARBALL_PATH" -C "$INSTALL_DIR" || exit_with_error "Failed to extract agent"

# Clean up the tarball
rm -f "$TARBALL_PATH"

# Verify extraction was successful
if [ ! -f "$AGENT_EXECUTABLE" ]; then
        exit_with_error "Agent executable not found after extraction at $AGENT_EXECUTABLE"
fi

# Create/update symlink at a fixed path for the systemd service
ln -sf "$AGENT_EXECUTABLE" "${INSTALL_DIR}/fivenines_agent"

# Remove old wrapper script if it exists
rm -f "${INSTALL_DIR}/run_agent.sh"

# Set permissions
chown -R fivenines:fivenines "$INSTALL_DIR"
chmod -R 755 "$AGENT_DIR"

# CloudLinux: ensure fivenines is in clsupergid group for proper permissions
if [ -f "/etc/cloudlinux-release" ]; then
        print_success "CloudLinux detected"
        if getent group clsupergid >/dev/null 2>&1; then
                if ! id -nG fivenines | grep -qw clsupergid; then
                        print_success "Adding fivenines user to clsupergid group"
                        usermod -a -G clsupergid fivenines
                fi
        fi
fi

print_success "Agent updated successfully at $AGENT_DIR"

print_warning "Updating the service file..."
download_with_fallback "fivenines-agent.service" "/etc/systemd/system/fivenines-agent.service" "${GITHUB_RAW_URL}/fivenines-agent.service"
print_warning "Reloading the systemd daemon..."
systemctl daemon-reload

# Restart the agent
print_warning "Restarting fivenines-agent service..."
systemctl restart fivenines-agent.service
print_success "Agent restarted"

echo ""
echo -e "${BLUE}===============================================================${NC}"
echo -e "${BLUE}  Update Complete!${NC}"
echo -e "${BLUE}===============================================================${NC}"
echo ""

# Remove the update script
rm fivenines_update.sh
