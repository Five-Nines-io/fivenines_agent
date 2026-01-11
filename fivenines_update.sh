#!/bin/bash
# This script is used to update the fivenines agent

# Mirror URLs (R2 is IPv6-compatible, GitHub is fallback)
R2_BASE_URL="https://releases.fivenines.io/latest"
GITHUB_RELEASES_URL="https://github.com/Five-Nines-io/fivenines_agent/releases/latest/download"
GITHUB_RAW_URL="https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main"

function download_with_fallback() {
  local filename="$1"
  local output="$2"
  local r2_url="${R2_BASE_URL}/${filename}"
  local github_url="$3"

  echo "Downloading ${filename}..."

  # Try R2 first (IPv6 compatible)
  if wget --connect-timeout=5 -q "$r2_url" -O "$output" 2>/dev/null; then
    echo "  Downloaded from releases.fivenines.io"
    return 0
  fi

  # Fallback to GitHub
  echo "  R2 mirror unavailable, trying GitHub..."
  if wget --connect-timeout=5 -q "$github_url" -O "$output" 2>/dev/null; then
    echo "  Downloaded from GitHub"
    return 0
  fi

  return 1
}

# stop the agent
systemctl stop fivenines-agent.service

# if the home directory of user "fivenines" is /home/fivenines (which is the old location), migrate user's home directory to /opt/fivenines
if [ "$(getent passwd fivenines | cut -d: -f6)" == "/home/fivenines" ]; then
        echo "Migrating fivenines.io's working directory from /home/fivenines to /opt/fivenines"
        # if /opt/fivenines exists, or /home/fivenines not exists, exit
        if [ -d /opt/fivenines ] || [ ! -d /home/fivenines ]; then
                echo "Error: /opt/fivenines already exists or /home/fivenines does not exists"
                exit 1
        fi
        usermod -m -d /opt/fivenines fivenines
        echo "fivenines.io's working directory migrated to /opt/fivenines"
fi

# Check if the package is installed
su - fivenines -s /bin/bash -c 'pipx list | grep -q fivenines_agent'

# Get the exit status of the pipx command
if [ $? -ne 0 ]; then
        echo "Agent is not installed with pipx. No need to clean the old package."
else
        echo "Uninstalling the old fivenines_agent package"
        su - fivenines -s /bin/bash -c 'python3 -m pipx uninstall fivenines_agent'
fi

CURRENT_ARCH=$(uname -m)
INSTALL_DIR="/opt/fivenines"

# Update the agent based on the architecture
echo "Detected architecture: $CURRENT_ARCH"
if [ "$CURRENT_ARCH" == "aarch64" ]; then
        BINARY_NAME="fivenines-agent-linux-arm64"
else
        BINARY_NAME="fivenines-agent-linux-amd64"
fi

TARBALL_NAME="${BINARY_NAME}.tar.gz"
TARBALL_PATH="/tmp/${TARBALL_NAME}"
AGENT_DIR="${INSTALL_DIR}/${BINARY_NAME}"
AGENT_EXECUTABLE="${AGENT_DIR}/${BINARY_NAME}"

download_with_fallback "$TARBALL_NAME" "$TARBALL_PATH" "${GITHUB_RELEASES_URL}/${TARBALL_NAME}" || { echo "Failed to download agent"; exit 1; }

# Remove old installation if it exists
if [ -d "$AGENT_DIR" ]; then
        echo "Removing previous installation..."
        rm -rf "$AGENT_DIR"
fi

# Also remove old single-binary format if present
if [ -f "${INSTALL_DIR}/fivenines_agent" ]; then
        echo "Removing old single-binary installation..."
        rm -f "${INSTALL_DIR}/fivenines_agent"
fi

# Extract the tarball
echo "Extracting agent to $INSTALL_DIR..."
tar -xzf "$TARBALL_PATH" -C "$INSTALL_DIR" || { echo "Failed to extract agent"; exit 1; }

# Clean up the tarball
rm -f "$TARBALL_PATH"

# Verify extraction was successful
if [ ! -f "$AGENT_EXECUTABLE" ]; then
        echo "Error: Agent executable not found after extraction at $AGENT_EXECUTABLE"
        exit 1
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
        echo "CloudLinux detected"
        if getent group clsupergid >/dev/null 2>&1; then
                if ! id -nG fivenines | grep -qw clsupergid; then
                        echo "Adding fivenines user to clsupergid group"
                        usermod -a -G clsupergid fivenines
                fi
        fi
fi

echo "Agent updated successfully at $AGENT_DIR"

echo "Updating the service file"
download_with_fallback "fivenines-agent.service" "/etc/systemd/system/fivenines-agent.service" "${GITHUB_RAW_URL}/fivenines-agent.service"
echo "Reloading the systemd daemon"
systemctl daemon-reload

# Restart the agent
systemctl restart fivenines-agent.service

# Remove the update script
rm fivenines_update.sh
