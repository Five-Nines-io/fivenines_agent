#!/bin/sh
# Fivenines Agent Boot Script for UNRAID

# Kill any existing instances
if pgrep -f "fivenines-agent-linux" > /dev/null; then
  echo "Killing existing fivenines agent instances"
  pkill -f "fivenines-agent-linux" 2>/dev/null || true
fi

# Detect userspace architecture (not kernel arch, which can differ on ARM)
if command -v dpkg >/dev/null 2>&1; then
  DEB_ARCH=$(dpkg --print-architecture 2>/dev/null)
  case "$DEB_ARCH" in
    armhf|armel) CURRENT_ARCH="armv7l" ;;
    arm64)       CURRENT_ARCH="aarch64" ;;
    amd64)       CURRENT_ARCH="x86_64" ;;
    *)           CURRENT_ARCH=$(uname -m) ;;
  esac
elif file /bin/sh 2>/dev/null | grep -q "32-bit.*ARM"; then
  CURRENT_ARCH="armv7l"
else
  CURRENT_ARCH=$(uname -m)
fi

if [ "$CURRENT_ARCH" = "aarch64" ]; then
  BINARY_NAME="fivenines-agent-linux-arm64"
elif [ "$CURRENT_ARCH" = "armv7l" ] || [ "$CURRENT_ARCH" = "armv6l" ]; then
  BINARY_NAME="fivenines-agent-linux-arm"
else
  BINARY_NAME="fivenines-agent-linux-amd64"
fi

AGENT_DIR="/boot/config/custom/fivenines_agent/${BINARY_NAME}"
AGENT_EXEC="${AGENT_DIR}/${BINARY_NAME}"
LOG_FILE="/var/log/fivenines-agent.log"

# Verify agent exists
if [ ! -f "$AGENT_EXEC" ]; then
  echo "Error: Agent executable not found at $AGENT_EXEC"
  exit 1
fi

# Create symlink for easy access
ln -sf "$AGENT_EXEC" /usr/local/bin/fivenines_agent

mkdir -p /etc/fivenines_agent

# Create user if it doesn't exist
if ! id -u fivenines >/dev/null 2>&1; then
  useradd --system --user-group fivenines --shell /bin/false --create-home
fi

cp /boot/config/custom/fivenines_agent/TOKEN /etc/fivenines_agent/TOKEN
chown fivenines:fivenines /etc/fivenines_agent/TOKEN
chmod 600 /etc/fivenines_agent/TOKEN

# Run the agent from its directory (so it can find its bundled libraries)
cd "$AGENT_DIR"
su fivenines -s /bin/sh -c "./${BINARY_NAME}" > $LOG_FILE 2>&1 &
