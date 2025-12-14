#!/bin/bash
# Fivenines Agent Boot Script for UNRAID

# Kill any existing instances
if pgrep -f "fivenines-agent-linux" > /dev/null; then
  echo "Killing existing fivenines agent instances"
  pkill -f "fivenines-agent-linux" 2>/dev/null || true
fi

# Detect architecture and set paths
CURRENT_ARCH=$(uname -m)
if [ "$CURRENT_ARCH" == "aarch64" ]; then
  BINARY_NAME="fivenines-agent-linux-arm64"
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
