#!/bin/sh
# Fivenines Agent Boot Script for UNRAID

# Kill any existing instances
if pgrep -f "fivenines-agent-linux" > /dev/null; then
  echo "Killing existing fivenines agent instances"
  pkill -f "fivenines-agent-linux" 2>/dev/null || true
fi

# Detect architecture and set paths
CURRENT_ARCH=$(uname -m)
if [ "$CURRENT_ARCH" = "aarch64" ]; then
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

# /etc is a ramdisk on UNRAID; the agent user must own the directory so the
# agent can persist MACHINE_ID (and the swapped per-host TOKEN) at runtime.
chown fivenines:fivenines /etc/fivenines_agent
chmod 750 /etc/fivenines_agent

cp /boot/config/custom/fivenines_agent/TOKEN /etc/fivenines_agent/TOKEN
chown fivenines:fivenines /etc/fivenines_agent/TOKEN
chmod 600 /etc/fivenines_agent/TOKEN

# Restore the persisted machine identity from flash so a reboot does not look
# like a brand-new machine to the backend (which would enroll a duplicate host
# on enrollment-token installs).
if [ -f /boot/config/custom/fivenines_agent/MACHINE_ID ]; then
  cp /boot/config/custom/fivenines_agent/MACHINE_ID /etc/fivenines_agent/MACHINE_ID
  chown fivenines:fivenines /etc/fivenines_agent/MACHINE_ID
  chmod 600 /etc/fivenines_agent/MACHINE_ID
fi

# Run the agent from its directory (so it can find its bundled libraries)
cd "$AGENT_DIR"
su fivenines -s /bin/sh -c "./${BINARY_NAME}" > $LOG_FILE 2>&1 &

# Copy the agent's runtime identity back to flash so it survives a reboot
# (/etc is wiped every boot). MACHINE_ID appears seconds after start, no
# network needed; TOKEN is rewritten once if an enrollment token is swapped
# for a per-host token. Bounded loop, not a daemon: with MACHINE_ID on flash,
# even a TOKEN swap missed after the window only causes a re-enrollment that
# the backend dedups onto the same host.
(
  i=0
  while [ "$i" -lt 40 ]; do
    sleep 15
    i=$((i + 1))
    for f in MACHINE_ID TOKEN; do
      src="/etc/fivenines_agent/$f"
      dst="/boot/config/custom/fivenines_agent/$f"
      if [ -f "$src" ] && ! cmp -s "$src" "$dst" 2>/dev/null; then
        cp "$src" "${dst}.tmp" && mv "${dst}.tmp" "$dst"
      fi
    done
  done
) > /dev/null 2>&1 &
