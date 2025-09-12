#!/bin/bash
# Fivenines Agent Boot Script for UNRAID

# Kill any existing instances
if ! pgrep -f "fivenines_agent" > /dev/null; then
  echo "Killing existing fivenines_agent instances"
  pkill -f "fivenines_agent" 2>/dev/null || true
fi

AGENT_PATH="/boot/config/custom/fivenines_agent/fivenines_agent"
AGENT_EXEC="/usr/local/bin/fivenines_agent"
LOG_FILE="/var/log/fivenines-agent.log"

cp $AGENT_PATH $AGENT_EXEC
chmod 755 $AGENT_EXEC
mkdir -p /etc/fivenines_agent

useradd --system --user-group fivenines --shell /bin/false --create-home

cp /boot/config/custom/fivenines_agent/TOKEN /etc/fivenines_agent/TOKEN
chown fivenines:fivenines /etc/fivenines_agent/TOKEN
chmod 600 /etc/fivenines_agent/TOKEN

su fivenines -s /bin/sh -c "$AGENT_EXEC" > $LOG_FILE 2>&1 &
