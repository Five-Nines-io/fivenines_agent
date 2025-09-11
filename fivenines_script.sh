#!/bin/bash

# Fivenines Agent Auto-Start Script for UNRAID
# This script starts the fivenines agent at array startup

AGENT_PATH="/boot/config/plugins/fivenines/fivenines_agent"
LOG_FILE="/var/log/fivenines-agent.log"

# Check if token file exists
if [ ! -f "/etc/fivenines_agent/TOKEN" ]; then
    echo "Error: Token file not found at $TOKEN_FILE"
    exit 1
fi

# Read the token
TOKEN=$(cat "$TOKEN_FILE")

# Check if already running
if pgrep -f "fivenines_agent" > /dev/null; then
    echo "Fivenines agent is already running"
    exit 0
fi

# Start the agent as fivenines user
echo "Starting fivenines agent..."
su - fivenines -s /bin/bash -c "\"$AGENT_PATH\"" > "$LOG_FILE" 2>&1 &

if [ $? -eq 0 ]; then
    echo "Fivenines agent started successfully"
    echo "Log file: $LOG_FILE"
else
    echo "Failed to start fivenines agent"
    exit 1
fi
