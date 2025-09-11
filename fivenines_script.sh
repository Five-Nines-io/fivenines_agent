#!/bin/bash
# Fivenines Agent Auto-Start Script for UNRAID
# This script starts the fivenines agent at array startup

AGENT_PATH="/usr/local/bin/fivenines_agent"
TOKEN_FILE="/etc/fivenines_agent/TOKEN"
LOG_FILE="/var/log/fivenines-agent.log"

# Check if token file exists
if [ ! -f "$TOKEN_FILE" ]; then
    echo "Error: Token file not found at $TOKEN_FILE"
    exit 1
fi
# Check if already running
if pgrep -f "fivenines_agent" > /dev/null; then
    echo "Fivenines agent is already running"
    exit 0
fi

# Start the agent as fivenines user, fallback to root if needed
echo "Starting fivenines agent..."
if id fivenines >/dev/null 2>&1; then
    su fivenines -s /bin/sh -c "$AGENT_PATH" > "$LOG_FILE" 2>&1 &
    sleep 2
    if ! pgrep -f "fivenines_agent" > /dev/null; then
        echo "Failed to start as fivenines user, running as root..."
        $AGENT_PATH > "$LOG_FILE" 2>&1 &
    fi
else
    $AGENT_PATH > "$LOG_FILE" 2>&1 &
fi

if pgrep -f "fivenines_agent" > /dev/null; then
    echo "Fivenines agent started successfully"
    echo "Log file: $LOG_FILE"
else
    echo "Failed to start fivenines agent"
    exit 1
fi