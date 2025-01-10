#!/bin/bash
# This script is used to update the fivenines agent

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

# Update the agent
wget https://github.com/Five-Nines-io/fivenines_agent/releases/download/v.1.0.6/fivenines-agent-linux-amd64 -O /opt/fivenines/fivenines_agent
chmod +x /opt/fivenines/fivenines_agent

# if the service file ExecStart is /home/fivenines/, replace it with /opt/fivenines/
if [ "$(grep -E '^ExecStart=/home/fivenines/.*' /etc/systemd/system/fivenines-agent.service)" ] || [ "$(grep -E '^ExecStart=/opt/fivenines/.local/bin/fivenines_agent' /etc/systemd/system/fivenines-agent.service)" ]; then
        echo "Updating the service file"
        wget https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines-agent.service -O /etc/systemd/system/fivenines-agent.service
        echo "Reloading the systemd daemon"
        systemctl daemon-reload
fi

# Restart the agent
systemctl restart fivenines-agent.service

# Remove the update script
rm fivenines_update.sh
