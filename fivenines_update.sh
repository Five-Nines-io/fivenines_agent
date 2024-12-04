#!/bin/bash
# This script is used to update the fivenines agent

# stop the agent
sudo systemctl stop fivenines-agent.service

# if the home directory of user "fivenines" is /home/fivenines (which is the old location), migrate user's home directory to /opt/fivenines
if [ "$(getent passwd fivenines | cut -d: -f6)" == "/home/fivenines" ]; then
        echo "Migrating fivenines.io's working directory from /home/fivenines to /opt/fivenines"
        # if /opt/fivenines exists, or /home/fivenines not exists, exit
        if [ -d /opt/fivenines ] || [ ! -d /home/fivenines ]; then
                echo "Error: /opt/fivenines already exists or /home/fivenines does not exists"
                exit 1
        fi
        sudo usermod -m -d /opt/fivenines fivenines
        echo "fivenines.io's working directory migrated to /opt/fivenines"

        # Reinstall the agent due to path changes
        echo "Reinstalling the fivenines_agent package"
        sudo su - fivenines -s /bin/bash -c 'python3 -m pipx uninstall fivenines_agent'
        sudo su - fivenines -s /bin/bash -c 'python3 -m pipx install --index-url https://pypi.org/simple/ --pip-args="--extra-index-url https://pypi.org/simple" fivenines_agent'
        # Check that the package is installed
        sudo su - fivenines -s /bin/bash -c 'pipx list | grep -q fivenines_agent'

        # Get the exit status of the pipx command
        if [ $? -ne 0 ]; then
                echo "Failed to Reinstall the fivenines_agent package"
                exit 1
        else
                echo "Successfully Reinstalled the fivenines_agent package"
        fi
fi

# if the service file ExecStart is /home/fivenines/, replace it with /opt/fivenines/
if [ "$(grep -E '^ExecStart=/home/fivenines/.*' /etc/systemd/system/fivenines-agent.service)" ]; then
        echo "Updating the service file"
        sudo wget https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines-agent.service -O /etc/systemd/system/fivenines-agent.service
        echo "Reloading the systemd daemon"
        sudo systemctl daemon-reload
fi

# Update the agent
sudo su - fivenines -s /bin/bash -c 'python3 -m pipx upgrade --index-url https://pypi.org/simple/ --pip-args="--extra-index-url https://pypi.org/simple" fivenines_agent'

# Restart the agent
sudo systemctl restart fivenines-agent.service

# Remove the update script
rm fivenines_update.sh
