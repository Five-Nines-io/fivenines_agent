#!/bin/bash

# Check that token parameter is present
if [ $# -eq 0 ] ; then
  echo 'Usage: ./setup.sh CLIENT_TOKEN'
  exit 1
fi

# Save the client token
sudo mkdir -p /etc/fivenines_agent
echo -n "$1" | sudo tee /etc/fivenines_agent/TOKEN > /dev/null

# Determine the package manager and install dependencies
if [ -x "$(command -v apt-get)" ]; then
  sudo apt-get update
  sudo apt-get install -y python3 python3-pipx
elif [ -x "$(command -v yum)" ]; then
  sudo yum update
  sudo yum install -y python3 python3-pipx
elif [ -x "$(command -v pacman)" ]; then
  sudo pacman -Syu
  sudo pacman -S --noconfirm python python-pipx
else
  echo 'Error: No package manager found'
  exit 1
fi

# Create a system user for the agent
if ! id -u fivenines >/dev/null 2>&1; then
  sudo useradd --system --user-group --key USERGROUPS_ENAB=yes fivenines --shell /bin/false --create-home
fi

# Install the agent
sudo su - fivenines -s /bin/bash -c 'python3 -m pipx install --index-url https://test.pypi.org/simple/ --pip-args="--extra-index-url https://pypi.org/simple" fivenines_agent'

# Download the service file
wget https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/develop/fivenines-agent.service -O fivenines-agent.service

# Move the service file to the systemd directory
sudo mv fivenines-agent.service /etc/systemd/system/

# Reload the service files to include the new fivenines-agent service
sudo systemctl daemon-reload

# Enable fivenines-agent service on every reboot
sudo systemctl enable fivenines-agent.service

# Start the fivenines-agent
sudo systemctl start fivenines-agent

# Remove the setup script
rm fivenines_setup.sh
