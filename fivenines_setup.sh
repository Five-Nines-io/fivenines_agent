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
  sudo apt-get install -y python3
elif [ -x "$(command -v yum)" ]; then
  sudo yum update
  sudo yum install -y python3
elif [ -x "$(command -v pacman)" ]; then
  sudo pacman -Syu
  sudo pacman -S --noconfirm python
else
  echo 'Error: No package manager found'
  exit 1
fi

# Copy the service file
sudo cp fivenines-agent.service /etc/systemd/system/

# Reload the service files to include the fivenines-agent service
sudo systemctl daemon-reload

# Enable fivenines-agent service on every reboot
sudo systemctl enable fivenines-agent.service

# Start the fivenines-agent
sudo systemctl start fivenines-agent
