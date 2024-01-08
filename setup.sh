#!/bin/bash

# Check that token parameter is present
if [ $# -eq 0 ] ; then
  echo 'Usage: ./setup.sh SERVER_TOKEN'
  exit 1
fi

# Save the server token
echo -n "$1" | sudo tee TOKEN > /dev/null

# Determine the package manager and install dependencies
if [ -x "$(command -v apt-get)" ]; then
  sudo apt-get update
  sudo apt-get install -y gcc python3 python3-venv
elif [ -x "$(command -v yum)" ]; then
  sudo yum update
  sudo yum install -y gcc python3 python3-venv
elif [ -x "$(command -v pacman)" ]; then
  sudo pacman -Syu
  sudo pacman -S --noconfirm gcc python python-virtualenv
else
  echo 'Error: No package manager found'
  exit 1
fi

# Generate the environment
sudo python3 -m venv venv

# Activate the environment
sudo source venv/bin/activate

# Install dependencies
sudo venv/bin/pip3 install -r requirements.txt

# Copy the service file
sudo cp five-nines-client.service /etc/systemd/system/

# Reload the service files to include the five-nines-client service
sudo systemctl daemon-reload

# Enable five-nines-client service on every reboot
sudo systemctl enable five-nines-client.service

# Start the five-nines-client
sudo systemctl start five-nines-client
