#!/bin/bash

# Check that token parameter is present
if [ $# -eq 0 ] ; then
  echo 'Usage: ./setup.sh SERVER_TOKEN'
  exit 1
fi

# Save the server token
echo -n "$1" > TOKEN

# Generate the environment
sudo python3 -m venv five_nines_client/venv

# Install dependencies
sudo five_nines_client/venv/bin/pip3 install -r requirements.txt

# Copy the service file
sudo cp /opt/five_nines_client/five-nines-client.service /etc/systemd/system/

# Reload the service files to include the five-nines-client service
sudo systemctl daemon-reload

# Enable five-nines-client service on every reboot
sudo systemctl enable five-nines-client.service

# Start the five-nines-client
sudo systemctl start five-nines-client
