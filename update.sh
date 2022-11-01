#!/bin/bash

# Fetch the latest client version
sudo git pull

# Install dependencies
sudo five_nines_client/venv/bin/pip3 install -r requirements.txt

# Copy the new service file
sudo cp /opt/five_nines_client/five-nines-client.service /etc/systemd/system/

# Reload the service files
sudo systemctl daemon-reload

# Restart the five-nines-client
sudo systemctl restart five-nines-client
