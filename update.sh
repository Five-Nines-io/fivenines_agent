#!/bin/bash

# Fetch the latest client version
sudo git pull

# Activate the environment
sudo source venv/bin/activate

# Install dependencies
sudo venv/bin/pip3 install -r requirements.txt

# Copy the new service file
sudo cp five-nines-client.service /etc/systemd/system/

# Reload the service files
sudo systemctl daemon-reload

# Restart the five-nines-client
sudo systemctl restart five-nines-client
