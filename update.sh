#!/bin/bash

# Fetch the latest client version
sudo git pull

# Copy the new service file
sudo cp /opt/five_nines_client/five-nines-client.service /etc/systemd/system/

# Reload the service files to include the five-nines-client service
sudo systemctl daemon-reload

# Restart the five-nines-client
sudo systemctl restart five-nines-client
