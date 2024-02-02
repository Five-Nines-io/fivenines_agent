#!/bin/bash

# Update the agent
sudo su - fivenines -s /bin/bash -c 'python3 -m pipx upgrade --index-url https://test.pypi.org/simple/ --pip-args="--extra-index-url https://pypi.org/simple" fivenines_agent'

# Restart the agent
sudo systemctl restart fivenines-agent.service

# Remove the update script
rm fivenines_update.sh
