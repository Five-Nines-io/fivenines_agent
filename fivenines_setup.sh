#!/bin/bash

function exit_with_contact() {
  echo "Error: $1"
  echo "Please contact sebastien@fivenines.io for assistance."
  exit 1
}

# Check that token parameter is present
if [ $# -eq 0 ] ; then
  echo 'Usage: ./setup.sh CLIENT_TOKEN'
  exit 1
fi

# Check if SELinux is installed
if command -v getenforce &> /dev/null; then
  selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
  echo "SELinux status: $selinux_status"
  if [ "$selinux_status" == "Enforcing" ]; then
    exit_with_contact "SELinux is enabled in enforcing mode. fivenines agent will not work without disabling SELinux."
  fi
else
  echo "SELinux is not installed on this system."
fi

# Save the client token
sudo mkdir -p /etc/fivenines_agent
echo -n "$1" | sudo tee /etc/fivenines_agent/TOKEN > /dev/null

# Create a system user for the agent
if ! id -u fivenines >/dev/null 2>&1; then
  sudo useradd --system --user-group --key USERGROUPS_ENAB=yes fivenines --shell /bin/false --create-home
fi

# Determine the package manager and install dependencies
if [ -x "$(command -v apt-get)" ]; then
  echo "apt-get found"
  sudo apt-get update
  sudo apt-get install -y python3 pipx gcc
elif [ -x "$(command -v yum)" ]; then
  echo "yum found"
  sudo yum update
  sudo yum install -y python3

  # Install pipx through pip3 if yum doesn't have it
  if ! sudo yum info pipx >/dev/null 2>&1; then
    sudo yum install -y python3-pip gcc
    sudo su - fivenines -s /bin/bash -c 'python3 -m pip install --user pipx'
  else
    sudo yum install -y pipx
  fi

elif [ -x "$(command -v pacman)" ]; then
  echo "pacman found"
  sudo pacman -Syu
  sudo pacman -S --noconfirm python python-pipx gcc
else
  exit_with_contact "No package manager found"
fi

if ! python3 --version | cut -d " " -f2 | grep -E '^3.(6|7|8|9|1.+|2.+)..+$' > /dev/null; then
  echo "Error: Python version must be 3.6 or higher, you have $(python3 --version | cut -d " " -f2)"
  exit_with_contact "Python version must be 3.6 or higher"
  exit 1
fi

# Install the agent
sudo su - fivenines -s /bin/bash -c 'python3 -m pipx install --index-url https://pypi.org/simple/ --pip-args="--extra-index-url https://pypi.org/simple" fivenines_agent'
# Check that the package is installed
sudo su - fivenines -s /bin/bash -c 'pipx list | grep -q fivenines_agent'

# Get the exit status of the pipx command
if [ $? -ne 0 ]; then
  exit_with_contact "Failed to install the fivenines_agent package"
fi

# Download the service file
wget https://raw.githubusercontent.com/Five-Nines-io/five_nines_agent/main/fivenines-agent.service -O fivenines-agent.service

# Move the service file to the systemd directory
sudo mv fivenines-agent.service /etc/systemd/system/

hosts=("asia.fivenines.io" "eu.fivenines.io" "us.fivenines.io")

# Loop through each host and ping once
for host in "${hosts[@]}"; do
  echo "Pinging $host..."
  if ping -c 1 -W 5 "$host" &> /dev/null; then
    echo "Ping to $host successful!"
  else
    exit_with_contact "Ping to $host failed or timed out. Check your network connection."
  fi
done

# Reload the service files to include the new fivenines-agent service
sudo systemctl daemon-reload

# Enable fivenines-agent service on every reboot
sudo systemctl enable fivenines-agent.service

# Start the fivenines-agent
sudo systemctl start fivenines-agent

if [ $? -ne 0 ]; then
  exit_with_contact "Failed to start the fivenines-agent service. Check the system logs for more information."
fi

# Remove the setup script
rm fivenines_setup.sh

echo "fivenines agent setup complete, happy monitoring!"
