#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./functions.sh
source "$SCRIPT_DIR/functions.sh"

title "Installing Connections Manager..."

# Install Python dependencies
print_step "Installing Python dependencies..."
sudo apt-get update
sudo apt-get install -y python3-pip python3-flask python3-psutil python3-toml

# Install Python modules
print_step "Installing Python packages..."
sudo pip3 install flask-cors

# Copy necessary files
print_step "Copying configuration files and scripts..."
sudo mkdir -p /etc/ark/network
sudo mkdir -p /usr/local/bin

# Copy Python service
sudo cp "$SCRIPT_DIR/../platform/common/scripts/connections_manager_service.py" /usr/local/bin/
sudo chmod +x /usr/local/bin/connections_manager_service.py

# Copy configuration file
if [ ! -f "/etc/ark/network/connections_manager.toml" ]; then
    sudo cp "$SCRIPT_DIR/../platform/common/scripts/connections_manager.toml" /etc/ark/network/
fi

# Copy systemd service file
sudo cp "$SCRIPT_DIR/../platform/common/services/connections-manager.service" /etc/systemd/system/

# Reload systemd, enable and start the service
print_step "Enabling connections-manager service..."
sudo systemctl daemon-reload
sudo systemctl enable connections-manager.service
sudo systemctl restart connections-manager.service

echo "Connections Manager installation complete"
print_step "To check service status, run: sudo systemctl status connections-manager"