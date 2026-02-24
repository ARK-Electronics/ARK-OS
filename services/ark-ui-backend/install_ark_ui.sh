#!/bin/bash

# Determine PROJECT_ROOT as two levels up from this script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
source "$PROJECT_ROOT/tools/functions.sh"

echo "Installing ARK-UI"

# clean up old nginx
sudo rm /etc/nginx/sites-enabled/ark-ui &>/dev/null
sudo rm /etc/nginx/sites-available/ark-ui &>/dev/null
sudo rm -rf /var/www/ark-ui &>/dev/null

# Clean up old Express backend service (no longer needed)
systemctl --user stop ark-ui-backend.service &>/dev/null
systemctl --user disable ark-ui-backend.service &>/dev/null
rm -f "$HOME/.config/systemd/user/ark-ui-backend.service" &>/dev/null
rm -f "$HOME/.local/bin/start_ark_ui_backend.sh" &>/dev/null

pushd .
cd $PROJECT_ROOT/frontend/ark-ui
./install.sh
popd

DEPLOY_PATH="/var/www/ark-ui"

# Install nginx proxy snippets
sudo mkdir -p /etc/nginx/snippets
sudo cp $PROJECT_ROOT/frontend/ark-proxy.conf /etc/nginx/snippets/ark-proxy.conf
sudo cp $PROJECT_ROOT/frontend/ark-ws.conf /etc/nginx/snippets/ark-ws.conf

# Copy nginx config
sudo cp $PROJECT_ROOT/frontend/ark-ui.nginx /etc/nginx/sites-available/ark-ui

# Copy frontend files to deployment path (no backend needed)
sudo mkdir -p $DEPLOY_PATH/html
sudo cp -r $PROJECT_ROOT/frontend/ark-ui/ark-ui/dist/* $DEPLOY_PATH/html/

# Set permissions: www-data owns the path and has read/write permissions
sudo chown -R www-data:www-data $DEPLOY_PATH
sudo chmod -R 755 $DEPLOY_PATH

if [ ! -L /etc/nginx/sites-enabled/ark-ui ]; then
  sudo ln -s /etc/nginx/sites-available/ark-ui /etc/nginx/sites-enabled/ark-ui
fi

# Remove default configuration
sudo rm /etc/nginx/sites-enabled/default &>/dev/null

# To check that it can run
sudo -u www-data stat $DEPLOY_PATH

# Test the configuration and restart nginx
sudo nginx -t
sudo systemctl restart nginx

echo "Finished $(basename $BASH_SOURCE)"
