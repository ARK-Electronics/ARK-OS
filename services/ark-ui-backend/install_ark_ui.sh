#!/bin/bash

# Determine PROJECT_ROOT as two levels up from this script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
source "$PROJECT_ROOT/setup/functions.sh"

echo "Installing ARK-UI"

# clean up old nginx
sudo rm /etc/nginx/sites-enabled/ark-ui &>/dev/null
sudo rm /etc/nginx/sites-available/ark-ui &>/dev/null
sudo rm -rf /var/www/ark-ui &>/dev/null

pushd .
cd $PROJECT_ROOT/frontend/ark-ui
./install.sh
popd

DEPLOY_PATH="/var/www/ark-ui"

# Copy nginx config
sudo cp $PROJECT_ROOT/frontend/ark-ui.nginx /etc/nginx/sites-available/ark-ui

# Copy frontend and backend files to deployment path
sudo mkdir -p $DEPLOY_PATH/html
sudo mkdir -p $DEPLOY_PATH/api
sudo cp -r $PROJECT_ROOT/frontend/ark-ui/ark-ui/dist/* $DEPLOY_PATH/html/
sudo cp -r $PROJECT_ROOT/frontend/ark-ui/backend/* $DEPLOY_PATH/api/

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
