#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh
echo "Installing ARK-UI"

# Remove old ark-ui
service_uninstall pilot-portal
service_uninstall ark-ui-backend

# clean up old nginx
sudo rm /etc/nginx/sites-enabled/ark-ui &>/dev/null
sudo rm /etc/nginx/sites-available/ark-ui &>/dev/null
sudo rm -rf /var/www/ark-ui &>/dev/null

pushd .
cd $PROJECT_ROOT/submodules/ark-ui
./install.sh
popd

NGINX_CONFIG_FILE_PATH="/etc/nginx/sites-available/ark-ui"
DEPLOY_PATH="$XDG_DATA_HOME/ark-ui"

# Copy nginx config
sudo cp "$PROJECT_ROOT/submodules/ark-ui/ark-ui.nginx" $NGINX_CONFIG_FILE_PATH

# Copy frontend and backend files to deployment path
sudo mkdir -p $DEPLOY_PATH/html
sudo mkdir -p $DEPLOY_PATH/api
sudo cp -r $PROJECT_ROOT/submodules/ark-ui/ark-ui/dist/* $DEPLOY_PATH/html/
sudo cp -r $PROJECT_ROOT/submodules/ark-ui/backend/* $DEPLOY_PATH/api/

# Set permissions: www-data owns the path and has read/write permissions
sudo chown -R www-data:www-data $DEPLOY_PATH
sudo chmod -R 755 $DEPLOY_PATH

if [ ! -L /etc/nginx/sites-enabled/ark-ui ]; then
  sudo ln -s $NGINX_CONFIG_FILE_PATH /etc/nginx/sites-enabled/ark-ui
fi

# Remove default configuration
sudo rm /etc/nginx/sites-enabled/default &>/dev/null

# To check that it can run
sudo -u www-data stat $DEPLOY_PATH

# Test the configuration and restart nginx
sudo nginx -t
sudo systemctl restart nginx

service_add_manifest ark-ui-backend

service_install ark-ui-backend

echo "Finished $(basename $BASH_SOURCE)"
