#!/bin/bash

export NVM_DIR="$HOME/.config/nvm"
source $NVM_DIR/nvm.sh

# Specify the Node version
nvm use 20.15.0

# Start your application
cd /var/www/ark-ui/api
npm start
