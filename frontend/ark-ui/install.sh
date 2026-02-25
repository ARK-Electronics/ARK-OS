#!/bin/bash

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
source "$PROJECT_ROOT/tools/functions.sh"

pushd .

cd "$SCRIPT_DIR"

apt_get_install update
apt_get_install install -y curl jq nginx

# Install NVM (Node Version Manager)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash

# Determine the correct NVM directory based on XDG_CONFIG_HOME
if [ -z "$XDG_CONFIG_HOME" ]; then
    export NVM_DIR="$HOME/.config/nvm"
else
    export NVM_DIR="$XDG_CONFIG_HOME/nvm"
fi

# Source the NVM scripts to use it in the same script
source $NVM_DIR/nvm.sh
source $NVM_DIR/bash_completion

# Install the desired Node.js version and set it as default
nvm install 20
nvm use 20
nvm alias default 20

# Install global Vue CLI
npm install -g @vue/cli @vue/cli-service@latest

# Install frontend dependencies and build project
cd ark-ui
npm install
npm run build

popd
