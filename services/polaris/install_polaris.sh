#!/bin/bash
# Determine PROJECT_ROOT as two levels up from this script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
source "$PROJECT_ROOT/setup/functions.sh"

echo "Installing polaris-client-mavlink"

# Clean up directories
sudo rm -rf ~/polaris-client-mavlink &>/dev/null
sudo rm -rf $XDG_DATA_HOME/polaris-client-mavlink &>/dev/null
sudo rm /usr/local/bin/polaris-client-mavlink &>/dev/null
sudo rm /usr/local/bin/polaris &>/dev/null

# Install dependencies
sudo apt-get install -y libssl-dev libgflags-dev libgoogle-glog-dev libboost-all-dev
pushd .
cd polaris-client-mavlink
make install
sudo ldconfig
popd
