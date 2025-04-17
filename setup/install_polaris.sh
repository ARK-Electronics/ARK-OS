#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

echo "Installing polaris-client-mavlink"

# Stop and remove the service
service_uninstall polaris
service_uninstall polaris-client-mavlink

# Clean up directories
sudo rm -rf ~/polaris-client-mavlink &>/dev/null
sudo rm -rf $XDG_DATA_HOME/polaris-client-mavlink &>/dev/null
sudo rm /usr/local/bin/polaris-client-mavlink &>/dev/null
sudo rm /usr/local/bin/polaris &>/dev/null

# Install dependencies
sudo apt-get install -y libssl-dev libgflags-dev libgoogle-glog-dev libboost-all-dev

pushd .
cd $PROJECT_ROOT/submodules/polaris-client-mavlink
make install
sudo ldconfig
popd

service_add_manifest polaris

service_install polaris
