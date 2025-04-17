#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

echo "Installing logloader"

# Stop and remove the service
service_uninstall logloader

# Clean up directories
sudo rm -rf ~/logloader &>/dev/null
sudo rm -rf ~/code/logloader &>/dev/null

pushd .
cd $PROJECT_ROOT/submodules/logloader
make install
sudo ldconfig
popd

service_add_manifest logloader

service_install logloader
