#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

echo "Installing RemoteIDTransmitter"

# Stop and remove the service
service_uninstall rid-transmitter

pushd .
cd $PROJECT_ROOT/submodules/RemoteIDTransmitter
make install
sudo ldconfig
popd

service_add_manifest rid-transmitter

service_install rid-transmitter
