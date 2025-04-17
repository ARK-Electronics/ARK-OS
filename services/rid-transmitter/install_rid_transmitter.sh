#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

echo "Installing RemoteIDTransmitter"

pushd .
cd RemoteIDTransmitter
make install
sudo ldconfig
popd
