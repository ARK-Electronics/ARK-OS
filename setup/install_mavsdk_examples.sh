#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

echo "Installing mavsdk-examples"
pushd .
cd $PROJECT_ROOT/misc/mavsdk-examples
make install
popd
