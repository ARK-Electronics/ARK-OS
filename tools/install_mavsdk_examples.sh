#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "$SCRIPT_DIR/functions.sh"

echo "Installing mavsdk-examples"
pushd .
cd $PROJECT_ROOT/libs/mavsdk-examples
make install
popd
