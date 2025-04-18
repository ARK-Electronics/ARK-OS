#!/bin/bash
# Determine PROJECT_ROOT as two levels up from this script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"
source "$PROJECT_ROOT/setup/functions.sh"

echo "Installing mavsdk-examples"
pushd .
cd $PROJECT_ROOT/misc/mavsdk-examples
make install
popd
