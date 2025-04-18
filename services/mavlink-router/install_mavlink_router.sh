#!/bin/bash
# Determine PROJECT_ROOT as two levels up from this script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
source "$PROJECT_ROOT/setup/functions.sh"

echo "Installing mavlink-router"

# remove old config, source, and binary
sudo rm -rf /etc/mavlink-router &>/dev/null
sudo rm -rf ~/code/mavlink-router &>/dev/null
sudo rm /usr/bin/mavlink-routerd &>/dev/null

pushd .
cd mavlink-router
meson setup build --prefix=$HOME/.local -Dsystemdsystemunitdir=
ninja -C build install
popd

mkdir -p $XDG_DATA_HOME/mavlink-router/
cp main.conf $XDG_DATA_HOME/mavlink-router/main.conf
