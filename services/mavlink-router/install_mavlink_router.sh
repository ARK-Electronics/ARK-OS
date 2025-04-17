#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

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
