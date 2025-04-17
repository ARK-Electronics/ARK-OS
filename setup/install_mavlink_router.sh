#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

echo "Installing mavlink-router"

# clean up legacy if it exists
service_uninstall mavlink-router

# remove old config, source, and binary
sudo rm -rf /etc/mavlink-router &>/dev/null
sudo rm -rf ~/code/mavlink-router &>/dev/null
sudo rm /usr/bin/mavlink-routerd &>/dev/null

pushd .
cd $PROJECT_ROOT/submodules/mavlink-router
meson setup build --prefix=$HOME/.local -Dsystemdsystemunitdir=
ninja -C build install
popd

mkdir -p $XDG_DATA_HOME/mavlink-router/
cp $TARGET_DIR/main.conf $XDG_DATA_HOME/mavlink-router/main.conf

service_add_manifest mavlink-router

service_install mavlink-router
