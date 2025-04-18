#!/bin/bash
# Determine PROJECT_ROOT as two levels up from this script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
source "$PROJECT_ROOT/setup/functions.sh"

echo "Installing rtsp-server"

sudo apt-get install -y  \
	libgstreamer1.0-dev \
	libgstreamer-plugins-base1.0-dev \
	libgstreamer-plugins-bad1.0-dev \
	libgstrtspserver-1.0-dev \
	gstreamer1.0-plugins-ugly \
	gstreamer1.0-tools \
	gstreamer1.0-gl \
	gstreamer1.0-gtk3 \
	gstreamer1.0-rtsp

if [ "$TARGET" = "pi" ]; then
	sudo apt-get install -y gstreamer1.0-libcamera

else
	# Ubuntu 22.04, see antimof/UxPlay#121
	sudo apt remove gstreamer1.0-vaapi
fi

pushd .
cd rtsp-server
make install
sudo ldconfig
popd
