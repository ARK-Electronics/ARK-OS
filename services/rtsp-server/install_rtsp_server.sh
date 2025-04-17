#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

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

service_uninstall rtsp-server

pushd .
cd $PROJECT_ROOT/submodules/rtsp-server
make install
sudo ldconfig
popd

service_add_manifest rtsp-server

service_install rtsp-server
