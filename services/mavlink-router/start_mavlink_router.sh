#!/bin/bash

# Assumes there is a conf file here
export MAVLINK_ROUTERD_CONF_FILE="/home/$USER/.local/share/mavlink-router/main.conf"

# Find the correct device path
DEVICE_PATH=$(ls /dev/serial/by-id/*ARK* | grep 'if00')

if [ -z "$DEVICE_PATH" ]; then
    echo "No matching device found for FCUSB endpoint."
    exit 1
fi

# Replace serial device "*if00" with correct device path for PX4/Ardupilot
sed -i "s|^Device =.*if00|Device = $DEVICE_PATH|" "$MAVLINK_ROUTERD_CONF_FILE"

# Enable mavlink usb stream first
python3 ~/.local/bin/vbus_enable.py

sleep 3

mavlink-routerd
