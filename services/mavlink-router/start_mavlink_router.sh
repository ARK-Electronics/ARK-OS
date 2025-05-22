#!/bin/bash

# Assumes there is a conf file here
export MAVLINK_ROUTERD_CONF_FILE="/home/$USER/.local/share/mavlink-router/main.conf"

# 1) Read the currently configured Device path from main.conf
CONFIGURED_PATH=$(grep -E '^Device\s*=' "$MAVLINK_ROUTERD_CONF_FILE" \
  | awk -F'=' '{print $2}' \
  | xargs)

# 2) If that path exists on the filesystem, use it.
if [ -n "$CONFIGURED_PATH" ] && [ -e "$CONFIGURED_PATH" ]; then
    echo "Using configured device path: $CONFIGURED_PATH"
    DEVICE_PATH="$CONFIGURED_PATH"
else
    # 3) Otherwise, fall back to scanning for the ARK serial endpoint
    echo "Configured device path '$CONFIGURED_PATH' not found. Scanning for ARK device..."
    DEVICE_PATH=$(ls /dev/serial/by-id/*ARK* 2>/dev/null | grep 'if00' || true)

    if [ -z "$DEVICE_PATH" ]; then
        echo "No matching device found for FCUSB endpoint."
        exit 1
    fi

    # 4) Update the config so future runs pick up the right path
    echo "Updating config to use detected device: $DEVICE_PATH"
    sed -i "s|^Device\s*=.*|Device = $DEVICE_PATH|" "$MAVLINK_ROUTERD_CONF_FILE"
fi

# Enable mavlink USB stream first
python3 ~/.local/bin/vbus_enable.py

sleep 3

# Finally, launch mavlink-routerd
mavlink-routerd
