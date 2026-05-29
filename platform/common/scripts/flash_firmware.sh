#!/bin/bash

DEFAULT_FW_PATH="/tmp/ark_fmu-v6x_default.px4"
FW_PATH=${1:-$DEFAULT_FW_PATH}

# Check if the firmware file exists
if [ ! -f "$FW_PATH" ]; then
    jq -n --arg msg "Firmware file does not exist" \
          '{status: "failed", message: $msg, percent: 0}'
    exit 1
fi

# Attempt to find the device
SERIALDEVICE=$(ls -l /dev/serial/by-id/*ARK* | grep 'if00' | awk -F'/' '{print "/dev/"$NF}')
if [ -z "$SERIALDEVICE" ]; then
    jq -n --arg msg "ARKV6X not found" \
          '{status: "failed", message: $msg, percent: 0}'
    exit 1
fi

# Stop mavlink-router so it releases the autopilot serial port. If it can't be
# stopped it keeps the port open at 2 Mbaud and the bootloader erase will stall,
# so fail loud instead of hanging. (systemctl stop succeeds as a no-op if the unit
# is already stopped.) A polkit denial here means the service user is missing the
# 99-ark-service-manager.pkla grant.
if ! systemctl stop mavlink-router &>/dev/null; then
    jq -n --arg msg "Could not stop mavlink-router; it still holds the autopilot serial port. Check the service-manager polkit authorization." \
          '{status: "failed", message: $msg, percent: 0}'
    exit 1
fi

if ! /usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/scripts/reset_fmu_wait_bl.py &>/dev/null; then
    jq -n --arg msg "Failed to reset the flight controller into bootloader mode." \
          '{status: "failed", message: $msg, percent: 0}'
    systemctl restart mavlink-router &>/dev/null
    exit 1
fi

echo "Flashing $SERIALDEVICE"

# If the device is found and file exists, run the uploader script and filter JSON output
/usr/lib/ark-os/venv/bin/python3 -u /usr/lib/ark-os/scripts/px_uploader.py --json-progress --port $SERIALDEVICE $FW_PATH 2>&1 | while IFS= read -r line
do
    echo "$line" | jq -c 'select(type == "object")' 2>/dev/null || :
done

# TODO: maybe need a delay here for ardupilot
/usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/scripts/reset_fmu_fast.py &>/dev/null

sleep 3

systemctl restart mavlink-router &>/dev/null
