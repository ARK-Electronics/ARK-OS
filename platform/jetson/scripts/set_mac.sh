#!/bin/bash

# Get the board serial number from get_serial_number.py in the same directory
serial_number=$(python3 $(dirname $0)/get_serial_number.py)
if [ $? -ne 0 ]; then
    echo "Error: could not get serial number"
    exit 1
fi

# Generate a MAC address from the serial number
# Use the first 6 bytes of the SHA256 hash of the serial number
mac=$(echo -n $serial_number | sha256sum | awk '{print $1}' | sed 's/^\(..\)\(..\)\(..\)\(..\)\(..\)\(..\).*/\1:\2:\3:\4:\5:\6/')
if [ $? -ne 0 ]; then
    echo "Error: could not generate MAC address"
    exit 1
fi

# Set the MAC address on the enP8p1s0 interface
interface="enP8p1s0"
sudo ip link set dev $interface address $mac
if [ $? -ne 0 ]; then
    echo "Error: could not set MAC address on $interface"
    exit 1
fi