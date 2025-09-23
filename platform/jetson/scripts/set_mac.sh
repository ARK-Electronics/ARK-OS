#!/bin/bash

# Get the board serial number from get_serial_number.py in the same directory
serial_number=$(python3 $(dirname $0)/get_serial_number.py)
if [ $? -ne 0 ]; then
    echo "Error: could not get serial number"
    exit 1
fi

# Print the serial number
echo "Board serial number: $serial_number"

# Generate a MAC address from the serial number
# This will be used for the device-specific part (last 3 bytes)
# The OUI (first 3 bytes) will be preserved from the existing interface

# Find the first available Ethernet interface
# Look for interfaces that are ethernet type and not loopback
interface=$(ip link show | grep -E '^[0-9]+: (en|eth)' | head -n1 | cut -d':' -f2 | tr -d ' ')

if [ -z "$interface" ]; then
    echo "Error: no Ethernet interface found"
    echo "Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | cut -d':' -f2 | tr -d ' '
    exit 1
fi

echo "Using interface: $interface"

# Get the current MAC address of the interface
current_mac=$(ip link show $interface | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}')
if [ -z "$current_mac" ]; then
    echo "Error: could not get current MAC address for $interface"
    exit 1
fi

echo "Current MAC address: $current_mac"

# Extract the first 3 bytes (OUI) from the current MAC address
oui=$(echo $current_mac | cut -d: -f1-3)

# Generate the last 3 bytes from the serial number hash
# Use the first 3 bytes of the SHA256 hash of the serial number for the device-specific part
device_specific=$(echo -n $serial_number | sha256sum | awk '{print $1}' | sed 's/^\(..\)\(..\)\(..\).*/\1:\2:\3/')
if [ $? -ne 0 ]; then
    echo "Error: could not generate device-specific MAC bytes"
    exit 1
fi

# Combine OUI with device-specific bytes
new_mac="${oui}:${device_specific}"

echo "New MAC address: $new_mac (preserving OUI: $oui)"

# Check if interface exists
if ! ip link show $interface > /dev/null 2>&1; then
    echo "Error: interface $interface not found"
    exit 1
fi

# Bring down the interface
sudo ip link set dev $interface down
if [ $? -ne 0 ]; then
    echo "Error: could not bring down $interface"
    exit 1
fi

# Set the new MAC address
sudo ip link set dev $interface address $new_mac
if [ $? -ne 0 ]; then
    echo "Error: could not set MAC address on $interface"
    # Try to bring the interface back up even if MAC setting failed
    sudo ip link set dev $interface up
    exit 1
fi

# Bring the interface back up
sudo ip link set dev $interface up
if [ $? -ne 0 ]; then
    echo "Error: could not bring up $interface"
    exit 1
fi

echo "Successfully set MAC address $new_mac on $interface"