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
# Use the first 6 bytes of the SHA256 hash of the serial number
mac=$(echo -n $serial_number | sha256sum | awk '{print $1}' | sed 's/^\(..\)\(..\)\(..\)\(..\)\(..\)\(..\).*/\1:\2:\3:\4:\5:\6/')
if [ $? -ne 0 ]; then
    echo "Error: could not generate MAC address"
    exit 1
fi

# Print the generated MAC address
echo "Generated MAC address: $mac"

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

# Set the MAC address
sudo ip link set dev $interface address $mac
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

echo "Successfully set MAC address $mac on $interface"