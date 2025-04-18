#!/bin/bash

detect_platform() {
    # Check if we're on Jetson (look for Tegra in kernel info)
    if uname -ar | grep -q tegra; then
        echo "jetson"
        return 0
    fi

    # Check if we're on Raspberry Pi
    if [ -f /proc/device-tree/model ] && grep -q "Raspberry Pi" /proc/device-tree/model; then
        echo "pi"
        return 0
    fi

    # Check for common files on Raspberry Pi
    if [ -f /etc/rpi-issue ] || [ -d /opt/vc/lib ]; then
        echo "pi"
        return 0
    fi

    # If not Jetson or Pi, assume regular Ubuntu
    echo "ubuntu"
    return 0
}

# Set platform as an environment variable
export TARGET=$(detect_platform)

echo "Detected platform: $TARGET"

# Start the DDS agent based on the detected platform
case "$TARGET" in
    jetson)
        echo "Starting DDS agent for Jetson platform"
        /snap/bin/micro-xrce-dds-agent serial -b 3000000 -D /dev/ttyTHS1
        ;;
    pi)
        echo "Starting DDS agent for Raspberry Pi platform"
        /snap/bin/micro-xrce-dds-agent serial -b 3000000 -D /dev/ttyAMA4
        ;;
    ubuntu)
        echo "Starting DDS agent for Ubuntu desktop"
        # For Ubuntu, use UDP on port 8888
        /snap/bin/micro-xrce-dds-agent udp4 -p 8888
        ;;
    *)
        echo "Unknown platform"
        exit 1
        ;;
esac
