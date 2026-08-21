#!/bin/bash

detect_platform() {
    # Modalix before Jetson: PAB V3 DTB model is
    # "ARK Jetson PAB V3 with SiMa Modalix SoM" and would match *Jetson*.
    if [ -r /proc/device-tree/compatible ] &&
       grep -z -q 'simaai,modalix' /proc/device-tree/compatible; then
        echo "modalix"
        return 0
    fi
    if [ -r /etc/os-release ] &&
       ( # shellcheck source=/dev/null
         . /etc/os-release
         [ "${ID:-}" = "elxr" ] || [ "${ID_LIKE:-}" = *"elxr"* ]
       ); then
        echo "modalix"
        return 0
    fi
    if uname -r | grep -q modalix; then
        echo "modalix"
        return 0
    fi

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

    # If not Jetson, Pi, or Modalix, assume regular Ubuntu
    echo "ubuntu"
    return 0
}

# Set platform as an environment variable
export TARGET=$(detect_platform)

echo "Detected platform: $TARGET"

# Start the DDS agent based on the detected platform
case "$TARGET" in
    jetson)
        echo "Starting DDS agent for Jetson platform (serial TELEM2)"
        exec /usr/lib/ark-os/bin/MicroXRCEAgent serial -b 3000000 -D /dev/ttyTHS1
        ;;
    pi)
        echo "Starting DDS agent for Raspberry Pi platform"
        exec /usr/lib/ark-os/bin/MicroXRCEAgent serial -b 3000000 -D /dev/ttyAMA4
        ;;
    modalix)
        # Modalix UART1/Telem2 is not usable; uXRCE-DDS goes over FC Ethernet.
        echo "Starting DDS agent for Modalix platform (UDP Ethernet :8888)"
        exec /usr/lib/ark-os/bin/MicroXRCEAgent udp4 -p 8888
        ;;
    ubuntu)
        echo "Starting DDS agent for Ubuntu desktop"
        exec /usr/lib/ark-os/bin/MicroXRCEAgent udp4 -p 8888
        ;;
    *)
        echo "Unknown platform"
        exit 1
        ;;
esac
