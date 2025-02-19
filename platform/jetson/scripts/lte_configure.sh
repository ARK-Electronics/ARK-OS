#!/bin/bash

set -euo pipefail

# Configuration
APN="fast.t-mobile.com"  # Change this to your carrier's APN
TIMEOUT=60  # Timeout in seconds to wait for modem

# Function to check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."

    # Check for QMI_WWAN kernel module
    if ! lsmod | grep -q "qmi_wwan"; then
        echo "Error: qmi_wwan kernel module not loaded"
        echo "Try: sudo modprobe qmi_wwan"
        exit 1
    fi

    # Check for required tools
    for cmd in mmcli nmcli; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Error: Required command '$cmd' not found"
            exit 1
        fi
    done

    # Check if NetworkManager is running
    if ! systemctl is-active --quiet NetworkManager; then
        echo "Error: NetworkManager is not running"
        exit 1
    fi

    # Check for SIM presence (basic check)
    if ! mmcli -L | grep -q "Sierra.*RC7611"; then
        echo "Warning: Modem not detected. Please check:"
        echo "  - SIM card is properly inserted"
        echo "  - Antennas are properly connected"
        echo "  - Device is properly powered"
        exit 1
    fi
}

# Function to wait for modem
wait_for_modem() {
    echo "Waiting for modem to be detected..."
    local count=0
    while [ $count -lt $TIMEOUT ]; do
        if mmcli -L | grep -q "Sierra.*RC7611"; then
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    echo "Error: Modem not detected within timeout period"
    exit 1
}

# Function to get modem index
get_modem_index() {
    local modem_index
    modem_index=$(mmcli -L | grep "Sierra.*RC7611" | grep -o "/[0-9]*" | tr -d '/')
    echo "$modem_index"
}

# Function to verify modem state
verify_modem_state() {
    local modem_index=$1
    local modem_status

    echo "Verifying modem state..."
    modem_status=$(mmcli -m "$modem_index")

    # Check if modem is enabled
    if ! echo "$modem_status" | grep -q "state: 'enabled'"; then
        echo "Error: Modem is not enabled"
        exit 1
    fi

    # Check for SIM
    if ! echo "$modem_status" | grep -q "SIM.*active"; then
        echo "Error: No active SIM detected"
        exit 1
    fi
}

# Function to setup initial EPS bearer
setup_eps_bearer() {
    local modem_index=$1
    echo "Configuring initial EPS bearer settings..."
    sudo mmcli -m "$modem_index" --3gpp-set-initial-eps-bearer-settings="apn=$APN"

    # Verify bearer setup
    local bearer_status
    bearer_status=$(mmcli -m "$modem_index" --bearer=0)
    if ! echo "$bearer_status" | grep -q "connected.*yes"; then
        echo "Error: Bearer not connected"
        exit 1
    fi
}

# Function to create NetworkManager connection
create_nm_connection() {
    local modem_index=$1
    local conn_name="sierra-lte"

    # Check if connection already exists
    if nmcli connection show | grep -q "^$conn_name "; then
        echo "Connection '$conn_name' already exists. Removing..."
        nmcli connection delete "$conn_name"
    fi

    echo "Creating NetworkManager connection..."
    nmcli connection add \
        type gsm \
        con-name "$conn_name" \
        ifname wwan0 \
        apn "$APN" \
        connection.autoconnect yes \
        gsm.auto-config yes \
        ipv4.method auto \
        ipv4.route-metric 4294967295 \
        ipv6.method auto

    echo "Setting connection permissions..."
    nmcli connection modify "$conn_name" connection.permissions "user:$USER"

    # Get bearer settings and configure interface
    local bearer_info
    bearer_info=$(mmcli -m "$modem_index" --bearer=0)
    local mtu
    mtu=$(echo "$bearer_info" | grep "mtu:" | awk '{print $3}')

    # If we couldn't get MTU from bearer, default to 1500
    if [ -z "$mtu" ]; then
        mtu=1500
    fi

    echo "Configuring interface settings..."
    nmcli connection modify "$conn_name" gsm.mtu "$mtu"
    nmcli connection modify "$conn_name" 802-3-ethernet.accept-all-mac-addresses no
    nmcli connection modify "$conn_name" ethernet.arp no

    return 0
}

# Function to verify connection
verify_connection() {
    local conn_name="sierra-lte"
    local max_attempts=12
    local attempt=0

    echo "Waiting for connection to become active..."
    while [ $attempt -lt $max_attempts ]; do
        if nmcli -g GENERAL.STATE connection show "$conn_name" 2>/dev/null | grep -q "activated"; then
            echo "Connection is active"
            return 0
        fi
        sleep 5
        attempt=$((attempt + 1))
    done

    echo "Error: Connection failed to activate"
    return 1
}

# Function for connection testing
test_connection() {
    echo "Testing connection..."

    # Test IPv4 connectivity
    if ! ping -c 4 -I wwan0 8.8.8.8; then
        echo "Warning: IPv4 connectivity test failed"
        echo "Troubleshooting steps:"
        echo "1. Check APN settings"
        echo "2. Verify SIM card is active"
        echo "3. Check signal strength"
        echo "4. Verify carrier account status"
        return 1
    fi

    return 0
}

# Main script
echo "Starting Sierra RC7611 modem setup with NetworkManager..."

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Please run this script as a regular user with sudo privileges"
    exit 1
fi

# Run setup steps
check_prerequisites
wait_for_modem

MODEM_INDEX=$(get_modem_index)
if [ -z "$MODEM_INDEX" ]; then
    echo "Error: Could not determine modem index"
    exit 1
fi

verify_modem_state "$MODEM_INDEX"
setup_eps_bearer "$MODEM_INDEX"
create_nm_connection "$MODEM_INDEX"

echo "Starting connection..."
nmcli connection up sierra-lte

if verify_connection; then
    if test_connection; then
        echo "Setup completed successfully!"
    else
        echo "Setup completed with warnings (connection test failed)"
    fi
else
    echo "Setup failed - connection could not be activated"
    exit 1
fi
