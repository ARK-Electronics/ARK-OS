#!/bin/bash

set -euo pipefail

# Help text
usage() {
    cat << EOF
Usage: $0 --apn <apn> [--dns1 <server1>] [--dns2 <server2>] [--user <username>] [--password <password>]

Required arguments:
    --apn <apn>           Access Point Name for the cellular connection

Optional arguments:
    --dns1 <server1>      Primary DNS server
    --dns2 <server2>      Secondary DNS server
    --user <username>     Username for carriers that require authentication
    --password <password> Password for carriers that require authentication
    --help               Show this help message
EOF
}

# Parse arguments
APN=""
DNS1=""
DNS2=""
USERNAME=""
PASSWORD=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --apn)
            APN="$2"
            shift 2
            ;;
        --dns1)
            DNS1="$2"
            shift 2
            ;;
        --dns2)
            DNS2="$2"
            shift 2
            ;;
        --user)
            USERNAME="$2"
            shift 2
            ;;
        --password)
            PASSWORD="$2"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown parameter $1"
            usage
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$APN" ]; then
    echo "Error: APN is required"
    usage
    exit 1
fi

# Function to check prerequisites
check_prerequisites() {
    echo "Checking prerequisites..."

    # Check for QMI_WWAN kernel module
    if ! lsmod | grep -q "qmi_wwan"; then
        echo "Error: qmi_wwan kernel module not loaded"
        echo "Try: modprobe qmi_wwan"
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
}

# Function to wait for modem with timeout
wait_for_modem() {
    local timeout=30
    local count=0

    echo "Waiting for modem to be detected..."
    while [ $count -lt $timeout ]; do
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
        echo "Please check:"
        echo "  - SIM card is properly inserted"
        echo "  - SIM card is not locked"
        echo "  - SIM card is activated with carrier"
        exit 1
    fi

    # Check signal quality
    local signal_quality
    signal_quality=$(echo "$modem_status" | grep "signal quality:" | grep -o "[0-9]*" | head -1)
    if [ -n "$signal_quality" ] && [ "$signal_quality" -lt 10 ]; then
        echo "Warning: Very weak signal strength ($signal_quality%)"
        echo "Please check antenna connections"
    fi
}

# Function to verify bearer state
verify_bearer_state() {
    local modem_index=$1

    echo "Verifying bearer state..."
    local bearer_status
    bearer_status=$(mmcli -m "$modem_index" --bearer=0 2>/dev/null || true)

    if [ -n "$bearer_status" ]; then
        if ! echo "$bearer_status" | grep -q "connected.*yes"; then
            echo "Warning: Bearer not connected"
            echo "This may be normal if connection hasn't been started yet"
        fi
    fi
}

# Function to configure connection
configure_connection() {
    local conn_name="ark-lte"

    # Remove existing connection if present
    if nmcli connection show | grep -q "^$conn_name "; then
        echo "Removing existing connection..."
        nmcli connection delete "$conn_name"
    fi

    # Build base connection command
    local cmd="nmcli connection add \
        type gsm \
        con-name $conn_name \
        ifname wwan0 \
        apn $APN \
        connection.autoconnect yes \
        gsm.auto-config yes \
        ipv4.method auto \
        ipv4.route-metric 4294967295 \
        ipv6.method auto \
        ethernet.arp no"

    # Add optional DNS servers if specified
    if [ -n "$DNS1" ] || [ -n "$DNS2" ]; then
        local dns_servers=""
        if [ -n "$DNS1" ]; then
            dns_servers="$DNS1"
            if [ -n "$DNS2" ]; then
                dns_servers="$dns_servers,$DNS2"
            fi
        elif [ -n "$DNS2" ]; then
            dns_servers="$DNS2"
        fi
        cmd="$cmd ipv4.dns \"$dns_servers\""
        cmd="$cmd ipv4.ignore-auto-dns yes"
    fi

    # Add authentication if specified
    if [ -n "$USERNAME" ]; then
        cmd="$cmd gsm.username \"$USERNAME\""
    fi
    if [ -n "$PASSWORD" ]; then
        cmd="$cmd gsm.password \"$PASSWORD\""
    fi

    # Execute the assembled command
    eval "$cmd"

    # Configure MTU and other link settings
    nmcli connection modify "$conn_name" gsm.mtu 1500
    nmcli connection modify "$conn_name" 802-3-ethernet.accept-all-mac-addresses no
}

# Main script
echo "Configuring ARK LTE modem..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

# Run prerequisite checks
check_prerequisites

# Wait for modem
wait_for_modem

# Verify modem state
verify_modem_state "$MODEM_INDEX"

# Verify bearer state
verify_bearer_state "$MODEM_INDEX"

# Get modem index
MODEM_INDEX=$(get_modem_index)
if [ -z "$MODEM_INDEX" ]; then
    echo "Error: Could not determine modem index"
    exit 1
fi

# Configure EPS bearer
echo "Configuring initial EPS bearer settings..."
mmcli -m "$MODEM_INDEX" --3gpp-set-initial-eps-bearer-settings="apn=$APN"

# Create and configure connection
echo "Creating NetworkManager connection..."
configure_connection

echo "Starting connection..."
nmcli connection up ark-lte

# Quick connection verification
echo "Verifying connection..."
sleep 5
if ! nmcli -g GENERAL.STATE connection show ark-lte 2>/dev/null | grep -q "activated"; then
    echo "Error: Connection failed to activate"
    exit 1
fi

echo "Configuration completed successfully"
exit 0
