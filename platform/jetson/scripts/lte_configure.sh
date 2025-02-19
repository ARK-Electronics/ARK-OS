#!/bin/bash

check_prerequisites() {
    if ! modprobe qmi_wwan; then
        echo "Error: Failed to load qmi_wwan kernel module"
        exit 1
    fi

    for cmd in mmcli; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Error: Required command '$cmd' not found"
            exit 1
        fi
    done

    if ! systemctl is-active --quiet NetworkManager; then
        echo "Error: NetworkManager is not running"
        exit 1
    fi
}

wait_for_modem_alive() {
    while true; do
        modem_instance=$(mmcli -L | grep -oP '(?<=/Modem/)\d+')
        if [ -n "$modem_instance" ]; then
            break
        fi
        sleep 2
    done
    echo "Modem instance: $modem_instance"
}

wait_for_modem_network_connected() {
    local modem_index=$1
    local timeout=60
    local count=0

    while [ $count -lt $timeout ]; do
        # Get status, strip colors, and check states
        local modem_status
        modem_status=$(mmcli -m "$modem_index" | TERM=dumb sed 's/\x1b\[[0-9;]*m//g')

        if echo "$modem_status" | sed 's/^[ \t]*//' | grep -q "state: connected" && \
           echo "$modem_status" | sed 's/^[ \t]*//' | grep -q "packet service state: attached"; then
            return 0
        fi

        echo -n "Waiting for modem to connect... ($count/$timeout seconds)\r"
        sleep 1
        count=$((count + 1))
    done

    echo -e "\nError: Timeout waiting for modem to connect"
    exit 1
}

usage() {
    cat << EOF
Usage: $0 --apn <apn>

Required arguments:
    --apn <apn>           Access Point Name for the cellular connection
EOF
}

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

if [ -z "$APN" ]; then
    echo "Error: APN is required"
    usage
    exit 1
fi

echo "Setting up ARK LTE modem"

if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    exit 1
fi

check_prerequisites

wait_for_modem_alive

MODEM_INDEX=$(mmcli -L | grep "Sierra.*RC7611" | grep -o "/[0-9]*" | tr -d '/' | tr -d '\n')
if [ -z "$MODEM_INDEX" ]; then
    echo "Error: Could not determine modem index"
    exit 1
fi

echo "Configuring initial EPS bearer settings"
mmcli -m "$MODEM_INDEX" --3gpp-set-initial-eps-bearer-settings="apn=$APN"

echo "Waiting for modem to connect to network"
mmcli -m "$MODEM_INDEX" --simple-connect="apn=$APN,ip-type=ipv4v6"
wait_for_modem_network_connected "$MODEM_INDEX"

echo "Creating connection"
modem_status=$(mmcli -m 0)
bearer_index=$(echo "$modem_status" | awk '/Bearer.*paths:/ { last = $NF } END { gsub(".*/", "", last); print last }')
bearer_info=$(mmcli -m 0 --bearer=$bearer_index)

interface=$(echo "$bearer_info" | awk -F': ' '/interface/ {print $2}')
address=$(echo "$bearer_info" | awk -F': ' '/address/ {print $2}')
prefix=$(echo "$bearer_info" | awk -F': ' '/prefix/ {print $2}')
gateway=$(echo "$bearer_info" | awk -F': ' '/gateway/ {print $2}')
dns=$(echo "$bearer_info" | awk -F': ' '/dns/ {print $2}')
mtu=$(echo "$bearer_info" | awk -F': ' '/mtu/ {print $2}')

IFS=', ' read -r dns1 dns2 <<< "$dns"
# Remove ending comma from dns1
dns1=${dns1%,}

echo "IPv4 Address: $address"
echo "IPv4 Prefix: $prefix"
echo "IPv4 Gateway: $gateway"
echo "IPv4 DNS1: $dns1"
echo "IPv4 DNS2: $dns2"
echo "IPv4 MTU: $mtu"

# Flush any existing ip or routes
sudo ip addr flush dev $interface
sudo ip route flush dev $interface

sudo ip link set $interface up

# Add IP if it doesn't already exist
if ! ip addr show $interface | grep -q "$address"; then
    sudo ip addr add "$address/$prefix" dev $interface
fi

sudo ip link set dev $interface arp off
sudo ip link set $interface mtu $mtu

sudo sh -c "echo 'nameserver $dns1' >> /etc/resolv.conf"
sudo sh -c "echo 'nameserver $dns2' >> /etc/resolv.conf"

# Add route if it doesn't already exist
if ! ip route show | grep -q "default via $gateway dev $interface"; then
    sudo ip route add default via $gateway dev $interface metric 4294967295
fi

echo "Testing connection"

if ! ping -4 -c 4 -I $interface 8.8.8.8 >/dev/null 2>&1; then
    echo "Failed!"
    exit 1
fi

echo "Connected!"

exit 0
