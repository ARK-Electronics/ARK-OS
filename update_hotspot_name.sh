#!/bin/bash

find_existing_ap() {
    local IFS=$'\n'  # Change the Internal Field Separator to new line
    local connections=$(nmcli -t -f NAME,TYPE con show | grep "802-11-wireless")

    echo "$connections" | while read -r connection; do
        local name=$(echo "$connection" | cut -d ':' -f1)
        local mode=$(nmcli -t -f 802-11-wireless.mode con show "$name")
        if [[ $mode == "802-11-wireless.mode:ap" ]]; then
            echo "$name"
            return
        fi
    done
    echo ""
}

# Get the first wireless interface
INTERFACE=$(iw dev | grep Interface | awk '{print $2}' | head -1)

if [ -z "$INTERFACE" ]; then
    echo "No wireless interface found"
    exit 1
fi

# Check if an AP connection already exists
AP_SSID="$(find_existing_ap)"

if [ -z "$AP_SSID" ]; then
    # Hot spot does not exist, create it
    HOSTNAME=$(hostname)
    SERIAL=$(cat /proc/device-tree/serial-number 2>/dev/null || echo "unknown")
    AP_SSID="${HOSTNAME}-${SERIAL}"
    AP_PASSWORD="password"

    echo "Creating new hotspot: $AP_SSID"

    sudo nmcli con add type wifi ifname '*' con-name "$AP_SSID" autoconnect yes ssid "$AP_SSID" \
        802-11-wireless.mode ap 802-11-wireless.band bg ipv4.method shared

    sudo nmcli con modify "$AP_SSID" wifi-sec.key-mgmt wpa-psk wifi-sec.psk "$AP_PASSWORD" \
        802-11-wireless-security.pmf disable connection.autoconnect-priority -1

    echo "Created new AP: $AP_SSID with autoconnect enabled"
else
    # Hot spot exists
    # - set priority to -1
    # - enable autoconnect

    PRIORITY=$(nmcli -g connection.autoconnect-priority con show "$AP_SSID")

    if [ "$PRIORITY" != "-1" ]; then
        echo "Setting autoconnect priority to -1 for existing AP: $AP_SSID"
        sudo nmcli con modify "$AP_SSID" connection.autoconnect-priority -1
    fi

    AUTOCONNECT=$(nmcli -g connection.autoconnect con show "$AP_SSID")

    if [ "$AUTOCONNECT" = "no" ]; then
        echo "Enabling autoconnect for existing AP: $AP_SSID"
        sudo nmcli con modify "$AP_SSID" connection.autoconnect yes
    else
        echo "AP already exists with autoconnect enabled: $AP_SSID"
    fi
fi

exit 0
