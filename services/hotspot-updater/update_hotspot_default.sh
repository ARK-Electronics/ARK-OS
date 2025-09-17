#!/bin/bash

find_existing_ap() {
    local IFS=$'\n'  # Change the Internal Field Separator to new line
    local connections=$(nmcli -t -f NAME,TYPE con show | grep "802-11-wireless")

    echo "$connections" | while read -r connection; do
        local name=$(echo "$connection" | cut -d ':' -f1)
        local mode=$(nmcli -t -f 802-11-wireless.mode con show "$name" 2>/dev/null)
        if [[ $mode == "802-11-wireless.mode:ap" ]]; then
            echo "$name"
            return
        fi
    done
    echo ""
}

wait_for_wireless_interface() {
    local max_attempts=30
    local attempt=0

    echo "Waiting for wireless interface to be available..."

    while [ $attempt -lt $max_attempts ]; do
        INTERFACE=$(iw dev 2>/dev/null | grep Interface | awk '{print $2}' | head -1)

        if [ -n "$INTERFACE" ]; then
            echo "Wireless interface found: $INTERFACE"
            return 0
        fi

        attempt=$((attempt + 1))
        echo "Waiting for wireless interface... (attempt $attempt/$max_attempts)"
        sleep 2
    done

    echo "No wireless interface found after $max_attempts attempts"
    return 1
}

echo "Starting hotspot-updater"

if ! wait_for_wireless_interface; then
    echo "Failed to find wireless interface. Exiting."
    exit 1
fi

EXISTING_AP="$(find_existing_ap)"

if [ -z "$EXISTING_AP" ]; then
    echo "No AP connection found. Nothing to update."
    exit 0
fi

echo "Found AP connection: $EXISTING_AP"

if [ "$EXISTING_AP" = "hotspot-default" ]; then

    HOSTNAME=$(hostname)
    SERIAL=$(cat /proc/device-tree/serial-number 2>/dev/null || echo "unknown")
    NEW_AP_NAME="${HOSTNAME}-${SERIAL}"

    echo "Found 'hotspot-default' - renaming to ${NEW_AP_NAME}"

    sudo nmcli con modify "hotspot-default" connection.id "$NEW_AP_NAME"
    sudo nmcli con modify "$NEW_AP_NAME" 802-11-wireless.ssid "$NEW_AP_NAME"

    # Ensure autoconnect and priority are set correctly
    sudo nmcli con modify "$NEW_AP_NAME" connection.autoconnect yes
    sudo nmcli con modify "$NEW_AP_NAME" connection.autoconnect-priority -1

    echo "Successfully renamed hotspot from 'hotspot-default' to '$NEW_AP_NAME'"

    # Check if the connection is currently active
    if nmcli connection show --active | grep -q "hotspot-default\|$NEW_AP_NAME"; then
        echo "Hotspot is active, restarting with new name..."
        sudo nmcli con down "$NEW_AP_NAME" 2>/dev/null || sudo nmcli con down "hotspot-default" 2>/dev/null
        sleep 1
        sudo nmcli con up "$NEW_AP_NAME"
        echo "Hotspot restarted with new name"
    fi
else
    echo "AP connection '$EXISTING_AP' is not 'hotspot-default'. No changes needed."
fi

exit 0
