#!/bin/bash
if [ -n "$SUDO_USER" ]; then
    RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")"
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user stop "rid-transmitter.service" 2>/dev/null || true
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user disable "rid-transmitter.service" 2>/dev/null || true
else
    systemctl --user stop "rid-transmitter.service" 2>/dev/null || true
    systemctl --user disable "rid-transmitter.service" 2>/dev/null || true
fi
