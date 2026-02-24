#!/bin/bash
loginctl enable-linger "${SUDO_USER:-$USER}" 2>/dev/null || true
if [ -n "$SUDO_USER" ]; then
    RUNTIME_DIR="/run/user/$(id -u "$SUDO_USER")"
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user daemon-reload
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user enable "autopilot-manager.service"
    sudo -u "$SUDO_USER" XDG_RUNTIME_DIR="$RUNTIME_DIR" systemctl --user restart "autopilot-manager.service"
else
    systemctl --user daemon-reload
    systemctl --user enable "autopilot-manager.service"
    systemctl --user restart "autopilot-manager.service"
fi
