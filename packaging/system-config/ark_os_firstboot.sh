#!/bin/bash
# ARK-OS first-boot finalization.
#
# The package's postinst defers these runtime-only steps so it stays a no-op inside
# an image-build chroot (no running systemd / NetworkManager). They run instead on
# the device's first boot via ark-os-firstboot.service, and the live postinst kicks
# this same script right after install. Idempotent and guarded by a sentinel so the
# work happens exactly once. ARK_USER / PLATFORM are substituted at build time by
# assemble_tree.sh.
set -e

ARK_USER="@ARK_USER@"
PLATFORM="@PLATFORM@"
SENTINEL="/var/lib/ark-os/.firstboot-complete"

[ -f "$SENTINEL" ] && exit 0

# Pi: the Wi-Fi radio can ship soft-blocked on stock Raspberry Pi OS.
if [ "$PLATFORM" = "pi" ]; then
    nmcli radio wifi on 2>/dev/null || true
fi

# Create the default hotspot if none exists (the script self-guards).
if [ -x /usr/lib/ark-os/scripts/create_hotspot_default.sh ]; then
    /usr/lib/ark-os/scripts/create_hotspot_default.sh 2>/dev/null || true
fi

# Initialise the flight-review database once.
if [ ! -f /var/lib/ark-os/flight-review/data/logs.sqlite ]; then
    ( cd /usr/lib/ark-os/flight-review/app && \
      sudo -u "$ARK_USER" /usr/lib/ark-os/venv/bin/python3 setup_db.py ) 2>/dev/null || true
fi

mkdir -p "$(dirname "$SENTINEL")"
touch "$SENTINEL"
exit 0
