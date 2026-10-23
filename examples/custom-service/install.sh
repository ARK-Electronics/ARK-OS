#!/bin/bash
# Install the hello-ark example add-on so it shows up on the ARK-OS web UI's
# Services page. Run on the device, after ARK-OS is installed:
#
#   sudo ./install.sh              # install (or update) and start it
#   sudo ./install.sh --uninstall  # stop it and remove every file it installed
set -euo pipefail

NAME=hello-ark
HERE="$(cd "$(dirname "$0")" && pwd)"

UNIT=/etc/systemd/system/$NAME.service
MANIFEST=/usr/lib/ark-os/manifests/$NAME.manifest.json
CONFIG=/etc/ark-os/$NAME.toml
BIN=/usr/local/bin/$NAME
POLKIT=/etc/polkit-1/rules.d/50-$NAME.rules

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo $0 $*" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now "$NAME.service" 2>/dev/null || true
    rm -f "$UNIT" "$MANIFEST" "$CONFIG" "$BIN" "$POLKIT"
    systemctl daemon-reload
    echo "Removed $NAME."
    exit 0
fi

# ARK-OS bakes its service user into its units at build time (jetson, pi, or sima
# on modalix). Read it back instead of hardcoding it.
ARK_USER=$(systemctl show -p User --value service-manager.service)
if [ -z "$ARK_USER" ] || [ ! -d /usr/lib/ark-os/manifests ]; then
    echo "ARK-OS does not appear to be installed (no service-manager.service)." >&2
    exit 1
fi

install -m 0755 "$HERE/hello_ark.sh" "$BIN"
sed "s/@ARK_USER@/$ARK_USER/g" "$HERE/$NAME.service" > "$UNIT"
chmod 0644 "$UNIT"
install -m 0644 "$HERE/$NAME.manifest.json" "$MANIFEST"
sed "s/@ARK_USER@/$ARK_USER/g" "$HERE/50-$NAME.rules" > "$POLKIT"
chmod 0644 "$POLKIT"

# The web UI saves configs as $ARK_USER, so the file must be group-writable by it.
# Seed it only once so a re-run keeps edits made from the UI.
if [ ! -f "$CONFIG" ]; then
    install -m 0664 -g "$ARK_USER" "$HERE/$NAME.toml" "$CONFIG"
fi

systemctl daemon-reload
systemctl enable "$NAME.service"
systemctl restart "$NAME.service"

echo "Installed $NAME for user $ARK_USER. It is now listed on the web UI's Services page."
