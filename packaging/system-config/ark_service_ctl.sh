#!/bin/bash
# Run one systemctl action on an ARK-OS service, as root, for the service user.
#
# The managers run as the unprivileged service user and reach this through sudo
# (/etc/sudoers.d/ark-os). It replaces polkit grants, which could not be scoped:
# enable/disable reach polkit as manage-unit-files with no unit name, the same
# action as `systemctl link <any file>`, so a grant wide enough for the web UI's
# Autostart toggle also let the service user link and start its own unit as root.
#
# Only a service with a manifest may be controlled. The manifest directory is
# root-owned, so registering a service takes root, like installing its unit does.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin

MANIFEST_DIR=/usr/lib/ark-os/manifests

usage() {
    echo "usage: ark_service_ctl.sh {start|stop|restart|reset-failed|enable|disable} <service>" >&2
    exit 2
}

[ $# -eq 2 ] || usage
verb=$1
name=$2

case "$verb" in
    start|stop|restart|reset-failed|enable|disable) ;;
    *) usage ;;
esac

# Unit-name characters only, so the name can't be a path or a systemctl option.
if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]*$ ]] || [ ! -f "$MANIFEST_DIR/$name.manifest.json" ]; then
    echo "Unknown or unmanaged service: $name" >&2
    exit 1
fi

exec systemctl "$verb" -- "$name.service"
