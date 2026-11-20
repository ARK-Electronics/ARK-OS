#!/bin/bash
# Stand-in for your application: reads its config once at startup, then logs a
# message on an interval. The Services page does not restart a service when its
# config is saved, so changes apply on the next start.
set -euo pipefail

CONFIG="${1:-/etc/ark-os/hello-ark.toml}"

# Minimal reader for top-level `key = value` lines; a real app would use a TOML library.
toml_get() {
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONFIG" | head -n1 | sed 's/^"\(.*\)"$/\1/'
}

message=$(toml_get message)
interval=$(toml_get interval_s)
[[ "$interval" =~ ^[0-9]+([.][0-9]+)?$ ]] || interval=5

# journald reads a leading <N> as the syslog priority, which the UI's log viewer
# colours by.
case "$(toml_get priority)" in
    err)     prio=3 ;;
    warning) prio=4 ;;
    *)       prio=6 ;;
esac

echo "<6>hello-ark started with $CONFIG"
while true; do
    echo "<$prio>${message:-hello}"
    sleep "$interval"
done
