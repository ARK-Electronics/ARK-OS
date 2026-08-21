#!/bin/bash
# Launch MicroXRCEAgent from /etc/ark-os/dds-agent.toml.
# Missing keys fall back to platform defaults (serial UART on Jetson/Pi,
# UDP Ethernet on Modalix/Ubuntu). DDS_AGENT_CONFIG and MICROXRCEAGENT
# override paths. --print prints the argv and exits without exec.

set -euo pipefail

CONFIG="${DDS_AGENT_CONFIG:-/etc/ark-os/dds-agent.toml}"
AGENT="${MICROXRCEAGENT:-/usr/lib/ark-os/bin/MicroXRCEAgent}"
PRINT_ONLY=0
if [ "${1:-}" = "--print" ]; then
    PRINT_ONLY=1
    shift
fi

detect_platform() {
    # Modalix before Jetson: PAB V3 DTB model contains "Jetson".
    if [ -r /proc/device-tree/compatible ] &&
       grep -z -q 'simaai,modalix' /proc/device-tree/compatible; then
        echo "modalix"
        return 0
    fi
    if [ -r /etc/os-release ] &&
       ( # shellcheck source=/dev/null
         . /etc/os-release
         [ "${ID:-}" = "elxr" ] || [ "${ID_LIKE:-}" = *"elxr"* ]
       ); then
        echo "modalix"
        return 0
    fi
    if uname -r | grep -q modalix; then
        echo "modalix"
        return 0
    fi
    if uname -ar | grep -q tegra; then
        echo "jetson"
        return 0
    fi
    if [ -f /proc/device-tree/model ] && grep -q "Raspberry Pi" /proc/device-tree/model; then
        echo "pi"
        return 0
    fi
    if [ -f /etc/rpi-issue ] || [ -d /opt/vc/lib ]; then
        echo "pi"
        return 0
    fi
    echo "ubuntu"
}

TARGET="$(detect_platform)"
echo "Detected platform: $TARGET"

case "$TARGET" in
    jetson)
        DEF_TRANSPORT=serial
        DEF_DEVICE=/dev/ttyTHS1
        DEF_BAUD=3000000
        ;;
    pi)
        DEF_TRANSPORT=serial
        DEF_DEVICE=/dev/ttyAMA4
        DEF_BAUD=3000000
        ;;
    modalix|ubuntu)
        DEF_TRANSPORT=ethernet
        DEF_DEVICE=/dev/ttyTHS1
        DEF_BAUD=3000000
        ;;
    *)
        echo "Unknown platform: $TARGET" >&2
        exit 1
        ;;
esac
DEF_PORT=8888
DEF_ADDRESS=0.0.0.0

# Parse flat TOML scalars (stdlib only). Arrays and comments are ignored.
read_toml() {
    python3 - "$CONFIG" "$DEF_TRANSPORT" "$DEF_DEVICE" "$DEF_BAUD" "$DEF_PORT" "$DEF_ADDRESS" <<'PY'
import re
import sys

path, d_transport, d_device, d_baud, d_port, d_address = sys.argv[1:7]
data = {
    "transport": d_transport,
    "device": d_device,
    "baudrate": d_baud,
    "port": d_port,
    "address": d_address,
}
try:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            s = line.split("#", 1)[0].strip()
            if not s or s.startswith("["):
                continue
            m = re.match(r"^([A-Za-z0-9_]+)\s*=\s*(.*)$", s)
            if not m:
                continue
            key, raw = m.group(1), m.group(2).strip()
            if key.endswith("_options") or key not in data:
                continue
            if raw.startswith("[") and raw.endswith("]"):
                continue
            if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
                raw = raw[1:-1]
            raw = raw.strip()
            if raw:
                data[key] = raw
except FileNotFoundError:
    pass
except OSError as exc:
    print(f"warning: could not read {path}: {exc}", file=sys.stderr)

def emit(k):
    # shell-safe single-quoted value
    print("%s='%s'" % (k, data[k].replace("'", "'\"'\"'")))

emit("transport")
emit("device")
emit("baudrate")
emit("port")
emit("address")
PY
}

eval "$(read_toml)"

normalize_transport() {
    local t
    t="$(echo "$1" | tr '[:upper:]' '[:lower:]')"
    case "$t" in
        serial|uart) echo serial ;;
        ethernet|udp|udp4|eth) echo ethernet ;;
        tcp|tcp4) echo tcp ;;
        *) echo "$t" ;;
    esac
}

transport="$(normalize_transport "$transport")"

build_cmd() {
    case "$transport" in
        serial)
            if [ -z "$device" ]; then
                echo "dds-agent: serial transport needs device" >&2
                exit 1
            fi
            if [ -z "$baudrate" ]; then
                echo "dds-agent: serial transport needs baudrate" >&2
                exit 1
            fi
            CMD=("$AGENT" serial -b "$baudrate" -D "$device")
            ;;
        ethernet)
            if [ -z "$port" ]; then
                echo "dds-agent: ethernet transport needs port" >&2
                exit 1
            fi
            CMD=("$AGENT" udp4 -p "$port")
            ;;
        tcp)
            if [ -z "$port" ]; then
                echo "dds-agent: tcp transport needs port" >&2
                exit 1
            fi
            CMD=("$AGENT" tcp4 -p "$port")
            ;;
        *)
            echo "dds-agent: unknown transport '$transport' (use serial, ethernet, or tcp)" >&2
            exit 1
            ;;
    esac
}

build_cmd

echo "Starting DDS agent ($transport) from ${CONFIG}"
if [ "$transport" = "serial" ]; then
    echo "  device=$device baudrate=$baudrate"
else
    echo "  port=$port address=$address (agent listens on all interfaces; set PX4 UXRCE_DDS_AG_IP to this companion)"
fi

if [ "$PRINT_ONLY" = "1" ]; then
    printf '%s\n' "${CMD[*]}"
    exit 0
fi

if [ ! -x "$AGENT" ]; then
    echo "dds-agent: MicroXRCEAgent not found at $AGENT" >&2
    exit 1
fi

if [ "$transport" = "serial" ] && [ ! -e "$device" ]; then
    echo "dds-agent: serial device $device does not exist" >&2
    exit 1
fi

exec "${CMD[@]}"
