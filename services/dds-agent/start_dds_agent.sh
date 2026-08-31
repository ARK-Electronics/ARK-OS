#!/bin/bash
# Launch MicroXRCEAgent from /etc/ark-os/dds-agent.toml.
#
# The config is the only source of truth: assemble_tree.sh seeds it with the
# platform's transport and UART at package build, and the Services tab edits it
# from there. Nothing here detects hardware or substitutes a default -- an
# unreadable config is a broken install, not something to guess around.
#
# DDS_AGENT_CONFIG and MICROXRCEAGENT override the paths; --print writes the argv
# and exits without exec'ing.

set -euo pipefail

CONFIG="${DDS_AGENT_CONFIG:-/etc/ark-os/dds-agent.toml}"
AGENT="${MICROXRCEAGENT:-/usr/lib/ark-os/bin/MicroXRCEAgent}"
PYTHON="${ARK_PYTHON:-/usr/lib/ark-os/venv/bin/python3}"

PRINT_ONLY=0
if [ "${1:-}" = "--print" ]; then
    PRINT_ONLY=1
    shift
fi

# The bundled venv carries the `toml` lib that merge_configs.py already uses;
# the system python3 is not a package dependency and Jetson's 3.10 predates
# tomllib, so always go through the venv interpreter.
read_config() {
    "$PYTHON" - "$CONFIG" <<'PY'
import shlex
import sys
import toml

try:
    cfg = toml.load(sys.argv[1])
except (OSError, toml.TomlDecodeError) as exc:
    sys.exit("dds-agent: %s" % exc)
for key in ("transport", "device", "baudrate", "port"):
    print("cfg_%s=%s" % (key, shlex.quote(str(cfg.get(key, "")))))
PY
}

if ! CONFIG_VARS="$(read_config)"; then
    echo "dds-agent: cannot read transport settings from $CONFIG" >&2
    exit 1
fi
# Declared so the eval below is the only writer and an empty value still reaches
# the per-transport checks rather than tripping `set -u`.
cfg_transport=""; cfg_device=""; cfg_baudrate=""; cfg_port=""
eval "$CONFIG_VARS"

# Tolerate the spellings a hand-edited config might use; the UI dropdown only
# ever writes serial/ethernet/tcp.
case "$(echo "$cfg_transport" | tr '[:upper:]' '[:lower:]')" in
    serial|uart)         transport=serial ;;
    ethernet|udp|udp4)   transport=ethernet ;;
    tcp|tcp4)            transport=tcp ;;
    *)                   transport="$cfg_transport" ;;
esac

case "$transport" in
    serial)
        [ -n "$cfg_device" ] || { echo "dds-agent: serial transport needs 'device'" >&2; exit 1; }
        [ -n "$cfg_baudrate" ] || { echo "dds-agent: serial transport needs 'baudrate'" >&2; exit 1; }
        # The unit deliberately carries no dev-*.device ordering -- transport is a
        # runtime setting, so the UART can only be checked here. Exiting fails the
        # unit under the same restart budget as mavlink-router with no FC attached.
        [ -e "$cfg_device" ] || { echo "dds-agent: serial device $cfg_device does not exist" >&2; exit 1; }
        CMD=("$AGENT" serial -b "$cfg_baudrate" -D "$cfg_device")
        echo "Starting DDS agent (serial $cfg_device @ $cfg_baudrate) from $CONFIG"
        ;;
    ethernet|tcp)
        [ -n "$cfg_port" ] || { echo "dds-agent: $transport transport needs 'port'" >&2; exit 1; }
        if [ "$transport" = "ethernet" ]; then
            CMD=("$AGENT" udp4 -p "$cfg_port")
        else
            CMD=("$AGENT" tcp4 -p "$cfg_port")
        fi
        echo "Starting DDS agent ($transport port $cfg_port, all interfaces) from $CONFIG"
        echo "  set PX4 UXRCE_DDS_AG_IP to this companion's address and UXRCE_DDS_PRT to $cfg_port"
        ;;
    *)
        echo "dds-agent: unknown transport '$cfg_transport' (use serial, ethernet, or tcp)" >&2
        exit 1
        ;;
esac

if [ "$PRINT_ONLY" = "1" ]; then
    printf '%s\n' "${CMD[*]}"
    exit 0
fi

[ -x "$AGENT" ] || { echo "dds-agent: MicroXRCEAgent not found at $AGENT" >&2; exit 1; }

exec "${CMD[@]}"
