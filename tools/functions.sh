#!/bin/bash

# Determine PROJECT_ROOT as one level up from this script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"

# Export the PROJECT_ROOT variable so it's available to scripts that source this file
export PROJECT_ROOT

# Refresh sudo credentials
sudo -v

# Setup XDG environment variables
DEFAULT_XDG_CONF_HOME="$HOME/.config"
DEFAULT_XDG_DATA_HOME="$HOME/.local/share"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$DEFAULT_XDG_CONF_HOME}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$DEFAULT_XDG_DATA_HOME}"

# Wrapper for apt-get that waits for dpkg/apt locks (up to 120s)
# Use this instead of "sudo apt-get" to avoid lock contention failures
function apt_get_install() {
	sudo apt-get -o DPkg::Lock::Timeout=120 "$@"
}

function detect_platform() {
	if [ -f /proc/device-tree/model ] && grep -q "Raspberry Pi" /proc/device-tree/model; then
		export TARGET=pi
		return 0
	fi

	if [ -f /proc/device-tree/model ] && grep -q "NVIDIA" /proc/device-tree/model; then
		export TARGET=jetson
		return 0
	fi

	# Default to ubuntu for development machines
	export TARGET=ubuntu
	return 0
}

detect_platform
