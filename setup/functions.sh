#!/bin/bash

# Refresh sudo credentials
sudo -v

# Setup XDG environment variables
DEFAULT_XDG_CONF_HOME="$HOME/.config"
DEFAULT_XDG_DATA_HOME="$HOME/.local/share"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$DEFAULT_XDG_CONF_HOME}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$DEFAULT_XDG_DATA_HOME}"

# Determine target platform
if uname -ar | grep -q tegra; then
	export TARGET=jetson
else
	export TARGET=pi
fi

# Setup paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_ROOT="$SCRIPT_DIR/.."
export TARGET_DIR="$PROJECT_ROOT/platform/$TARGET"
export COMMON_DIR="$PROJECT_ROOT/platform/common"

########## FUNCTIONS ##########

function ask_yes_no() {
	local prompt="$1"
	local var_name="$2"
	local default="$3"
	local default_display="${!var_name^^}"  # Convert to uppercase for display purposes

	while true; do
		echo "$prompt (y/n) [default: $default_display]"
		read -r REPLY
		if [ -z "$REPLY" ]; then
			REPLY="${!var_name}"
		fi
		case "$REPLY" in
			y|Y) eval $var_name="y"; break ;;
			n|N) eval $var_name="n"; break ;;
			*) echo "Invalid input. Please enter y or n." ;;
		esac
	done
}

function sudo_refresh_loop() {
	while true; do
		sudo -v
		sleep 5
	done
}

function service_install() {
	mkdir -p $XDG_CONFIG_HOME/systemd/user/
	# Check in COMMON_DIR first, then TARGET_DIR if not found
	if [[ -f $COMMON_DIR/services/$1.service ]]; then
		cp $COMMON_DIR/services/$1.service $XDG_CONFIG_HOME/systemd/user/
	elif [[ -f $TARGET_DIR/services/$1.service ]]; then
		cp $TARGET_DIR/services/$1.service $XDG_CONFIG_HOME/systemd/user/
	else
		echo "Service file for $1 not found."
		return 1
	fi

	systemctl --user daemon-reload
	systemctl --user enable $1.service
	systemctl --user restart $1.service
}

function service_uninstall() {
	sudo systemctl stop $1.service &>/dev/null
	sudo systemctl disable $1.service &>/dev/null
	systemctl --user stop $1.service &>/dev/null
	systemctl --user disable $1.service &>/dev/null
	sudo rm /etc/systemd/system/$1.service &>/dev/null
	sudo rm /lib/systemd/system/$1.service &>/dev/null
	sudo rm $XDG_CONFIG_HOME/systemd/user/$1.service &>/dev/null
	sudo systemctl daemon-reload
	systemctl --user daemon-reload
}

function service_add_manifest() {
	local SERVICE_NAME="$1"
	local MANIFEST_SOURCE="${PROJECT_ROOT}/manifests/${SERVICE_NAME}.manifest.json"
	local APP_DIR="$XDG_DATA_HOME/${SERVICE_NAME}"

	if [ ! -f "$MANIFEST_SOURCE" ]; then
		echo "Error: Manifest file ${SERVICE_NAME}.manifest.json not found in ${PROJECT_ROOT}/manifests/"
		return 1
	fi

	if [ ! -d "$APP_DIR" ]; then
		mkdir -p "$APP_DIR"
	fi

	cp "$MANIFEST_SOURCE" "$APP_DIR"

	if [ $? -eq 0 ]; then
		echo "Successfully copied ${SERVICE_NAME}.manifest.json to ${APP_DIR}/"
		return 0
	else
		echo "Error: Failed to copy manifest file for ${SERVICE_NAME}"
		return 1
	fi
}

function git_clone_retry() {
	local url="$1" dir="$2" branch="$3" retries=3 delay=5

	if [ -n "$branch" ]; then
		# Clone with a specific branch and avoid shallow clone
		until git clone --recurse-submodules -b "$branch" "$url" "$dir"; do
			((retries--)) || return 1
			echo "git clone failed, retrying in $delay seconds..."
			rm -rf "$dir" &>/dev/null
			sleep $delay
		done
	else
		# Shallow clone if no branch is specified
		until git clone --recurse-submodules --depth=1 --shallow-submodules "$url" "$dir"; do
			((retries--)) || return 1
			echo "git clone failed, retrying in $delay seconds..."
			rm -rf "$dir" &>/dev/null
			sleep $delay
		done
	fi
}

function check_and_add_alias() {
	local name="$1"
	local command="$2"
	local file="$HOME/.bash_aliases"

	# Check if the alias file exists, create if not
	[ -f "$file" ] || touch "$file"

	# Check if the alias already exists
	if grep -q "^alias $name=" "$file"; then
		echo "Alias '$name' already exists."
	else
		# Add the new alias
		echo "alias $name='$command'" >> "$file"
		echo "Alias '$name' added."
	fi

	# Source the aliases file
	source "$file"
}
