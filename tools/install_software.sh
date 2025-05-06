#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
source "$SCRIPT_DIR/functions.sh"

DEFAULT_XDG_CONF_HOME="$HOME/.config"
DEFAULT_XDG_DATA_HOME="$HOME/.local/share"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$DEFAULT_XDG_CONF_HOME}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$DEFAULT_XDG_DATA_HOME}"

if ! detect_platform; then
    echo "ERROR: This script should be run on the target device (Jetson or Raspberry Pi)."
    echo "Running this script on a host computer may cause unintended system modifications."
    exit 1
fi

# Check if system is holding package management lock
if fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
    echo "Another apt process is running. Please try again later."
    exit 1
fi

# Load helper functions
source $(dirname $BASH_SOURCE)/functions.sh

function sudo_refresh_loop() {
	while true; do
		sudo -v
		sleep 5
	done
}

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

function cleanup() {
	kill -9 $SUDO_PID
	exit 0
}

trap cleanup SIGINT SIGTERM

# keep sudo credentials alive in the background
sudo -v
sudo_refresh_loop &
SUDO_PID=$!

# Source the main configuration file
if [ -f "default.env" ]; then
	source "default.env"
else
	echo "Configuration file default.env not found!"
	exit 1
fi

export TARGET_DIR="$PWD/platform/$TARGET"
export COMMON_DIR="$PWD/platform/common"

if [ -f "user.env" ]; then
	echo "Found user.env, skipping interactive prompt"
	source "user.env"
else
	ask_yes_no "Install micro-xrce-dds-agent?" INSTALL_DDS_AGENT
	ask_yes_no "Install logloader?" INSTALL_LOGLOADER

	if [ "$INSTALL_LOGLOADER" = "y" ]; then
		ask_yes_no "Upload automatically to PX4 Flight Review?" UPLOAD_TO_FLIGHT_REVIEW
		if [ "$UPLOAD_TO_FLIGHT_REVIEW" = "y" ]; then
			echo "Please enter your email: "
			read -r USER_EMAIL
			ask_yes_no "Do you want your logs to be public?" PUBLIC_LOGS
		fi
	fi

	ask_yes_no "Install rtsp-server?" INSTALL_RTSP_SERVER

	if [ "$TARGET" = "jetson" ]; then
		ask_yes_no "Install rid-transmitter?" INSTALL_RID_TRANSMITTER
		if [ "$INSTALL_RID_TRANSMITTER" = "y" ]; then
			while true; do
				echo "Enter Manufacturer Code (4 characters, digits and uppercase letters only, no O or I) [default: $MANUFACTURER_CODE]: "
				read -r input
				if [ -z "$input" ]; then
					# Use the preset value if the input is empty
					input=$MANUFACTURER_CODE
				fi
				if [[ $input =~ ^[A-HJ-NP-Z0-9]{4}$ ]]; then
					MANUFACTURER_CODE=$input
					break
				else
					echo "Invalid Manufacturer Code. Please try again."
				fi
			done

			while true; do
				echo "Enter Serial Number (1-15 characters, digits and uppercase letters only, no O or I) [default: $SERIAL_NUMBER]: "
				read -r input
				if [ -z "$input" ]; then
					# Use the preset value if the input is empty
					input=$SERIAL_NUMBER
				fi
				if [[ $input =~ ^[A-HJ-NP-Z0-9]{1,15}$ ]]; then
					SERIAL_NUMBER=$input
					break
				else
					echo "Invalid Serial Number. Please try again."
				fi
			done
		fi
	fi

	ask_yes_no "Install polaris-client-mavlink?" INSTALL_POLARIS

	if [ "$INSTALL_POLARIS" = "y" ]; then
		echo "Enter API key: [default: none]"
		read -r POLARIS_API_KEY
	fi

	if [ "$TARGET" = "jetson" ]; then
		ask_yes_no "Install JetPack?" INSTALL_JETPACK
	fi
fi

########## validate submodules ##########
git submodule update --init --recursive
git submodule foreach git reset --hard
git submodule foreach git clean -fd

# TODO: some of these dependencies should be part of
# the specific service install script. Next pass should be to install
# each service independently to determine what deps are missing.
########## install dependencies ##########
echo "Installing dependencies"
sudo apt-get update
sudo apt-get install -y \
		apt-utils \
		gcc-arm-none-eabi \
		python3-pip \
		git \
		ninja-build \
		pkg-config \
		gcc \
		g++ \
		systemd \
		nano \
		git-lfs \
		cmake \
		astyle \
		curl \
		jq \
		snap \
		snapd \
		avahi-daemon \
		libssl-dev \
		libsqlite3-dev

########## jetson dependencies ##########
if [ "$TARGET" = "jetson" ]; then
	if [ "$INSTALL_JETPACK" = "y" ]; then
		echo "Installing JetPack"
		sudo apt-get install -y nvidia-jetpack
		echo "JetPack installation finished"
	fi

	# Required for FW updating ARK LTE
	sudo apt-get install libqmi-utils -y

	sudo pip3 install \
		'Jetson.GPIO>=2.1.9' \
		smbus2 \
		meson \
		pyserial \
		jetson-stats

########## pi dependencies ##########
elif [ "$TARGET" = "pi" ]; then
	sudo apt-get install python3-RPi.GPIO
	# https://www.raspberrypi.com/documentation/computers/os.html#python-on-raspberry-pi
	PI_PYTHON_INSTALL_ARG="--break-system-packages"
fi

# Common python dependencies
sudo pip3 install ${PI_PYTHON_INSTALL_ARG} \
	pymavlink \
	dronecan \
	flask \
	psutil \
	toml \
	eventlet \
	flask-cors \
	flask-socketio \
	python-socketio

########## configure environment ##########
echo "Configuring environment"
sudo usermod -a -G dialout $USER
sudo groupadd -f -r gpio
sudo usermod -a -G gpio $USER
sudo usermod -a -G i2c $USER
mkdir -p $XDG_CONFIG_HOME/systemd/user/

if [ "$TARGET" = "jetson" ]; then
	sudo systemctl stop nvgetty
	sudo systemctl disable nvgetty
	sudo cp $TARGET_DIR/99-gpio.rules /etc/udev/rules.d/
	sudo udevadm control --reload-rules && sudo udevadm trigger
fi

########## journalctl ##########
echo "Configuring journalctl"
CONF_FILE="/etc/systemd/journald.conf"
if ! grep -q "^Storage=persistent$" "$CONF_FILE"; then
	echo "Storage=persistent" | sudo tee -a "$CONF_FILE" > /dev/null
	echo "Storage=persistent has been added to $CONF_FILE."
else
	echo "Storage=persistent is already set in $CONF_FILE."
fi

sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo chown root:systemd-journal /var/log/journal
sudo chmod 2755 /var/log/journal
sudo systemctl restart systemd-journald
journalctl --disk-usage

########## scripts ##########
echo "Installing scripts"
mkdir -p ~/.local/bin
cp $TARGET_DIR/scripts/* ~/.local/bin
cp $COMMON_DIR/scripts/* ~/.local/bin

########## sudoers permissions ##########
echo "Adding sudoers"
sudo cp $COMMON_DIR/ark_scripts.sudoers /etc/sudoers.d/ark_scripts
sudo chmod 0440 /etc/sudoers.d/ark_scripts

########## user network control ##########
echo "Giving user network control permissions"
sudo adduser $USER netdev
sudo cp $COMMON_DIR/wifi/99-network.pkla /etc/polkit-1/localauthority/90-mandatory.d/
sudo mkdir -p /etc/polkit-1/rules.d/
sudo cp $COMMON_DIR/wifi/02-network-manager.rules /etc/polkit-1/rules.d/
sudo systemctl restart polkit

########## bash aliases ##########
echo "Adding aliases"
declare -A aliases
aliases[mavshell]="mavlink_shell.py udp:0.0.0.0:14569"
aliases[ll]="ls -alF"
aliases[submodupdate]="git submodule update --init --recursive"
for alias_name in "${!aliases[@]}"; do
	check_and_add_alias "$alias_name" "${aliases[$alias_name]}"
done

########## create hotspot connection ##########
~/.local/bin/create_hotspot_connection.sh

########## Always install MAVSDK ##########
./tools/install_mavsdk.sh

########## mavsdk-examples ##########
./tools/install_mavsdk_examples.sh

########## install services ##########
echo "Installing services..."
./tools/service_control.sh install

########## Ensure time synchronization ##########
sudo systemctl enable systemd-time-wait-sync.service

sync

duration=$SECONDS
minutes=$(((duration % 3600) / 60))
seconds=$((duration % 60))

echo "Finished, took $minutes min, $seconds sec"
echo "Please reboot your device"

cleanup
