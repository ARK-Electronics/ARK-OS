#!/bin/bash

# Determine PROJECT_ROOT as two levels up from this script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
source "$PROJECT_ROOT/tools/functions.sh"

echo "Installing flight_review"

sudo rm -rf /opt/flight_review

pushd .
cd flight_review

# Install dependencies
if [ "$TARGET" = "jetson" ]; then
	sudo apt-get install -y sqlite3 fftw3 libfftw3-dev
	sudo pip install -r app/requirements.txt
	sudo python3 -m pip install --upgrade pandas scipy matplotlib

elif [ "$TARGET" = "pi" ]; then
	sudo apt-get install -y sqlite3 fftw3 libfftw3-dev
	# https://www.raspberrypi.com/documentation/computers/os.html#python-on-raspberry-pi
	sudo pip install --break-system-packages -r app/requirements.txt
	sudo pip install --break-system-packages --upgrade pandas scipy matplotlib
fi

# Create user config overrides
mkdir -p $XDG_CONFIG_HOME/flight_review
CONFIG_USER_FILE="$XDG_CONFIG_HOME/flight_review/config_user.ini"
touch $CONFIG_USER_FILE

echo "[general]" >> $CONFIG_USER_FILE
echo "domain_name = $(hostname -f)/flight-review" >> $CONFIG_USER_FILE
echo "verbose_output = 1" >> $CONFIG_USER_FILE
echo "storage_path = /opt/flight_review/data" >> $CONFIG_USER_FILE

# Copy the app to $XDG_DATA_HOME
APP_DIR="$XDG_DATA_HOME/flight_review/app"
mkdir -p $APP_DIR
cp -r app/* $APP_DIR/

popd

# Make user owner
sudo chown -R $USER:$USER $XDG_DATA_HOME/flight_review

# Initialize database
$APP_DIR/setup_db.py
