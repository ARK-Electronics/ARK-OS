#!/usr/bin/env bash
# Create the Python virtualenv AT ITS FINAL INSTALL PATH so that shebangs and
# pyvenv.cfg resolve correctly on the device, then move it into the package tree.
# The runner must be arm64 with Python 3.10 (matches the JetPack 6 / Jammy
# rootfs). Invoked by build.sh.
set -euo pipefail

cd "$REPO_ROOT"

VENV="$PKG_PREFIX/venv"   # /usr/lib/ark-os/venv — the real target path

sudo mkdir -p "$PKG_PREFIX"
sudo chown "$(id -un)" "$PKG_PREFIX"
rm -rf "$VENV"

python3 -m venv --copies "$VENV"
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install \
    pymavlink dronecan flask psutil toml eventlet \
    flask-cors flask-socketio python-socketio pyserial

echo "==> flight-review requirements"
"$VENV/bin/pip" install -r services/flight-review/flight_review/app/requirements.txt

# Platform GPIO/sensor libs go INTO the venv (built without system-site-packages,
# so apt-installed modules are invisible to the venv interpreter).
if [ "$PLATFORM" = "jetson" ]; then
    "$VENV/bin/pip" install "Jetson.GPIO>=2.1.12" smbus2 jetson-stats
elif [ "$PLATFORM" = "pi" ]; then
    "$VENV/bin/pip" install RPi.GPIO
fi

# Move the finished venv into the package tree.
mkdir -p "$BUILD_DIR$PKG_PREFIX"
rm -rf "$BUILD_DIR$PKG_PREFIX/venv"
mv "$VENV" "$BUILD_DIR$PKG_PREFIX/venv"

echo "==> venv staged at $BUILD_DIR$PKG_PREFIX/venv"
