#!/usr/bin/env bash
# Create the Python virtualenv AT ITS FINAL INSTALL PATH so that shebangs and
# pyvenv.cfg resolve correctly on the device, then move it into the package tree.
# The build host must be arm64 with the target's system Python: 3.10 for jetson
# (JetPack 6 / Jammy) or 3.11 for pi (Raspberry Pi OS / Bookworm). build.sh
# enforces this baseline. Invoked by build.sh.
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

# Platform GPIO/sensor libs are pinned INTO the venv rather than relying on
# whatever the device has system-wide.
#
# jetson-stats is intentionally NOT installed here. Its jtop client talks to a
# root-owned jtop.service daemon that only a system-wide install provides (and
# its setup.py refuses venv installs off-target). It is installed system-wide
# during Jetson provisioning instead; system-manager degrades gracefully when
# the jtop client is unavailable.
if [ "$PLATFORM" = "jetson" ]; then
    "$VENV/bin/pip" install "Jetson.GPIO>=2.1.12" smbus2
elif [ "$PLATFORM" = "pi" ]; then
    # No Python GPIO library is installed for Pi. The vbus_*/reset_fmu_* helpers
    # drive GPIO via the system `pinctrl` tool (raspi-utils) instead. Classic
    # RPi.GPIO can't reach the CM5's RP1 I/O controller, and gpiochip-based shims
    # (rpi-lgpio) RELEASE the line when the process exits — reverting the pin —
    # which the set-and-exit helpers can't tolerate. pinctrl writes the pad
    # register directly and persists the level across exit on both CM4 and CM5.
    :
fi

# The Jetson venv must import the host's system-wide jetson-stats (the jtop
# client, version-matched to the running jtop.service). Enable system-site-
# packages AFTER the installs above, so build-time pip still populates the venv
# fully — with the flag on, pip can skip deps already present on the builder.
# venv-local packages stay ahead of system ones on sys.path, so pinned deps win.
if [ "$PLATFORM" = "jetson" ]; then
    sed -i 's/^include-system-site-packages = false$/include-system-site-packages = true/' "$VENV/pyvenv.cfg"
    grep -q '^include-system-site-packages = true$' "$VENV/pyvenv.cfg" \
        || { echo "ERROR: failed to enable system-site-packages in $VENV/pyvenv.cfg" >&2; exit 1; }
fi

# Move the finished venv into the package tree.
mkdir -p "$BUILD_DIR$PKG_PREFIX"
rm -rf "$BUILD_DIR$PKG_PREFIX/venv"
mv "$VENV" "$BUILD_DIR$PKG_PREFIX/venv"

echo "==> venv staged at $BUILD_DIR$PKG_PREFIX/venv"
