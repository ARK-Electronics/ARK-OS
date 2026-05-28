#!/usr/bin/env bash
# Compile the C++ submodules natively and stage their binaries into the package
# tree at $PKG_PREFIX/bin. Invoked by build.sh (PLATFORM, BUILD_DIR, REPO_ROOT,
# PKG_PREFIX in the environment). Requires MAVSDK already installed on the
# system (the CI workflow installs libmavsdk-dev before this runs) so that
# libs/mavsdk-examples can link.
set -euo pipefail

cd "$REPO_ROOT"
BIN_DIR="$BUILD_DIR$PKG_PREFIX/bin"
mkdir -p "$BIN_DIR"
NPROC="$(nproc)"

echo "==> mavlink-router (meson + ninja)"
( cd services/mavlink-router/mavlink-router
  # -Dsystemdsystemunitdir= keeps meson from trying to install a unit file;
  # ARK-OS ships its own unit.
  meson setup build --prefix="$PKG_PREFIX" -Dsystemdsystemunitdir= --reconfigure 2>/dev/null \
    || meson setup build --prefix="$PKG_PREFIX" -Dsystemdsystemunitdir=
  ninja -C build )
install -m 0755 services/mavlink-router/mavlink-router/build/src/mavlink-routerd "$BIN_DIR/"

echo "==> Micro-XRCE-DDS-Agent (cmake)"
( cd services/dds-agent/Micro-XRCE-DDS-Agent
  cmake -B build -DCMAKE_BUILD_TYPE=Release
  cmake --build build -j"$NPROC" )
install -m 0755 services/dds-agent/Micro-XRCE-DDS-Agent/build/MicroXRCEAgent "$BIN_DIR/"

echo "==> logloader (make -> cmake)"
( cd services/logloader/logloader && make )
install -m 0755 services/logloader/logloader/build/logloader "$BIN_DIR/"

echo "==> rtsp-server (make -> cmake)"
( cd services/rtsp-server/rtsp-server && make )
install -m 0755 services/rtsp-server/rtsp-server/build/rtsp-server "$BIN_DIR/"

echo "==> polaris-client-mavlink (make -> cmake)"
( cd services/polaris/polaris-client-mavlink && make )
install -m 0755 services/polaris/polaris-client-mavlink/build/polaris-client-mavlink "$BIN_DIR/"

if [ "$PLATFORM" = "jetson" ]; then
    echo "==> rid-transmitter (make -> cmake, jetson only)"
    ( cd services/rid-transmitter/RemoteIDTransmitter && make )
    install -m 0755 services/rid-transmitter/RemoteIDTransmitter/build/rid-transmitter "$BIN_DIR/"
fi

echo "==> mavsdk-examples (cmake)"
( cd libs/mavsdk-examples
  cmake -B build -DCMAKE_BUILD_TYPE=Release
  cmake --build build -j"$NPROC" )
# Each example builds to build/<subdir>/<output_name>. Collect every ELF
# executable except CMake's own compiler-probe artifacts under CMakeFiles/.
find libs/mavsdk-examples/build -type f -perm -u+x -not -path '*/CMakeFiles/*' | while read -r f; do
    if file -b "$f" | grep -q 'ELF .* executable'; then
        install -m 0755 "$f" "$BIN_DIR/"
    fi
done

echo "==> binaries staged in $BIN_DIR:"
ls -1 "$BIN_DIR"
