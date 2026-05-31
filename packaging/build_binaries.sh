#!/usr/bin/env bash
# Compile the C++ submodules natively and stage their binaries into the package
# tree at $PKG_PREFIX/bin. Invoked by build.sh (PLATFORM, BUILD_DIR, REPO_ROOT,
# PKG_PREFIX in the environment). Requires MAVSDK already installed on the
# system (the CI workflow installs libmavsdk-dev before this runs) so that
# libs/mavsdk-examples can link.
set -euo pipefail

cd "$REPO_ROOT"
BIN_DIR="$BUILD_DIR$PKG_PREFIX/bin"
LIB_DIR="$BUILD_DIR$PKG_PREFIX/lib"
mkdir -p "$BIN_DIR" "$LIB_DIR"
NPROC="$(nproc)"

# Bundle a freshly-built binary's private (build-tree) shared-library deps into
# LIB_DIR. The polaris SDK (libpolaris_cpp_client) and the Micro-XRCE-DDS agent +
# its FastDDS/FastCDR chain are FetchContent/temp_install libs that exist only in
# the submodule build trees, so `install`-ing just the executable leaves them
# missing on-device (loader error 127). ldd is run while the binary's build-tree
# RUNPATH still resolves; only libs resolving inside $REPO_ROOT are copied — system
# libs and apt Depends (libmavsdk, gstreamer, bluez, openssl, sqlite) resolve
# elsewhere and stay external. A shipped /etc/ld.so.conf.d/ark-os.conf + ldconfig
# (postinst) make these findable, so the stale build-tree RUNPATH is harmless (the
# loader falls through to the cache). Fail loud if anything is unresolved at build.
bundle_build_tree_libs() {
    local built_bin="$1" ldd_out
    ldd_out="$(ldd "$built_bin")"
    if grep -q 'not found' <<<"$ldd_out"; then
        echo "ERROR: $built_bin has unresolved shared libraries at build time:" >&2
        grep 'not found' <<<"$ldd_out" >&2
        exit 1
    fi
    awk '/=> \// {print $3}' <<<"$ldd_out" | while read -r lib; do
        case "$lib" in
            "$REPO_ROOT"/*) install -m 0644 "$(readlink -f "$lib")" "$LIB_DIR/$(basename "$lib")" ;;
        esac
    done
}

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
bundle_build_tree_libs services/dds-agent/Micro-XRCE-DDS-Agent/build/MicroXRCEAgent

echo "==> logloader (make -> cmake)"
( cd services/logloader/logloader && make )
install -m 0755 services/logloader/logloader/build/logloader "$BIN_DIR/"

echo "==> rtsp-server (make -> cmake)"
( cd services/rtsp-server/rtsp-server && make )
install -m 0755 services/rtsp-server/rtsp-server/build/rtsp-server "$BIN_DIR/"

echo "==> polaris-client-mavlink (make -> cmake)"
( cd services/polaris/polaris-client-mavlink && make )
install -m 0755 services/polaris/polaris-client-mavlink/build/polaris-client-mavlink "$BIN_DIR/"
bundle_build_tree_libs services/polaris/polaris-client-mavlink/build/polaris-client-mavlink
# The Polaris SDK also links libglog (and, where glog links it, libgflags), which
# are installed on the build runner (see the CI build-deps step) but ship on
# neither the Jetson nor the Pi rootfs and are not apt Depends. Their package names
# differ across releases (libgoogle-glog0v5 / 0v6t64 / Debian's own), so a single
# shared Depends would be wrong on one target — bundle the libs instead. ldd
# resolves them (recursively, so glog's gflags dep is included) to system paths.
polaris_extra_libs="$(ldd services/polaris/polaris-client-mavlink/build/polaris-client-mavlink \
    | awk '/=> \// {print $3}' | grep -E '/lib(glog|gflags)\.so' || true)"
[ -n "$polaris_extra_libs" ] \
    || { echo "ERROR: polaris no longer links libglog/libgflags — revisit the bundling list" >&2; exit 1; }
while read -r lib; do
    install -m 0644 "$(readlink -f "$lib")" "$LIB_DIR/$(basename "$lib")"
done <<<"$polaris_extra_libs"

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

# Fail loud if the private libs the FetchContent/cmake services need did not get
# bundled (e.g. an ldd / path-filter regression) — shipping the binaries without
# them reproduces the on-device "cannot open shared object" crash.
for must in 'libpolaris_cpp_client.so*' 'libmicroxrcedds_agent.so*' 'libglog.so*'; do
    compgen -G "$LIB_DIR/$must" >/dev/null \
        || { echo "ERROR: no library matching '$must' was bundled into $LIB_DIR" >&2; exit 1; }
done

echo "==> binaries staged in $BIN_DIR:"
ls -1 "$BIN_DIR"
echo "==> libraries bundled in $LIB_DIR:"
ls -1 "$LIB_DIR"
