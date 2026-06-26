#!/usr/bin/env bash
# Compile the C++ submodules natively and stage their binaries into the package
# tree at $PKG_PREFIX/bin. Invoked by build.sh (PLATFORM, BUILD_DIR, REPO_ROOT,
# PKG_PREFIX, MAVSDK_VERSION, CODENAME in the environment). Linking needs a
# system-installed MAVSDK; the .deb ships its own copy (MAVSDK step below).
set -euo pipefail

cd "$REPO_ROOT"
BIN_DIR="$BUILD_DIR$PKG_PREFIX/bin"
LIB_DIR="$BUILD_DIR$PKG_PREFIX/lib"
mkdir -p "$BIN_DIR" "$LIB_DIR"
NPROC="$(nproc)"

# Bundle a binary's build-tree-only shared libs (polaris SDK, Micro-XRCE-DDS +
# FastDDS chain — FetchContent libs that exist nowhere on-device) into LIB_DIR,
# found via ldd while the build-tree RUNPATH still resolves. Only paths inside
# $REPO_ROOT are copied: system libs and apt Depends stay external, which also
# skips the system-installed MAVSDK (staged separately below). On-device they
# resolve via /etc/ld.so.conf.d/ark-os.conf + postinst ldconfig, so the stale
# build-tree RUNPATH is harmless. A same-name lib with different bytes aborts:
# silently overwriting one service's private lib with another's would break the
# loser at load time.
install_bundled_lib() {
    local src dest
    src="$(readlink -f "$1")"
    dest="$LIB_DIR/$(basename "$1")"
    if [ -e "$dest" ]; then
        if ! cmp -s "$src" "$dest"; then
            echo "ERROR: shared-library name collision in $LIB_DIR: $(basename "$1")" >&2
            echo "       '$src' differs from the copy already bundled — two services" >&2
            echo "       ship different libraries with the same soname." >&2
            exit 1
        fi
        return 0
    fi
    install -m 0644 "$src" "$dest"
}

bundle_build_tree_libs() {
    local built_bin="$1" ldd_out
    ldd_out="$(ldd "$built_bin")"
    if grep -q 'not found' <<<"$ldd_out"; then
        echo "ERROR: $built_bin has unresolved shared libraries at build time:" >&2
        grep 'not found' <<<"$ldd_out" >&2
        exit 1
    fi
    # Process substitution (not a pipe) keeps the loop in this shell so a collision
    # in install_bundled_lib aborts the build, not just a subshell.
    while read -r lib; do
        case "$lib" in
            "$REPO_ROOT"/*) install_bundled_lib "$lib" ;;
        esac
    done < <(awk '/=> \// {print $3}' <<<"$ldd_out")
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
# glog/gflags ship on neither rootfs, and their package names differ across
# releases (libgoogle-glog0v5 / 0v6t64 / …) so no single Depends fits — bundle.
polaris_extra_libs="$(ldd services/polaris/polaris-client-mavlink/build/polaris-client-mavlink \
    | awk '/=> \// {print $3}' | grep -E '/lib(glog|gflags)\.so' || true)"
[ -n "$polaris_extra_libs" ] \
    || { echo "ERROR: polaris no longer links libglog/libgflags — revisit the bundling list" >&2; exit 1; }
while read -r lib; do
    install_bundled_lib "$lib"
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
# Collect every built ELF executable, skipping CMake's compiler probes.
find libs/mavsdk-examples/build -type f -perm -u+x -not -path '*/CMakeFiles/*' | while read -r f; do
    if file -b "$f" | grep -q 'ELF .* executable'; then
        install -m 0755 "$f" "$BIN_DIR/"
    fi
done

# --- MAVSDK: stage the pinned upstream deb's full SDK under $PKG_PREFIX/mavsdk ---
# MAVSDK is on no apt repo, so it cannot be a Depends (issue #74). Bundle the
# deb the build linked against (link == ship), headers and CMake config included
# so users can build against it (README). The directory is deliberately absent
# from ld.so.conf.d: a globally visible libmavsdk.so.3 would shadow a
# user-installed MAVSDK. ark-os binaries reach it via RUNPATH instead (below).
echo "==> MAVSDK SDK ($MAVSDK_VERSION)"
MAVSDK_DEB_NAME="libmavsdk-dev_${MAVSDK_VERSION}_debian12_arm64.deb"
# Prefer the deb CI's "Install MAVSDK" step left in the workspace root, then a
# cached download under build/.
MAVSDK_DEB=""
for cand in "$REPO_ROOT/$MAVSDK_DEB_NAME" "$REPO_ROOT/build/$MAVSDK_DEB_NAME"; do
    if [ -f "$cand" ]; then MAVSDK_DEB="$cand"; break; fi
done
if [ -z "$MAVSDK_DEB" ]; then
    MAVSDK_DEB="$REPO_ROOT/build/$MAVSDK_DEB_NAME"
    echo "    downloading $MAVSDK_DEB_NAME"
    curl -fsSL -o "$MAVSDK_DEB.partial" \
        "https://github.com/mavlink/MAVSDK/releases/download/v${MAVSDK_VERSION}/${MAVSDK_DEB_NAME}"
    mv "$MAVSDK_DEB.partial" "$MAVSDK_DEB"
fi

MAVSDK_STAGE="$BUILD_DIR$PKG_PREFIX/mavsdk"
echo "    staging $(basename "$MAVSDK_DEB") -> $MAVSDK_STAGE"
mavsdk_extract="$(mktemp -d)"
dpkg-deb -x "$MAVSDK_DEB" "$mavsdk_extract"
mkdir -p "$MAVSDK_STAGE"
# usr/{include,lib} is the whole SDK (usr/share is just a changelog); the
# CMake config is relocatable.
cp -a "$mavsdk_extract/usr/include" "$mavsdk_extract/usr/lib" "$MAVSDK_STAGE/"
rm -rf "$mavsdk_extract"

# Upstream ships only the versioned file, relying on ldconfig for the soname
# symlink — which never runs for this off-loader-path dir, so ship the chain:
# RUNPATH lookup is by soname filename, and the dev symlink lets -lmavsdk link.
mavsdk_so=""
for f in "$MAVSDK_STAGE"/lib/libmavsdk.so.*; do
    [ -e "$f" ] || continue
    [ -z "$mavsdk_so" ] || { echo "ERROR: multiple libmavsdk.so.* in $MAVSDK_DEB_NAME" >&2; exit 1; }
    mavsdk_so="$f"
done
[ -n "$mavsdk_so" ] || { echo "ERROR: no libmavsdk.so.* found in $MAVSDK_DEB_NAME" >&2; exit 1; }
mavsdk_soname="$(readelf -d "$mavsdk_so" | sed -n 's/.*(SONAME).*\[\(.*\)\]$/\1/p')"
[ -n "$mavsdk_soname" ] || { echo "ERROR: could not read SONAME from $mavsdk_so" >&2; exit 1; }
if [ "$(basename "$mavsdk_so")" != "$mavsdk_soname" ]; then
    ln -snf "$(basename "$mavsdk_so")" "$MAVSDK_STAGE/lib/$mavsdk_soname"
fi
ln -snf "$mavsdk_soname" "$MAVSDK_STAGE/lib/libmavsdk.so"

# mavsdk.pc ships with upstream's CI build prefix baked in; fix it. Drop
# Requires.private: those deps are static inside libmavsdk, and their missing
# .pc files would fail every on-device pkg-config query.
sed -i \
    -e "s|^prefix=.*|prefix=$PKG_PREFIX/mavsdk|" \
    -e 's|^exec_prefix=.*|exec_prefix=${prefix}|' \
    -e 's|^libdir=.*|libdir=${prefix}/lib|' \
    -e 's|^includedir=.*|includedir=${prefix}/include|' \
    -e '/^Requires\.private:/d' \
    "$MAVSDK_STAGE/lib/pkgconfig/mavsdk.pc"

# The .so is upstream's debian12 build: verify the glibc/libstdc++ symbol
# versions it needs exist on this host (== target codename, per build.sh), else
# it fails on-device with "version not found". Likely trip: a MAVSDK_VERSION bump.
max_symver() {  # highest <FAMILY>_x[.y...] referenced/provided by an ELF
    readelf -V "$1" 2>/dev/null | grep -oE "${2}_[0-9]+(\.[0-9]+)+" | sort -uV | tail -1 || true
}
for fam_provider in GLIBC:libc.so.6 GLIBCXX:libstdc++.so.6 CXXABI:libstdc++.so.6; do
    fam="${fam_provider%%:*}"
    req="$(max_symver "$mavsdk_so" "$fam")"
    [ -n "$req" ] || continue
    # no early exit in awk: SIGPIPE on ldconfig would trip pipefail
    provider="$(ldconfig -p | awk -v so="${fam_provider#*:}" '$1 == so && !found {print $NF; found=1}')"
    [ -n "$provider" ] || { echo "ERROR: ${fam_provider#*:} not found on the build host" >&2; exit 1; }
    prov="$(max_symver "$provider" "$fam")"
    if [ -z "$prov" ] || [ "$(printf '%s\n%s\n' "$req" "$prov" | sort -V | tail -1)" != "$prov" ]; then
        echo "ERROR: bundled MAVSDK needs $fam $req; the $CODENAME build host (= target rootfs) provides ${prov:-none}." >&2
        echo "       It would fail on-device with a 'version not found' load error. Pin a" >&2
        echo "       MAVSDK_VERSION / deb variant compatible with $CODENAME in versions.env." >&2
        exit 1
    fi
    echo "    ABI: $fam $req required <= $prov provided (ok)"
done

# RUNPATH beats the loader cache, pinning every libmavsdk-linking binary to the
# bundled copy even if a system libmavsdk appears later; ../lib stays on it for
# the other bundled private libs.
command -v patchelf >/dev/null \
    || { echo "ERROR: patchelf not found — required to pin the bundled-MAVSDK RUNPATH" >&2; exit 1; }
mavsdk_linkers=0
while read -r bin; do
    readelf -d "$bin" 2>/dev/null | grep -q 'NEEDED.*\[libmavsdk\.so' || continue
    patchelf --set-rpath '$ORIGIN/../lib:$ORIGIN/../mavsdk/lib' "$bin"
    mavsdk_linkers=$((mavsdk_linkers + 1))
done < <(find "$BIN_DIR" -maxdepth 1 -type f -perm -u+x)
[ "$mavsdk_linkers" -gt 0 ] \
    || { echo "ERROR: no staged binary links libmavsdk — MAVSDK bundling found nothing to pin" >&2; exit 1; }

# A missed bundle (ldd/path-filter regression) crashes on-device at load — fail here instead.
for must in 'libpolaris_cpp_client.so*' 'libmicroxrcedds_agent.so*' 'libglog.so*'; do
    compgen -G "$LIB_DIR/$must" >/dev/null \
        || { echo "ERROR: no library matching '$must' was bundled into $LIB_DIR" >&2; exit 1; }
done
for must in "lib/$mavsdk_soname" lib/libmavsdk.so lib/cmake/MAVSDK/MAVSDKConfig.cmake \
            lib/pkgconfig/mavsdk.pc include/mavsdk/mavsdk.h; do
    [ -e "$MAVSDK_STAGE/$must" ] \
        || { echo "ERROR: staged MAVSDK SDK is missing $must" >&2; exit 1; }
done

# --- go2rtc: prebuilt WebRTC/RTSP gateway (single static Go binary, no apt repo) ---
# The web UI's Video page plays the camera over WebRTC; go2rtc restreams rtsp-server's
# H.264 RTSP feed to the browser and dials it only while someone is watching, so the
# camera runs on demand. Pin + verify the upstream release binary (link == ship), same
# rationale as the bundled MAVSDK above.
echo "==> go2rtc ($GO2RTC_VERSION)"
GO2RTC_ASSET="go2rtc_linux_arm64"
GO2RTC_CACHE="$REPO_ROOT/build/${GO2RTC_ASSET}-${GO2RTC_VERSION}"
if [ ! -f "$GO2RTC_CACHE" ]; then
    echo "    downloading $GO2RTC_ASSET"
    curl -fsSL -o "$GO2RTC_CACHE.partial" \
        "https://github.com/AlexxIT/go2rtc/releases/download/v${GO2RTC_VERSION}/${GO2RTC_ASSET}"
    mv "$GO2RTC_CACHE.partial" "$GO2RTC_CACHE"
fi
# Verify on every build, not just on download: a corrupted cache or a tampered release
# must fail the build rather than ship a bad binary we run as a service.
echo "${GO2RTC_SHA256}  ${GO2RTC_CACHE}" | sha256sum -c - \
    || { echo "ERROR: go2rtc checksum mismatch — GO2RTC_SHA256 in versions.env does not match $GO2RTC_ASSET $GO2RTC_VERSION" >&2; exit 1; }
install -m 0755 "$GO2RTC_CACHE" "$BIN_DIR/go2rtc"

echo "==> binaries staged in $BIN_DIR:"
ls -1 "$BIN_DIR"
echo "==> libraries bundled in $LIB_DIR:"
ls -1 "$LIB_DIR"
echo "==> MAVSDK SDK staged in $MAVSDK_STAGE:"
ls -1 "$MAVSDK_STAGE/lib"
