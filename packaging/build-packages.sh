#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
OUTPUT_DIR="$PROJECT_ROOT/dist"
VERSION=$(cat "$PROJECT_ROOT/VERSION" | tr -d '[:space:]')
ARCH="${ARCH:-arm64}"

echo "=== ARK-OS Package Builder ==="
echo "Version: $VERSION"
echo "Architecture: $ARCH"
echo ""

mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

# ─── Build C++ submodule services ───

build_cpp_service() {
    local name="$1"
    local src_dir="$2"
    local build_subdir="$3"
    local extra_cmake_args="${4:-}"

    echo "Building $name..."
    mkdir -p "$BUILD_DIR/$build_subdir"
    pushd "$src_dir" > /dev/null

    if [ -f "Makefile" ] && grep -q "cmake" Makefile 2>/dev/null; then
        # cmake-based (logloader, rid-transmitter)
        cmake -B "$BUILD_DIR/$build_subdir" -H. $extra_cmake_args
        cmake --build "$BUILD_DIR/$build_subdir" -j"$(nproc)"
    elif [ -f "meson.build" ]; then
        # meson-based (mavlink-router)
        meson setup "$BUILD_DIR/$build_subdir" --prefix=/opt/ark -Dsystemdsystemunitdir=
        ninja -C "$BUILD_DIR/$build_subdir"
    elif [ -f "CMakeLists.txt" ]; then
        cmake -B "$BUILD_DIR/$build_subdir" -H. $extra_cmake_args
        cmake --build "$BUILD_DIR/$build_subdir" -j"$(nproc)"
    fi

    popd > /dev/null
    echo "$name built successfully"
}

build_logloader() {
    echo "Building logloader..."
    pushd "$PROJECT_ROOT/services/logloader/logloader" > /dev/null
    cmake -B "$BUILD_DIR/logloader" -H.
    cmake --build "$BUILD_DIR/logloader" -j"$(nproc)"
    popd > /dev/null
}

build_mavlink_router() {
    echo "Building mavlink-router..."
    pushd "$PROJECT_ROOT/services/mavlink-router/mavlink-router" > /dev/null
    meson setup "$BUILD_DIR/mavlink-router" --prefix=/opt/ark -Dsystemdsystemunitdir=
    ninja -C "$BUILD_DIR/mavlink-router"
    popd > /dev/null
}

build_dds_agent() {
    echo "Building dds-agent..."
    pushd "$PROJECT_ROOT/services/dds-agent/Micro-XRCE-DDS-Agent" > /dev/null
    cmake -B "$BUILD_DIR/dds-agent" -H.
    cmake --build "$BUILD_DIR/dds-agent" -j"$(nproc)"
    popd > /dev/null
}

build_polaris() {
    echo "Building polaris..."
    pushd "$PROJECT_ROOT/services/polaris/polaris-client-mavlink" > /dev/null
    cmake -B "$BUILD_DIR/polaris" -H.
    cmake --build "$BUILD_DIR/polaris" -j"$(nproc)"
    popd > /dev/null
}

build_rid_transmitter() {
    echo "Building rid-transmitter..."
    pushd "$PROJECT_ROOT/services/rid-transmitter/RemoteIDTransmitter" > /dev/null
    cmake -B "$BUILD_DIR/rid-transmitter" -H.
    cmake --build "$BUILD_DIR/rid-transmitter" -j"$(nproc)"
    popd > /dev/null
}

build_rtsp_server() {
    echo "Building rtsp-server..."
    pushd "$PROJECT_ROOT/services/rtsp-server/rtsp-server" > /dev/null
    cmake -B "$BUILD_DIR/rtsp-server" -H.
    cmake --build "$BUILD_DIR/rtsp-server" -j"$(nproc)"
    popd > /dev/null
}

build_frontend() {
    echo "Building frontend..."
    pushd "$PROJECT_ROOT/frontend/ark-ui/ark-ui" > /dev/null
    npm ci
    npm run build
    mkdir -p "$BUILD_DIR/ark-ui"
    cp -r dist "$BUILD_DIR/ark-ui/"
    popd > /dev/null
}

# ─── Package services with nfpm ───

package_service() {
    local yaml_file="$1"
    local pkg_name
    pkg_name=$(basename "$yaml_file" .yaml)

    echo "Packaging $pkg_name..."
    pushd "$SCRIPT_DIR" > /dev/null
    VERSION="$VERSION" ARCH="$ARCH" nfpm package \
        --config "$yaml_file" \
        --packager deb \
        --target "$OUTPUT_DIR/"
    popd > /dev/null
    echo "$pkg_name packaged"
}

# ─── Main ───

case "${1:-all}" in
    build-cpp)
        echo "--- Building C++ services ---"
        build_logloader
        build_mavlink_router
        build_dds_agent
        build_polaris
        build_rid_transmitter
        build_rtsp_server
        ;;
    build-frontend)
        echo "--- Building frontend ---"
        build_frontend
        ;;
    package)
        echo "--- Packaging all services ---"
        for yaml in "$SCRIPT_DIR"/ark-*.yaml; do
            package_service "$yaml"
        done
        ;;
    package-python)
        echo "--- Packaging Python services (no build needed) ---"
        for svc in autopilot-manager connection-manager service-manager system-manager; do
            package_service "$SCRIPT_DIR/ark-${svc}.yaml"
        done
        ;;
    package-bash)
        echo "--- Packaging Bash services (no build needed) ---"
        for svc in hotspot-updater jetson-can; do
            package_service "$SCRIPT_DIR/ark-${svc}.yaml"
        done
        ;;
    all)
        echo "--- Full build + package ---"
        build_logloader
        build_mavlink_router
        build_dds_agent
        build_polaris
        build_rid_transmitter
        build_rtsp_server
        build_frontend

        for yaml in "$SCRIPT_DIR"/ark-*.yaml; do
            package_service "$yaml"
        done

        echo ""
        echo "=== Build complete ==="
        echo "Packages in: $OUTPUT_DIR/"
        ls -lh "$OUTPUT_DIR/"*.deb 2>/dev/null || echo "(no packages found)"
        ;;
    *)
        echo "Usage: $0 [build-cpp|build-frontend|package|package-python|package-bash|all]"
        exit 1
        ;;
esac
