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

# ─── Generate packaging files from packages.yaml ───

generate() {
    echo "Generating packaging files..."
    python3 "$SCRIPT_DIR/generate.py" --output-dir "$SCRIPT_DIR/generated"
}

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
    pushd "$SCRIPT_DIR/generated" > /dev/null
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
        build_cpp_service logloader "$PROJECT_ROOT/services/logloader/logloader" logloader
        build_cpp_service mavlink-router "$PROJECT_ROOT/services/mavlink-router/mavlink-router" mavlink-router
        build_cpp_service dds-agent "$PROJECT_ROOT/services/dds-agent/Micro-XRCE-DDS-Agent" dds-agent
        build_cpp_service polaris "$PROJECT_ROOT/services/polaris/polaris-client-mavlink" polaris
        build_cpp_service rid-transmitter "$PROJECT_ROOT/services/rid-transmitter/RemoteIDTransmitter" rid-transmitter
        build_cpp_service rtsp-server "$PROJECT_ROOT/services/rtsp-server/rtsp-server" rtsp-server
        ;;
    build-frontend)
        echo "--- Building frontend ---"
        build_frontend
        ;;
    package)
        echo "--- Packaging all services ---"
        generate
        for yaml in "$SCRIPT_DIR/generated"/ark-*.yaml; do
            package_service "$yaml"
        done
        ;;
    package-python)
        echo "--- Packaging Python services (no build needed) ---"
        generate
        for svc in autopilot-manager connection-manager service-manager system-manager; do
            package_service "$SCRIPT_DIR/generated/ark-${svc}.yaml"
        done
        ;;
    package-bash)
        echo "--- Packaging Bash services (no build needed) ---"
        generate
        for svc in hotspot-updater jetson-can; do
            package_service "$SCRIPT_DIR/generated/ark-${svc}.yaml"
        done
        ;;
    all)
        echo "--- Full build + package ---"
        build_cpp_service logloader "$PROJECT_ROOT/services/logloader/logloader" logloader
        build_cpp_service mavlink-router "$PROJECT_ROOT/services/mavlink-router/mavlink-router" mavlink-router
        build_cpp_service dds-agent "$PROJECT_ROOT/services/dds-agent/Micro-XRCE-DDS-Agent" dds-agent
        build_cpp_service polaris "$PROJECT_ROOT/services/polaris/polaris-client-mavlink" polaris
        build_cpp_service rid-transmitter "$PROJECT_ROOT/services/rid-transmitter/RemoteIDTransmitter" rid-transmitter
        build_cpp_service rtsp-server "$PROJECT_ROOT/services/rtsp-server/rtsp-server" rtsp-server
        build_frontend

        generate
        for yaml in "$SCRIPT_DIR/generated"/ark-*.yaml; do
            package_service "$yaml"
        done

        echo ""
        echo "=== Build complete ==="
        echo "Packages in: $OUTPUT_DIR/"
        ls -lh "$OUTPUT_DIR/"*.deb 2>/dev/null || echo "(no packages found)"
        ;;
    build-service)
        # Build a single service by name (reads type from packages.yaml)
        SERVICE_NAME="${2:?Usage: $0 build-service <name>}"
        SERVICE_TYPE=$(python3 -c "
import yaml
with open('$SCRIPT_DIR/packages.yaml') as f:
    cfg = yaml.safe_load(f)
svc = cfg.get('services', {}).get('$SERVICE_NAME', {})
print(svc.get('type', 'unknown'))
")
        case "$SERVICE_TYPE" in
            cpp)
                BUILD_SRC=$(python3 -c "
import yaml
with open('$SCRIPT_DIR/packages.yaml') as f:
    cfg = yaml.safe_load(f)
svc = cfg['services']['$SERVICE_NAME']
print(svc.get('build_dir', ''))
")
                if [ -z "$BUILD_SRC" ]; then
                    echo "Error: No build_dir for $SERVICE_NAME"
                    exit 1
                fi
                build_cpp_service "$SERVICE_NAME" "$PROJECT_ROOT/$BUILD_SRC" "$SERVICE_NAME"
                ;;
            python|bash|custom)
                echo "$SERVICE_NAME is type '$SERVICE_TYPE' — no build step needed."
                ;;
            *)
                echo "Error: Unknown service '$SERVICE_NAME'"
                exit 1
                ;;
        esac
        ;;
    package-service)
        # Package a single service by name
        SERVICE_NAME="${2:?Usage: $0 package-service <name>}"
        generate
        YAML_FILE="$SCRIPT_DIR/generated/ark-${SERVICE_NAME}.yaml"
        if [ ! -f "$YAML_FILE" ]; then
            echo "Error: No generated config for $SERVICE_NAME (expected $YAML_FILE)"
            exit 1
        fi
        package_service "$YAML_FILE"
        ;;
    *)
        echo "Usage: $0 [build-cpp|build-frontend|package|package-python|package-bash|build-service|package-service|all]"
        exit 1
        ;;
esac
