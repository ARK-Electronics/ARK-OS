#!/bin/bash

# Service control script — builds and installs services as .deb packages via nfpm.
#
# Usage:
#   ./service_control.sh install [service]   Build+package+install a service (or all)
#   ./service_control.sh uninstall <service> Remove a service's deb package
#   ./service_control.sh list                List available and installed services
#   ./service_control.sh status              Show systemd status of services

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

SERVICES_DIR="$(realpath "$SCRIPT_DIR/../services")"
PACKAGING_DIR="$(realpath "$SCRIPT_DIR/../packaging")"
BUILD_DIR="$PROJECT_ROOT/build"
OUTPUT_DIR="$PROJECT_ROOT/dist"
VERSION=$(cat "$PROJECT_ROOT/VERSION" | tr -d '[:space:]')
ARCH=$(dpkg --print-architecture)

# ─── Helpers ──────────────────────────────────────────────────────────────────

check_nfpm() {
    if ! command -v nfpm &>/dev/null; then
        echo "ERROR: nfpm is not installed."
        echo ""
        echo "Install it with:"
        echo "  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
        echo "  or: curl -sfL https://install.goreleaser.com/github.com/goreleaser/nfpm.sh | sh"
        echo ""
        echo "See: https://nfpm.goreleaser.com/install/"
        exit 1
    fi
}

read_json_value() {
    local json_file="$1"
    local property="$2"
    local default_value="$3"

    if [ ! -f "$json_file" ]; then
        echo "$default_value"
        return
    fi

    local value
    value=$(jq -r ".$property // \"$default_value\"" "$json_file" 2>/dev/null)
    if [ "$value" = "null" ]; then
        echo "$default_value"
    else
        echo "$value"
    fi
}

is_platform_supported() {
    local manifest_file="$1"
    local platforms
    platforms=$(jq -r '.platform | if type == "array" then . else [.] end | @json' "$manifest_file" 2>/dev/null)

    if [ -z "$platforms" ] || [ "$platforms" = "null" ]; then
        platforms='["all"]'
    fi

    if [[ "$platforms" == *"\"all\""* ]]; then
        return 0
    fi

    if [[ "$platforms" == *"\"$TARGET\""* ]]; then
        return 0
    fi

    return 1
}

is_service_enabled() {
    local manifest_file="$1"
    local env_var
    env_var=$(read_json_value "$manifest_file" "env_var" "")

    if [ -z "$env_var" ]; then
        return 0
    fi

    if [ "${!env_var:-}" = "y" ]; then
        return 0
    fi

    return 1
}

# Look up a service's type from packages.yaml
get_service_type() {
    local name="$1"
    python3 -c "
import yaml, sys
with open('$PACKAGING_DIR/packages.yaml') as f:
    cfg = yaml.safe_load(f)
svc = cfg.get('services', {}).get('$name')
if svc:
    print(svc.get('type', 'custom'))
else:
    print('unknown')
"
}

# ─── Build ────────────────────────────────────────────────────────────────────

build_service() {
    local name="$1"

    "$PACKAGING_DIR/build-packages.sh" build-service "$name"
}

# ─── Package ──────────────────────────────────────────────────────────────────

package_service() {
    local name="$1"

    "$PACKAGING_DIR/build-packages.sh" package-service "$name"
}

# ─── Install ──────────────────────────────────────────────────────────────────

install_service() {
    local name="$1"
    local manifest_file="$SERVICES_DIR/$name/$name.manifest.json"

    echo "=== Installing $name ==="

    if [ ! -f "$manifest_file" ]; then
        echo "Error: Manifest file for $name not found."
        return 1
    fi

    if ! is_platform_supported "$manifest_file"; then
        echo "Service $name is not supported on platform $TARGET, skipping."
        return 0
    fi

    if ! is_service_enabled "$manifest_file"; then
        echo "Service $name is disabled in configuration, skipping."
        return 0
    fi

    local svc_type
    svc_type=$(get_service_type "$name")

    # Build if needed
    if [ "$svc_type" = "cpp" ]; then
        build_service "$name"
    fi

    # Generate configs + package
    package_service "$name"

    # Install the deb
    local deb_file
    deb_file=$(ls -t "$OUTPUT_DIR"/ark-"${name}"_*.deb 2>/dev/null | head -1)

    if [ -z "$deb_file" ]; then
        echo "Error: No .deb package found for $name"
        return 1
    fi

    echo "Installing $deb_file..."
    sudo dpkg -i "$deb_file"
    echo "$name installed successfully."
}

install_all_services() {
    for service_dir in "$SERVICES_DIR"/*/; do
        if [ -d "$service_dir" ]; then
            local service_name
            service_name=$(basename "$service_dir")
            local manifest_file="$service_dir/$service_name.manifest.json"

            # Skip services without a manifest
            [ -f "$manifest_file" ] || continue

            # Skip services not in packages.yaml (e.g. removed/legacy)
            local svc_type
            svc_type=$(get_service_type "$service_name")
            [ "$svc_type" = "unknown" ] && continue

            install_service "$service_name"
        fi
    done
}

# ─── Uninstall ────────────────────────────────────────────────────────────────

uninstall_service() {
    local name="$1"
    local pkg_name="ark-${name}"

    if dpkg -s "$pkg_name" &>/dev/null; then
        echo "Removing $pkg_name..."
        sudo dpkg -r "$pkg_name"
        echo "$pkg_name removed."
    else
        echo "$pkg_name is not installed."
    fi
}

# ─── List ─────────────────────────────────────────────────────────────────────

list_services() {
    echo "Available services (platform: $TARGET):"
    echo ""

    for service_dir in "$SERVICES_DIR"/*/; do
        if [ -d "$service_dir" ]; then
            local service_name
            service_name=$(basename "$service_dir")
            local manifest_file="$service_dir/$service_name.manifest.json"

            [ -f "$manifest_file" ] || continue

            if ! is_platform_supported "$manifest_file"; then
                continue
            fi

            local display_name
            display_name=$(read_json_value "$manifest_file" "displayName" "$service_name")
            local description
            description=$(read_json_value "$manifest_file" "description" "")
            local pkg_name="ark-${service_name}"

            local installed="not installed"
            if dpkg -s "$pkg_name" &>/dev/null; then
                local pkg_ver
                pkg_ver=$(dpkg -s "$pkg_name" 2>/dev/null | grep '^Version:' | awk '{print $2}')
                installed="installed ($pkg_ver)"
            fi

            echo "  $display_name ($service_name)"
            [ -n "$description" ] && echo "    $description"
            echo "    Package: $pkg_name — $installed"
            echo ""
        fi
    done
}

# ─── Status ───────────────────────────────────────────────────────────────────

show_status() {
    echo "Service status:"
    for service_dir in "$SERVICES_DIR"/*/; do
        if [ -d "$service_dir" ]; then
            local service_name
            service_name=$(basename "$service_dir")
            local manifest_file="$service_dir/$service_name.manifest.json"

            [ -f "$manifest_file" ] || continue

            if ! is_platform_supported "$manifest_file"; then
                continue
            fi

            local requires_sudo
            requires_sudo=$(read_json_value "$manifest_file" "requires_sudo" "false")

            echo -n "  $service_name: "
            local status
            if [ "$requires_sudo" = "true" ]; then
                status=$(systemctl is-active "$service_name.service" 2>/dev/null)
            else
                status=$(systemctl --user is-active "$service_name.service" 2>/dev/null)
            fi

            if [ "$status" = "active" ]; then
                echo "running"
            else
                echo "not running"
            fi
        fi
    done
}

# ─── Main ─────────────────────────────────────────────────────────────────────

case "${1:-help}" in
    install)
        check_nfpm
        mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"
        if [ -n "${2:-}" ]; then
            install_service "$2"
        else
            install_all_services
        fi
        ;;
    uninstall)
        if [ -n "${2:-}" ]; then
            uninstall_service "$2"
        else
            echo "Error: Please specify a service to uninstall."
            exit 1
        fi
        ;;
    list)
        list_services
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        echo "Usage: $0 <command> [service]"
        echo ""
        echo "Commands:"
        echo "  install [service]     Build, package, and install a service (or all)"
        echo "  uninstall <service>   Remove a service's deb package"
        echo "  list                  List available services and install status"
        echo "  status                Show systemd status of services"
        echo "  help                  Show this help message"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information."
        exit 1
        ;;
esac
