#!/bin/bash

# Source functions and configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/functions.sh"

# Set up paths
SERVICES_DIR="$(realpath "$SCRIPT_DIR/../services")"

# Function to read values from a JSON manifest using jq
function read_json_value() {
    local json_file="$1"
    local property="$2"
    local default_value="$3"

    if [ ! -f "$json_file" ]; then
        echo "$default_value"
        return
    fi

    local value=$(jq -r ".$property // \"$default_value\"" "$json_file" 2>/dev/null)
    if [ "$value" = "null" ]; then
        echo "$default_value"
    else
        echo "$value"
    fi
}

# Function to check if current platform is in the platform list
function is_platform_supported() {
    local manifest_file="$1"
    # Always expect an array from JSON
    local platforms=$(jq -r '.platform | if type == "array" then . else [.] end | @json' "$manifest_file" 2>/dev/null)

    # If jq fails or returns null, default to ["all"]
    if [ -z "$platforms" ] || [ "$platforms" = "null" ]; then
        platforms='["all"]'
    fi

    # Check if "all" is in the array
    if [[ "$platforms" == *"\"all\""* ]]; then
        return 0
    fi

    # Check if current platform is in the array
    if [[ "$platforms" == *"\"$TARGET\""* ]]; then
        return 0
    fi

    return 1
}

# Check if a service is enabled based on its environment variable
function is_service_enabled() {
    local manifest_file="$1"

    # Check if service has an environment variable for enabling
    local env_var=$(read_json_value "$manifest_file" "env_var" "")

    # If no environment variable specified, service is always enabled
    if [ -z "$env_var" ]; then
        echo "No env var specified, enabling service"
        return 0
    fi

    # Check the value of the environment variable
    if [ "${!env_var}" = "y" ]; then
        echo "Env var enabled"
        return 0
    fi

    return 1
}

# Function to install files specified in manifest
function install_service_files() {
    local SERVICE_NAME="$1"
    local SERVICE_DIR="$2"
    local MANIFEST_FILE="$3"
    local REQUIRES_SUDO="$4"

    # Get the install files list from the manifest
    local install_files=$(jq -r '.install_files | if . == null then [] else . end | .[]' "$MANIFEST_FILE" 2>/dev/null)

    if [ -n "$install_files" ]; then
        echo "Installing files for $SERVICE_NAME..."

        for file in $install_files; do
            if [ -f "$SERVICE_DIR/$file" ]; then
                if [ "$REQUIRES_SUDO" = "true" ]; then
                    # Install to /usr/local/bin with sudo
                    sudo cp "$SERVICE_DIR/$file" /usr/local/bin/
                    sudo chmod +x "/usr/local/bin/$file"
                    echo "  - Installed $file to /usr/local/bin/"
                else
                    # Install to ~/.local/bin
                    mkdir -p ~/.local/bin
                    cp "$SERVICE_DIR/$file" ~/.local/bin/
                    chmod +x "$HOME/.local/bin/$file"
                    echo "  - Installed $file to ~/.local/bin/"
                fi
            else
                echo "  - Warning: File $file not found in $SERVICE_DIR/"
            fi
        done
    fi
}

function uninstall_service() {
    sudo systemctl stop $1.service &>/dev/null
    sudo systemctl disable $1.service &>/dev/null
    systemctl --user stop $1.service &>/dev/null
    systemctl --user disable $1.service &>/dev/null
    sudo rm /etc/systemd/system/$1.service &>/dev/null
    sudo rm /lib/systemd/system/$1.service &>/dev/null
    sudo rm $XDG_CONFIG_HOME/systemd/user/$1.service &>/dev/null
    sudo rm -rf "$XDG_DATA_HOME/$1"
    sudo systemctl daemon-reload
    systemctl --user daemon-reload
}

function install_service() {
    local SERVICE_NAME="$1"
    local SERVICE_DIR="$SERVICES_DIR/$SERVICE_NAME"
    local MANIFEST_FILE="$SERVICE_DIR/$SERVICE_NAME.manifest.json"

    echo "Installing $SERVICE_NAME..."

    # Check if manifest exists
    if [ ! -f "$MANIFEST_FILE" ]; then
        echo "Error: Manifest file for $SERVICE_NAME not found."
        return 1
    fi

    # Check if this service is supported on the current platform
    if ! is_platform_supported "$MANIFEST_FILE"; then
        echo "Service $SERVICE_NAME is not supported on platform $TARGET, skipping."
        return 0
    fi

    # Check if service is enabled in configuration
    if ! is_service_enabled "$MANIFEST_FILE"; then
        echo "Service $SERVICE_NAME is disabled in configuration, skipping."
        uninstall_service "$SERVICE_NAME"
        return 0
    fi

    # Uninstall first to ensure clean installation
    uninstall_service "$SERVICE_NAME"

    # Get the install script from the manifest
    local install_script=$(read_json_value "$MANIFEST_FILE" "install_script" "")

    # Run service-specific install script if specified in manifest
    if [ -n "$install_script" ] && [ -f "$SERVICE_DIR/$install_script" ]; then
        echo "Running installation script: $install_script"
        # Execute the script with proper path
        (cd "$SERVICE_DIR" && bash "./$install_script")
    fi

    # Check if service requires sudo
    local requires_sudo=$(read_json_value "$MANIFEST_FILE" "requires_sudo" "false")

    # Install service files specified in manifest
    install_service_files "$SERVICE_NAME" "$SERVICE_DIR" "$MANIFEST_FILE" "$requires_sudo"

    # Install service file
    if [ -f "$SERVICE_DIR/$SERVICE_NAME.service" ]; then
        if [ "$requires_sudo" = "true" ]; then
            # Install as root service
            sudo cp "$SERVICE_DIR/$SERVICE_NAME.service" /etc/systemd/system/
            sudo systemctl daemon-reload
            sudo systemctl enable "$SERVICE_NAME.service"
            sudo systemctl restart "$SERVICE_NAME.service"
        else
            # Install as user service
            mkdir -p $XDG_CONFIG_HOME/systemd/user/
            cp "$SERVICE_DIR/$SERVICE_NAME.service" "$XDG_CONFIG_HOME/systemd/user/"

            # Add manifest to user data directory
            mkdir -p "$XDG_DATA_HOME/$SERVICE_NAME"
            cp "$MANIFEST_FILE" "$XDG_DATA_HOME/$SERVICE_NAME/"

            systemctl --user daemon-reload
            systemctl --user enable "$SERVICE_NAME.service"
            systemctl --user restart "$SERVICE_NAME.service"
        fi

        echo "$SERVICE_NAME installed successfully."
    else
        echo "Error: Service file for $SERVICE_NAME not found."
        return 1
    fi

    return 0
}

# Function to install all services
function install_all_services() {
    # Discover all service directories
    for service_dir in "$SERVICES_DIR"/*; do
        if [ -d "$service_dir" ]; then
            service_name=$(basename "$service_dir")
            install_service "$service_name"
        fi
    done
}

# Process command line arguments
if [ $# -gt 0 ]; then
    case "$1" in
        install)
            if [ -n "$2" ]; then
                install_service "$2"
            else
                install_all_services
            fi
            ;;
        uninstall)
            if [ -n "$2" ]; then
                uninstall_service "$2"
                echo "$2 uninstalled."
            else
                echo "Error: Please specify a service to uninstall."
                exit 1
            fi
            ;;
        list)
            echo "Available services:"
            for service_dir in "$SERVICES_DIR"/*; do
                if [ -d "$service_dir" ]; then
                    service_name=$(basename "$service_dir")
                    manifest_file="$service_dir/$service_name.manifest.json"

                    if [ -f "$manifest_file" ]; then
                        display_name=$(read_json_value "$manifest_file" "displayName" "$service_name")
                        description=$(read_json_value "$manifest_file" "description" "")
                        platforms=$(read_json_value "$manifest_file" "platform" "all")
                        requires_sudo=$(read_json_value "$manifest_file" "requires_sudo" "false")
                        env_var=$(read_json_value "$manifest_file" "env_var" "")
                        install_script=$(read_json_value "$manifest_file" "install_script" "")
                        install_files=$(jq -r '.install_files | if . == null then "none" else (. | join(", ")) end' "$manifest_file" 2>/dev/null)

                        # Skip services that aren't supported on this platform
                        if ! is_platform_supported "$manifest_file"; then
                            continue
                        fi

                        # Determine if the service is enabled
                        if is_service_enabled "$manifest_file"; then
                            enabled="enabled"
                        else
                            enabled="disabled"
                        fi

                        echo "  - $display_name ($service_name)"
                        if [ -n "$description" ]; then
                            echo "    Description: $description"
                        fi
                        echo "    Platforms: $platforms"
                        echo "    Requires sudo: $requires_sudo"
                        if [ -n "$env_var" ]; then
                            echo "    Environment variable: $env_var=${!env_var}"
                        fi
                        if [ -n "$install_script" ]; then
                            echo "    Install script: $install_script"
                        fi
                        echo "    Install files: $install_files"
                        echo "    Status: $enabled"
                        echo ""
                    else
                        echo "  - $service_name (no manifest)"
                    fi
                fi
            done
            ;;
        status)
            echo "Service status:"
            for service_dir in "$SERVICES_DIR"/*; do
                if [ -d "$service_dir" ]; then
                    service_name=$(basename "$service_dir")
                    manifest_file="$service_dir/$service_name.manifest.json"

                    # Skip services that aren't supported on this platform
                    if [ -f "$manifest_file" ] && ! is_platform_supported "$manifest_file"; then
                        continue
                    fi

                    requires_sudo="false"
                    if [ -f "$manifest_file" ]; then
                        requires_sudo=$(read_json_value "$manifest_file" "requires_sudo" "false")
                    fi

                    echo -n "  - $service_name: "
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
            ;;
        help|--help|-h)
            echo "Usage: $0 [command] [service]"
            echo "Commands:"
            echo "  install [service]     - Install all services or a specific service"
            echo "  uninstall <service>   - Uninstall a specific service"
            echo "  list                  - List available services"
            echo "  status                - Show the status of all services"
            echo "  help                  - Show this help message"
            ;;
        *)
            echo "Unknown command: $1"
            echo "Use '$0 help' for usage information."
            exit 1
            ;;
    esac
else
    # Default: install all services
    install_all_services
fi
