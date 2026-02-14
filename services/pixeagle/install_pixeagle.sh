#!/bin/bash
# Determine PROJECT_ROOT as two levels up from this script's location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." &> /dev/null && pwd )"
source "$PROJECT_ROOT/tools/functions.sh"

PIXEAGLE_DIR="$HOME/PixEagle"
PIXEAGLE_REPO="https://github.com/alireza787b/PixEagle.git"
PIXEAGLE_BRANCH="main"

echo "Installing PixEagle (this may take 15-30 minutes on first install)..."

# Clone or update
if [ -d "$PIXEAGLE_DIR" ]; then
    echo "PixEagle directory exists, pulling latest..."
    pushd . &>/dev/null
    cd "$PIXEAGLE_DIR"
    git pull origin "$PIXEAGLE_BRANCH" || echo "Warning: git pull failed, using existing code"
    popd &>/dev/null
else
    echo "Cloning PixEagle..."
    if ! git clone --branch "$PIXEAGLE_BRANCH" "$PIXEAGLE_REPO" "$PIXEAGLE_DIR"; then
        echo "ERROR: Failed to clone PixEagle repository"
        exit 1
    fi
fi

# Run PixEagle initialization (non-interactive, full profile)
pushd . &>/dev/null
cd "$PIXEAGLE_DIR"
export PIXEAGLE_INSTALL_PROFILE="full"
export PIXEAGLE_NONINTERACTIVE="1"
bash scripts/init.sh
popd &>/dev/null

echo "PixEagle installation complete"
