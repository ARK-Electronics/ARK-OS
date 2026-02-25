#!/bin/bash
# Add ARK-OS APT repository to system
set -euo pipefail

REPO_URL="https://ark-electronics.github.io/ARK-OS"
KEYRING_PATH="/usr/share/keyrings/ark-archive-keyring.gpg"

# Download and install GPG keyring
curl -fsSL "${REPO_URL}/ark-archive-keyring.gpg" | sudo tee "${KEYRING_PATH}" > /dev/null

# Add repository source
echo "deb [signed-by=${KEYRING_PATH} arch=arm64] ${REPO_URL} stable main" \
  | sudo tee /etc/apt/sources.list.d/ark.list > /dev/null

sudo apt update
echo "ARK-OS APT repository configured successfully."
