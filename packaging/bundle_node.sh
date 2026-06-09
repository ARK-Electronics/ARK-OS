#!/usr/bin/env bash
# Download a pinned Node.js arm64 runtime, verify its checksum, and stage it into
# the package tree. Avoids depending on NodeSource/NVM on the device. Invoked by
# build.sh (NODE_VERSION, BUILD_DIR, PKG_PREFIX in the environment).
set -euo pipefail

cd "$REPO_ROOT"

NODE_VER="${NODE_VERSION:-20.20.2}"
NODE_TARBALL="node-v${NODE_VER}-linux-arm64.tar.xz"
NODE_URL="https://nodejs.org/dist/v${NODE_VER}/${NODE_TARBALL}"
SHASUMS_URL="https://nodejs.org/dist/v${NODE_VER}/SHASUMS256.txt"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

echo "==> downloading $NODE_TARBALL"
curl -fsSLO "$NODE_URL"
echo "==> verifying sha256"
curl -fsSL "$SHASUMS_URL" | grep " ${NODE_TARBALL}\$" | sha256sum -c -
tar -xJf "$NODE_TARBALL"

NODE_HOME="$TMP/node-v${NODE_VER}-linux-arm64"
DEST_BIN="$BUILD_DIR$PKG_PREFIX/bin"
DEST_LIB="$BUILD_DIR$PKG_PREFIX/lib"
mkdir -p "$DEST_BIN" "$DEST_LIB"

install -m 0755 "$NODE_HOME/bin/node" "$DEST_BIN/node"
# node_modules carries npm/npx/corepack; ship it and recreate the bin symlinks as
# relative links so they resolve under /usr/lib/ark-os (node itself is all the
# services need at runtime — npm is only here for maintenance convenience).
cp -r "$NODE_HOME/lib/node_modules" "$DEST_LIB/"
ln -sf ../lib/node_modules/npm/bin/npm-cli.js "$DEST_BIN/npm"
ln -sf ../lib/node_modules/npm/bin/npx-cli.js "$DEST_BIN/npx"

echo "==> node $NODE_VER staged at $DEST_BIN/node"
