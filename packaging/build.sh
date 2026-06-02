#!/usr/bin/env bash
# Master build orchestrator for the ARK-OS .deb.
#
# Usage: ./packaging/build.sh <jetson|pi> [--version=X.Y.Z]
#
# Must run on arm64 (native compilation, arm64 venv, arm64 Node). Produces
# ark-os-<platform>_<version>_arm64.deb in the repo root. The helper scripts read
# the exported environment below; run them via this orchestrator, not directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Pinned toolchain/runtime versions ---
# versions.env is the single source of truth (shared with install_ark_os.sh and
# the CI workflow). Source it, then export the pins the helper scripts consume.
# shellcheck source=packaging/versions.env
source "$SCRIPT_DIR/versions.env"
export NODE_VERSION MAVSDK_VERSION

# --- Parse args ---
PLATFORM="${1:-}"
VERSION=""
shift || true
for arg in "$@"; do
    case "$arg" in
        --version=*) VERSION="${arg#--version=}" ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

case "$PLATFORM" in
    jetson|pi) ;;
    *) echo "Usage: $0 <jetson|pi> [--version=X.Y.Z]" >&2; exit 1 ;;
esac

if [ -z "$VERSION" ]; then
    VERSION="$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null | sed 's/^v//' || true)"
    [ -z "$VERSION" ] && VERSION="0.0.0"
fi

export PLATFORM VERSION REPO_ROOT
export ARK_USER="$PLATFORM"          # the service user matches the platform name
export PKG_PREFIX="/usr/lib/ark-os"  # install prefix inside the package
export BUILD_DIR="$REPO_ROOT/build/ark-os-$PLATFORM"

echo "==> Building ark-os-$PLATFORM version $VERSION"
echo "    REPO_ROOT=$REPO_ROOT"
echo "    BUILD_DIR=$BUILD_DIR"

if [ "$(uname -m)" != "aarch64" ]; then
    echo "WARNING: building on $(uname -m), not aarch64 — the compiled binaries," >&2
    echo "         venv, and Node will not run on the target. Use an arm64 runner" >&2
    echo "         for a release build (see .github/workflows/build-deb.yml)." >&2
fi

# The bundled venv (built with `python3 -m venv --copies`, which references the
# system python's stdlib at runtime), the natively-compiled binaries, and Node
# assume the build host's OS/ABI matches the target. Each platform has a distinct
# baseline, so building on the wrong host silently produces a .deb that won't run
# on the device. Fail fast on a mismatch unless ARK_OS_ALLOW_HOST_MISMATCH=1.
case "$PLATFORM" in
    jetson) EXPECT_CODENAME="jammy";    EXPECT_PYTHON="3.10" ;;  # JetPack 6 / Ubuntu 22.04
    pi)     EXPECT_CODENAME="bookworm"; EXPECT_PYTHON="3.11" ;;  # Raspberry Pi OS / Debian 12
esac
HOST_CODENAME=""
[ -r /etc/os-release ] && HOST_CODENAME="$(. /etc/os-release; echo "${VERSION_CODENAME:-}")"
HOST_PYTHON="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
if [ "$HOST_CODENAME" != "$EXPECT_CODENAME" ] || [ "$HOST_PYTHON" != "$EXPECT_PYTHON" ]; then
    MSG="build host is ${HOST_CODENAME:-unknown}/python${HOST_PYTHON:-unknown}, expected $EXPECT_CODENAME/python$EXPECT_PYTHON for the $PLATFORM target"
    if [ "${ARK_OS_ALLOW_HOST_MISMATCH:-0}" = "1" ]; then
        echo "WARNING: $MSG — continuing because ARK_OS_ALLOW_HOST_MISMATCH=1." >&2
    else
        echo "ERROR: $MSG." >&2
        echo "       The venv/binaries/Node would not run on the target. Build $PLATFORM on" >&2
        echo "       its matching host (see .github/workflows/build-deb.yml), or set" >&2
        echo "       ARK_OS_ALLOW_HOST_MISMATCH=1 to override." >&2
        exit 1
    fi
fi

# Fresh staging tree.
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

"$SCRIPT_DIR/build_binaries.sh"
"$SCRIPT_DIR/build_frontend.sh"
"$SCRIPT_DIR/build_venv.sh"
"$SCRIPT_DIR/bundle_node.sh"
"$SCRIPT_DIR/assemble_tree.sh"

DEB="$REPO_ROOT/ark-os-${PLATFORM}_${VERSION}_arm64.deb"
echo "==> dpkg-deb --build"
dpkg-deb --build --root-owner-group "$BUILD_DIR" "$DEB"

echo "==> lintian (non-fatal — file-in-etc-not-marked-as-conffile is expected)"
lintian --no-tag-display-limit "$DEB" || true

echo "==> Done: $DEB"
