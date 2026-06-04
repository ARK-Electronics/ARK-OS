#!/usr/bin/env bash
# Install (or update) ARK-OS on a live, already-flashed device.
#
# This is the live-system counterpart to ark_jetson_kernel/provision.sh, which
# bakes the same packages into a Jetson image at build time (--provision). It
# performs the installs a plain `apt install ./ark-os-*.deb` does NOT do itself:
#
#   1. libmavsdk-dev  — a hard Depends of ark-os that lives on no apt repo, so
#                       apt cannot auto-resolve it; it must be installed first.
#   2. jetson-stats   — the jtop client system-manager uses for the web UI's
#      (Jetson only)    Jetson stats. Not an apt Depends and not in the bundled
#                       venv (the venv imports it via system-site-packages).
#   3. ark-os-<plat>  — the package itself; its postinst does the rest. apt pulls
#                       the remaining Depends (nginx, gstreamer, bluez, …) from
#                       the device's normal Ubuntu repos.
#
# Re-running is safe: MAVSDK and jetson-stats are skipped when already at the
# pinned version, and re-installing the ark-os deb upgrades it in place — so this
# is also the supported way to update a live device.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pinned versions: versions.env is the single source of truth (shared with
# build.sh and the CI workflow). Flags/env override it, which also lets this
# script run when downloaded on its own, without a repo checkout.
# shellcheck source=packaging/versions.env
[ -f "$SCRIPT_DIR/versions.env" ] && source "$SCRIPT_DIR/versions.env"

MAVSDK_REPO="https://github.com/mavlink/MAVSDK"
ARK_OS_REPO="https://github.com/ARK-Electronics/ARK-OS"

die()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARNING: $*" >&2; }
info() { echo "==> $*"; }

usage() {
    cat >&2 <<'EOF'
Usage: sudo ./install_ark_os.sh [options] [ARK_OS_DEB]

Installs MAVSDK, jetson-stats (Jetson only), and ARK-OS on a live device in the
correct order. Also the supported way to update a live device.

Positional:
  ARK_OS_DEB                Path to a local ark-os-<platform>-<codename>_<ver>_arm64.deb. If
                            omitted, a single matching deb in the current
                            directory is used, or one is downloaded when
                            --ark-os-version is given.

Options:
  --platform=jetson|pi      Override platform autodetection.
  --codename=NAME           Override OS-release codename autodetection (bookworm, trixie,
                            jammy, …). Only needed to name a download when /etc/os-release
                            can't be read.
  --ark-os-version=X.Y.Z    Download this ark-os release when no local deb is given.
  --mavsdk-deb=PATH         Install MAVSDK from a local deb instead of downloading.
  --mavsdk-version=X.Y.Z    Override the MAVSDK version (default from versions.env).
  --jetson-stats-version=X  Override the jetson-stats version (default from versions.env).
  --skip-jtop               Do not install jetson-stats (Jetson only).
  -h, --help                Show this help.

Versions default to packaging/versions.env. MAVSDK has no apt repo; jetson-stats
is installed system-wide via pip so the web UI can report Jetson stats.
EOF
}

# --- Arg parsing ---
PLATFORM=""
CODENAME=""
DEB_ARG=""
ARK_OS_VERSION=""
MAVSDK_DEB=""
SKIP_JTOP=0
OPT_MAVSDK_VERSION=""
OPT_JETSON_STATS_VERSION=""

for arg in "$@"; do
    case "$arg" in
        --platform=*)            PLATFORM="${arg#*=}" ;;
        --codename=*)             CODENAME="${arg#*=}" ;;
        --ark-os-version=*)       ARK_OS_VERSION="${arg#*=}" ;;
        --mavsdk-deb=*)           MAVSDK_DEB="${arg#*=}" ;;
        --mavsdk-version=*)       OPT_MAVSDK_VERSION="${arg#*=}" ;;
        --jetson-stats-version=*) OPT_JETSON_STATS_VERSION="${arg#*=}" ;;
        --skip-jtop)              SKIP_JTOP=1 ;;
        -h|--help)                usage; exit 0 ;;
        -*)                       usage; die "unknown option: $arg" ;;
        *)
            [ -z "$DEB_ARG" ] || die "more than one ark-os deb given: '$DEB_ARG' and '$arg'"
            DEB_ARG="$arg" ;;
    esac
done

# Flags/env override versions.env.
MAVSDK_VERSION="${OPT_MAVSDK_VERSION:-${MAVSDK_VERSION:-}}"
JETSON_STATS_VERSION="${OPT_JETSON_STATS_VERSION:-${JETSON_STATS_VERSION:-}}"

# --- Preconditions ---
[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)."
[ "$(uname -m)" = "aarch64" ] || \
    die "this installs arm64 packages; run it on the aarch64 device, not your workstation."

# --- Helpers ---
platform_from_deb() {
    case "$(basename "$1")" in
        ark-os-jetson-*) echo jetson ;;
        ark-os-pi-*)     echo pi ;;
        *)               return 1 ;;
    esac
}

detect_platform() {
    [ -f /etc/nv_tegra_release ] && { echo jetson; return; }
    if [ -r /proc/device-tree/model ]; then
        local model; model="$(tr -d '\0' < /proc/device-tree/model)"
        case "$model" in
            *Jetson*|*Tegra*) echo jetson; return ;;
            *Raspberry*Pi*)   echo pi;     return ;;
        esac
    fi
    return 1
}

detect_codename() {
    [ -r /etc/os-release ] || return 1
    local c; c="$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")"
    [ -n "$c" ] && { echo "$c"; return; }
    return 1
}

fetch() {
    local url="$1" out="$2"
    info "Downloading $(basename "$out")"
    if command -v curl >/dev/null 2>&1; then
        curl -fSL --retry 3 -o "$out" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$out" "$url"
    else
        die "need curl or wget to download $url"
    fi
}

# apt-get treats a bare filename as a package name; only a path containing a
# slash is read as a local deb. Resolve to an absolute path so cwd-relative and
# downloaded debs both install correctly.
apt_install_deb() { apt-get install -y "$(readlink -f "$1")"; }

install_jtop() {
    apt-get install -y python3-pip || return 1
    pip3 install "jetson-stats==$JETSON_STATS_VERSION" || return 1
    # Bring the jtop daemon up now (pip's setup.py installs the unit) and enable
    # it for next boot; harmless if already active.
    systemctl enable --now jtop.service 2>/dev/null || true
    return 0
}

# --- Platform: explicit flag > deb filename > hardware autodetect ---
if [ -z "$PLATFORM" ] && [ -n "$DEB_ARG" ]; then
    PLATFORM="$(platform_from_deb "$DEB_ARG" || true)"
fi
[ -n "$PLATFORM" ] || PLATFORM="$(detect_platform || true)"
[ -n "$PLATFORM" ] || die "could not determine platform; pass --platform=jetson|pi."
case "$PLATFORM" in jetson|pi) ;; *) die "invalid platform '$PLATFORM' (expected jetson or pi)." ;; esac
info "Platform: $PLATFORM"

# Codename: explicit flag wins; otherwise read from the device's /etc/os-release.
# Only required to construct a download URL (--ark-os-version); a local/cwd deb
# carries its codename in the filename, and the deb's preinst guards a mismatch.
[ -n "$CODENAME" ] || CODENAME="$(detect_codename || true)"
[ -n "$CODENAME" ] && info "OS codename: $CODENAME"

# Every ARK-OS service runs as User=$PLATFORM (baked into the unit files). Modern
# Raspberry Pi OS no longer ships a default 'pi' account, so fail before touching
# the system rather than letting the deb's postinst abort on a missing user.
getent passwd "$PLATFORM" >/dev/null 2>&1 || \
    die "ARK-OS services run as the user '$PLATFORM', which does not exist on this device. Re-image with the username '$PLATFORM', or create it first: sudo useradd -m -s /bin/bash $PLATFORM && sudo passwd $PLATFORM && sudo usermod -aG sudo $PLATFORM"

[ -n "$MAVSDK_VERSION" ] || die "MAVSDK version unknown (no versions.env and no --mavsdk-version)."

# --- Scratch space for downloads ---
DL_DIR="$(mktemp -d)"
trap 'rm -rf "$DL_DIR"' EXIT

# --- Resolve the ark-os deb up front, so we fail before touching the system if
#     it is missing. ---
ARK_OS_DEB=""
if [ -n "$DEB_ARG" ]; then
    [ -f "$DEB_ARG" ] || die "ark-os deb not found: $DEB_ARG"
    ARK_OS_DEB="$DEB_ARG"
else
    shopt -s nullglob
    matches=( "ark-os-${PLATFORM}-"*_arm64.deb )
    shopt -u nullglob
    if [ "${#matches[@]}" -eq 1 ]; then
        ARK_OS_DEB="${matches[0]}"
        info "Using ark-os deb from current directory: $ARK_OS_DEB"
    elif [ "${#matches[@]}" -gt 1 ]; then
        die "multiple ark-os-${PLATFORM} debs in $(pwd); pass the one to install as an argument."
    elif [ -n "$ARK_OS_VERSION" ]; then
        [ -n "$CODENAME" ] || die "could not determine this device's OS codename to name the download; pass --codename=<bookworm|trixie|jammy|…>."
        ARK_OS_DEB="$DL_DIR/ark-os-${PLATFORM}-${CODENAME}_${ARK_OS_VERSION}_arm64.deb"
        fetch "$ARK_OS_REPO/releases/download/v${ARK_OS_VERSION}/$(basename "$ARK_OS_DEB")" "$ARK_OS_DEB"
    else
        die "no ark-os deb given: pass a path, place one in $(pwd), or use --ark-os-version=X.Y.Z."
    fi
fi

# --- Refresh apt indices (best effort; install still works off cached indices) ---
info "Refreshing apt package indices"
apt-get update || warn "apt-get update failed; continuing with existing indices."

# ===========================================================================
# 1. MAVSDK — hard Depends of ark-os, not in any apt repo. Install first.
# ===========================================================================
installed_mavsdk="$(dpkg-query -W -f='${Version}' libmavsdk-dev 2>/dev/null || true)"
if [ "$installed_mavsdk" = "$MAVSDK_VERSION" ]; then
    info "libmavsdk-dev $MAVSDK_VERSION already installed — skipping."
else
    if [ -n "$MAVSDK_DEB" ]; then
        [ -f "$MAVSDK_DEB" ] || die "MAVSDK deb not found: $MAVSDK_DEB"
    else
        # Upstream ships no ubuntu22.04_arm64 asset; debian12_arm64 is glibc-
        # compatible with the JetPack 6 / Jammy rootfs in practice.
        MAVSDK_DEB="$DL_DIR/libmavsdk-dev_${MAVSDK_VERSION}_debian12_arm64.deb"
        fetch "$MAVSDK_REPO/releases/download/v${MAVSDK_VERSION}/$(basename "$MAVSDK_DEB")" "$MAVSDK_DEB"
    fi
    info "Installing MAVSDK $MAVSDK_VERSION"
    apt_install_deb "$MAVSDK_DEB"
fi

# ===========================================================================
# 2. jetson-stats (jtop) — Jetson only. Optional: system-manager degrades
#    gracefully without it, so a failure here warns but does not abort.
#    Installed before ark-os so jtop.service is up when system-manager starts.
# ===========================================================================
if [ "$PLATFORM" = "jetson" ] && [ "$SKIP_JTOP" -eq 0 ]; then
    if [ -z "$JETSON_STATS_VERSION" ]; then
        warn "jetson-stats version unknown — skipping jtop (web UI Jetson stats will be unavailable)."
    else
        installed_js="$(pip3 show jetson-stats 2>/dev/null | awk '/^Version:/{print $2}' || true)"
        if [ "$installed_js" = "$JETSON_STATS_VERSION" ]; then
            info "jetson-stats $JETSON_STATS_VERSION already installed — skipping."
        elif install_jtop; then
            info "jetson-stats $JETSON_STATS_VERSION installed."
        else
            warn "jetson-stats install failed — Jetson stats in the web UI will be unavailable."
            warn "  retry later with: sudo pip3 install \"jetson-stats==${JETSON_STATS_VERSION}\""
        fi
    fi
fi

# ===========================================================================
# 3. ark-os — its postinst configures users/groups/services and (on a running
#    system) starts everything.
# ===========================================================================
info "Installing $(basename "$ARK_OS_DEB")"
apt_install_deb "$ARK_OS_DEB"

info "Done. ARK-OS ($PLATFORM) is installed."
echo "    Manage services and configuration from the web UI (http://<hostname>.local)."
echo "    If the install output above asked you to reboot (migration from a source"
echo "    install), do so now."
