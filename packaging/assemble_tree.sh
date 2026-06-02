#!/usr/bin/env bash
# Lay out the FHS package tree under $BUILD_DIR and assemble DEBIAN/, substituting
# build-time tokens and renaming/namespacing files. Runs LAST, after the binaries,
# frontend, venv, and node have been staged. Invoked by build.sh.
set -euo pipefail

cd "$REPO_ROOT"

PKG="$BUILD_DIR"
P="$PLATFORM"
ARK="$PKG_PREFIX"   # /usr/lib/ark-os

# Platform-specific control Depends. EXTRA_DEPENDS is a suffix inserted after
# libmavsdk-dev. PYTHON_PKG (the system python the bundled venv binds to) and
# CODENAME come from build.sh, which resolves them from the build host's release.
# NOTE: the base Depends in DEBIAN/control use bookworm/jammy package names; revisit
# them per release when adding one (e.g. Debian 13/trixie renamed several libs *t64).
case "$P" in
    jetson) EXTRA_DEPENDS=", bluez, bluez-tools, libbluetooth3, libqmi-utils" ;;
    pi)     EXTRA_DEPENDS=", gstreamer1.0-libcamera, raspi-utils" ;;
esac

# --- directory skeleton ---
mkdir -p "$PKG/DEBIAN"
mkdir -p "$PKG/lib/systemd/system"
mkdir -p "$PKG$ARK/bin" "$PKG$ARK/scripts" "$PKG$ARK/python" "$PKG$ARK/manifests"
mkdir -p "$PKG/etc/ark-os"
mkdir -p "$PKG/etc/nginx/sites-available"
mkdir -p "$PKG/etc/polkit-1/rules.d"
mkdir -p "$PKG/etc/polkit-1/localauthority/90-mandatory.d"
mkdir -p "$PKG/etc/systemd/journald.conf.d"
mkdir -p "$PKG/etc/sudoers.d"

# --- systemd units (platform set) + group target ---
install -m 0644 packaging/service-files/ark-os.target "$PKG/lib/systemd/system/ark-os.target"
install -m 0644 packaging/service-files/ark-os-firstboot.service "$PKG/lib/systemd/system/ark-os-firstboot.service"
for f in packaging/service-files/"$P"/*.service; do
    install -m 0644 "$f" "$PKG/lib/systemd/system/$(basename "$f")"
done

# --- start scripts for always-present services ---
install -m 0755 services/mavlink-router/start_mavlink_router.sh   "$PKG$ARK/scripts/"
install -m 0755 services/dds-agent/start_dds_agent.sh             "$PKG$ARK/scripts/"
install -m 0755 services/flight-review/start_flight_review.sh     "$PKG$ARK/scripts/"
install -m 0755 services/hotspot-updater/update_hotspot_default.sh "$PKG$ARK/scripts/"
if [ "$P" = "jetson" ]; then
    install -m 0755 services/jetson-can/start_can_interface.sh "$PKG$ARK/scripts/"
    install -m 0755 services/jetson-can/stop_can_interface.sh  "$PKG$ARK/scripts/"
fi

# --- platform + common utility scripts ---
for f in platform/"$P"/scripts/* platform/common/scripts/*; do
    [ -f "$f" ] && install -m 0755 "$f" "$PKG$ARK/scripts/$(basename "$f")"
done

# --- operator scripts on PATH: a profile.d snippet adds $ARK/scripts to PATH for
# login shells. The scripts carry #!/usr/lib/ark-os/venv/bin/python3, so they run
# under the bundled venv with nothing to activate -- operators run them by name.
mkdir -p "$PKG/etc/profile.d"
install -m 0644 packaging/system-config/ark-os-path.sh "$PKG/etc/profile.d/ark-os.sh"

# --- first-boot finalization script (tokens substituted like the postinst). Runs the
# runtime-only steps that can't happen in the build chroot; see ark-os-firstboot.service. ---
sed -e "s/@ARK_USER@/$ARK_USER/g" -e "s/@PLATFORM@/$PLATFORM/g" \
    packaging/system-config/ark_os_firstboot.sh > "$PKG$ARK/scripts/ark_os_firstboot.sh"
chmod 0755 "$PKG$ARK/scripts/ark_os_firstboot.sh"

# --- python services ---
for svc in autopilot_manager connection_manager service_manager system_manager; do
    dir=$(echo "$svc" | tr '_' '-')
    install -m 0644 "services/$dir/$svc.py" "$PKG$ARK/python/$svc.py"
done

# --- manifests: install one per service unit that exists on this platform ---
for f in services/*/*.manifest.json; do
    svc=$(basename "$f" .manifest.json)
    if [ -f "packaging/service-files/$P/$svc.service" ]; then
        install -m 0644 "$f" "$PKG$ARK/manifests/$svc.manifest.json"
    fi
done

# --- flight-review app (verbatim submodule copy) ---
mkdir -p "$PKG$ARK/flight-review"
cp -r services/flight-review/flight_review/app "$PKG$ARK/flight-review/"

# --- default configs -> /etc/ark-os ---
install -m 0644 services/mavlink-router/main.conf "$PKG/etc/ark-os/mavlink-router.conf"
for f in packaging/config/*; do
    base=$(basename "$f")
    # rid-transmitter is jetson-only; skip its config on pi.
    [ "$P" = "pi" ] && [ "$base" = "rid-transmitter.toml" ] && continue
    install -m 0644 "$f" "$PKG/etc/ark-os/$base"
done

# --- nginx site ---
install -m 0644 frontend/ark-ui.nginx "$PKG/etc/nginx/sites-available/ark-ui"

# --- sudoers (renamed, 0440) ---
install -m 0440 platform/common/ark_scripts.sudoers "$PKG/etc/sudoers.d/ark-os"

# --- NetworkManager polkit rule + pkla (renamed) ---
install -m 0644 platform/common/wifi/02-network-manager.rules \
    "$PKG/etc/polkit-1/rules.d/02-ark-network-manager.rules"
install -m 0644 platform/common/wifi/99-network.pkla \
    "$PKG/etc/polkit-1/localauthority/90-mandatory.d/99-ark-network.pkla"

# --- service-manager polkit rule: substitute @ARK_USER@; pi strips JETSON-ONLY ---
SMR="$PKG/etc/polkit-1/rules.d/03-ark-service-manager.rules"
if [ "$P" = "pi" ]; then
    sed "s/@ARK_USER@/$ARK_USER/g" packaging/system-config/03-ark-service-manager.rules \
        | grep -v 'JETSON-ONLY' > "$SMR"
else
    sed "s/@ARK_USER@/$ARK_USER/g" packaging/system-config/03-ark-service-manager.rules > "$SMR"
fi
chmod 0644 "$SMR"

# --- service-manager polkit pkla: the JetPack-6 / Ubuntu 22.04 rootfs runs polkit
# 0.105, which honors .pkla (local authority) and ignores JS .rules; Pi/Bookworm is
# the reverse. Ship both so the grant applies on each. pkla can't scope per-unit, so
# it grants the service user blanket systemd manage rights (same breadth as the
# NetworkManager grant above); the .rules file keeps per-unit scoping where honored.
SMPKLA="$PKG/etc/polkit-1/localauthority/90-mandatory.d/99-ark-service-manager.pkla"
sed "s/@ARK_USER@/$ARK_USER/g" packaging/system-config/99-ark-service-manager.pkla > "$SMPKLA"
chmod 0644 "$SMPKLA"

# --- udev gpio rules (jetson only, renamed) ---
if [ "$P" = "jetson" ]; then
    mkdir -p "$PKG/etc/udev/rules.d"
    install -m 0644 platform/jetson/99-gpio.rules "$PKG/etc/udev/rules.d/99-ark-gpio.rules"
fi

# --- journald drop-in ---
install -m 0644 packaging/system-config/10-ark-os.conf \
    "$PKG/etc/systemd/journald.conf.d/10-ark-os.conf"

# --- ld.so.conf for the private C++ libs (polaris SDK + Micro-XRCE-DDS agent and
# its FastDDS chain) that build_binaries.sh bundles under $ARK/lib. ldconfig in the
# postinst builds the cache so the loader finds them on-device. ---
mkdir -p "$PKG/etc/ld.so.conf.d"
printf '%s\n' "$ARK/lib" > "$PKG/etc/ld.so.conf.d/ark-os.conf"
chmod 0644 "$PKG/etc/ld.so.conf.d/ark-os.conf"

# --- DEBIAN control (token substitution) + maintainer scripts ---
sed -e "s/@PLATFORM@/$PLATFORM/g" \
    -e "s/@CODENAME@/$CODENAME/g" \
    -e "s/@VERSION@/$VERSION/g" \
    -e "s/@PYTHON@/$PYTHON_PKG/g" \
    -e "s|@EXTRA_DEPENDS@|$EXTRA_DEPENDS|g" \
    packaging/DEBIAN/control > "$PKG/DEBIAN/control"
chmod 0644 "$PKG/DEBIAN/control"

sed -e "s/@PLATFORM@/$PLATFORM/g" \
    -e "s/@CODENAME@/$CODENAME/g" \
    packaging/DEBIAN/preinst > "$PKG/DEBIAN/preinst"
chmod 0755 "$PKG/DEBIAN/preinst"

sed -e "s/@ARK_USER@/$ARK_USER/g" \
    -e "s/@PLATFORM@/$PLATFORM/g" \
    packaging/DEBIAN/postinst > "$PKG/DEBIAN/postinst"
chmod 0755 "$PKG/DEBIAN/postinst"

install -m 0755 packaging/DEBIAN/prerm  "$PKG/DEBIAN/prerm"
install -m 0755 packaging/DEBIAN/postrm "$PKG/DEBIAN/postrm"

# --- sanity: confirm the staged payloads from the other build steps are present ---
missing=0
for p in \
    "$PKG$ARK/bin/mavlink-routerd" \
    "$PKG$ARK/bin/node" \
    "$PKG$ARK/venv/bin/python3" \
    "$PKG$ARK/ark-ui-backend/index.js" \
    "$PKG/var/www/ark-ui/html" \
    "$PKG$ARK/flight-review/app/serve.py" \
    "$PKG$ARK/scripts/ark_os_firstboot.sh" \
    "$PKG/lib/systemd/system/ark-os-firstboot.service" \
    "$PKG/DEBIAN/control"; do
    if [ ! -e "$p" ]; then echo "MISSING: $p" >&2; missing=1; fi
done
[ "$missing" -eq 0 ] || { echo "assemble_tree: staging is incomplete (see MISSING above)" >&2; exit 1; }

echo "==> package tree assembled at $PKG"
