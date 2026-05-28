## Summary

Package ARK-OS into `.deb` files (`ark-os-jetson`, `ark-os-pi`) for installation via `apt` or chroot during `ark_jetson_kernel` image builds. Replace the 30-60 min clone-and-compile install with a ~1 min `dpkg -i`.

## Problem

ARK-OS is installed by cloning the repo on-device and running `install.sh`, which compiles 6 C++ submodules from source, installs Python/Node dependencies globally, and configures systemd user services. This is slow, fragile (build failures, network timeouts, apt lock contention), and makes field updates painful (re-clone + re-run). It also cannot be pre-baked into Jetson images because the install script requires a running system (systemd, network, user session).

## Solution

Pre-build everything in CI (ARM64 GitHub runners on Ubuntu 22.04 Jammy to match the JetPack 6 rootfs Python 3.10) and ship `.deb` packages. System-level systemd units with `User=jetson` (or `User=pi` on Pi) replace user-session services for chroot compatibility. Configs move to `/etc/ark-os/` as plain package files (intentionally **not** dpkg conffiles — package updates reset them to current defaults and operators reconfigure via the web UI; see Task 1). On Jetson the package installs cleanly via `dpkg -i` in a chroot during `ark_jetson_kernel --provision` builds (Task 9), and devices boot fully provisioned after flashing. On Pi there is no kernel-repo provisioning step — Pi flow is "flash stock Raspberry Pi OS, then `sudo apt install ./libmavsdk-dev_<ver>_debian12_arm64.deb ./ark-os-pi_<ver>_arm64.deb`" on the running system, where the default `pi` user already exists. Field updates on either platform: download the new `.deb` from the GitHub release and `sudo apt install ./ark-os-<plat>_<ver>_arm64.deb` — there's no apt repo to subscribe to.

---

# Implementation Plan

This plan is structured as ordered tasks for implementation. The `.deb` is the **only** supported install path after this PR — the legacy `install.sh` mechanism and its supporting scripts are removed (Task 10), and the postinst cleans up remnants from any prior source-based install (Task 1, step 0).

## Naming convention

Service unit files and manifests retain their current names — **no `ark-` prefix**. Example: `mavlink-router.service`, `mavlink-router.manifest.json`. Only the package itself is `ark-os-jetson` / `ark-os-pi`.

## Codebase context

The tables and bullets in this section describe **pre-PR state** — the legacy install.sh world that Task 10 dismantles. Use them to understand what's being replaced; they're not the post-merge spec.

### Repository structure

ARK-OS has 14 services, 8 of which have git submodule dependencies. Services are managed by JSON manifest files and installed via `tools/service_control.sh`.

### Git submodules (require `--recurse-submodules` in CI checkout)

| Submodule path | Build system | Binary output |
|---|---|---|
| `services/mavlink-router/mavlink-router` | meson + ninja | `build/src/mavlink-routerd` |
| `services/dds-agent/Micro-XRCE-DDS-Agent` | cmake | `MicroXRCEAgent` |
| `services/logloader/logloader` | make (cmake) | `logloader` |
| `services/rtsp-server/rtsp-server` | make (cmake + GStreamer) | `rtsp-server` |
| `services/polaris/polaris-client-mavlink` | make (cmake) | `polaris-client-mavlink` |
| `services/rid-transmitter/RemoteIDTransmitter` | cmake | `rid-transmitter` |
| `services/flight-review/flight_review` | Python (no compilation) | Python app |
| `libs/mavsdk-examples` | cmake | Example binaries |

### Services overview

All 14 services, showing current install location and config:

| Service | Type | Current binary/script location | Config location | Env gate | Platform |
|---|---|---|---|---|---|
| mavlink-router | C++ (meson) | `~/.local/bin/mavlink-routerd` | `~/.local/share/mavlink-router/main.conf` | always | all |
| dds-agent | C++ (cmake) | `/usr/local/bin/MicroXRCEAgent` | none | `INSTALL_DDS_AGENT` | jetson, pi |
| logloader | C++ (cmake) | `~/.local/bin/logloader` | `~/.local/share/logloader/config.toml` | `INSTALL_LOGLOADER` | jetson, pi |
| rtsp-server | C++ (cmake) | `~/.local/bin/rtsp-server` | `~/.local/share/rtsp-server/config.toml` | `INSTALL_RTSP_SERVER` | all |
| polaris | C++ (cmake) | `~/.local/bin/polaris-client-mavlink` | `~/.local/share/polaris/config.toml` | `INSTALL_POLARIS` | jetson, pi |
| rid-transmitter | C++ (cmake) | `~/.local/bin/rid-transmitter` | `~/.local/share/rid-transmitter/config.toml` | `INSTALL_RID_TRANSMITTER` | jetson |
| flight-review | Python | `~/.local/share/flight_review/app/serve.py` | `~/.local/share/flight_review/app/config_user.ini` | `INSTALL_LOGLOADER` | jetson, pi |
| ark-ui-backend | Node.js | `/var/www/ark-ui/api/` (npm start) | none | always | all |
| autopilot-manager | Python | `~/.local/bin/autopilot_manager.py` | none | always | all |
| connection-manager | Python | `~/.local/bin/connection_manager.py` | none | always | all |
| service-manager | Python | `~/.local/bin/service_manager.py` | none | always | all |
| system-manager | Python | `~/.local/bin/system_manager.py` | none | always | all |
| hotspot-updater | Shell | `/usr/local/bin/update_hotspot_default.sh` | none | always | all |
| jetson-can | Shell | `/usr/local/bin/start_can_interface.sh` | none | always | jetson |

### Current systemd model

- 12 services are **user services** (`~/.config/systemd/user/`, `WantedBy=default.target`, managed via `systemctl --user`)
- 2 services are **system services** (`/etc/systemd/system/`, `WantedBy=multi-user.target`, `requires_sudo: true`): `hotspot-updater` and `jetson-can`
- `service-manager.py` discovers services from `~/.config/systemd/user/`, reads manifests from `~/.local/share/<svc>/`, and calls `systemctl --user` for all control operations
- Service files use `%h` (home dir) specifier for paths: `ExecStart=%h/.local/bin/start_mavlink_router.sh`

### Python dependencies to bundle in venv

**Core (all services):**
```
pymavlink dronecan flask psutil toml eventlet flask-cors flask-socketio python-socketio pyserial
```

`mavsdk` (Python) is **not** included — no ARK-OS Python code imports it. The C++ MAVSDK runtime is installed via its own deb (see Task 6).

**Jetson-specific:**
```
Jetson.GPIO>=2.1.12 smbus2 jetson-stats
```

**Flight Review (`services/flight-review/flight_review/app/requirements.txt`):**
```
bokeh==3.3.2 jinja2 jupyter pyfftw pylint pyulog>=1.1 requests scipy>=1.8.1 simplekml smopy
```

### Existing permission model

- **sudoers** (`platform/common/ark_scripts.sudoers`): `ALL ALL=(ALL) NOPASSWD: /bin/hostnamectl` — used by connection-manager
- **polkit** (`platform/common/wifi/02-network-manager.rules`): allows `netdev` group full NetworkManager control
- **polkit** (`platform/common/wifi/99-network.pkla`): backup NetworkManager authorization for `netdev` group
- **groups**: user added to `dialout`, `gpio`, `i2c`, `netdev`

---

## Task 1: Package control files

Create `packaging/DEBIAN/` with the dpkg control files.

### `packaging/DEBIAN/control`

Template — `VERSION` and `PLATFORM` are substituted by the build script.

```
Package: ark-os-PLATFORM
Version: VERSION
Section: embedded
Priority: optional
Architecture: arm64
Depends: nginx, python3 (>= 3.8), python3-venv, avahi-daemon, libgstreamer1.0-0, libgstreamer-plugins-base1.0-0, libgstrtspserver-1.0-0, gstreamer1.0-plugins-ugly, gstreamer1.0-tools, gstreamer1.0-gl, gstreamer1.0-rtsp, libssl3, libsqlite3-0, libcap2-bin, curl, jq, systemd, network-manager, libmavsdk-dev (>= 3.0)
Maintainer: ARK Electronics <info@arkelectron.com>
Description: ARK-OS companion computer platform
 Pre-compiled services, web UI, and system configuration for autonomous vehicles.
```

Jetson adds to Depends: `bluez, bluez-tools, libbluetooth3, libqmi-utils` (`libqmi-utils` is needed for ARK LTE firmware updates). Pi adds: `gstreamer1.0-libcamera`. (RPi.GPIO is pip-installed into the venv on Pi — see Task 6 `build_venv.sh` — not shipped as the apt `python3-rpi.gpio`, because the venv is built without system-site-packages so the venv interpreter that runs the platform scripts can't see apt-installed modules. Its C extension binds to `/dev/gpiomem` at runtime, not build time, so a generic-arm64 wheel built in CI works on the Pi.)

MAVSDK has no public apt repo. The upstream package name is `libmavsdk-dev` (confirmed via `dpkg-deb -f` on the upstream asset — not `mavsdk`) and the closest arm64 build for the JetPack 6 Jammy rootfs is `libmavsdk-dev_<ver>_debian12_arm64.deb` — upstream does not publish an `ubuntu22.04_arm64` asset, so the debian12 variant is canonical here (the legacy `tools/install_mavsdk.sh` already uses this asset on Jammy, so glibc compatibility is proven in practice). The deb is downloaded from `github.com/mavlink/MAVSDK/releases` at install time: chroot installs fetch it during `provision.sh` (Task 9) before installing the ARK-OS deb, and field updates use the same upstream download. `Depends: libmavsdk-dev (>= 3.0)` gives correctness validation — `dpkg -i ark-os-jetson.deb` fails loudly if MAVSDK isn't already installed. Pin the same MAVSDK version in `packaging/build.sh` (used during CI for linking `libs/mavsdk-examples`) and in `ark_jetson_kernel/provision.sh`; bump both together when upgrading.

### `packaging/DEBIAN/conffiles` — intentionally omitted

**ARK-OS ships no dpkg conffiles.** Every file the package installs under `/etc/` (the per-service configs in `/etc/ark-os/`, the nginx site, the polkit/sudoers/udev files, the journald snippet) is a plain package file. dpkg overwrites plain files with the packaged version on every upgrade, **discarding any local edits**. This is deliberate: a release may add or remove settings, so each upgrade resets configuration to the current upstream defaults and the operator reconfigures via the web UI. Treating them as conffiles would instead preserve stale local copies (and prompt on changed files), which we explicitly do not want.

Consequences the rest of the plan relies on:
- The web UI (`service-manager.py`) writes the per-service configs at runtime; those writes survive until the next package upgrade, then revert to defaults. Call this out in the release notes ("upgrading resets service configuration").
- `start_mavlink_router.sh` re-detects the autopilot device path and re-`sed`s `/etc/ark-os/mavlink-router.conf` on each boot, so an upgrade that resets that file is self-healing — the device path is re-applied on the next boot with no conffile prompt.
- `lintian` will emit `file-in-etc-not-marked-as-conffile` for these paths. That warning is expected and acceptable (the `build.sh` lintian step is already non-fatal).

### `packaging/DEBIAN/postinst`

Post-install script. Key requirements:
- Hardcode `ARK_USER="jetson"` (or `"pi"` for Pi package) — no runtime platform detection, which is critical because `/proc/device-tree/model` reflects the build host in chroot, not the target. Pi package assumes the default `pi` user exists (document this in the package description for the Pi platform).
- All filesystem operations (group creation, user modification, symlinks, `systemctl enable`) work in chroot
- Guard runtime operations (`systemctl start/restart`, `udevadm trigger`, `nginx -t`, hotspot creation, flight-review DB init) behind `[ -d /run/systemd/system ]` — this is the standard mechanism and the sole guard since `ark_jetson_kernel` does not install a `policy-rc.d`. Note: in the `ark_jetson_kernel` chroot, `/dev` is bind-mounted from host but `/run` is not, so `[ -d /run/systemd/system ]` is correctly false.

Operations in order:

**0. Legacy cleanup** — runs first to remove remnants of any pre-deb install. Idempotent; on a clean chroot or first install everything is a no-op. The block is structured as:

```sh
ARK_HOME=$(getent passwd "$ARK_USER" | cut -d: -f6)
UID_VAL=$(id -u "$ARK_USER" 2>/dev/null || true)

# (a) Backup legacy configs (only the first time, so re-install doesn't clobber the backup)
LEGACY_BACKUP="$ARK_HOME/.config/ark-os-legacy-backup"
if [ -d "$ARK_HOME/.local/share/mavlink-router" ] && [ ! -d "$LEGACY_BACKUP" ]; then
    mkdir -p "$LEGACY_BACKUP"
    for d in mavlink-router logloader polaris rtsp-server rid-transmitter flight_review; do
        [ -d "$ARK_HOME/.local/share/$d" ] && cp -r "$ARK_HOME/.local/share/$d" "$LEGACY_BACKUP/" 2>/dev/null || true
    done
    chown -R "$ARK_USER:$ARK_USER" "$LEGACY_BACKUP"
    echo "Legacy configs backed up to $LEGACY_BACKUP — merge custom edits into /etc/ark-os/ if needed."
fi

# (b) Stop and disable legacy user services (only on running system)
if [ -d /run/systemd/system ] && [ -n "$UID_VAL" ] && [ -d "$ARK_HOME/.config/systemd/user" ]; then
    LEGACY_USER_SERVICES="mavlink-router dds-agent logloader rtsp-server polaris rid-transmitter flight-review ark-ui-backend autopilot-manager connection-manager service-manager system-manager"
    for svc in $LEGACY_USER_SERVICES; do
        sudo -u "$ARK_USER" XDG_RUNTIME_DIR="/run/user/$UID_VAL" systemctl --user stop "$svc.service" 2>/dev/null || true
        sudo -u "$ARK_USER" XDG_RUNTIME_DIR="/run/user/$UID_VAL" systemctl --user disable "$svc.service" 2>/dev/null || true
    done
fi

# (c) Remove legacy user-service unit files
rm -f "$ARK_HOME"/.config/systemd/user/{mavlink-router,dds-agent,logloader,rtsp-server,polaris,rid-transmitter,flight-review,ark-ui-backend,autopilot-manager,connection-manager,service-manager,system-manager}.service

# (d) Remove legacy binaries and scripts from ~/.local/bin
rm -f "$ARK_HOME"/.local/bin/{mavlink-routerd,logloader,rtsp-server,polaris-client-mavlink,rid-transmitter}
rm -f "$ARK_HOME"/.local/bin/{start_mavlink_router.sh,start_dds_agent.sh,start_ark_ui_backend.sh,start_flight_review.sh}
rm -f "$ARK_HOME"/.local/bin/{autopilot_manager.py,connection_manager.py,service_manager.py,system_manager.py}
rm -f "$ARK_HOME"/.local/bin/{vbus_enable.py,vbus_disable.py,get_serial_number.py,reset_fmu_fast.py,reset_fmu_wait_bl.py}
rm -f "$ARK_HOME"/.local/bin/{flash_firmware.sh,mavlink_shell.py,px4_shell_command.py,px_uploader.py,mavlink_ftp_upload.sh}
rm -f "$ARK_HOME"/.local/bin/{pcie_set_speed.sh,self_test.sh,set_mac.sh,create_hotspot_default.sh}
# example/diagnostic scripts the legacy installer copied wholesale from platform/jetson/scripts (now in extras/, Task 10)
rm -f "$ARK_HOME"/.local/bin/{i2s_gpio_example.py,icm42688p_driver.py,ina238_test.py,test_jtop.py}

# (e) Remove legacy data dirs (configs were backed up in step a)
rm -rf "$ARK_HOME"/.local/share/{mavlink-router,logloader,polaris,rtsp-server,rid-transmitter,flight_review}

# (f) Remove legacy /usr/local/bin entries (replaced by /usr/lib/ark-os/{bin,scripts}/)
rm -f /usr/local/bin/{MicroXRCEAgent,update_hotspot_default.sh,start_can_interface.sh,stop_can_interface.sh}

# (g) Remove legacy system unit files (relocated to /lib/systemd/system/ and renamed)
rm -f /etc/systemd/system/{hotspot-updater,jetson-can}.service

# (h) Remove legacy sudoers/polkit/udev files (replaced by ark-os.* / ark-* prefixed versions)
rm -f /etc/sudoers.d/ark_scripts
rm -f /etc/polkit-1/rules.d/02-network-manager.rules
rm -f /etc/polkit-1/localauthority/90-mandatory.d/99-network.pkla
rm -f /etc/udev/rules.d/99-gpio.rules

# (i) Remove NVM install (legacy install bootstrapped Node via nvm; we ship our own)
rm -rf "$ARK_HOME"/.config/nvm

# (j) Remove legacy backend deploy path (moves to /usr/lib/ark-os/ark-ui-backend/)
rm -rf /var/www/ark-ui/api

# (k) Reload daemons to drop unloaded units (runtime only)
if [ -d /run/systemd/system ]; then
    [ -n "$UID_VAL" ] && sudo -u "$ARK_USER" XDG_RUNTIME_DIR="/run/user/$UID_VAL" systemctl --user daemon-reload 2>/dev/null || true
    systemctl daemon-reload
fi
```

The `[ -d /run/systemd/system ]` guard means the systemctl operations are skipped in the `ark_jetson_kernel` chroot (where the rootfs is virgin and there's nothing to clean up anyway). File deletions run unconditionally — `rm -f` is a no-op when the target doesn't exist.

1. `groupadd -f -r gpio` and `usermod -a -G dialout,gpio,i2c,netdev "$ARK_USER"`
2. Create runtime dirs: `/var/lib/ark-os/logs`, `/var/lib/ark-os/flight-review/data` owned by `$ARK_USER`
3. Make `/etc/ark-os/` writable by the service user: `chgrp -R $ARK_USER /etc/ark-os && chmod 2775 /etc/ark-os && chmod 0664 /etc/ark-os/*` — setgid bit on the directory means new files inherit the group. Files stay root-owned but group-writable so `service-manager.py` (running as `$ARK_USER`) can rewrite configs from the web UI. postinst re-applies this ownership/permission on every install and upgrade — the configs are plain package files (not conffiles), so each upgrade unpacks fresh root-owned defaults that this step then re-permissions.
4. Symlink flight-review config into the app tree: `ln -sf /etc/ark-os/flight-review.ini /usr/lib/ark-os/flight-review/app/config_user.ini` — `serve.py` takes no config-file flag, `plot_app/config.py` reads `config_user.ini` from a hardcoded path relative to the script.
5. `systemctl enable` always-on services: `mavlink-router`, `rtsp-server`, `ark-ui-backend`, `autopilot-manager`, `connection-manager`, `service-manager`, `system-manager`, `hotspot-updater`, `jetson-can` (Jetson only), `systemd-time-wait-sync.service` (so time-dependent services don't fire before NTP converges — Jetsons typically have no RTC). Same as the legacy install (`tools/install_software.sh:374`), which has been doing this in the field — `systemd-timesyncd` is the active NTP client on JetPack 6 in practice.
6. Opt-in services are installed but **not** enabled: `dds-agent`, `logloader`, `polaris`, `flight-review`, `rid-transmitter`. Operator turns them on via the web UI or `systemctl enable --now <svc>`. systemd's enabled-state is the single source of truth for what runs — there's no parallel enable/disable config to drift.
7. On Jetson, `systemctl disable nvgetty.service 2>/dev/null || true` (the NVIDIA serial-console daemon holds `/dev/ttyTHS*`, blocking mavlink-router and dds-agent from opening the UART). The corresponding stop runs inside the runtime block (step 11).
8. `setcap 'cap_net_raw,cap_net_admin+eip' /usr/lib/ark-os/bin/rid-transmitter 2>/dev/null || true` (file present only on Jetson; `|| true` covers non-xattr filesystems).
9. Journal directory: `mkdir -p /var/log/journal && chown root:systemd-journal /var/log/journal && chmod 2755 /var/log/journal`. The `[Journal] Storage=persistent` setting ships as a packaged drop-in (`/etc/systemd/journald.conf.d/10-ark-os.conf`, see Task 7), so postinst doesn't write it.
10. Nginx: `ln -sf /etc/nginx/sites-available/ark-ui /etc/nginx/sites-enabled/ark-ui` and `rm -f /etc/nginx/sites-enabled/default`.
11. **Runtime-only block** (inside `if [ -d /run/systemd/system ]`):
    - `systemctl daemon-reload`
    - `systemctl stop nvgetty.service 2>/dev/null || true` (Jetson only — paired with the disable in step 7)
    - Pi only: `nmcli radio wifi on` (legacy installer did this at `install_software.sh:282`; stock Raspberry Pi OS can ship with the radio soft-blocked)
    - `systemctl start ark-os.target` — starts all enabled units in the target (see Task 2)
    - `nginx -t && systemctl reload nginx`
    - `udevadm control --reload-rules && udevadm trigger`
    - run `create_hotspot_default.sh` if hotspot NM connection missing
    - init flight-review DB: `[ -f /var/lib/ark-os/flight-review/data/logs.sqlite ] || (cd /usr/lib/ark-os/flight-review/app && sudo -u $ARK_USER /usr/lib/ark-os/venv/bin/python3 setup_db.py)`

**Migration reboot**: when postinst runs on a *running* device that had a legacy source install, the step-0(b) stop/disable of the old `systemctl --user` services only succeeds if that user currently has an active session (a live user bus + `/run/user/$UID`). If the operator isn't logged in, the old user units can't be stopped from postinst (the calls are `|| true`) and a stale `mavlink-routerd` (etc.) may keep holding the UART/UDP ports, conflicting with the new system service until reboot. The unit files are removed regardless, so the conflict never survives a reboot. **End postinst with an `echo` telling the operator to reboot after migrating from a source install, and say so in the README migration note.**

### `packaging/DEBIAN/prerm`

On removal/upgrade, stop all ARK-OS services via the target — one command handles the group:

```bash
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl stop ark-os.target 2>/dev/null || true
fi
```

### `packaging/DEBIAN/postrm`

On purge, clean up:
```bash
#!/bin/sh
set -e
case "$1" in
    purge)
        rm -rf /var/lib/ark-os
        rm -rf /etc/ark-os
        rm -f /etc/nginx/sites-enabled/ark-ui
        rm -f /etc/systemd/journald.conf.d/10-ark-os.conf
        ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
```

---

## Task 2: System service unit files

Create `packaging/service-files/` with all 14 service unit files. All services become system-level units (`/lib/systemd/system/`) with `User=jetson` and `Group=jetson` (or `pi`/`pi`) for unprivileged execution. **Service names retain current naming — no `ark-` prefix.**

The key differences from current user service files:
- `WantedBy=multi-user.target ark-os.target` — `multi-user.target` for boot autostart, `ark-os.target` for grouping (enables bulk start/stop; see Task 5 #1 for why discovery uses manifest globbing instead)
- Absolute paths instead of `%h` specifier
- `User=jetson` and `Group=jetson` directives
- Binaries at `/usr/lib/ark-os/bin/`, scripts at `/usr/lib/ark-os/scripts/`
- Python services use `/usr/lib/ark-os/venv/bin/python3`
- Config at `/etc/ark-os/`

**All other `[Service]` directives are preserved verbatim from the current `services/<svc>/<svc>.service` files** — `Type=`, `Restart=`, `RestartSec=`, `KillMode=`, `Environment=`, `LimitNOFILE=`, etc. The per-service breakdown below highlights only the additions and the path/User changes; treat the current unit file as the source for everything else (notably `Restart=on-failure` / `Restart=always` + `RestartSec=5` on most services, `Type=exec` on mavlink-router, and `KillMode=process` on hotspot-updater / jetson-can). Once Task 2 is implemented, diff `packaging/service-files/jetson/<svc>.service` against the legacy `services/<svc>/<svc>.service` (which Task 10 deletes) and confirm only the path/User/WantedBy/`%h`→absolute differences remain.

Create service files for both platforms under `packaging/service-files/jetson/` and `packaging/service-files/pi/`. The only differences between platforms are `User=`/`Group=` values and which services exist (rid-transmitter and jetson-can are Jetson-only).

### `ark-os.target` — Group target

Create `packaging/service-files/ark-os.target`:

```ini
[Unit]
Description=ARK-OS service group
Documentation=https://github.com/ARK-Electronics/ARK-OS

[Install]
WantedBy=multi-user.target
```

Every ARK-OS service unit declares `WantedBy=ark-os.target` in its `[Install]` section. This gives:

- **Bulk control of the enabled set**: `systemctl stop ark-os.target` stops every currently-enabled ARK-OS service in one command (used in `prerm` above).
- **Self-documenting membership**: each unit declares its own membership; adding a new service auto-registers it for bulk control.

`systemctl list-dependencies ark-os.target` is NOT used for service-manager discovery — that approach only surfaces enabled units pulled into the target by their `WantedBy` symlink, so the five opt-in (installed-but-disabled) services would be invisible. service-manager instead globs `/usr/lib/ark-os/manifests/*.manifest.json` to enumerate all installed ARK-OS services regardless of enabled state (see Task 5 #1). The polkit rule (Task 5) and the manifest directory are the two explicit lists; everything else derives from them or from systemd's enabled-state.

### Service file details

**mavlink-router.service**
- `ExecStart=/usr/lib/ark-os/scripts/start_mavlink_router.sh`
- `After=network-online.target`

**dds-agent.service**
- `ExecStart=/usr/lib/ark-os/scripts/start_dds_agent.sh`
- `After=dev-ttyTHS1.device dev-ttyAMA4.device network-online.target` (Jetson uses ttyTHS1, Pi uses ttyAMA4 — the start script handles detection)
- `ExecStartPre=/bin/sleep 2` (wait for UART device)

**logloader.service**
- `ExecStart=/usr/lib/ark-os/bin/logloader --config /etc/ark-os/logloader.toml` (config-path arg added to the submodule — see Task 4 "C++ services config paths")
- `After=network.target mavlink-router.service`
- `Environment=SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`
- `Restart=always`, `Nice=10`, `CPUWeight=50`

**rtsp-server.service**
- `ExecStart=/usr/lib/ark-os/bin/rtsp-server --config /etc/ark-os/rtsp-server.toml` (config-path arg added to the submodule — see Task 4)
- `After=network-online.target`

**polaris.service**
- `ExecStart=/usr/lib/ark-os/bin/polaris-client-mavlink --config /etc/ark-os/polaris.toml` (config-path arg added to the submodule — see Task 4)
- `After=network-online.target mavlink-router.service`

**rid-transmitter.service** (Jetson only)
- `ExecStart=/usr/lib/ark-os/bin/rid-transmitter --config /etc/ark-os/rid-transmitter.toml` (config-path arg added to the submodule — see Task 4)
- `After=network-online.target bluetooth.target mavlink-router.service`
- `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` (new directive — the legacy user unit had none; works alongside the `setcap` in postinst step 8)
- Preserve the legacy unit's `ConditionPathIsDirectory=/sys/class/bluetooth` (keeps it from starting on boards with no BT). The legacy unit also has **no** `Restart=` — leave it that way unless you consciously add one.

**flight-review.service**
- `ExecStart=/usr/lib/ark-os/scripts/start_flight_review.sh`
- `After=network-online.target nginx.service`

**ark-ui-backend.service**
- `WorkingDirectory=/usr/lib/ark-os/ark-ui-backend`
- `ExecStart=/usr/lib/ark-os/bin/node /usr/lib/ark-os/ark-ui-backend/index.js`
- `After=network-online.target nginx.service`
- `Environment=NODE_ENV=production`
- `Environment=PATH=/usr/lib/ark-os/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`
- Replaces the legacy `start_ark_ui_backend.sh` which sourced nvm to invoke `npm start`. The new unit invokes the bundled Node 20 binary at `/usr/lib/ark-os/bin/node` directly (matching `backend/package.json`'s `start` script, which is literally `node index.js`); nvm is no longer involved.

**autopilot-manager.service**
- `ExecStart=/usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/python/autopilot_manager.py`
- `After=network-online.target`
- `Environment=PYTHONUNBUFFERED=1`

**connection-manager.service**
- `ExecStart=/usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/python/connection_manager.py`
- `After=network-online.target NetworkManager.service`
- `Environment=PYTHONUNBUFFERED=1`
- Drop the legacy unit's `ModemManager.service` from **both** `After=` and `Wants=` (the "preserve verbatim" rule would otherwise carry the `Wants=` over). Pi has no modem. *(Jetson note: ARK LTE uses ModemManager — if Jetson field testing shows connection-manager racing ModemManager, re-add `ModemManager.service` to `After=`/`Wants=` in the Jetson unit only.)*

**service-manager.service**
- `ExecStart=/usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/python/service_manager.py`
- `After=network-online.target`
- `Environment=PYTHONUNBUFFERED=1`

**system-manager.service**
- `ExecStart=/usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/python/system_manager.py`
- `After=network-online.target`
- `Environment=PYTHONUNBUFFERED=1`

**hotspot-updater.service**
- `ExecStart=/usr/lib/ark-os/scripts/update_hotspot_default.sh`
- `After=network-online.target NetworkManager.service`
- Runs as **root** (no `User=` directive) — needs direct NetworkManager access

**jetson-can.service** (Jetson only)
- `ExecStart=/usr/lib/ark-os/scripts/start_can_interface.sh`
- `After=network-online.target`
- Runs as **root** (no `User=` directive) — needs `modprobe` and `ip link`

---

## Task 3: Modified start scripts for FHS paths

Edit the start scripts **in place** at `services/<svc>/start_<svc>.sh` and `platform/<plat>/scripts/` to use FHS paths. The legacy install is gone (Task 10), so there's no need for two copies — `assemble_tree.sh` copies these into the deb tree at build time.

### Path mapping (old → new)

| Old path | New path |
|---|---|
| `~/.local/bin/<binary>` | `/usr/lib/ark-os/bin/<binary>` |
| `~/.local/bin/<script>.sh` | `/usr/lib/ark-os/scripts/<script>.sh` |
| `~/.local/bin/<script>.py` | `/usr/lib/ark-os/scripts/<script>.py` |
| `~/.local/share/<svc>/config.toml` | `/etc/ark-os/<svc>.toml` |
| `~/.local/share/mavlink-router/main.conf` | `/etc/ark-os/mavlink-router.conf` |
| `~/.local/share/flight_review/app/` | `/usr/lib/ark-os/flight-review/app/` |
| `~/.config/nvm/` | not used — system Node.js binary bundled |
| `python3` | `/usr/lib/ark-os/venv/bin/python3` |

### Files to edit in place

**`services/mavlink-router/start_mavlink_router.sh`**:
- Config var → `/etc/ark-os/mavlink-router.conf`
- Binary → `/usr/lib/ark-os/bin/mavlink-routerd`
- vbus_enable → `/usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/scripts/vbus_enable.py`

**`services/dds-agent/start_dds_agent.sh`**:
- `MicroXRCEAgent` invocation → `/usr/lib/ark-os/bin/MicroXRCEAgent`
- Platform detection logic stays unchanged (reads kernel info)

**`services/flight-review/start_flight_review.sh`**:
- `python3` → `/usr/lib/ark-os/venv/bin/python3`
- App path → `/usr/lib/ark-os/flight-review/app/serve.py`

**`services/jetson-can/start_can_interface.sh`** and **`stop_can_interface.sh`**: no path changes (uses system `modprobe`, `ip`).

**`services/hotspot-updater/update_hotspot_default.sh`**: no path changes (uses system `nmcli`, `hostname`).

**`platform/common/scripts/create_hotspot_default.sh`**: no path changes.

There is no `start_ark_ui_backend.sh` — the ark-ui-backend service runs `node index.js` directly (see Task 2 unit file). Delete the existing `services/ark-ui-backend/start_ark_ui_backend.sh` as part of Task 10 since it sources NVM and is obsolete.

### Platform utility scripts — edit in place

Under `platform/jetson/scripts/`, `platform/pi/scripts/`, and `platform/common/scripts/`:

- `vbus_enable.py`, `vbus_disable.py`, `get_serial_number.py`, `reset_fmu_fast.py`, `reset_fmu_wait_bl.py`
- `flash_firmware.sh`, `mavlink_shell.py`, `px4_shell_command.py`, `px_uploader.py`, `mavlink_ftp_upload.sh`
- `pcie_set_speed.sh`, `self_test.sh`, `set_mac.sh` (Jetson only)

For each Python file, rewrite the shebang to `#!/usr/lib/ark-os/venv/bin/python3` in place. `assemble_tree.sh` copies all of these into `/usr/lib/ark-os/scripts/` at build time.

---

## Task 4: Default config files

Create `packaging/config/` with default configuration files that get installed to `/etc/ark-os/`. The `mavlink-router.conf` source stays at its existing location `services/mavlink-router/main.conf` (edit in place if needed) — `assemble_tree.sh` copies it to `/etc/ark-os/mavlink-router.conf`. The rest live under `packaging/config/` so the shipped defaults are decoupled from the submodules' internal `config.toml` and have an editable home in our tree.

### No master `ark-os.conf`

There is **no** `ark-os.conf`. Per-service settings (logloader `email`/`upload_enabled`/`public_logs`, rid `manufacturer_code`/`serial_number`, polaris `api_key`) live only in that service's own config at `/etc/ark-os/<svc>.toml` — the same file the binary reads (see "C++ services config paths" below) and the file the web UI edits (Task 5). A separate master config would just duplicate those keys with nothing to consume it.

First-time configuration of an opt-in service is therefore: the `/etc/ark-os/<svc>.toml` ships with empty/placeholder values; the operator fills them in via the web UI (or by editing the file directly), then enables the service. There is no install-time prompt — the legacy `USER_EMAIL`/`POLARIS_API_KEY`/`MANUFACTURER_CODE`/`SERIAL_NUMBER` flow is replaced entirely by the web UI.

Service enable/disable is not stored in any config file either — systemd's enabled-state is the single source of truth, so there's no parallel knob for the UI to drift against.

### `services/mavlink-router/main.conf` → `/etc/ark-os/mavlink-router.conf`

The hub config (UART endpoint + UDP endpoints, ports 14550-14571). Edit in place if you need to change defaults; no FHS-path rewrites are required since the file references `/dev/serial/by-id/` device paths.

**Upgrade behavior**: `start_mavlink_router.sh` writes this file in place via `sed` on first boot (and on any boot where the auto-detected device path differs from the recorded one). Because it is a plain package file, not a conffile (see Task 1), an apt upgrade overwrites it with the packaged default — no prompt, no stall in any context (chroot install, `unattended-upgrades`, or an interactive shell). That's fine: the start script re-detects the device path and re-`sed`s it on the next boot, so the only thing "lost" on upgrade is a custom endpoint set, which is the intended reset-to-defaults behavior. If a future release needs to *preserve* operator endpoint edits across upgrades, that's a deliberate design change (move the editable copy out of the package payload), not the default here.

### `packaging/config/{logloader,polaris,rtsp-server,rid-transmitter}.toml`

Copy from each submodule's `config.toml` default (e.g., `services/logloader/logloader/config.toml`) into `packaging/config/<svc>.toml` so the deployed default is a stable copy in our tree. No path changes inside the configs — they contain connection URLs, API keys, and streaming parameters only. Ship them with empty/placeholder secrets (the operator fills them via the web UI).

### C++ services: read config from `/etc/ark-os/` (submodule source edits)

The four compiled services read their config from a **hardcoded `$HOME/.local/share/<svc>/config.toml`** path baked into their C++ source (`getenv("HOME") + "/.local/share/<svc>/config.toml"`):

| Submodule | Source line | logloader also |
|---|---|---|
| `services/logloader/logloader` | `src/main.cpp:21` | stages downloaded ulogs to `getenv("HOME") + "/.local/share/logloader/"` (`src/main.cpp:38`) |
| `services/rtsp-server/rtsp-server` | `src/main.cpp:24` | — |
| `services/polaris/polaris-client-mavlink` | `src/main.cpp:22` | — |
| `services/rid-transmitter/RemoteIDTransmitter` | `src/main.cpp:23` | — |

A `User=jetson` system service has `HOME=/home/jetson`, so without a change each binary would look in `/home/jetson/.local/share/<svc>/config.toml` — which the deb does not create (it installs `/etc/ark-os/<svc>.toml`) and which postinst step 0(e) deletes. logloader's read is fatal (`return -1` on a missing/unparsable file); rtsp/polaris/rid fall back to compiled defaults. The web UI (Task 5) reads/writes `/etc/ark-os/<svc>.toml`, so unless the binary reads the same file, the UI and the running service would edit different files.

**These submodules are owned by the ARK-Electronics org — edit them.** In each, add a `--config <path>` command-line argument and have the systemd unit pass `--config /etc/ark-os/<svc>.toml` (per Task 2). A `--config` flag is preferred over hardcoding `/etc/ark-os/...` because it keeps the binary path-agnostic and testable; keep the current `$HOME/...` value as the fallback default so dev-machine behavior is unchanged. For logloader, also make the log-staging directory (`application_directory`, `src/main.cpp:38`) configurable (a config key or second flag) and point it at `/var/lib/ark-os/logs`. These are small, mechanical source changes — land them as PRs in the four submodule repos and bump the submodule pointers in this repo as part of this work. Once done, the `/etc/ark-os/<svc>.toml` file, the web UI, and the running binary all reference the same path. (mavlink-router already takes its conf path via the `MAVLINK_ROUTERD_CONF_FILE` env var set in its start script, and flight-review via the symlinked `config_user.ini`, so only these four need the source edit.)

### `flight-review.ini`

Based on `services/flight-review/flight_review/app/config_default.ini`. Changes:
- `domain_name` = leave as default. (The start script does **not** override `domain_name` — it only sets `--address`/`--allow-websocket-origin`. `domain_name` is read straight from this ini by `plot_app/config.py`; set it here if a specific value is needed.)
- `storage_path` = `/var/lib/ark-os/flight-review/data`

---

## Task 5: Service manager transition

This is the most significant code change. `service_manager.py` must switch from managing user services (`systemctl --user`) to managing system services (`systemctl`).

### Changes to `service_manager.py`

Edit `services/service-manager/service_manager.py` **in place** (the legacy install path that consumed the user-service version is gone, so there's no need for a separate `packaging/python/` copy). Describe each change by behavior and verify with `grep` — do not rely on line numbers, which drift as the file is edited:

1. **Service discovery**: Replace the `~/.config/systemd/user/` directory scan with a glob over `/usr/lib/ark-os/manifests/*.manifest.json`. Each `<svc>.manifest.json` corresponds to `<svc>.service` (filename-based mapping). Manifest-based discovery surfaces installed-but-disabled opt-in services (`dds-agent`, `logloader`, `polaris`, `flight-review`, `rid-transmitter`), which a `systemctl list-dependencies ark-os.target` approach would miss (that only returns enabled units pulled into the target). The deb is the source of truth for what's installed, so scanning what the deb dropped is the right move.
2. **Manifest location**: Read manifests from `/usr/lib/ark-os/manifests/<svc>.manifest.json` instead of `~/.local/share/<svc>/<svc>.manifest.json`.
3. **Config location**: `os.path.join('/etc/ark-os', configFile)` where `configFile` is read from the manifest. Manifests must also be updated in place at `services/<svc>/<svc>.manifest.json` so `configFile` holds the new filename (e.g., `mavlink-router.conf`, `logloader.toml`) instead of the bare `main.conf` / `config.toml`. The current `flight-review.manifest.json` has an empty `configFile` — set it to `flight-review.ini`.
4. **systemctl commands**: Replace every `systemctl --user` with `systemctl`. Service names are unchanged (no `ark-` prefix).
5. **Journal logs**: Replace `journalctl --user -u <svc>` with `journalctl -u <svc>`.

**Verify the rewrite is complete** — after editing, this must return no matches:
`grep -n 'systemctl --user\|journalctl --user\|\.local\|\.config/systemd' service_manager.py`
(The `\.local`/`\.config/systemd` patterns catch every home-relative path, including the easy-to-miss `~/.local/share` assignment in `get_service_statuses` that the discovery/manifest changes don't otherwise touch.)

The service manager runs as `User=jetson` in its system service unit. The polkit rule (below) grants it permission to manage the specific ARK-OS units.

### New polkit rule for service management

Create `packaging/system-config/03-ark-service-manager.rules`. Covers systemd unit management — `manage-units` (start/stop/restart), `manage-unit-files` (enable/disable), and `reload-daemon` (daemon-reload) — plus `hostname1` so connection-manager/system-manager can set the hostname without an active login session (see "Hostname permissions" below):

```javascript
polkit.addRule(function(action, subject) {
    var ARK_OS_UNITS = [
        "mavlink-router.service",
        "dds-agent.service",
        "logloader.service",
        "rtsp-server.service",
        "polaris.service",
        "rid-transmitter.service",
        "flight-review.service",
        "ark-ui-backend.service",
        "autopilot-manager.service",
        "connection-manager.service",
        "service-manager.service",
        "system-manager.service",
        "hotspot-updater.service",
        "jetson-can.service"
    ];

    if (subject.user != "jetson") { return; }

    if (action.id == "org.freedesktop.systemd1.reload-daemon") {
        return polkit.Result.YES;
    }

    if (action.id == "org.freedesktop.systemd1.manage-units" ||
        action.id == "org.freedesktop.systemd1.manage-unit-files") {
        var unit = action.lookup("unit");
        if (unit && ARK_OS_UNITS.indexOf(unit) !== -1) {
            return polkit.Result.YES;
        }
    }

    // Hostname control for connection-manager / system-manager
    // (no active session as a system service, so it can't authorize interactively)
    if (action.id == "org.freedesktop.hostname1.set-hostname" ||
        action.id == "org.freedesktop.hostname1.set-static-hostname" ||
        action.id == "org.freedesktop.hostname1.set-pretty-hostname") {
        return polkit.Result.YES;
    }
});
```

(Pi package uses the same rule template with `"pi"` instead of `"jetson"` AND the `ARK_OS_UNITS` array drops `rid-transmitter.service` and `jetson-can.service` — those services don't exist on Pi. The `hostname1` branch is unchanged.)

**Hostname permissions**: as `systemctl --user` services the managers ran inside the user's login session, where polkit could authorize `hostnamectl` by active seat. As system services running `User=jetson` there is no active session, so the `hostname1` actions must be granted explicitly — that's the new branch. (connection-manager additionally calls `sudo hostnamectl`, covered by the shipped sudoers; system-manager calls `hostnamectl` directly, which needs this polkit grant. The legacy install shipped only the sudoers entry, never a hostname1 polkit rule — so system-manager's direct hostname path was not actually authorized before; this rule fixes that.)

### Changes to other Python services

Edit in place at `services/<svc>/<svc>.py`. Specific edits required:

**`services/autopilot-manager/autopilot_manager.py`** (verify after editing: `grep -n 'systemctl --user\|~/.local' autopilot_manager.py` returns no matches):
- Lines 389, 401, 418: drop `"--user"` from each `subprocess.run(["systemctl", "--user", ...])` call (is-active, stop, restart respectively).
- Line 441: `subprocess.run(["python3", os.path.expanduser(f"~/.local/bin/{script}")], ...)` → `subprocess.run(["/usr/lib/ark-os/venv/bin/python3", f"/usr/lib/ark-os/scripts/{script}"], ...)`.
- Line ~521 (inside `flash_firmware`): rewrite `os.path.expanduser("~/.local/bin/px_uploader.py")` to `/usr/lib/ark-os/scripts/px_uploader.py`.

**`services/connection-manager/connection_manager.py`**: no code edits required — it calls `nmcli` (authorized by the `netdev`-group polkit `.rules` + `.pkla`, which are group-based and `ResultInactive=yes`, so they work for a sessionless system service) and `sudo hostnamectl` (authorized by the shipped sudoers). No path edits.

**`services/system-manager/system_manager.py`**: no code edits required for paths/systemctl — it calls `vcgencmd`, `hostnamectl`, and reads sysfs/procfs. **But** it sets the hostname via `hostnamectl` *without* sudo (and a fallback that writes `/etc/hostname` + runs the `hostname` command, both needing root). As a `User=jetson` system service this only works because of the `hostname1` polkit grant added above; the `/etc/hostname`/`hostname`-command fallbacks still need root and won't run as `jetson` — but they only fire when `hostnamectl` is absent, which isn't the case on the target, so this is acceptable (just don't assume the fallback path works under the service user).

`assemble_tree.sh` copies all four Python service files from `services/<svc>/<svc>.py` into `/usr/lib/ark-os/python/` at build time.

---

## Task 6: Build scripts

Create `packaging/build.sh` as the master build orchestrator, with helper scripts for each build phase.

### `packaging/build.sh` — Master build script

Usage: `./packaging/build.sh <jetson|pi> [--version=X.Y.Z]`

Steps:
1. Parse args, set `PLATFORM` and `VERSION` (default from `git describe --tags`)
2. Set `BUILD_DIR=build/ark-os-$PLATFORM`
3. Call `build_binaries.sh`
4. Call `build_frontend.sh`
5. Call `build_venv.sh`
6. Call `bundle_node.sh`
7. Call `assemble_tree.sh`
8. Run `dpkg-deb --build --root-owner-group "$BUILD_DIR" "ark-os-${PLATFORM}_${VERSION}_arm64.deb"`
9. Run `lintian --no-tag-display-limit "ark-os-${PLATFORM}_${VERSION}_arm64.deb" || true` for sanity reporting (non-fatal)

### `packaging/build_binaries.sh` — Compile all C++ submodules

Must run on arm64 (native compilation on CI runner). Build each submodule:

```bash
# mavlink-router (meson + ninja)
cd services/mavlink-router/mavlink-router
meson setup build --prefix=/usr/lib/ark-os -Dsystemdsystemunitdir=
ninja -C build
# Output: build/src/mavlink-routerd

# Micro-XRCE-DDS-Agent (cmake)
cd services/dds-agent/Micro-XRCE-DDS-Agent
mkdir build && cd build
cmake ..
make -j$(nproc)
# Output: build/MicroXRCEAgent

# logloader (Makefile wraps cmake)
cd services/logloader/logloader
make
# Output: build/logloader

# rtsp-server (Makefile wraps cmake, needs GStreamer dev libs)
cd services/rtsp-server/rtsp-server
make
# Output: build/rtsp-server

# polaris-client-mavlink (Makefile wraps cmake)
cd services/polaris/polaris-client-mavlink
make
# Output: build/polaris-client-mavlink

# rid-transmitter (Makefile wraps cmake, Jetson only, needs libbluetooth-dev)
cd services/rid-transmitter/RemoteIDTransmitter
make
# Output: build/rid-transmitter

# mavsdk-examples (cmake) — needs MAVSDK installed on the runner
cd libs/mavsdk-examples
cmake -B build
cmake --build build -j$(nproc)
# Output: various example binaries
```

Collect all binaries into the staging tree at `/usr/lib/ark-os/bin/` — `mavlink-routerd`, `MicroXRCEAgent`, `logloader`, `rtsp-server`, `polaris-client-mavlink`, `rid-transmitter` (Jetson only), and all `mavsdk-examples` outputs go there.

### `packaging/build_frontend.sh` — Build Vue.js frontend + backend deps

```bash
# Use system Node.js (installed on CI runner) or bundled node
cd frontend/ark-ui/ark-ui
npm install
npm run build
# Output: dist/ directory → /var/www/ark-ui/html/

# Backend deps
cd frontend/ark-ui/backend
npm install --production
# Output: node_modules/ directory → /usr/lib/ark-os/ark-ui-backend/
```

### `packaging/build_venv.sh` — Create Python virtualenv

**Critical**: The venv must be created at its final install path (`/usr/lib/ark-os/venv`) so shebangs and paths are correct. Use `--copies` to avoid symlink issues.

```bash
sudo mkdir -p /usr/lib/ark-os
sudo chown $USER /usr/lib/ark-os
python3 -m venv --copies /usr/lib/ark-os/venv
/usr/lib/ark-os/venv/bin/pip install --upgrade pip
/usr/lib/ark-os/venv/bin/pip install \
    pymavlink dronecan flask psutil toml eventlet \
    flask-cors flask-socketio python-socketio pyserial

# Flight Review deps
/usr/lib/ark-os/venv/bin/pip install -r services/flight-review/flight_review/app/requirements.txt

# Platform-specific GPIO/sensor libs — installed INTO the venv (the venv is built
# with --copies and no system-site-packages, so apt-installed modules are invisible
# to the venv interpreter that runs the platform scripts).
if [ "$PLATFORM" = "jetson" ]; then
    /usr/lib/ark-os/venv/bin/pip install "Jetson.GPIO>=2.1.12" smbus2 jetson-stats
elif [ "$PLATFORM" = "pi" ]; then
    /usr/lib/ark-os/venv/bin/pip install RPi.GPIO
fi

# Move into package tree
mkdir -p "$BUILD_DIR/usr/lib/ark-os"
mv /usr/lib/ark-os/venv "$BUILD_DIR/usr/lib/ark-os/venv"
```

The venv is created at the real target path so all internal paths (shebangs, `pyvenv.cfg`) resolve correctly on the device. The `ubuntu-22.04-arm` runner uses Python 3.10, matching JetPack 6 Jammy.

### `packaging/assemble_tree.sh` — Lay out FHS structure

Assembles all build outputs into the `BUILD_DIR` following the package file layout. Creates the full directory tree, copies files, substitutes `PLATFORM`/`VERSION` in DEBIAN/control, sets file permissions (scripts +x, DEBIAN scripts +x, configs 644, dirs 755).

Source-of-truth for each tree entry (where `assemble_tree.sh` reads from):

| Package path | Source in repo |
|---|---|
| `lib/systemd/system/<svc>.service` | `packaging/service-files/<platform>/<svc>.service` |
| `lib/systemd/system/ark-os.target` | `packaging/service-files/ark-os.target` |
| `usr/lib/ark-os/bin/<binary>` | Compiled outputs from `build_binaries.sh` + `bundle_node.sh` |
| `usr/lib/ark-os/scripts/start_<svc>.sh` | `services/<svc>/start_<svc>.sh` (edited in place per Task 3) |
| `usr/lib/ark-os/scripts/<util>.{sh,py}` | `platform/{jetson,pi,common}/scripts/<util>.{sh,py}` (edited in place per Task 3) |
| `usr/lib/ark-os/python/<svc>.py` | `services/<svc>/<svc>.py` (edited in place per Task 5) |
| `usr/lib/ark-os/manifests/<svc>.manifest.json` | `services/<svc>/<svc>.manifest.json` (edited in place per Task 5) |
| `usr/lib/ark-os/venv/` | Built by `build_venv.sh` |
| `usr/lib/ark-os/flight-review/` | `services/flight-review/flight_review/app/` (submodule, copied verbatim) |
| `usr/lib/ark-os/ark-ui-backend/` | `frontend/ark-ui/backend/` + `node_modules/` from `build_frontend.sh` |
| `var/www/ark-ui/html/` | `frontend/ark-ui/ark-ui/dist/` from `build_frontend.sh` |
| `etc/ark-os/mavlink-router.conf` | `services/mavlink-router/main.conf` |
| `etc/ark-os/<svc>.toml`, `flight-review.ini` | `packaging/config/` |
| `etc/nginx/sites-available/ark-ui` | `frontend/ark-ui.nginx` |
| `etc/sudoers.d/ark-os` | `platform/common/ark_scripts.sudoers` (renamed at install time) |
| `etc/polkit-1/rules.d/02-ark-network-manager.rules` | `platform/common/wifi/02-network-manager.rules` (renamed) |
| `etc/polkit-1/localauthority/90-mandatory.d/99-ark-network.pkla` | `platform/common/wifi/99-network.pkla` (renamed) |
| `etc/polkit-1/rules.d/03-ark-service-manager.rules` | `packaging/system-config/03-ark-service-manager.rules` (new file) |
| `etc/udev/rules.d/99-ark-gpio.rules` | `platform/jetson/99-gpio.rules` (renamed, Jetson only) |
| `etc/systemd/journald.conf.d/10-ark-os.conf` | `packaging/system-config/10-ark-os.conf` (new file) |
| `DEBIAN/{control,postinst,prerm,postrm}` | `packaging/DEBIAN/` (no `conffiles` — see Task 1) |

### `packaging/bundle_node.sh` — Download and extract Node.js binary

Pin **Node 20.20.2** (latest 20.x LTS released 2026-03-24). 20 not 22 because the current frontend was developed against Node 20 (`nvm install 20`); no reason to bump major in a packaging change.

```bash
NODE_VER=20.20.2
NODE_TARBALL=node-v${NODE_VER}-linux-arm64.tar.xz
NODE_URL=https://nodejs.org/dist/v${NODE_VER}/${NODE_TARBALL}
SHASUMS_URL=https://nodejs.org/dist/v${NODE_VER}/SHASUMS256.txt

curl -fsSLO "$NODE_URL"
curl -fsSL "$SHASUMS_URL" | grep "$NODE_TARBALL" | sha256sum -c -
tar -xJf "$NODE_TARBALL"

# Extract into package tree
install -m 0755 "node-v${NODE_VER}-linux-arm64/bin/node" "$BUILD_DIR/usr/lib/ark-os/bin/node"
install -m 0755 "node-v${NODE_VER}-linux-arm64/bin/npm" "$BUILD_DIR/usr/lib/ark-os/bin/npm"
cp -r "node-v${NODE_VER}-linux-arm64/lib/node_modules" "$BUILD_DIR/usr/lib/ark-os/lib/"
```

This avoids depending on NodeSource or NVM and locks the runtime version to a known-good release.

---

## Task 7: System config files

Most system-config files already exist under `platform/` and `frontend/`. `assemble_tree.sh` copies them into the package tree, renaming where needed to namespace under `ark-` / `ark-os.`. Only one new file is added under `packaging/system-config/` (plus the journald snippet).

| Source in repo | Destination in package | Mode |
|---|---|---|
| `frontend/ark-ui.nginx` | `/etc/nginx/sites-available/ark-ui` | 0644 |
| `platform/jetson/99-gpio.rules` | `/etc/udev/rules.d/99-ark-gpio.rules` (Jetson only) | 0644 |
| `platform/common/ark_scripts.sudoers` | `/etc/sudoers.d/ark-os` | 0440 |
| `platform/common/wifi/02-network-manager.rules` | `/etc/polkit-1/rules.d/02-ark-network-manager.rules` | 0644 |
| `platform/common/wifi/99-network.pkla` | `/etc/polkit-1/localauthority/90-mandatory.d/99-ark-network.pkla` | 0644 |
| `packaging/system-config/03-ark-service-manager.rules` (new — systemd unit mgmt + hostname1, see Task 5) | `/etc/polkit-1/rules.d/03-ark-service-manager.rules` | 0644 |
| `packaging/system-config/10-ark-os.conf` (new — journald snippet) | `/etc/systemd/journald.conf.d/10-ark-os.conf` | 0644 |

The `ark-ui.nginx` content needs no changes — it already references `/var/www/ark-ui/html` and proxies to `localhost:3000`/`localhost:5006`.

The journald snippet (`10-ark-os.conf`) contains:
```
[Journal]
Storage=persistent
```

Ownership in postinst:
- `/var/www/ark-ui/html` → `chown -R www-data:www-data` (nginx-served static files)
- `/usr/lib/ark-os/ark-ui-backend` → `chown -R $ARK_USER:$ARK_USER` (read by node running as $ARK_USER)

---

## Task 8: CI pipeline

Create `.github/workflows/build-deb.yml`.

### Trigger

On tag push matching `v*` (e.g., `v1.0.0`).

### Build matrix

```yaml
strategy:
  matrix:
    include:
      - platform: jetson
        runner: ubuntu-22.04-arm
        extra_deps: "libbluetooth-dev"
      - platform: pi
        runner: ubuntu-22.04-arm
        extra_deps: ""
```

`ubuntu-22.04-arm` is required — it provides Python 3.10 which matches the JetPack 6 (L4T r36.4.x) Jammy rootfs. A Noble (24.04) runner would produce a Python 3.12 venv that won't run on the target.

### Job steps

1. `actions/checkout@v4` with `submodules: recursive`
2. Install build dependencies: `cmake, meson, ninja-build, pkg-config, gcc, g++, python3-pip, python3-venv, libssl-dev, libsqlite3-dev, libgstreamer1.0-dev, libgstreamer-plugins-base1.0-dev, libgstrtspserver-1.0-dev, lintian, ${{ matrix.extra_deps }}`
3. Download and install the pinned `libmavsdk-dev_<ver>_debian12_arm64.deb` from `github.com/mavlink/MAVSDK/releases` (needed only at build time to link `libs/mavsdk-examples`). Do **not** re-upload it — `ark_jetson_kernel/provision.sh` (Task 9) and field installs download MAVSDK directly from the upstream release.
4. Install Node.js 20: `actions/setup-node@v4`
5. Extract version from tag: `echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_ENV`
6. Run `./packaging/build.sh ${{ matrix.platform }} --version=${{ env.VERSION }}`
7. Upload the `ark-os-${platform}_${VERSION}_arm64.deb` artifact
8. Create GitHub Release and attach the ARK-OS `.deb` (single file per platform). MAVSDK is **not** rebundled — its canonical source remains the upstream MAVSDK release page.

### Considerations

- ARM64 runners compile natively — no cross-compilation needed
- Python venv must be created at `/usr/lib/ark-os/venv` (the target path) for correct shebangs — the CI script uses `sudo mkdir -p /usr/lib/ark-os` and chowns it, creates the venv there, then moves it into the package tree
- `ubuntu-22.04-arm` provides Python 3.10, matching the JetPack 6 / Jammy target

---

## Task 9: `ark_jetson_kernel` integration (Jetson only)

Pi has no equivalent kernel-repo provisioning flow — ARK-OS for Pi installs on a running stock Raspberry Pi OS image via `sudo apt install ./ark-os-pi_<ver>_arm64.deb` (after first installing the MAVSDK deb the same way). This section covers the Jetson chroot flow only.

Update `provision.sh` in the `ark_jetson_kernel` repo to install the `.deb` during image builds. The current `provision.sh` is a stub of commented examples (verified at `/home/jake/code/ark/ark_jetson_kernel/provision.sh`); nothing else runs that would conflict.

```bash
#!/bin/bash
set -e

ARK_OS_VERSION="1.0.0"
MAVSDK_VERSION="3.17.1"  # pin; bump alongside ARK-OS

ARK_OS_DEB="ark-os-jetson_${ARK_OS_VERSION}_arm64.deb"
# No ubuntu22.04_arm64 build is published upstream; debian12_arm64 is what
# tools/install_mavsdk.sh has historically used on Jammy.
MAVSDK_DEB="libmavsdk-dev_${MAVSDK_VERSION}_debian12_arm64.deb"

ARK_OS_URL="https://github.com/ARK-Electronics/ARK-OS/releases/download/v${ARK_OS_VERSION}/${ARK_OS_DEB}"
MAVSDK_URL="https://github.com/mavlink/MAVSDK/releases/download/v${MAVSDK_VERSION}/${MAVSDK_DEB}"

echo "Downloading MAVSDK and ARK-OS debs..."
sudo wget -q -O "$ROOTFS_DIR/tmp/$MAVSDK_DEB" "$MAVSDK_URL"
sudo wget -q -O "$ROOTFS_DIR/tmp/$ARK_OS_DEB" "$ARK_OS_URL"

# ARK-OS ships no conffiles (Task 1), so chroot/non-interactive installs never
# stall on conffile prompts regardless of dpkg's frontend.
echo "Installing MAVSDK first (ark-os depends on libmavsdk-dev)..."
sudo chroot "$ROOTFS_DIR" apt-get update
sudo chroot "$ROOTFS_DIR" dpkg -i "/tmp/$MAVSDK_DEB" || true
sudo chroot "$ROOTFS_DIR" apt-get install -f -y

echo "Installing ark-os-jetson..."
sudo chroot "$ROOTFS_DIR" dpkg -i "/tmp/$ARK_OS_DEB" || true
sudo chroot "$ROOTFS_DIR" apt-get install -f -y

sudo rm "$ROOTFS_DIR/tmp/$MAVSDK_DEB" "$ROOTFS_DIR/tmp/$ARK_OS_DEB"
```

MAVSDK installs first because ARK-OS declares `Depends: libmavsdk-dev (>= 3.0)` — `dpkg -i ark-os` would fail without it, and `apt-get install -f` can't resolve `libmavsdk-dev` since it's not in any apt repo.

This works because `build.sh` already (verified against current `ark_jetson_kernel/build.sh`):
- Registers `qemu-aarch64` binfmt handler (lines 177-181)
- Bind-mounts `/proc`, `/sys`, `/dev`, `/dev/pts` into the rootfs (lines 214-217)
- Copies `/etc/resolv.conf` for DNS (line 218)
- Creates the `jetson` user via `l4t_create_default_user.sh` (lines 189-190) before invoking `provision.sh` (line ~200)
- Does **not** install a `policy-rc.d` and does **not** bind-mount `/run` — so `[ -d /run/systemd/system ]` is correctly false inside the chroot, gating runtime-only operations in postinst (Task 1)

Both versions are hardcoded — update manually when bumping ARK-OS or MAVSDK.

**Out of scope for the deb**: the legacy installer ran `apt-mark hold` on the L4T kernel/firmware packages (`install_software.sh:231`) to stop an `apt upgrade` from breaking Wi-Fi/drivers. That is an **image-layer responsibility** — `ark_jetson_kernel` owns the kernel/BSP and should set those holds during image build. The ARK-OS deb deliberately does not touch apt pins.

---

## Task 10: Remove legacy install mechanism

Delete the source-based install path from the repo. After this PR, the `.deb` is the only supported way to install ARK-OS — operators who previously ran `install.sh` get migrated by the postinst legacy-cleanup block (Task 1, step 0).

### Files to delete from the repo

```
install.sh                              # Top-level legacy installer entry point
default.env                             # Legacy install env config
all_submodules_main.sh                  # Submodule sync helper used only by the legacy path
tools/install_software.sh               # Main legacy installer
tools/install_mavsdk.sh                 # MAVSDK now downloaded by ark_jetson_kernel/provision.sh (Task 9)
tools/install_mavsdk_examples.sh        # Now part of build_binaries.sh
tools/service_control.sh                # Replaced by dpkg + systemctl
tools/functions.sh                      # Helper for the deleted scripts above

services/ark-ui-backend/ark-ui-backend.service
services/autopilot-manager/autopilot-manager.service
services/connection-manager/connection-manager.service
services/dds-agent/dds-agent.service
services/flight-review/flight-review.service
services/hotspot-updater/hotspot-updater.service
services/jetson-can/jetson-can.service
services/logloader/logloader.service
services/mavlink-router/mavlink-router.service
services/polaris/polaris.service
services/rid-transmitter/rid-transmitter.service
services/rtsp-server/rtsp-server.service
services/service-manager/service-manager.service
services/system-manager/system-manager.service
```

The per-service `<svc>.service` files were user-session units (`%h/.local/bin/...`, `WantedBy=default.target`). They're fully replaced by `packaging/service-files/{jetson,pi}/<svc>.service`. Leaving them would only confuse future readers.

After these deletions, `tools/` is empty — remove the directory itself.

**Move (not delete) — standalone dev-machine helpers, no longer part of the install path:**

- `tools/install_opencv.sh` → `extras/install_opencv.sh`
- `tools/install_ros2.sh` → `extras/install_ros2.sh`
- `platform/jetson/scripts/i2s_gpio_example.py` → `extras/i2s_gpio_example.py`
- `platform/jetson/scripts/icm42688p_driver.py` → `extras/icm42688p_driver.py`
- `platform/jetson/scripts/ina238_test.py` → `extras/ina238_test.py`
- `platform/jetson/scripts/test_jtop.py` → `extras/test_jtop.py`

The four `platform/jetson/scripts/` files are example/diagnostic tools the legacy installer copied wholesale into `~/.local/bin`, but no service uses them. They are not packaged into the deb (Task 3 only carries forward the scripts services actually call), and the postinst legacy-cleanup step 0(d) removes any stale copies from a prior install. Add `extras/README.md` explaining that nothing in `extras/` is invoked by the deb build or install — they're convenience scripts for a dev workstation (OpenCV/ROS2 installs, plus the Jetson sensor/GPIO examples). Kept around because they encode non-trivial Jetson-specific build flags / register maps that would be expensive to rediscover.

Keep (and edit in place — these are the canonical sources `assemble_tree.sh` reads from):

- `services/<svc>/start_<svc>.sh` — start scripts, edited per Task 3 to use FHS paths. Exception: `services/ark-ui-backend/start_ark_ui_backend.sh` is deleted (the new service runs `node index.js` directly).
- `services/<svc>/<svc>.py` — Python services (autopilot-manager, connection-manager, service-manager, system-manager), edited per Task 5.
- `services/<svc>/<svc>.manifest.json` — edited per Task 5 (update `configFile` field to new filename).
- `services/mavlink-router/main.conf` — copied to `/etc/ark-os/mavlink-router.conf` at install time.
- `platform/<plat>/scripts/*.{sh,py}` — utility scripts, edited per Task 3 (shebang rewrites for Python files).
- `platform/jetson/99-gpio.rules`, `platform/common/ark_scripts.sudoers`, `platform/common/wifi/*` — copied (and renamed) into the package by `assemble_tree.sh`.
- `frontend/ark-ui.nginx` — copied verbatim to `/etc/nginx/sites-available/ark-ui` by `assemble_tree.sh` (Task 7).
- `frontend/ark-ui/ark-ui/` (Vue source) and `frontend/ark-ui/backend/` (Node source) — built by `build_frontend.sh` (Task 6). Outputs go into the deb tree; sources stay in the repo for development.
- Submodules under `services/<svc>/<svc>/` — untouched, built by `build_binaries.sh`.

Also delete from the repo: `services/ark-ui-backend/start_ark_ui_backend.sh` (NVM-based start script, obsolete — backend now runs `node index.js` directly from a system service unit).

### `README.md` update

Replace the source-install instructions with the `.deb` install path. MAVSDK lives on the upstream `github.com/mavlink/MAVSDK/releases` page (no apt repo); ARK-OS lives on the ARK-OS release page:

```
# 1. Download both debs (replace <mavsdk-ver> and <ark-os-ver> with current pins)
wget https://github.com/mavlink/MAVSDK/releases/download/v<mavsdk-ver>/libmavsdk-dev_<mavsdk-ver>_debian12_arm64.deb
wget https://github.com/ARK-Electronics/ARK-OS/releases/download/v<ark-os-ver>/ark-os-jetson_<ark-os-ver>_arm64.deb

# 2. Install MAVSDK first (ark-os Depends on it)
sudo apt install ./libmavsdk-dev_<mavsdk-ver>_debian12_arm64.deb
sudo apt install ./ark-os-jetson_<ark-os-ver>_arm64.deb
```

Pi flow is identical, replacing `ark-os-jetson` with `ark-os-pi`. ARK-OS ships no conffiles (Task 1), so upgrades never prompt — but they **reset `/etc/ark-os/` configs to packaged defaults**. The README must state that (a) upgrading resets service configuration (reconfigure via the web UI), and (b) **migrating from a legacy source install requires a reboot** (Task 1, step 0 / runtime block).

Plus a one-line note for Jetson image bakers: "For chroot install during `ark_jetson_kernel --provision`, see `packaging/PLAN.md` Task 9."

Drop the README sections covering `default.env`, `user.env`, the per-component `INSTALL_*=y` env vars, and the manual submodule sync — none of those exist after this PR.

---

## Verification checklist

1. **Build locally on ARM64**: Run `./packaging/build.sh jetson` on a Jetson, verify it produces a valid `.deb`
2. **Install on clean system**: `sudo dpkg -i ark-os-jetson.deb && sudo apt-get install -f -y`, verify all enabled services start (`systemctl list-units '*.service' | grep -E 'mavlink-router|dds-agent|ark-ui'`), web UI accessible on `:80`
3. **Chroot install**: Install `.deb` into an `ark_jetson_kernel` rootfs via `--provision`, flash, boot — verify services come up without manual intervention
4. **Service manager**: Toggle services via web UI, verify start/stop/enable/disable work with system units (confirms polkit rule)
5. **Config reset on upgrade (not persistence)**: Modify `/etc/ark-os/logloader.toml`, upgrade the package — verify the file is **overwritten** to the packaged default with **no** dpkg conffile prompt (configs are intentionally not conffiles, Task 1). For `mavlink-router.conf`, confirm the device path is re-detected and re-written on the next boot.
6. **Removal**: `sudo apt remove ark-os-jetson` — verify services stop and package files are removed. Note: because the configs are not conffiles, `apt remove` also removes `/etc/ark-os/*.toml`; runtime data under `/var/lib/ark-os/` is left intact (only `purge` removes it).
7. **Purge**: `sudo apt purge ark-os-jetson` — verify `/etc/ark-os/` also removed
8. **Opt-in services**: Verify `dds-agent`, `logloader`, `polaris`, `flight-review`, `rid-transmitter` are installed (unit files present) but not running by default; `systemctl enable --now <svc>` brings them up
9. **Target grouping**: `systemctl list-dependencies ark-os.target --plain` returns the **enabled** ARK-OS services (always-on plus any opt-in the operator has enabled); `systemctl stop ark-os.target` stops the running set. service-manager discovery of all installed services (including disabled opt-ins) is verified separately by globbing `/usr/lib/ark-os/manifests/*.manifest.json` (Task 5 #1).
10. **Legacy migration**: on a device that previously had a source-based install (`~/.local/share/mavlink-router/` etc. present), `sudo dpkg -i ark-os-jetson.deb` removes the legacy user services and binaries, leaves a backup at `~/.config/ark-os-legacy-backup/`, and brings the new system services up cleanly with no conflicting processes (`systemctl --user list-units --type=service` shows no ARK-OS units; `systemctl list-units 'mavlink-router.service'` shows the new system unit active). Confirm that **after a reboot** no stale `systemctl --user` ARK-OS process remains (if the operator was logged in during install the old user units stop immediately; if not, they're removed but a running instance may persist until reboot — see Task 1 "Migration reboot").
11. **C++ service config wiring**: with an opt-in C++ service enabled (e.g. logloader), edit `/etc/ark-os/logloader.toml` via the web UI, restart the service, and confirm the running binary picks up the change — i.e. the unit's `--config /etc/ark-os/logloader.toml` and the submodule edit (Task 4) point the binary at the same file the UI writes. Also confirm logloader stages logs under `/var/lib/ark-os/logs`, not `/home/jetson/.local/share/logloader/`.

---

## File tree summary

New files created by this PR (in-place edits to `services/`, `platform/`, `frontend/` are not listed here — see Tasks 3, 5, 10 for those):

```
packaging/
├── PLAN.md                           # This document
├── build.sh                          # Master build orchestrator
├── build_binaries.sh                 # Compile C++ submodules
├── build_frontend.sh                 # Build Vue.js + backend deps
├── build_venv.sh                     # Create Python virtualenv
├── bundle_node.sh                    # Download Node.js arm64 binary
├── assemble_tree.sh                  # Lay out FHS tree + DEBIAN/
├── DEBIAN/
│   ├── control                       # Package metadata (template)
│   ├── postinst                      # Post-install script (incl. legacy cleanup, step 0)
│   ├── prerm                         # Pre-removal script (systemctl stop ark-os.target)
│   └── postrm                        # Post-removal script
│                                     # (no conffiles — ARK-OS ships none; see Task 1)
├── service-files/
│   ├── ark-os.target                 # Group target for bulk start/stop (discovery uses manifest glob — Task 5 #1)
│   ├── jetson/
│   │   ├── mavlink-router.service
│   │   ├── dds-agent.service
│   │   ├── logloader.service
│   │   ├── rtsp-server.service
│   │   ├── polaris.service
│   │   ├── rid-transmitter.service
│   │   ├── ark-ui-backend.service
│   │   ├── flight-review.service
│   │   ├── autopilot-manager.service
│   │   ├── connection-manager.service
│   │   ├── service-manager.service
│   │   ├── system-manager.service
│   │   ├── hotspot-updater.service
│   │   └── jetson-can.service
│   └── pi/
│       └── ... (same minus jetson-can and rid-transmitter, User=pi)
├── config/                           # default /etc/ark-os/ configs (plain files, not conffiles; no master ark-os.conf)
│   ├── logloader.toml                # Submodule-default-derived; binary reads it via --config (Task 4)
│   ├── polaris.toml
│   ├── rtsp-server.toml
│   ├── rid-transmitter.toml
│   └── flight-review.ini
└── system-config/
    ├── 03-ark-service-manager.rules  # New polkit rule (per-unit allowlist for jetson user)
    └── 10-ark-os.conf                # journald snippet: Storage=persistent

.github/workflows/build-deb.yml       # CI pipeline

extras/                               # Moved out of tools/ + platform/jetson/scripts/ (Task 10) — dev-workstation helpers
├── README.md                         # Explains: not part of the deb path; manual installs only
├── install_opencv.sh                 # Moved from tools/
├── install_ros2.sh                   # Moved from tools/
├── i2s_gpio_example.py               # Moved from platform/jetson/scripts/ (unused by services)
├── icm42688p_driver.py               # Moved from platform/jetson/scripts/
├── ina238_test.py                    # Moved from platform/jetson/scripts/
└── test_jtop.py                      # Moved from platform/jetson/scripts/
```

Files edited in place (see Tasks 3, 5, 10):
- `services/<svc>/start_<svc>.sh` — FHS path rewrites
- `services/<svc>/<svc>.py` — FHS path rewrites + `systemctl --user` → `systemctl`
- `services/<svc>/<svc>.manifest.json` — `configFile` field updated
- `services/mavlink-router/main.conf` — sourced for `/etc/ark-os/mavlink-router.conf`
- `platform/<plat>/scripts/*.py` — shebangs rewritten to `/usr/lib/ark-os/venv/bin/python3`

Files deleted (Task 10): `install.sh`, `default.env`, `all_submodules_main.sh`, `tools/install_software.sh`, `tools/install_mavsdk.sh`, `tools/install_mavsdk_examples.sh`, `tools/service_control.sh`, `tools/functions.sh`, the empty `tools/` directory, all 14 `services/<svc>/<svc>.service` user units, `services/ark-ui-backend/start_ark_ui_backend.sh`.

Files moved (Task 10): `tools/install_opencv.sh` → `extras/install_opencv.sh`, `tools/install_ros2.sh` → `extras/install_ros2.sh`, and `platform/jetson/scripts/{i2s_gpio_example,icm42688p_driver,ina238_test,test_jtop}.py` → `extras/` (+ new `extras/README.md` explaining their role).
