## Summary

Package ARK-OS into `.deb` files (`ark-os-jetson`, `ark-os-pi`) for installation via `apt` or chroot during `ark_jetson_kernel` image builds. Replace the 30-60 min clone-and-compile install with a ~1 min `dpkg -i`.

## Problem

ARK-OS is installed by cloning the repo on-device and running `install.sh`, which compiles 6 C++ submodules from source, installs Python/Node dependencies globally, and configures systemd user services. This is slow, fragile (build failures, network timeouts, apt lock contention), and makes field updates painful (re-clone + re-run). It also cannot be pre-baked into Jetson images because the install script requires a running system (systemd, network, user session).

## Solution

Pre-build everything in CI (ARM64 GitHub runners on Ubuntu 22.04 Jammy to match the JetPack 6 rootfs Python 3.10) and ship `.deb` packages. System-level systemd units with `User=jetson` replace user-session services for chroot compatibility. Configs move to `/etc/ark-os/` as dpkg conffiles. The package installs cleanly via `dpkg -i` in a chroot during `ark_jetson_kernel --provision` builds, and devices boot fully provisioned after flashing. Field updates via `sudo apt upgrade`.

---

# Implementation Plan

This plan is structured as ordered tasks for implementation. The `.deb` is the **only** supported install path after this PR — the legacy `install.sh` mechanism and its supporting scripts are removed (Task 10), and the postinst cleans up remnants from any prior source-based install (Task 1, step 0).

## Naming convention

Service unit files and manifests retain their current names — **no `ark-` prefix**. Example: `mavlink-router.service`, `mavlink-router.manifest.json`. Only the package itself is `ark-os-jetson` / `ark-os-pi`.

## Codebase context

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
Depends: nginx, python3 (>= 3.8), python3-venv, avahi-daemon, libgstreamer1.0-0, libgstreamer-plugins-base1.0-0, libgstrtspserver-1.0-0, gstreamer1.0-plugins-ugly, gstreamer1.0-tools, gstreamer1.0-gl, gstreamer1.0-rtsp, libssl3, libsqlite3-0, libcap2-bin, curl, jq, systemd, network-manager
Maintainer: ARK Electronics <info@arkelectron.com>
Description: ARK-OS companion computer platform
 Pre-compiled services, web UI, and system configuration for autonomous vehicles.
```

Jetson adds to Depends: `bluez, bluez-tools, libbluetooth3, mavsdk`. Pi adds: `gstreamer1.0-libcamera, mavsdk`.

MAVSDK has no public apt repo, so the upstream MAVSDK arm64 `.deb` is bundled alongside `ark-os-*.deb` on the same GitHub release. `Depends: mavsdk` gives correctness validation (`dpkg -i` fails loudly if missing) but doesn't auto-install — installer order matters. Pin a specific MAVSDK release (check `github.com/mavlink/MAVSDK/releases` for the current `v3.x.x`) in `packaging/build.sh` and update on each ARK-OS bump.

### `packaging/DEBIAN/conffiles`

List every config file under `/etc/ark-os/` — dpkg preserves user edits on upgrade:

```
/etc/ark-os/ark-os.conf
/etc/ark-os/mavlink-router.conf
/etc/ark-os/logloader.toml
/etc/ark-os/polaris.toml
/etc/ark-os/rtsp-server.toml
/etc/ark-os/rid-transmitter.toml
/etc/ark-os/flight-review.ini
/etc/nginx/sites-available/ark-ui
```

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
3. Make `/etc/ark-os/` writable by the service user: `chgrp -R $ARK_USER /etc/ark-os && chmod 2775 /etc/ark-os && chmod 0664 /etc/ark-os/*` — setgid bit on the directory means new files inherit the group. Files stay root-owned but group-writable so `service-manager.py` (running as `$ARK_USER`) can rewrite configs from the web UI. Conffile mechanics in dpkg track files by name/hash, not ownership, so this survives upgrades.
4. Symlink flight-review config into the app tree: `ln -sf /etc/ark-os/flight-review.ini /usr/lib/ark-os/flight-review/app/config_user.ini` — `serve.py` takes no config-file flag, `plot_app/config.py` reads `config_user.ini` from a hardcoded path relative to the script.
5. `systemctl enable` always-on services: `mavlink-router`, `rtsp-server`, `ark-ui-backend`, `autopilot-manager`, `connection-manager`, `service-manager`, `system-manager`, `hotspot-updater`, `jetson-can` (Jetson only).
6. Opt-in services are installed but **not** enabled: `dds-agent`, `logloader`, `polaris`, `flight-review`, `rid-transmitter`. Operator turns them on via the web UI or `systemctl enable --now <svc>`. There is no `[services]` section in `ark-os.conf` — systemd's enabled-state is the source of truth, so there's no parallel config to drift.
7. `setcap 'cap_net_raw,cap_net_admin+eip' /usr/lib/ark-os/bin/rid-transmitter 2>/dev/null || true` (file present only on Jetson; `|| true` covers non-xattr filesystems)
8. Drop `/etc/systemd/journald.conf.d/10-ark-os.conf` containing `[Journal]\nStorage=persistent`; `mkdir -p /var/log/journal && chown root:systemd-journal /var/log/journal && chmod 2755 /var/log/journal`
9. Nginx: `ln -sf /etc/nginx/sites-available/ark-ui /etc/nginx/sites-enabled/ark-ui` and `rm -f /etc/nginx/sites-enabled/default`
10. **Runtime-only block** (inside `if [ -d /run/systemd/system ]`):
    - `systemctl daemon-reload`
    - `systemctl start ark-os.target` — starts all enabled units in the target (see Task 2)
    - `nginx -t && systemctl reload nginx`
    - `udevadm control --reload-rules && udevadm trigger` (skipped in chroot via the outer guard)
    - run `create_hotspot_default.sh` if hotspot NM connection missing
    - init flight-review DB: `[ -f /var/lib/ark-os/flight-review/data/logs.sqlite ] || (cd /usr/lib/ark-os/flight-review/app && sudo -u $ARK_USER /usr/lib/ark-os/venv/bin/python3 setup_db.py)`

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
- `WantedBy=multi-user.target ark-os.target` — `multi-user.target` for boot autostart, `ark-os.target` for grouping (enables bulk start/stop and dynamic discovery)
- Absolute paths instead of `%h` specifier
- `User=jetson` and `Group=jetson` directives
- Binaries at `/usr/lib/ark-os/bin/`, scripts at `/usr/lib/ark-os/scripts/`
- Python services use `/usr/lib/ark-os/venv/bin/python3`
- Config at `/etc/ark-os/`

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

Every ARK-OS service unit declares `WantedBy=ark-os.target` in its `[Install]` section. This gives three things for free:

- **Discovery**: `systemctl list-dependencies ark-os.target --plain` returns the live list of ARK-OS units — no separate `services.list` file, no drift between the package and the discovery code.
- **Bulk control**: `systemctl stop ark-os.target` stops every ARK-OS service in one command (used in `prerm` above).
- **Self-documenting**: each unit declares its own membership; adding a new service auto-registers it.

The polkit rule (Task 5) still needs an explicit list — polkit can't shell out to `systemctl` — but that's now the only place duplication exists.

### Service file details

**mavlink-router.service**
- `ExecStart=/usr/lib/ark-os/scripts/start_mavlink_router.sh`
- `After=network-online.target`

**dds-agent.service**
- `ExecStart=/usr/lib/ark-os/scripts/start_dds_agent.sh`
- `After=dev-ttyTHS1.device dev-ttyAMA4.device network-online.target` (Jetson uses ttyTHS1, Pi uses ttyAMA4 — the start script handles detection)
- `ExecStartPre=/bin/sleep 2` (wait for UART device)

**logloader.service**
- `ExecStart=/usr/lib/ark-os/bin/logloader`
- `After=network.target mavlink-router.service`
- `Environment=SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt`
- `Restart=always`, `Nice=10`, `CPUWeight=50`

**rtsp-server.service**
- `ExecStart=/usr/lib/ark-os/bin/rtsp-server`
- `After=network-online.target`

**polaris.service**
- `ExecStart=/usr/lib/ark-os/bin/polaris-client-mavlink`
- `After=network-online.target mavlink-router.service`

**rid-transmitter.service** (Jetson only)
- `ExecStart=/usr/lib/ark-os/bin/rid-transmitter`
- `After=network-online.target bluetooth.target mavlink-router.service`
- `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`

**flight-review.service**
- `ExecStart=/usr/lib/ark-os/scripts/start_flight_review.sh`
- `After=network-online.target nginx.service`

**ark-ui-backend.service**
- `WorkingDirectory=/usr/lib/ark-os/ark-ui-backend`
- `ExecStart=/usr/lib/ark-os/bin/node /usr/lib/ark-os/ark-ui-backend/index.js`
- `After=network-online.target`
- `Environment=NODE_ENV=production`
- `Environment=PATH=/usr/lib/ark-os/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`

**autopilot-manager.service**
- `ExecStart=/usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/python/autopilot_manager.py`
- `After=network-online.target`
- `Environment=PYTHONUNBUFFERED=1`

**connection-manager.service**
- `ExecStart=/usr/lib/ark-os/venv/bin/python3 /usr/lib/ark-os/python/connection_manager.py`
- `After=network-online.target NetworkManager.service ModemManager.service`
- `Environment=PYTHONUNBUFFERED=1`

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

Create `packaging/scripts/` with modified versions of each start script. These replace `$XDG_DATA_HOME`, `$HOME/.local/bin`, and `$HOME/.config/nvm` references with FHS paths.

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

### Scripts to create

**`start_mavlink_router.sh`** — Based on `services/mavlink-router/start_mavlink_router.sh`. Changes:
- Config: `/etc/ark-os/mavlink-router.conf`
- Binary: `/usr/lib/ark-os/bin/mavlink-routerd`
- vbus_enable: `/usr/lib/ark-os/scripts/vbus_enable.py` (called via `/usr/lib/ark-os/venv/bin/python3`)

**`start_dds_agent.sh`** — Based on `services/dds-agent/start_dds_agent.sh`. Changes:
- Binary: `/usr/lib/ark-os/bin/MicroXRCEAgent`
- Platform detection logic stays the same (reads kernel info)

**`start_flight_review.sh`** — Based on `services/flight-review/start_flight_review.sh`. Changes:
- Python: `/usr/lib/ark-os/venv/bin/python3`
- App path: `/usr/lib/ark-os/flight-review/app/serve.py`
- Config: `/etc/ark-os/flight-review.ini`

**`start_can_interface.sh`** — Based on `services/jetson-can/start_can_interface.sh`. No path changes needed (uses system commands `modprobe`, `ip`).

**`stop_can_interface.sh`** — Based on `services/jetson-can/stop_can_interface.sh`. No path changes needed.

**`update_hotspot_default.sh`** — Based on `services/hotspot-updater/update_hotspot_default.sh`. No path changes needed (uses system commands `nmcli`, `hostname`).

**`create_hotspot_default.sh`** — Based on `platform/common/scripts/create_hotspot_default.sh`. No path changes needed.

Note: there is no separate `start_ark_ui_backend.sh` in the package. The ark-ui-backend service runs `node index.js` directly from `/usr/lib/ark-os/ark-ui-backend/` (see Task 2 unit file).

**Platform utility scripts** — Copy from `platform/jetson/scripts/` and `platform/common/scripts/`:
- `vbus_enable.py`, `vbus_disable.py`, `get_serial_number.py`, `reset_fmu_fast.py`, `reset_fmu_wait_bl.py`
- `flash_firmware.sh`, `mavlink_shell.py`, `px4_shell_command.py`, `px_uploader.py`, `mavlink_ftp_upload.sh`
- `pcie_set_speed.sh`, `self_test.sh`, `set_mac.sh` (Jetson only)
- These go into `/usr/lib/ark-os/scripts/` with Python shebangs rewritten to `#!/usr/lib/ark-os/venv/bin/python3`

---

## Task 4: Default config files

Create `packaging/config/` with default configuration files that get installed to `/etc/ark-os/`.

### `ark-os.conf` — Master config

Runtime parameters only — service enable/disable lives in systemd state, not here:

```ini
[logloader]
upload_enabled = false
public_logs = false
email =

[rid]
manufacturer_code = MFR1
serial_number = 000000000000

[polaris]
api_key =
```

Service enable/disable is **not** in this file. Opt-in services (`dds-agent`, `logloader`, `polaris`, `flight-review`, `rid-transmitter`) are installed but disabled; operator turns them on via the web UI or `systemctl enable --now <svc>`. Using systemd state as the single source of truth means there's no parallel config knob for the UI to drift against.

### `mavlink-router.conf`

Copy from `services/mavlink-router/main.conf` — this is the hub config with UART endpoint and UDP endpoints (ports 14550-14571). No path changes needed (it references `/dev/serial/by-id/` device paths).

### `logloader.toml`, `polaris.toml`, `rtsp-server.toml`, `rid-transmitter.toml`

Copy from each service's existing config file. No path changes needed — they contain connection URLs, API keys, and streaming parameters.

### `flight-review.ini`

Based on `services/flight-review/flight_review/app/config_default.ini`. Changes:
- `domain_name` = leave as default (overridden by start script)
- `storage_path` = `/var/lib/ark-os/flight-review/data`

---

## Task 5: Service manager transition

This is the most significant code change. `service_manager.py` must switch from managing user services (`systemctl --user`) to managing system services (`systemctl`).

### Changes to `service_manager.py`

Create a deb-compatible version at `packaging/python/service_manager.py`. Key changes (showing current line numbers from `services/service-manager/service_manager.py`):

1. **Service discovery** (line 106-112): Replace the `~/.config/systemd/user/` scan with a call to `systemctl list-dependencies ark-os.target --plain --no-legend` and parse the output (one unit name per line). This gives the live list of ARK-OS units derived from filesystem state — no hardcoded list to maintain in Python.
2. **Manifest location** (lines 69-70, 89-90): Read from `/usr/lib/ark-os/manifests/<svc>.manifest.json` instead of `~/.local/share/<svc>/<svc>.manifest.json`.
3. **Config location** (lines 67-85): `os.path.join('/etc/ark-os', configFile)` where `configFile` is read from the manifest. The `configFile` field already holds the bare filename (`main.conf`, `config.toml`) — the rename to `/etc/ark-os/mavlink-router.conf` etc. means manifests must also be updated so `configFile` holds the new filename (e.g., `mavlink-router.conf`, `logloader.toml`).
4. **systemctl commands** (line 30, 53): Replace all `systemctl --user` with `systemctl`. Service names are unchanged (no `ark-` prefix).
5. **Journal logs** (line 212): Replace `journalctl --user -u <svc>` with `journalctl -u <svc>`.

The service manager runs as `User=jetson` in its system service unit. The polkit rule (below) grants it permission to manage the specific ARK-OS units.

### New polkit rule for service management

Create `packaging/system-config/03-ark-service-manager.rules`. Covers `manage-units` (start/stop/restart), `manage-unit-files` (enable/disable), and `reload-daemon` (daemon-reload) — all three are required:

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
});
```

(Pi package uses the same rule with `"pi"` instead of `"jetson"`.)

### Changes to other Python services

Create deb-compatible versions at `packaging/python/`. Specific edits required:

**`autopilot_manager.py`** (current `services/autopilot-manager/autopilot_manager.py`):
- Line 401: `subprocess.run(["systemctl", "--user", "stop", "mavlink-router"], ...)` → drop `"--user"`
- Line 418: `subprocess.run(["systemctl", "--user", "restart", "mavlink-router"], ...)` → drop `"--user"`
- Line 441: `subprocess.run(["python3", os.path.expanduser(f"~/.local/bin/{script}")], ...)` → `subprocess.run(["/usr/lib/ark-os/venv/bin/python3", f"/usr/lib/ark-os/scripts/{script}"], ...)`
- Line 526 onwards (`flash_firmware` `Popen`): audit the firmware flash subprocess invocation for any `~/.local/bin/` paths and rewrite to `/usr/lib/ark-os/scripts/`. The flash function calls `px_uploader.py` — confirm and rewrite.

**`connection_manager.py`**: works as-is — only calls `nmcli` and `hostnamectl` (system utilities). Existing sudoers/polkit handle permissions.

**`system_manager.py`**: works as-is — only calls `vcgencmd`, `hostnamectl`, and reads sysfs/procfs.

For all three, copy them to `packaging/python/` to keep one source of truth for the deb build.

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

# logloader (make)
cd services/logloader/logloader
make
# Output: logloader (in source dir)

# rtsp-server (make, needs GStreamer dev libs)
cd services/rtsp-server/rtsp-server
make
# Output: rtsp-server

# polaris-client-mavlink (make)
cd services/polaris/polaris-client-mavlink
make
# Output: polaris-client-mavlink

# rid-transmitter (cmake, Jetson only, needs libbluetooth-dev)
cd services/rid-transmitter/RemoteIDTransmitter
mkdir build && cd build
cmake ..
make -j$(nproc)
# Output: rid-transmitter

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

# Platform-specific
if [ "$PLATFORM" = "jetson" ]; then
    /usr/lib/ark-os/venv/bin/pip install "Jetson.GPIO>=2.1.12" smbus2 jetson-stats
fi

# Move into package tree
mkdir -p "$BUILD_DIR/usr/lib/ark-os"
mv /usr/lib/ark-os/venv "$BUILD_DIR/usr/lib/ark-os/venv"
```

The venv is created at the real target path so all internal paths (shebangs, `pyvenv.cfg`) resolve correctly on the device. The `ubuntu-22.04-arm` runner uses Python 3.10, matching JetPack 6 Jammy.

### `packaging/assemble_tree.sh` — Lay out FHS structure

Assembles all build outputs into the `BUILD_DIR` following the package file layout. Creates the full directory tree, copies files, substitutes `PLATFORM`/`VERSION` in DEBIAN/control, sets file permissions (scripts +x, DEBIAN scripts +x, configs 644, dirs 755).

Final tree (relative to `$BUILD_DIR`):

```
DEBIAN/                          # control, conffiles, postinst, prerm, postrm
etc/ark-os/                      # configs (conffiles)
etc/nginx/sites-available/ark-ui
etc/polkit-1/rules.d/            # 02-ark-network-manager.rules, 03-ark-service-manager.rules
etc/polkit-1/localauthority/90-mandatory.d/99-ark-network.pkla
etc/sudoers.d/ark-os
etc/systemd/journald.conf.d/10-ark-os.conf
etc/udev/rules.d/99-ark-gpio.rules         # Jetson only
lib/systemd/system/                # service units
usr/lib/ark-os/bin/                # native binaries + bundled node/npm + mavsdk-examples
usr/lib/ark-os/lib/                # bundled node lib/node_modules/npm/
usr/lib/ark-os/scripts/            # start scripts + platform utility scripts
usr/lib/ark-os/venv/               # Python venv
usr/lib/ark-os/python/             # autopilot_manager.py etc.
usr/lib/ark-os/manifests/          # mavlink-router.manifest.json etc.
usr/lib/ark-os/flight-review/      # full flight_review app tree
usr/lib/ark-os/ark-ui-backend/     # index.js, package.json, node_modules/
var/www/ark-ui/html/               # built Vue dist (owned root:root, chowned to www-data in postinst)
```

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

Create `packaging/system-config/` with system-level configuration files. Install destinations:

| Source | Destination | Mode |
|---|---|---|
| `ark-ui.nginx` (from `frontend/ark-ui.nginx`) | `/etc/nginx/sites-available/ark-ui` | 0644 |
| `99-ark-gpio.rules` (from `platform/jetson/99-gpio.rules`) | `/etc/udev/rules.d/99-ark-gpio.rules` | 0644 (Jetson only) |
| `ark-os.sudoers` (from `platform/common/ark_scripts.sudoers`) | `/etc/sudoers.d/ark-os` | 0440 |
| `02-ark-network-manager.rules` (from `platform/common/wifi/02-network-manager.rules`) | `/etc/polkit-1/rules.d/02-ark-network-manager.rules` | 0644 |
| `99-ark-network.pkla` (from `platform/common/wifi/99-network.pkla`) | `/etc/polkit-1/localauthority/90-mandatory.d/99-ark-network.pkla` | 0644 |
| `03-ark-service-manager.rules` (new — see Task 5) | `/etc/polkit-1/rules.d/03-ark-service-manager.rules` | 0644 |

The `ark-ui.nginx` content needs no changes — it already references `/var/www/ark-ui/html` and proxies to `localhost:3000`/`localhost:5006`.

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
3. Download and install the pinned MAVSDK arm64 `.deb` from `github.com/mavlink/MAVSDK/releases` (needed by `libs/mavsdk-examples` link step). Cache the downloaded `.deb` — it gets re-uploaded to the ARK-OS release in step 8.
4. Install Node.js 20: `actions/setup-node@v4`
5. Extract version from tag: `echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_ENV`
6. Run `./packaging/build.sh ${{ matrix.platform }} --version=${{ env.VERSION }}`
7. Upload `.deb` artifact (both `ark-os-${platform}_${VERSION}_arm64.deb` and the cached `mavsdk_*_arm64.deb`)
8. Create GitHub Release and attach **both** `.deb` files (ARK-OS and MAVSDK) so `ark_jetson_kernel/provision.sh` can fetch them from the same release page

### Considerations

- ARM64 runners compile natively — no cross-compilation needed
- Python venv must be created at `/usr/lib/ark-os/venv` (the target path) for correct shebangs — the CI script uses `sudo mkdir -p /usr/lib/ark-os` and chowns it, creates the venv there, then moves it into the package tree
- `ubuntu-22.04-arm` provides Python 3.10, matching the JetPack 6 / Jammy target

---

## Task 9: `ark_jetson_kernel` integration

Update `provision.sh` in the `ark_jetson_kernel` repo to install the `.deb` during image builds.

```bash
#!/bin/bash
set -e

RELEASE_BASE="https://github.com/ARK-Electronics/ARK-OS/releases/download/v1.0.0"
ARK_OS_DEB="ark-os-jetson_1.0.0_arm64.deb"
MAVSDK_DEB="mavsdk_3.0.0_arm64.deb"   # pin to whatever the release attaches

echo "Downloading ARK-OS debs..."
sudo wget -q -O "$ROOTFS_DIR/tmp/$MAVSDK_DEB" "$RELEASE_BASE/$MAVSDK_DEB"
sudo wget -q -O "$ROOTFS_DIR/tmp/$ARK_OS_DEB" "$RELEASE_BASE/$ARK_OS_DEB"

echo "Installing MAVSDK first (ark-os depends on it)..."
sudo chroot "$ROOTFS_DIR" apt-get update
sudo chroot "$ROOTFS_DIR" dpkg -i "/tmp/$MAVSDK_DEB" || true
sudo chroot "$ROOTFS_DIR" apt-get install -f -y

echo "Installing ark-os-jetson..."
sudo chroot "$ROOTFS_DIR" dpkg -i "/tmp/$ARK_OS_DEB" || true
sudo chroot "$ROOTFS_DIR" apt-get install -f -y

sudo rm "$ROOTFS_DIR/tmp/$MAVSDK_DEB" "$ROOTFS_DIR/tmp/$ARK_OS_DEB"
```

MAVSDK installs first because ARK-OS declares `Depends: mavsdk` — `dpkg -i ark-os` would fail without it (and `apt-get install -f` can't resolve MAVSDK since it's not in any apt repo).

This works because `build.sh` already:
- Registers `qemu-aarch64` binfmt handler (line 169-171)
- Bind-mounts `/proc`, `/sys`, `/dev`, `/dev/pts` (lines 205-208)
- Copies `/etc/resolv.conf` for DNS (line 209)
- Creates the `jetson` user via `l4t_create_default_user.sh` (lines 180-181) before provisioning runs

Both versions are hardcoded — update manually when bumping ARK-OS or MAVSDK.

---

## Task 10: Remove legacy install mechanism

Delete the source-based install path from the repo. After this PR, the `.deb` is the only supported way to install ARK-OS — operators who previously ran `install.sh` get migrated by the postinst legacy-cleanup block (Task 1, step 0).

### Files to delete from the repo

```
install.sh                              # Top-level legacy installer entry point
default.env                             # Legacy install env config
all_submodules_main.sh                  # Submodule sync helper used only by the legacy path
tools/install_software.sh               # Main legacy installer
tools/install_mavsdk.sh                 # MAVSDK now comes from the upstream deb (Task 8)
tools/install_mavsdk_examples.sh        # Now part of build_binaries.sh
tools/install_opencv.sh                 # Unused by deb path
tools/install_ros2.sh                   # Unused by deb path
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

Keep:
- `services/<svc>/start_<svc>.sh` and `services/<svc>/<svc>.py` — these are the **source** that `packaging/scripts/` and `packaging/python/` derive from (Tasks 3, 5).
- `services/<svc>/<svc>.manifest.json` — source for `packaging/manifests/`; update the `configFile` field in place (Task 5).
- `services/mavlink-router/main.conf` — source for `packaging/config/mavlink-router.conf`.
- Submodules under `services/<svc>/<svc>/` — untouched.
- `platform/` tree — referenced by `packaging/system-config/` and `packaging/scripts/`.

### `README.md` update

Replace the source-install instructions with the `.deb` install path:

```
sudo apt install ./mavsdk_<ver>_arm64.deb
sudo apt install ./ark-os-jetson_<ver>_arm64.deb
```

Plus a one-line note for Jetson image bakers: "For chroot install during `ark_jetson_kernel --provision`, see `packaging/PLAN.md` Task 9."

Drop the README sections covering `default.env`, `user.env`, the per-component `INSTALL_*=y` env vars, and the manual submodule sync — none of those exist after this PR.

---

## Verification checklist

1. **Build locally on ARM64**: Run `./packaging/build.sh jetson` on a Jetson, verify it produces a valid `.deb`
2. **Install on clean system**: `sudo dpkg -i ark-os-jetson.deb && sudo apt-get install -f -y`, verify all enabled services start (`systemctl list-units '*.service' | grep -E 'mavlink-router|dds-agent|ark-ui'`), web UI accessible on `:80`
3. **Chroot install**: Install `.deb` into an `ark_jetson_kernel` rootfs via `--provision`, flash, boot — verify services come up without manual intervention
4. **Service manager**: Toggle services via web UI, verify start/stop/enable/disable work with system units (confirms polkit rule)
5. **Config persistence**: Modify `/etc/ark-os/mavlink-router.conf`, upgrade package — verify dpkg prompts about changed conffile
6. **Removal**: `sudo apt remove ark-os-jetson` — verify services stopped, files removed, `/etc/ark-os/` preserved
7. **Purge**: `sudo apt purge ark-os-jetson` — verify `/etc/ark-os/` also removed
8. **Opt-in services**: Verify `dds-agent`, `logloader`, `polaris`, `flight-review`, `rid-transmitter` are installed (unit files present) but not running by default; `systemctl enable --now <svc>` brings them up
9. **Target grouping**: `systemctl list-dependencies ark-os.target --plain` returns all 14 (Jetson) / 12 (Pi) services; `systemctl stop ark-os.target` stops the running set
10. **Legacy migration**: on a device that previously had a source-based install (`~/.local/share/mavlink-router/` etc. present), `sudo dpkg -i ark-os-jetson.deb` removes the legacy user services and binaries, leaves a backup at `~/.config/ark-os-legacy-backup/`, and brings the new system services up cleanly with no conflicting processes (`systemctl --user list-units --type=service` shows no ARK-OS units; `systemctl list-units 'mavlink-router.service'` shows the new system unit active)

---

## File tree summary

All new files created by this PR:

```
packaging/
├── build.sh                          # Master build orchestrator
├── build_binaries.sh                 # Compile C++ submodules
├── build_frontend.sh                 # Build Vue.js + backend deps
├── build_venv.sh                     # Create Python virtualenv
├── bundle_node.sh                    # Download Node.js arm64 binary
├── assemble_tree.sh                  # Lay out FHS tree + DEBIAN/
├── DEBIAN/
│   ├── control                       # Package metadata (template)
│   ├── conffiles                     # Config files list
│   ├── postinst                      # Post-install script
│   ├── prerm                         # Pre-removal script
│   └── postrm                        # Post-removal script
├── service-files/
│   ├── ark-os.target               # Group target for discovery + bulk control
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
├── scripts/
│   ├── start_mavlink_router.sh
│   ├── start_dds_agent.sh
│   ├── start_flight_review.sh
│   ├── start_can_interface.sh
│   ├── stop_can_interface.sh
│   ├── update_hotspot_default.sh
│   ├── create_hotspot_default.sh
│   └── ... (platform utility scripts)
├── python/
│   ├── service_manager.py            # Updated for system service management
│   ├── autopilot_manager.py          # Updated paths + systemctl (no --user)
│   ├── connection_manager.py         # Unchanged (system utilities only)
│   └── system_manager.py             # Unchanged (system utilities only)
├── manifests/
│   ├── mavlink-router.manifest.json  # Updated configFile field
│   ├── logloader.manifest.json
│   └── ... (one per service)
├── config/
│   ├── ark-os.conf                   # Master config
│   ├── mavlink-router.conf
│   ├── logloader.toml
│   ├── polaris.toml
│   ├── rtsp-server.toml
│   ├── rid-transmitter.toml
│   └── flight-review.ini
└── system-config/
    ├── ark-ui.nginx
    ├── 99-ark-gpio.rules
    ├── ark-os.sudoers
    ├── 02-ark-network-manager.rules
    ├── 99-ark-network.pkla
    └── 03-ark-service-manager.rules

.github/workflows/build-deb.yml      # CI pipeline
```
