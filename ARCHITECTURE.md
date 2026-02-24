# ARK-OS Architecture

## Overview

ARK-OS is a modular collection of services for drone companion computers. It runs on
ARK Electronics platforms (ARK Jetson Carrier, ARK Pi6X Flow) and provides mavlink
routing, video streaming, flight log management, firmware updates, RTK corrections,
remote ID, and a web-based management UI.

### Design Principles

- **Modular** — Each service is independent. Install only what you need.
- **Simple** — No orchestration frameworks. Just systemd, nginx, and straightforward
  REST APIs.
- **Extensible** — Adding a new service means adding a directory, a manifest, and
  a systemd unit. The system discovers and manages it automatically.
- **Consistent** — Every service follows the same structure: code, manifest,
  install script, systemd unit.

## System Architecture

```
┌──────────────────────────────────────────────────────┐
│  Browser (ARK UI)                                    │
│  http://jetson.local  or  http://pi6x.local          │
└──────────────────┬───────────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────────┐
│  nginx (port 80)                                     │
│  ├── /              → Vue SPA static files           │
│  ├── /api/network/* → connection-manager  :3001      │
│  ├── /api/service/* → service-manager     :3002      │
│  ├── /api/autopilot/* → autopilot-manager :3003      │
│  ├── /api/system/*  → system-manager      :3004      │
│  └── /flight-review → flight-review       :5006      │
└──────────────────────────────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────────┐
│  Backend Services (systemd user services)            │
│                                                      │
│  Python REST APIs        C++ Services                │
│  ├── connection-manager  ├── mavlink-router           │
│  ├── service-manager     ├── logloader                │
│  ├── autopilot-manager   ├── rtsp-server              │
│  └── system-manager      ├── polaris                  │
│                          ├── dds-agent                │
│                          └── rid-transmitter (Jetson) │
└──────────────────┬───────────────────────────────────┘
                   │ USB / Serial / MAVLink
┌──────────────────▼───────────────────────────────────┐
│  Flight Controller (PX4)                             │
└──────────────────────────────────────────────────────┘
```

## Services

| Service | Type | Port | Platform | Purpose |
|---------|------|------|----------|---------|
| mavlink-router | C++ | — | all | Routes MAVLink from FC USB to UDP endpoints |
| dds-agent | C++ | — | all | Bridges PX4 uORB ↔ ROS2 topics over serial |
| logloader | C++ | — | all | Downloads flight logs from FC, uploads to review servers |
| flight-review | Python | 5006 | all | Local PX4 Flight Review server |
| rtsp-server | C++ | 5600 | all | RTSP video stream from CSI cameras |
| polaris | C++ | — | all | RTK corrections via PointOne GNSS service |
| service-manager | Python | 3002 | all | REST API for systemd service management |
| system-manager | Python | 3004 | all | REST API for system management (power, updates, etc.) |
| autopilot-manager | Python | 3003 | all | REST API for flight controller management |
| connection-manager | Python | 3001 | all | REST API for network/connection management |
| rid-transmitter | C++ | — | jetson | RemoteID broadcast via Bluetooth |
| jetson-can | Bash | — | jetson | Enables Jetson CAN bus interface |
| hotspot-updater | Bash | — | all | Updates default WiFi hotspot name |

## Service Anatomy

Every service follows the same structure:

```
services/<service-name>/
├── <service-name>.manifest.json   # Metadata (see below)
├── install.sh                     # Installation script
├── <code files>                   # Python script, C++ source, or bash script
└── config.toml (optional)         # Default configuration
```

### Manifest Schema

The manifest tells service-manager how to discover and present the service:

```json
{
  "version": "1.0.0",
  "displayName": "Human Readable Name",
  "description": "What this service does.",
  "platform": ["jetson", "pi"],
  "configFile": "config.toml",
  "visible": true,
  "requires_sudo": false,
  "env_var": "INSTALL_SERVICE_NAME",
  "install_script": "install.sh",
  "install_files": ["main_binary_or_script"]
}
```

- **platform** — Which targets this service supports (`["jetson"]`, `["pi"]`, or `["jetson", "pi"]`)
- **visible** — Whether the service appears in the ARK UI
- **requires_sudo** — Whether the systemd unit runs as a system service (vs user service)
- **configFile** — If set, the UI exposes a config editor for this service

### Systemd Integration

- User services: `/etc/systemd/user/<service>.service`
- System services (requires_sudo): `/etc/systemd/system/<service>.service`
- All services auto-start on boot via `WantedBy=default.target`
- service-manager controls lifecycle via `systemctl --user` commands

## Frontend

- **Vue.js SPA** built with `npm run build`, served as static files by nginx
- **nginx** handles reverse proxying, CORS, WebSocket upgrades, and access logging
- Proxy config split into reusable snippets: `ark-proxy.conf` (HTTP) and `ark-ws.conf` (WebSocket)
- Source: `frontend/ark-ui/`
- Served from: `/var/www/ark-ui/html/`

## Packaging & Deployment

Services are distributed as Debian packages (`.deb`) built with [nfpm](https://nfpm.goreleaser.com/).

### Install Paths

| Content | Path |
|---------|------|
| Binaries & scripts | `/opt/ark/bin/` |
| Default configs | `/opt/ark/share/<service>/` |
| Systemd units (user) | `/etc/systemd/user/` |
| Systemd units (system) | `/etc/systemd/system/` |
| Frontend | `/var/www/ark-ui/html/` |
| Nginx config | `/etc/nginx/sites-available/ark-ui` |

### Package Lifecycle

```bash
sudo dpkg -i ark-<service>_1.0.0_arm64.deb   # Install (postinst enables + starts)
sudo dpkg -i ark-<service>_1.1.0_arm64.deb   # Update (same command)
sudo dpkg -r ark-<service>                     # Remove (prerm stops + disables)
```

### CI/CD

GitHub Actions pipeline (`.github/workflows/build.yml`):
1. **Lint** — ruff on Python services
2. **Build** — Cross-compile C++ for ARM64, package Python services, build frontend
3. **Release** — Attach `.deb` artifacts to GitHub Release on version tags

Package definitions: `packaging/ark-<name>.yaml`

## Adding a New Service

1. Create `services/<name>/` with your code
2. Create `<name>.manifest.json` following the schema above
3. Create `install.sh` for legacy installation
4. Create a systemd unit file
5. Add `packaging/ark-<name>.yaml` for Debian packaging
6. Add postinst/prerm scripts in `packaging/scripts/`
7. The service will be auto-discovered by service-manager via its manifest
