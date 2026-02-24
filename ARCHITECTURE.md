# ARK-OS Architecture

## Overview

ARK-OS is a modular collection of services for drone companion computers. It runs on
ARK Electronics platforms (ARK Jetson Carrier, ARK Pi6X Flow) and can also be used on
Ubuntu desktop machines for development and testing. It provides mavlink routing, video
streaming, flight log management, firmware updates, RTK corrections, remote ID, and a
web-based management UI.

### Design Principles

- **Modular** — Each service is independent. Install only what you need.
- **Simple** — No orchestration frameworks. Just systemd, nginx, and straightforward
  REST APIs.
- **Extensible** — Adding a new service means adding a directory, a manifest, and an
  entry in `packages.yaml`. The system discovers and manages it automatically.
- **Consistent** — Every service follows the same structure: code, manifest, and
  generated systemd unit. All services are packaged and installed as `.deb` packages.

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
                   │
          ┌────────┴────────┐
          │ USB (MAVLink)   │ High-speed UART (DDS)
          ▼                 ▼
┌──────────────────────────────────────────────────────┐
│  Flight Controller (PX4)                             │
└──────────────────────────────────────────────────────┘
```

## Platforms

ARK-OS supports three platforms:

| Platform | Description | Typical use |
|----------|-------------|-------------|
| `jetson` | NVIDIA Jetson (ARK Jetson Carrier) | Production flight computer |
| `pi` | Raspberry Pi (ARK Pi6X Flow) | Production flight computer |
| `ubuntu` | Ubuntu desktop/laptop | Development and testing |

Each service declares which platforms it supports in its manifest (`platform` field).
The special value `"all"` means the service runs on all platforms including ubuntu.

## Services

| Service | Type | Port | Platform | Purpose |
|---------|------|------|----------|---------|
| mavlink-router | C++ | — | all | Routes MAVLink from FC USB to UDP endpoints |
| dds-agent | C++ | — | jetson, pi, ubuntu | Bridges PX4 uORB ↔ ROS2 topics over serial/UDP |
| logloader | C++ | — | jetson, pi, ubuntu | Downloads flight logs from FC, uploads to review servers |
| flight-review | Custom | 5006 | jetson, pi, ubuntu | Local PX4 Flight Review server |
| rtsp-server | C++ | 5600 | all | RTSP video stream from CSI cameras |
| polaris | C++ | — | jetson, pi, ubuntu | RTK corrections via PointOne GNSS service |
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
├── <code files>                   # Python script, C++ source, or bash script
└── config.toml (optional)         # Default configuration
```

Systemd unit files are **generated** by `packaging/generate.py` from `packages.yaml` —
they are not stored in the service directory.

### Manifest Schema

The manifest tells service-manager how to discover and present the service:

```json
{
  "version": "1.0.0",
  "displayName": "Human Readable Name",
  "description": "What this service does.",
  "platform": ["jetson", "pi", "ubuntu"],
  "configFile": "config.toml",
  "visible": true,
  "requires_sudo": false,
  "env_var": "INSTALL_SERVICE_NAME",
  "install_script": "",
  "install_files": []
}
```

- **platform** — Which targets this service supports. Values: `"jetson"`, `"pi"`,
  `"ubuntu"`, or `"all"` (shorthand for all platforms)
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

All services are distributed as Debian packages (`.deb`) built with [nfpm](https://nfpm.goreleaser.com/).
This is the **only** install method — both CI/CD and local development use deb packages.

### Package Definitions

All packages are defined in `packaging/packages.yaml`. Running `python3 packaging/generate.py`
produces nfpm configs, systemd units, and install/remove scripts in `packaging/generated/`.

### Install Paths

| Content | Path |
|---------|------|
| Binaries & scripts | `/opt/ark/bin/` |
| Default configs | `/opt/ark/share/<service>/` |
| Systemd units (user) | `/etc/systemd/user/` |
| Systemd units (system) | `/etc/systemd/system/` |
| Frontend | `/var/www/ark-ui/html/` |
| Nginx config | `/etc/nginx/sites-available/ark-ui` |

### Local Development

Use `service_control.sh` to build, package, and install services locally:

```bash
./tools/service_control.sh install service-manager   # Single service
./tools/service_control.sh install                    # All platform-appropriate services
./tools/service_control.sh uninstall service-manager  # Remove
./tools/service_control.sh list                       # Show available + installed
./tools/service_control.sh status                     # Show systemd status
```

This requires `nfpm` to be installed locally.

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

## Adding a New Service

1. Create `services/<name>/` with your code
2. Create `<name>.manifest.json` following the schema above
3. Add an entry in `packaging/packages.yaml` defining the service type, dependencies, and systemd config
4. Run `python3 packaging/generate.py` to generate packaging files
5. The service will be auto-discovered by service-manager via its manifest
