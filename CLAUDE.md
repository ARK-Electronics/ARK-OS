# ARK-OS

Modular drone companion computer platform by ARK Electronics. Runs on ARK Jetson
Carrier, ARK Pi6X Flow, and Ubuntu desktop (dev/test). Provides MAVLink routing,
video streaming, flight log management, firmware updates, RTK corrections, RemoteID,
and a web-based management UI.

**Architecture details**: [`ARCHITECTURE.md`](ARCHITECTURE.md)
**Improvement roadmap**: [`claude_plan/CLAUDE.md`](claude_plan/CLAUDE.md)

## Design Principles

- **Modular** — Each service is an independent systemd unit + deb package
- **Simple** — systemd + nginx + REST APIs, no orchestration frameworks
- **Manifest-driven** — `packages.yaml` is the single source of truth for packaging
- **Consistent** — Every service follows the same structure: code, manifest, generated unit

## Key Conventions

### Source of Truth

- **`packaging/packages.yaml`** defines all deb packages, dependencies, systemd config, and
  install paths. Run `python3 packaging/generate.py` to regenerate nfpm configs, systemd
  units, and install/remove scripts.
- **`<service>.manifest.json`** in each service directory defines UI metadata (display name,
  platform support, config file, visibility).

### Install Paths (deb packages)

| Content | Path |
|---------|------|
| Binaries & scripts | `/opt/ark/bin/` |
| Default configs | `/opt/ark/share/<service>/` |
| Systemd units (user) | `/etc/systemd/user/` |
| Systemd units (system) | `/etc/systemd/system/` |
| Frontend | `/var/www/ark-ui/html/` |
| Nginx config | `/etc/nginx/sites-available/ark-ui` |

### Config Path Strategy

Services use a two-tier config lookup:
1. **User config** at `~/.config/ark/<service>/config.toml` — writable, persists across upgrades
2. **Default config** at `/opt/ark/share/<service>/config.toml` — installed by deb, read-only

Services that write runtime state (e.g. logloader's SQLite DB) use
`~/.local/share/ark/<service>/` as a writable data directory.

## Repository Layout

```
ARK-OS/
├── services/               # All 13 services (Python, C++, Bash)
├── frontend/               # Vue.js SPA + nginx config
├── packaging/              # packages.yaml, generate.py, build scripts
├── platform/               # Platform-specific scripts and configs
│   ├── common/             # Shared across all platforms
│   ├── jetson/             # NVIDIA Jetson specific
│   └── pi/                 # Raspberry Pi specific
├── tools/                  # service_control.sh, install_software.sh
├── libs/                   # External libraries (mavsdk-examples)
├── tests/                  # Test files
├── ARCHITECTURE.md         # Full architecture documentation
├── VERSION                 # Current version (used by CI)
└── default.env             # Default env vars for legacy install
```

## Services

| Service | Type | Port | Platform | Purpose |
|---------|------|------|----------|---------|
| mavlink-router | C++ | — | all | Routes MAVLink from FC to UDP endpoints |
| dds-agent | C++ | — | all | Bridges PX4 uORB ↔ ROS2 topics |
| logloader | C++ | — | all | Downloads flight logs, uploads to review servers |
| flight-review | Custom | 5006 | all | Local PX4 Flight Review server |
| rtsp-server | C++ | 5600 | all | RTSP video stream from CSI cameras |
| polaris | C++ | — | all | RTK corrections via PointOne GNSS |
| service-manager | Python | 3002 | all | REST API: systemd service management |
| system-manager | Python | 3004 | all | REST API: system management |
| autopilot-manager | Python | 3003 | all | REST API: flight controller management |
| connection-manager | Python | 3001 | all | REST API: network management |
| rid-transmitter | C++ | — | jetson | RemoteID broadcast via Bluetooth |
| jetson-can | Bash | — | jetson | Enables Jetson CAN bus interface |
| hotspot-updater | Bash | — | all | Updates default WiFi hotspot name |

## Submodule Ownership

| Submodule | Owner | Editable? |
|-----------|-------|-----------|
| `services/logloader/logloader` | ARK | Yes |
| `services/polaris/polaris-client-mavlink` | ARK | Yes |
| `services/rid-transmitter/RemoteIDTransmitter` | ARK | Yes |
| `services/rtsp-server/rtsp-server` | ARK | Yes |
| `libs/mavsdk-examples` | ARK | Yes |
| `services/flight-review/flight_review` | PX4 (upstream) | No |
| `services/dds-agent/Micro-XRCE-DDS-Agent` | eProsima (upstream) | No |
| `services/mavlink-router/mavlink-router` | upstream | No |

## Install Workflows

### 1. Source Build (development)

For developers working on the codebase. Requires `nfpm` installed locally.

```bash
git clone --recurse-submodules https://github.com/ARK-Electronics/ARK-OS.git
cd ARK-OS
./tools/service_control.sh install              # Build + install all services
./tools/service_control.sh install logloader     # Single service
./tools/service_control.sh status               # Check running services
```

### 2. Deb Download (PR testing)

Download `.deb` artifacts from a GitHub Actions CI run to test a PR.

```bash
# Download debs from the GitHub Actions artifacts for the PR
sudo dpkg -i ark-*.deb
```

### 3. APT Upgrade (end users)

*Not yet implemented* — see [`claude_plan/P1-apt-repository.md`](claude_plan/P1-apt-repository.md).
Once the APT repository is set up:

```bash
sudo apt update && sudo apt upgrade
```

## Common Tasks

```bash
# Regenerate packaging files after editing packages.yaml
python3 packaging/generate.py

# Build all deb packages locally
./packaging/build-packages.sh

# Lint Python services
ruff check services/

# Run frontend dev server
cd frontend/ark-ui/ark-ui && npm run serve

# Check service logs
journalctl --user -u logloader -f
```

## Platform Details

| Platform | Hostname | User | Hardware |
|----------|----------|------|----------|
| jetson | jetson.local | jetson | ARK Jetson Carrier |
| pi | pi6x.local | pi | ARK Pi6X Flow |
| ubuntu | — | — | Desktop/laptop (dev) |

## Build Notes

- C++ services: CMake (or Meson for mavlink-router), cross-compiled for ARM64 in CI
- C++ flags: `-Wall -Wextra -Werror -Wpedantic`, C++20
- Python: 3.9+, linted with ruff
- Frontend: Vue.js SPA, built with npm, served by nginx
- CI: GitHub Actions (`.github/workflows/build.yml`) — lint, build, package, release

## Session Workflow

When starting a new Claude session on this project:
1. Read this file for project context
2. Read `claude_plan/CLAUDE.md` for the current improvement roadmap
3. Check `claude_plan/completed/` for recently finished work

Before ending a session that made changes:
1. Follow the **End-of-Session Checklist** in `claude_plan/CLAUDE.md`
2. Ensure this file, `ARCHITECTURE.md`, and `claude_plan/CLAUDE.md` are all up to date
3. Record completion notes with session IDs so future sessions can retrieve full context

Session transcripts are stored at `~/.claude/projects/-home-jake-code-ark-ARK-OS/<uuid>.jsonl`
