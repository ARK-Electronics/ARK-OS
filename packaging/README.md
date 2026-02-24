# ARK-OS Packaging

ARK-OS services are packaged as individual `.deb` files. Each service can be installed, updated, and rolled back independently using standard Debian package tools (`dpkg`, `apt`).

## Quick Reference

```bash
# Install a service
sudo dpkg -i ark-autopilot-manager_1.0.0_arm64.deb

# Update a service (same command — installs over the old version)
sudo dpkg -i ark-autopilot-manager_1.1.0_arm64.deb

# Rollback to a previous version
sudo dpkg -i ark-autopilot-manager_1.0.0_arm64.deb

# Remove a service
sudo dpkg -r ark-autopilot-manager

# Install everything at once (meta-package)
sudo dpkg -i ark-companion_1.0.0_arm64.deb
```

## How It Works

All packaging is driven by a single config file and a generator:

```
packaging/
├── packages.yaml        # Single source of truth — all packages declared here
├── generate.py          # Reads packages.yaml + service manifests → generates all configs
├── build-packages.sh    # Calls generate.py, then builds and packages with nfpm
├── Dockerfile.build     # CI build environment (cross-compilation)
├── README.md
└── generated/           # gitignored — produced by generate.py
    ├── ark-*.yaml       # nfpm package configs
    ├── scripts/         # postinst/prerm shell scripts
    └── service-files/   # systemd unit files
```

### Adding a New Service

Add ~5 lines to `packages.yaml`:

```yaml
services:
  my-new-service:
    type: python           # or cpp, bash, custom
    description: "My new service"
    script: my_new_service.py
    depends: [some-package]
```

Then run `python3 generate.py` — it produces the nfpm config, systemd unit, and install/remove scripts automatically.

### Type Defaults

Each service type has sensible defaults (see `generate.py` TYPE_DEFAULTS):

| | `python` | `cpp` | `bash` |
|---|---|---|---|
| depends | `python3, python3-flask` + extras | extras only | extras only |
| exec_start | `python3 /opt/ark/bin/{script}` | `/opt/ark/bin/{binary}` | `/opt/ark/bin/{script}` |
| environment | `PYTHONUNBUFFERED=1` | — | — |
| restart | `on-failure` | `on-failure` | `on-failure` |

Services only specify what differs from the defaults.

## Packages

| Package | Type | Contents |
|---------|------|----------|
| `ark-autopilot-manager` | Python | autopilot_manager.py + systemd unit |
| `ark-connection-manager` | Python | connection_manager.py + systemd unit |
| `ark-service-manager` | Python | service_manager.py + systemd unit |
| `ark-system-manager` | Python | system_manager.py + systemd unit |
| `ark-logloader` | C++ binary | logloader + systemd unit |
| `ark-mavlink-router` | C++ binary | mavlink-routerd + start script + config + systemd unit |
| `ark-polaris` | C++ binary | polaris-client-mavlink + systemd unit |
| `ark-rid-transmitter` | C++ binary | rid-transmitter + systemd unit (Jetson only) |
| `ark-rtsp-server` | C++ binary | rtsp-server + systemd unit |
| `ark-dds-agent` | C++ binary | MicroXRCEAgent + start script + systemd unit |
| `ark-flight-review` | Python app | flight_review app + start script + systemd unit |
| `ark-ui` | Frontend | Vue dist + nginx config + proxy snippets |
| `ark-hotspot-updater` | Bash | update script + systemd unit |
| `ark-jetson-can` | Bash | CAN scripts + systemd unit (Jetson only) |
| **`ark-companion`** | **Meta** | **Depends on all core packages above** |

## Install Paths

Packaged services install to standardized paths:

| What | Path |
|------|------|
| Binaries & scripts | `/opt/ark/bin/` |
| Default configs | `/opt/ark/share/<service>/` |
| Systemd units (user) | `/etc/systemd/user/` |
| Systemd units (root) | `/etc/systemd/system/` |
| Frontend files | `/var/www/ark-ui/html/` |
| Nginx config | `/etc/nginx/sites-available/ark-ui` |

## What Happens on Install/Update

Each `.deb` includes postinst/prerm scripts that automatically:

1. **On install/update (postinst):** reload systemd, enable the service, restart it
2. **On remove (prerm):** stop the service, disable it

You don't need to manually restart services after installing a `.deb`.

## PR Testing Workflow

This is the primary use case for packaging — testing a single service change from a PR without rebuilding everything:

1. Developer pushes a PR that modifies `autopilot-manager`
2. GitHub Actions CI builds `ark-autopilot-manager_1.0.0-pr42_arm64.deb`
3. The `.deb` is attached as a build artifact on the PR
4. Tester downloads it and copies to the device:
   ```bash
   scp ark-autopilot-manager_1.0.0-pr42_arm64.deb user@device:~
   ssh user@device sudo dpkg -i ark-autopilot-manager_1.0.0-pr42_arm64.deb
   ```
5. The service restarts automatically with the new code
6. To rollback: install the previous `.deb` or the stable release version

## Building Packages Locally

### Python/Bash services (no compilation needed)

```bash
cd packaging
python3 generate.py
VERSION=1.0.0 ARCH=arm64 nfpm package --config generated/ark-autopilot-manager.yaml --packager deb --target ../dist/
```

Or use the build script:

```bash
./packaging/build-packages.sh package-python
```

### C++ services (need ARM64 compilation)

On an ARM64 device (Jetson/Pi), you can build natively:

```bash
./packaging/build-packages.sh all
# Packages appear in dist/
```

For cross-compilation (x86 host → ARM64 target), the CI uses Docker + QEMU. See `.github/workflows/build.yml`.

### Frontend

```bash
cd frontend/ark-ui/ark-ui
npm ci && npm run build
mkdir -p build/ark-ui && cp -r dist build/ark-ui/
cd ../../../packaging
python3 generate.py
VERSION=1.0.0 ARCH=arm64 nfpm package --config generated/ark-ui.yaml --packager deb --target ../dist/
```

## How This Relates to the Legacy install.sh

The existing `install.sh` / `tools/install_software.sh` still works and builds everything from source on-device. The `.deb` packages are a parallel, better path:

- **Legacy (`install.sh`):** Clones submodules, compiles on-device, copies files to `~/.local/bin/`. Good for development.
- **Packages (`.deb`):** Pre-built binaries, installs to `/opt/ark/bin/`, managed by dpkg. Good for deployment and updates.

Both can coexist. Once packaging is stable, `install.sh` can become a thin wrapper that installs the `.deb` packages.

## Architecture: What Docker Is For

The `Dockerfile.build` is **not deployed to the device**. It's a CI build environment that contains all the compiler toolchains and libraries needed to cross-compile ARM64 C++ binaries on GitHub's x86 runners. The flow is:

```
GitHub Actions (x86) → Docker + QEMU (emulated ARM64) → compile C++ → nfpm → .deb files → GitHub Release
```

The device only ever sees the final `.deb` files.
