# Modalix platform (SiMa eLxr + ARK JAJ)

ARK-OS as a **Debian package** for SiMa **Modalix** SoM running **eLxr 12 (aria)** —
typically **ARK Just a Jetson** with Modalix.

## Not a full OS flash

ARK-OS does **not** replace the SiMa base image. Order of operations:

1. Flash / netboot **SiMa Modalix eLxr** (see [meta-ark-simaai](https://github.com/ARK-Electronics/meta-ark-simaai)
   `docs/bringup-jaj.md`, `deploy-jaj-dtbo.sh`).
2. Deploy `ark-jaj.dtbo` (cameras, I2C, UART, INA238 DT nodes).
3. Build/install **`ark-os-modalix-<codename>_*.deb`** on the board.

## Build

```bash
# On aarch64 with Debian 12/bookworm or eLxr 12/aria (Python 3.11):
./packaging/build.sh modalix --version=0.0.0-modalix

# On x86_64 workstations the arm64 binaries/venv will not run on the SoM.
# Use CI (ubuntu-22.04-arm + debian:bookworm) or an arm64 builder.
```

Package name examples:

- `ark-os-modalix-bookworm_*_arm64.deb` — CI / Debian 12 builders  
- `ark-os-modalix-aria_*_arm64.deb` — native eLxr 12 builders  

`preinst` treats **aria ↔ bookworm** as compatible for modalix only.

## Install on the SoM

```bash
# as root on the device (user must be sima — SiMa default)
sudo ./packaging/install_ark_os.sh --platform=modalix ./ark-os-modalix-bookworm_*.deb
# or:
sudo ./packaging/install_ark_os.sh --platform=modalix --ark-os-version=X.Y.Z
```

- **Service user:** `sima` (not `jetson` / not `modalix`)  
- **No jtop** (Jetson-stats)  
- **No jetson-can** (Modalix has no SoM CAN)  
- **No rid-transmitter** in the first cut  
- **FMU reset / VBUS GPIO helpers** are no-ops until JAJ nRESET is mapped  

## Autopilot link

mavlink-router still prefers `/dev/serial/by-id/*ARK*if00` (USB FC). That path is
the same as Jetson when the flight controller is USB.

## Board power / unique ID

Prefer meta-ark-simaai’s `ark-jaj-sys-power` (INA238 + AT24CSW010 on I2C1) when that
image layer is present:

```bash
cat /run/ark-jaj/sys-power/voltage_uV
cat /run/ark-jaj/board/unique_id
```
