# Modalix platform (SiMa eLxr + ARK JAJ / PAB V3)

ARK-OS as a **Debian package** for SiMa **Modalix** SoM running **eLxr 12 (aria)** —
**ARK Just a Jetson** or **ARK Jetson PAB Carrier V3** with Modalix.

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
- **FMU reset:** `reset_fmu_fast.py` / `reset_fmu_wait_bl.py` pulse gpio
  `fmu_rst_req` (PAB V3 SODIMM 228 / SIO7[5], active-high). Overlay must
  **not** hog that line. VBUS_SENSE stays hogged high for USB CDC.  

## Autopilot link

mavlink-router still prefers `/dev/serial/by-id/*ARK*if00` (USB FC). That path is
the same as Jetson when the flight controller is USB.

**uXRCE-DDS defaults to Ethernet, not UART.** Modalix UART1/Telem2 is not usable,
so the packaged `dds-agent.toml` starts `MicroXRCEAgent udp4 -p 8888`. Change
transport and port from the Services tab. On the flight controller
set `UXRCE_DDS_CFG` to Ethernet, `UXRCE_DDS_PRT` to match the agent port, and
`UXRCE_DDS_AG_IP` to the companion address the FC can reach (factory FC is
`192.168.0.4` on the PAB V3 KSZ — add `192.168.0.1/24` on the SoM `end0`, or DHCP
the FC onto the same LAN as the SoM).

## Board power / unique ID

Prefer meta-ark-simaai’s `ark-jaj-sys-power` (INA238 + AT24CSW010 on I2C1) when that
image layer is present:

```bash
cat /run/ark-jaj/sys-power/voltage_uV
cat /run/ark-jaj/board/unique_id
```
