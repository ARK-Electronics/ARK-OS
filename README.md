# About
ARK-OS is a collection of software services and tools for drones. These services provide essential features such as mavlink routing, video streaming, automatic flight log upload, flight controller firmware updating, network RTK corrections, and more.

#### Supported targets
- **ARK Jetson Carrier** <br> https://arkelectron.com/product/ark-jetson-pab-carrier/
- **ARK Pi6X Flow** <br> https://arkelectron.com/product/ark-pi6x-flow/

# Getting started
If you haven't set up an internet connection on your device, ssh in and connect to your wifi network.
```
ssh <user>@<hostname>.local
```

| User   | Password | Hostname |
|--------|----------|----------|
| jetson | jetson   | jetson   |
| pi     | pi       | pi6x     |

Connect to your WiFi network using Network Manager
```
sudo nmcli dev wifi connect <ssid> password <password>
```

# Installation

ARK-OS is distributed as a Debian package on the [Releases page](https://github.com/ARK-Electronics/ARK-OS/releases). Install the matching MAVSDK runtime first (ARK-OS depends on it) — MAVSDK lives on the [upstream MAVSDK releases](https://github.com/mavlink/MAVSDK/releases), there is no apt repository to subscribe to. Replace `<mavsdk-ver>` and `<ark-os-ver>` with the current pinned versions.

### Jetson
```
wget https://github.com/mavlink/MAVSDK/releases/download/v<mavsdk-ver>/libmavsdk-dev_<mavsdk-ver>_debian12_arm64.deb
wget https://github.com/ARK-Electronics/ARK-OS/releases/download/v<ark-os-ver>/ark-os-jetson_<ark-os-ver>_arm64.deb

sudo apt install ./libmavsdk-dev_<mavsdk-ver>_debian12_arm64.deb
sudo apt install ./ark-os-jetson_<ark-os-ver>_arm64.deb
```

### Raspberry Pi
Identical, replacing `ark-os-jetson` with `ark-os-pi`:
```
wget https://github.com/mavlink/MAVSDK/releases/download/v<mavsdk-ver>/libmavsdk-dev_<mavsdk-ver>_debian12_arm64.deb
wget https://github.com/ARK-Electronics/ARK-OS/releases/download/v<ark-os-ver>/ark-os-pi_<ark-os-ver>_arm64.deb

sudo apt install ./libmavsdk-dev_<mavsdk-ver>_debian12_arm64.deb
sudo apt install ./ark-os-pi_<ark-os-ver>_arm64.deb
```

### Updating
Download the newer `.deb` from the Releases page and `sudo apt install ./ark-os-<platform>_<ver>_arm64.deb`. **Upgrading resets the per-service configuration under `/etc/ark-os/` to packaged defaults** — reconfigure via the web UI afterward.

### Migrating from a source install
Installing the package on a device that was set up with the old `install.sh` flow migrates it automatically: the legacy user services and binaries are removed and your previous configs are backed up to `~/.config/ark-os-legacy-backup/`. **Reboot after installing** so no stale user-session services keep holding the autopilot UART / MAVLink ports.

### Building Jetson images
To install ARK-OS into a Jetson image during an `ark_jetson_kernel --provision` build (chroot), see `packaging/PLAN.md` Task 9.

## ARK-UI
A web based UI is provided to more easily manage your device. The webpage is hosted with nginx and is available at http://jetson.local or http://pi6x.local.

![alt text](ark-ui1.png)
![alt text](ark-ui2.png)
![alt text](ark-ui3.png)
![alt text](ark-ui4.png)

## Services
The package installs the services below as system-level [systemd services](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) running as the unprivileged platform user (`jetson` or `pi`). The always-on services are enabled automatically; the optional services (`dds-agent`, `logloader`, `polaris`, `flight-review`, `rid-transmitter`) are installed but disabled — enable them from the web UI or with `systemctl enable --now <service>`.

## Jetson and Pi

**mavlink-router.service** <br>
This service enables mavlink-router to route mavlink packets from the flight controller USB port to user defined UDP endpoints. You can add and remove endpoints using the service configuration enditor in the UI.

**dds-agent.service** <br>
The dds-agent service bridges the PX4 uORB and ROS2 topics. The bridged topics are defined in PX4 Firmware and can be [found here](https://github.com/PX4/PX4-Autopilot/blob/main/src/modules/uxrce_dds_client/dds_topics.yaml). The **dds-agent** runs the [micro-xrce-dds-agent](https://github.com/eProsima/Micro-XRCE-DDS-Agent) over the high speed serial connection between flight controller and Companion.

**logloader.service** <br>
This service downloads log files from the SD card of the flight controller via MAVLink and optionally uploads them to [PX4 Flight Review](https://review.px4.io/).

**flight-review.service** <br>
This service hosts a local PX4 Flight Review server on port 5006. All logloader downloaded logs are available here.

**rtsp-server.service** <br>
This service provides an RTSP server via gstreamer. The stream from the first connected CSI camera can be accessed by default at `rtsp://<hostname>.local:5600/camera1`.

**polaris.service** <br>
This service receives RTCM corrections from the PointOne GNSS Corrections service and publishes them to the flight controller via MAVLink.

**ark-ui-backend.service** <br>
This service provides an API gateway for the ARK UI.

**system-manager.service** <br>
This service provides a REST API for linux system management via the ARK UI.

**autopilot-manager.service** <br>
This service provides a REST API for autopilot management via the ARK UI.

**connecton-manager.service** <br>
This service provides a REST API for connection management via the ARK UI.

**service-manager.service** <br>
This service provides a REST API for systemd service management via the ARK UI.

### Jetson only

**rid-transmitter.service** <br>
This service starts the RemoteIDTransmitter service which broadcasts RemoteID data via Bluetooth.

**jetson-can.service** <br>
This service enables the Jetson CAN interface.
