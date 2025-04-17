# About
ARK-OS is a collection of software services and tools for drones. These services provide essential features such as mavlink routing, video streaming, automatic flight log upload, flight controller firmware updating, network RTK corrections, and more.

#### Supported targets
- **ARK Jetson Carrier** <br> https://arkelectron.com/product/ark-jetson-pab-carrier/
- **ARK Pi6X Flow** <br> https://arkelectron.com/product/ark-pi6x-flow/

# Getting started
Clone this repository on the device
```
git clone --recurse-submodules https://github.com/ARK-Electronics/ARK-OS.git
```
Run the install script on the device. You will be prompted y/n to install the services, you can press enter to skip and use the recommended defaults.
```
./install.sh
```
You can skip the interactive prompt by copying the **default.env** file and renaming it **user.env**. You can adjust the options in the **user.env**. This script can be safely run multiple times to update your system.

## ARK-UI
A web based UI is provided to more easily manage your device. The main page shows the status of the services and includes controls to edit their settings, start/stop, and view journal log files. There are also pages to manage your network connections and update the flight controller firmware. The webpage is hosted with nginx and is available at http://jetson.local or http://pi6x.local.

![alt text](ark-ui.png)

## Services
When running the **install.sh** script you will be prompted to install the below services. The services are installed as [systemd user services](https://www.unixsysadmin.com/systemd-user-services/) and conform to the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/index.html).

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
This service provides a REST API for systemd user service management via the ARK UI.

### Jetson only

**rid-transmitter.service** <br>
This service starts the RemoteIDTransmitter service which broadcasts RemoteID data via Bluetooth.

**jetson-can.service** <br>
This service enables the Jetson CAN interface.
