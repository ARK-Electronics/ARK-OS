# extras

Standalone Jetson dev/diagnostic convenience scripts. They are kept separate
from the service and operator scripts in `platform/jetson/scripts/`, but the
`.deb` does install them (Jetson only) to `/usr/lib/ark-os/scripts/extras/`,
which is on PATH for login shells — so a dev can run them by name on the target.
Nothing in the build or the running services invokes them automatically.

They encode non-trivial, Jetson-specific build flags and sensor register maps
that would be expensive to rediscover.

| Script | What it does |
|---|---|
| `install_opencv.sh` | Builds/installs OpenCV with CUDA support on a Jetson dev box. |
| `install_ros2.sh` | Installs ROS 2 on a dev box. |
| `i2s_gpio_example.py` | Example: drive the Jetson I2S/GPIO pins. |
| `icm42688p_driver.py` | Example: read the ICM-42688-P IMU over SPI. |
| `ina238_test.py` | Example: read the INA238 power monitor over I2C/SMBus. |
| `test_jtop.py` | Example: query `jtop` for Jetson telemetry. |

Run them manually on the target as needed; they expect their own dependencies
(OpenCV/ROS toolchains, `spidev`, `smbus2`, `jtop`) to be present.
