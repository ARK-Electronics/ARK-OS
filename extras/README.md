# extras

Standalone convenience scripts for a **developer workstation**. Nothing here is
invoked by the ARK-OS `.deb` build (`packaging/`) or by the package's install
scripts — these are not shipped in the package and are safe to ignore for a
normal install.

They are kept in the repo because they encode non-trivial, Jetson-specific build
flags and sensor register maps that would be expensive to rediscover.

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
