#!/bin/bash
# Dev extra: ROS 2 Humble + the JP6 workspace. Humble has no noble packages;
# on JetPack 7 / Ubuntu 24.04 use ROS 2 Jazzy instead and do not clone
# ros2_jetpack6_ws.
if [ -r /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    if [ "${VERSION_CODENAME:-}" = "noble" ]; then
        echo "ERROR: extras/install_ros2.sh installs ROS 2 Humble (Jammy / JetPack 6)." >&2
        echo "       JetPack 7 is Ubuntu 24.04 — install ROS 2 Jazzy by hand." >&2
        exit 1
    fi
fi
sudo apt update
sudo apt-get install software-properties-common
sudo add-apt-repository universe
sudo apt-get install curl -y
sudo curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key -o /usr/share/keyrings/ros-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] http://packages.ros.org/ros2/ubuntu $(. /etc/os-release && echo $UBUNTU_CODENAME) main" | sudo tee /etc/apt/sources.list.d/ros2.list > /dev/null
sudo apt update
sudo apt upgrade
sudo apt-get install ros-humble-ros-base ros-dev-tools
sudo apt-get install -y ros-humble-cv-bridge ros-humble-vision-opencv ros-humble-aruco-opencv

# Add to bashrc if necessary
BASHRC="$HOME/.bashrc"
ROS2_SOURCE="source /opt/ros/humble/setup.bash"
exists=$(cat $BASHRC | grep "$ROS2_SOURCE")
if [ -z "$exists" ]; then
	echo $ROS2_SOURCE >> $BASHRC
fi

echo "WARNING: install opencv from source first! Run:  ./install_opencv.sh"

# Download ARK ros2_ws
git clone --recurse-submodules https://github.com/ARK-Electronics/ros2_jetpack6_ws.git ~/code/ros2_jetpack6_ws
cd ~/code/ros2_jetpack6_ws
sudo rosdep init
rosdep update
rosdep install -r --from-paths src -i -y --rosdistro humble
colcon build
