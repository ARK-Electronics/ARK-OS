#!/bin/bash
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
