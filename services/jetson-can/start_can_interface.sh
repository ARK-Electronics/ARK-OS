#!/bin/bash
sudo modprobe mttcan
sudo ip link set can0 down
sudo ip link set can0 up type can bitrate 1000000 dbitrate 1000000 sample-point 0.875 restart-ms 100 fd on
