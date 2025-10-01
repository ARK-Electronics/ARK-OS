#!/bin/bash
echo "Installing micro-xrce-dds-agent"
pushd .
cd Micro-XRCE-DDS-Agent
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
sudo ldconfig
popd
