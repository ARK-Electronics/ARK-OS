#!/bin/bash

echo "Installing logloader"

# Clean up directories
pushd .
cd logloader
make install
sudo ldconfig
popd

