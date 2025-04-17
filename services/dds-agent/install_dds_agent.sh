#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

echo "Installing micro-xrce-dds-agent"

sudo snap install micro-xrce-dds-agent --edge
