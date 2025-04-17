#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

echo "Installing micro-xrce-dds-agent"

service_uninstall dds-agent

sudo snap install micro-xrce-dds-agent --edge

service_add_manifest dds-agent

service_install dds-agent
