#!/bin/bash
systemctl stop "hotspot-updater.service" 2>/dev/null || true
systemctl disable "hotspot-updater.service" 2>/dev/null || true
