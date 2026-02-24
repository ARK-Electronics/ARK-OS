#!/bin/bash
systemctl stop "jetson-can.service" 2>/dev/null || true
systemctl disable "jetson-can.service" 2>/dev/null || true
