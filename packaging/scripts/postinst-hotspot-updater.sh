#!/bin/bash
systemctl daemon-reload
systemctl enable "hotspot-updater.service"
systemctl restart "hotspot-updater.service"
