#!/bin/bash
systemctl daemon-reload
systemctl enable "jetson-can.service"
systemctl restart "jetson-can.service"
