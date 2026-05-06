#!/usr/bin/env python3

# I2S GPIO loopback demo for ARK Jetson Carriers.
#
# Toggles HDR40 pin 40 (I2S0_DOUT) HIGH/LOW/HIGH/LOW and reads each
# transition back on pin 38 (I2S0_DIN). Connect pin 40 to pin 38 with
# a jumper wire before running.
#
# Requires the ARK I2S to GPIO overlay:
#   sudo /opt/nvidia/jetson-io/config-by-hardware.py -n "ARK I2S to GPIO"
#   sudo reboot
#
# Requires Jetson.GPIO >= 2.1.12 (the apt-shipped version doesn't
# recognize the Orin Nano Super and fails with "Could not determine
# Jetson model"). ARK-OS installs this for you; standalone users:
#   sudo pip3 install 'Jetson.GPIO>=2.1.12'

import time
import Jetson.GPIO as GPIO

GPIO.setmode(GPIO.BOARD)
GPIO.setup(40, GPIO.OUT, initial=GPIO.LOW)  # I2S0_DOUT
GPIO.setup(38, GPIO.IN)                     # I2S0_DIN

try:
    for level in (GPIO.HIGH, GPIO.LOW, GPIO.HIGH, GPIO.LOW):
        GPIO.output(40, level)
        time.sleep(0.2)
        got = GPIO.input(38)
        label = "HIGH" if level else "LOW"
        result = "PASS" if got == level else f"FAIL (read {got})"
        print(f"DOUT=40 {label}  DIN=38 {got}  {result}")
finally:
    GPIO.cleanup()
