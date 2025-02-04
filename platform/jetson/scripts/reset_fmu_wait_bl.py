#!/usr/bin/env python

# Copyright (c) 2019-2022, NVIDIA CORPORATION. All rights reserved.
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import os

def detect_jetson_model():
    try:
        with open("/proc/device-tree/model", "r") as f:
            model = f.read().lower()
            if "orin nx" in model:
                return "JETSON_ORIN_NX"
            elif "orin nano" in model:
                return "JETSON_ORIN_NANO"
            else:
                print(f"Warning: Unknown Jetson model detected: {model}")
                return None
    except FileNotFoundError:
        print("Warning: Could not detect Jetson model")
        return None

# Detect and set model before importing RPi.GPIO
jetson_model = detect_jetson_model()
if jetson_model:
    os.environ['JETSON_MODEL_NAME'] = jetson_model
    print(f"Detected and set JETSON_MODEL_NAME={jetson_model}")
else:
    print("Could not set JETSON_MODEL_NAME environment variable")

import RPi.GPIO as GPIO
import time

# Pin Definitions
reset_pin = 33  # BCM pin 18, BOARD pin 12
vbus_det_pin = 32

def main():
    jetpack_6 = False

    # Check Jetpack version. R36 can't use VBUS Enable
    with open("/etc/nv_tegra_release") as f:
        jetpack_version = f.read()
    if "R36" in jetpack_version:
        print("Jetpack version is R36, skipping VBUS Control")
        jetpack_6 = True

    # Pin Setup:
    GPIO.setmode(GPIO.BOARD)  # BCM pin-numbering scheme from Raspberry Pi
    # set pin as an output pin with optional initial state of HIGH
    GPIO.setup(reset_pin, GPIO.OUT, initial=GPIO.HIGH)

    if not jetpack_6:
        GPIO.setup(vbus_det_pin, GPIO.OUT, initial=GPIO.HIGH)

    print("Resetting Flight Controller!")

    GPIO.output(reset_pin, GPIO.HIGH)
    time.sleep(0.1)
    GPIO.output(reset_pin, GPIO.LOW)

    if not jetpack_6:
        # Enable VBUS immediatly to catch bootloader and wait
        GPIO.output(vbus_det_pin, GPIO.HIGH)

if __name__ == '__main__':
    main()
