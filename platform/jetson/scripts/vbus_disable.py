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
vbus_det_pin = 32

def main():
    # Check Jetpack version. R36 can't use VBUS Enable
    with open("/etc/nv_tegra_release") as f:
        jetpack_version = f.read()
    if "R36" in jetpack_version:
        print("Jetpack version is R36, skipping VBUS Disable")
        return

    # Pin Setup:
    GPIO.setmode(GPIO.BOARD)  # BCM pin-numbering scheme from Raspberry Pi
    # set pin as an output pin with optional initial state of HIGH
    GPIO.setup(vbus_det_pin, GPIO.OUT, initial=GPIO.HIGH)

    value = GPIO.LOW
    print("Outputting {} to pin {}".format(value, vbus_det_pin))
    GPIO.output(vbus_det_pin, value)

if __name__ == '__main__':
    main()
