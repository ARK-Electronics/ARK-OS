#!/usr/bin/env python3

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
import sys


def detect_platform():
    try:
        with open("/proc/device-tree/model") as f:
            model = f.read()
        if "NVIDIA" in model:
            return "jetson"
        if "Raspberry Pi" in model:
            return "pi"
    except FileNotFoundError:
        pass
    return "ubuntu"


def disable_jetson():
    import Jetson.GPIO as GPIO

    vbus_det_pin = 32

    with open("/etc/nv_tegra_release") as f:
        jetpack_version = f.read()
    if "R36" in jetpack_version:
        print("Jetpack version is R36, skipping VBUS Disable")
        return

    GPIO.setmode(GPIO.BOARD)
    GPIO.setup(vbus_det_pin, GPIO.OUT, initial=GPIO.HIGH)
    value = GPIO.LOW
    print("Outputting {} to pin {}".format(value, vbus_det_pin))
    GPIO.output(vbus_det_pin, value)


def disable_pi():
    import RPi.GPIO as GPIO

    vbus_det_pin = 27

    GPIO.setwarnings(False)
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(vbus_det_pin, GPIO.OUT, initial=GPIO.HIGH)
    value = GPIO.LOW
    print("Outputting {} to pin {}".format(value, vbus_det_pin))
    GPIO.output(vbus_det_pin, value)


def main():
    platform = detect_platform()
    if platform == "jetson":
        disable_jetson()
    elif platform == "pi":
        disable_pi()
    else:
        print("VBUS disable not supported on platform: {}".format(platform))
        sys.exit(0)


if __name__ == "__main__":
    main()
