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

import Jetson.GPIO as GPIO
import os
import time

# Pin definitions at:
# ark_jetson_orin_nano_nx_device_tree/Linux_for_Tegra/source/hardware/nvidia/
#   t23x/nv-public/include/platforms/dt-bindings/tegra234-p3767-0000-common.h

vbus_det_pin = 32

def main():
    # Check Jetpack version. R36 can't use VBUS Enable
    with open("/etc/nv_tegra_release") as f:
        jetpack_version = f.read()
    if "R36" in jetpack_version:
        print("Jetpack version is R36, skipping VBUS Enable")
        return

    # Configure VBUS_SENSE_BOOTLOADER
    GPIO.setmode(GPIO.BOARD)
    GPIO.setup(vbus_det_pin, GPIO.OUT, initial=GPIO.HIGH)

    value = GPIO.HIGH
    print("Outputting {} to pin {}".format(value, vbus_det_pin))
    GPIO.output(vbus_det_pin, value)

if __name__ == '__main__':
    main()
