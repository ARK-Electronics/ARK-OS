#!/usr/lib/ark-os/venv/bin/python3

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

# GPIO is driven via the Raspberry Pi `pinctrl` tool (raspi-utils) rather than a
# Python GPIO library. The carrier ships either a CM4 or a CM5: classic RPi.GPIO
# memory-maps the SoC registers and cannot reach the CM5's RP1 I/O controller,
# while gpiochip-based libraries release the line (reverting the pin) when the
# process exits. pinctrl writes the pad register directly and the level PERSISTS
# after exit on both CM4 and CM5 -- required here, since this helper drives the
# line and returns while mavlink-router keeps running. Pin numbers are BCM.

import subprocess

vbus_det_pin = 27


def pinctrl_set(pin, *args):
    subprocess.run(["pinctrl", "set", str(pin), *args], check=True)


def main():
    print(f"Driving VBUS-detect (GPIO{vbus_det_pin}) high")
    pinctrl_set(vbus_det_pin, "op", "dh")


if __name__ == '__main__':
    main()
