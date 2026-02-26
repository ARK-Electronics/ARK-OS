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

import RPi.GPIO as GPIO
import time
import subprocess
import sys

# Pin Definitions
vbus_det_pin = 27

def main():
    try:
        # Pin Setup:
        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)  # BCM pin-numbering scheme from Raspberry Pi
        # set pin as an output pin with optional initial state of HIGH
        GPIO.setup(vbus_det_pin, GPIO.OUT, initial=GPIO.HIGH)

        value = GPIO.LOW
        print("Outputting {} to pin {}".format(value, vbus_det_pin))
        GPIO.output(vbus_det_pin, value)
    except RuntimeError as e:
        if "Cannot determine SOC peripheral base address" in str(e):
            print("RPi.GPIO failed (likely Pi 5). Trying pinctrl...")
            try:
                # Fallback to pinctrl for Pi 5
                # Set pin to Output High (dh) initially
                subprocess.run(["pinctrl", "set", str(vbus_det_pin), "op", "dh"], check=True)

                value = 0 # LOW
                print("Outputting {} to pin {}".format(value, vbus_det_pin))
                # Set low
                subprocess.run(["pinctrl", "set", str(vbus_det_pin), "op", "dl"], check=True)
            except FileNotFoundError:
                print("Error: pinctrl not found. Cannot control GPIOs.")
                sys.exit(1)
            except subprocess.CalledProcessError as e2:
                print(f"Error running pinctrl: {e2}")
                sys.exit(1)
        else:
            raise e

if __name__ == '__main__':
    main()
