#!/usr/lib/ark-os/venv/bin/python3
"""Pulse FMU_RST_REQ and give USB CDC time to re-enumerate in the bootloader.

VBUS_SENSE_BOOTLOADER is held high by a DT hog on this carrier, so unlike
Jetson and Pi there is no VBUS line to raise here -- see vbus_enable.py.
"""
import sys
import time

from fmu_gpio import pulse_fmu_reset


def main() -> int:
    where = pulse_fmu_reset(hold_s=0.1)
    print(f"Resetting Flight Controller into bootloader! (FMU_RST_REQ on {where})")
    time.sleep(0.5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
