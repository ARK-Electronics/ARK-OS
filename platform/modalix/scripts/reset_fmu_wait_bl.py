#!/usr/lib/ark-os/venv/bin/python3
"""Pulse FMU_RST_REQ and leave VBUS_SENSE high so USB CDC catches the bootloader.

PAB V3 VBUS_SENSE_BOOTLOADER is a DT hog output-high (FMU USB). Same reset
pulse as reset_fmu_fast; USB stays enumerated for px_uploader.
"""
import sys
import time

from fmu_gpio import pulse_fmu_reset


def main() -> int:
    chip = pulse_fmu_reset(hold_s=0.1)
    print(f"Resetting Flight Controller into bootloader! ({chip} line 5 FMU_RST_REQ)")
    time.sleep(0.5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
