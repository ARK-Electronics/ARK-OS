#!/usr/lib/ark-os/venv/bin/python3
"""Pulse FMU_RST_REQ (PAB V3 SIO7[5], active-high) to reset the FC."""
import sys
import time

from fmu_gpio import pulse_fmu_reset


def main() -> int:
    chip = pulse_fmu_reset(hold_s=0.1)
    print(f"Resetting Flight Controller! ({chip} line 5 FMU_RST_REQ)")
    time.sleep(0.2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
