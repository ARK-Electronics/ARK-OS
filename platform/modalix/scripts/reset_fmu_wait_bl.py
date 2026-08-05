#!/usr/lib/ark-os/venv/bin/python3
"""Modalix / JAJ: FMU nRESET not mapped like Jetson. No-op success.

Prefer USB bootloader mode (hold boot button) when flashing until a
Modalix GPIO reset path is implemented.
"""
import sys


def main() -> int:
    print("Modalix: reset_fmu_wait_bl is a no-op until nRESET GPIO is mapped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
