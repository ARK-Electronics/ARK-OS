#!/usr/lib/ark-os/venv/bin/python3
"""Modalix / JAJ: VBUS detect is a SoM hog (input), not a Jetson board pin.

FC flashing over USB does not need the Jetson VBUS GPIO dance. This is a
no-op so mavlink-router / flash helpers stay callable on Modalix.
"""
import sys


def main() -> int:
    print("Modalix: vbus_enable is a no-op (no Jetson VBUS GPIO path)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
