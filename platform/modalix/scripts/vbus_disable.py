#!/usr/lib/ark-os/venv/bin/python3
"""Modalix / JAJ: VBUS_SENSE is held high by a DT hog, so this is a no-op.

See vbus_enable.py for why the level cannot be driven from a helper that exits.
Nothing in ARK-OS calls this on any platform today; it exists so the flash and
mavlink-router paths stay callable across platforms.
"""
import sys


def main() -> int:
    print("Modalix: VBUS_SENSE is held high by the carrier overlay; nothing to do")
    return 0


if __name__ == "__main__":
    sys.exit(main())
