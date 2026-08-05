#!/usr/lib/ark-os/venv/bin/python3
"""Modalix / JAJ: VBUS detect is not Jetson-board-GPIO-driven. No-op."""
import sys


def main() -> int:
    print("Modalix: vbus_disable is a no-op (no Jetson VBUS GPIO path)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
