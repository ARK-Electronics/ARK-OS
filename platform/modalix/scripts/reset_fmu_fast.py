#!/usr/lib/ark-os/venv/bin/python3
"""Modalix / JAJ: FMU nRESET is not mapped like Jetson BOARD pin 33 yet.

USB bootloader entry still works if the FC exposes the ARK CDC interface.
This helper exits 0 so call sites do not hard-fail; operators can use a
hardware reset or map a Modalix GPIO later.
"""
import sys


def main() -> int:
    print("Modalix: reset_fmu_fast is a no-op until nRESET GPIO is mapped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
