#!/usr/lib/ark-os/venv/bin/python3
"""Modalix / JAJ: VBUS_SENSE is held high by a DT hog, so this is a no-op.

The Jetson and Pi helpers drive a VBUS-detect pin and rely on the level
PERSISTING after the process exits -- Jetson.GPIO writes the pin register and
`pinctrl` writes the pad register. The Modalix SoC has neither; its lines are
reachable only through the gpio character device, which RELEASES a line when
the requesting process exits. A set-and-exit helper therefore cannot hold VBUS,
and mavlink-router calls this one and moves on.

Holding it in DT gives the same end state as the Jetson helper (VBUS asserted
for the FMU's USB CDC), which is also what current Jetsons do: JetPack 6 skips
VBUS control outright. Dropping the hog to drive this from userspace would need
a long-lived unit holding the line open, not a change here.
"""
import sys


def main() -> int:
    print("Modalix: VBUS_SENSE is held high by the carrier overlay; nothing to do")
    return 0


if __name__ == "__main__":
    sys.exit(main())
