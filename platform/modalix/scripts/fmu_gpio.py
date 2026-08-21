#!/usr/lib/ark-os/venv/bin/python3
"""PAB V3 / Modalix FMU_RST_REQ via gpio chardev (SIO7 line 5).

Active-high reset request. Pulse high then leave low. Do not hog this line
in DT so userspace can claim it. Carrier 1V8 pulldown holds idle low.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import glob
import os
import sys
import time

FMU_RST_LINE = 5  # port7 / SIO7[5] = SODIMM 228
GPIOHANDLE_REQUEST_OUTPUT = 1 << 1
GPIO_GET_CHIPINFO_IOCTL = 0x8044B401
GPIO_GET_LINEHANDLE_IOCTL = 0xC16CB403
GPIOHANDLE_SET_LINE_VALUES_IOCTL = 0xC040B409


class gpiochip_info(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 32),
        ("label", ctypes.c_char * 32),
        ("lines", ctypes.c_uint32),
    ]


class gpiohandle_request(ctypes.Structure):
    _fields_ = [
        ("lineoffsets", ctypes.c_uint32 * 64),
        ("flags", ctypes.c_uint32),
        ("default_values", ctypes.c_uint8 * 64),
        ("consumer_label", ctypes.c_char * 32),
        ("lines", ctypes.c_uint32),
        ("fd", ctypes.c_int),
    ]


class gpiohandle_data(ctypes.Structure):
    _fields_ = [("values", ctypes.c_uint8 * 64)]


def find_port7_chip() -> str:
    for path in glob.glob("/sys/bus/gpio/devices/gpiochip*/of_node"):
        real = os.path.realpath(path)
        if "04071000" in real or "4071000.gpio" in real:
            return "/dev/" + os.path.basename(os.path.dirname(path))
    raise FileNotFoundError("SIO7 gpiochip (0x04071000) not found")


def _set_value(handle_fd: int, high: bool) -> None:
    data = gpiohandle_data()
    data.values[0] = 1 if high else 0
    fcntl.ioctl(handle_fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, data, True)


def pulse_fmu_reset(hold_s: float = 0.1) -> str:
    """Assert FMU_RST_REQ for hold_s seconds, then deassert. Returns chip path."""
    chip = find_port7_chip()
    try:
        fd = os.open(chip, os.O_RDONLY | os.O_CLOEXEC)
    except PermissionError as e:
        raise PermissionError(
            f"Cannot open {chip}; need udev root:gpio 0660 and user in group gpio"
        ) from e

    req = gpiohandle_request()
    try:
        info = gpiochip_info()
        fcntl.ioctl(fd, GPIO_GET_CHIPINFO_IOCTL, info, True)
        if info.lines < FMU_RST_LINE + 1:
            raise RuntimeError(f"{chip} has only {info.lines} lines")
        req.lineoffsets[0] = FMU_RST_LINE
        req.flags = GPIOHANDLE_REQUEST_OUTPUT
        req.default_values[0] = 0
        req.consumer_label = b"ark-os-fmu-reset"
        req.lines = 1
        try:
            fcntl.ioctl(fd, GPIO_GET_LINEHANDLE_IOCTL, req, True)
        except OSError as e:
            if e.errno == errno.EBUSY:
                raise RuntimeError(
                    f"{chip} line {FMU_RST_LINE} busy (still hogged in DT?). "
                    "ark-pab-v3.dtbo must name fmu_rst_req without gpio-hog."
                ) from e
            raise
    finally:
        os.close(fd)

    handle = req.fd
    if handle < 0:
        raise RuntimeError(f"{chip} linehandle ioctl returned fd {handle}")
    try:
        _set_value(handle, True)
        time.sleep(hold_s)
        _set_value(handle, False)
    finally:
        os.close(handle)
    return chip


if __name__ == "__main__":
    print(pulse_fmu_reset())
    sys.exit(0)
