#!/usr/lib/ark-os/venv/bin/python3
"""PAB V3 / Modalix FMU_RST_REQ over the gpio character device.

Active-high reset request: drive high, then release so the carrier's 1V8
pulldown returns the line low. The line must not be hogged in DT, or userspace
cannot claim it.

Two backends. libgpiod's gpioset is preferred and is a package dependency on
modalix; the ctypes ioctl path is the fallback for a host whose tools are
missing or speak libgpiod 2.x, which dropped the v1 flags used here. Set
ARK_GPIO_BACKEND=gpiod or =ioctl to pin one during bring-up.

The line is looked up by its DT name, so the carrier overlay decides which pin
this is. FMU_RST_LINE below is only the fallback for an overlay that does not
name it.
"""
from __future__ import annotations

import ctypes
import errno
import fcntl
import glob
import os
import shutil
import subprocess
import sys
import time

FMU_RST_LINE_NAME = "fmu_rst_req"
FMU_RST_CHIP_ADDR = "04071000"  # SIO7
FMU_RST_LINE = 5                # SIO7[5] = SODIMM 228

GPIOHANDLE_REQUEST_OUTPUT = 1 << 1


class gpiochip_info(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * 32),
        ("label", ctypes.c_char * 32),
        ("lines", ctypes.c_uint32),
    ]


class gpioline_info(ctypes.Structure):
    _fields_ = [
        ("line_offset", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("name", ctypes.c_char * 32),
        ("consumer", ctypes.c_char * 32),
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


def _iowr(nr: int, struct: type[ctypes.Structure], read: bool = True) -> int:
    """Linux _IOR/_IOWR for the 0xB4 (gpio) ioctl family.

    Spelled out rather than pasted as hex so the request numbers cannot drift
    from the structs above.
    """
    direction = 3 if read else 2
    return (direction << 30) | (ctypes.sizeof(struct) << 16) | (0xB4 << 8) | nr


GPIO_GET_CHIPINFO_IOCTL = _iowr(0x01, gpiochip_info, read=False)
GPIO_GET_LINEINFO_IOCTL = _iowr(0x02, gpioline_info)
GPIO_GET_LINEHANDLE_IOCTL = _iowr(0x03, gpiohandle_request)
GPIOHANDLE_SET_LINE_VALUES_IOCTL = _iowr(0x09, gpiohandle_data)


def _chip_line_count(path: str) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = gpiochip_info()
        fcntl.ioctl(fd, GPIO_GET_CHIPINFO_IOCTL, info, True)
        return int(info.lines)
    finally:
        os.close(fd)


def _find_named_line(name: str) -> tuple[str, int] | None:
    """(chip, offset) of the DT-named line, or None if no chip exposes it."""
    target = name.encode()
    for chip in sorted(glob.glob("/dev/gpiochip*")):
        try:
            count = _chip_line_count(chip)
            fd = os.open(chip, os.O_RDONLY | os.O_CLOEXEC)
        except OSError:
            continue
        try:
            for offset in range(count):
                info = gpioline_info()
                info.line_offset = offset
                try:
                    fcntl.ioctl(fd, GPIO_GET_LINEINFO_IOCTL, info, True)
                except OSError:
                    continue
                if info.name == target:
                    return chip, offset
        finally:
            os.close(fd)
    return None


def _find_chip_by_address(address: str) -> str:
    for path in glob.glob("/sys/bus/gpio/devices/gpiochip*/of_node"):
        real = os.path.realpath(path)
        if address in real:
            return "/dev/" + os.path.basename(os.path.dirname(path))
    raise FileNotFoundError(f"gpiochip at 0x{address} not found")


def resolve_fmu_reset_line() -> tuple[str, int]:
    """Locate FMU_RST_REQ, preferring the DT line name over the fixed offset."""
    found = _find_named_line(FMU_RST_LINE_NAME)
    if found is not None:
        return found
    return _find_chip_by_address(FMU_RST_CHIP_ADDR), FMU_RST_LINE


def _pulse_gpioset(chip: str, offset: int, hold_s: float) -> bool:
    """libgpiod 1.x gpioset. False if the tool is absent or rejects the call."""
    if shutil.which("gpioset") is None:
        return False
    argv = [
        "gpioset",
        "--mode=time",
        f"--usec={int(hold_s * 1e6)}",
        os.path.basename(chip),
        f"{offset}=1",
    ]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=hold_s + 5)
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        print(f"gpioset failed ({result.returncode}): {result.stderr.strip()}", file=sys.stderr)
        return False
    return True


def _set_value(handle_fd: int, high: bool) -> None:
    data = gpiohandle_data()
    data.values[0] = 1 if high else 0
    fcntl.ioctl(handle_fd, GPIOHANDLE_SET_LINE_VALUES_IOCTL, data, True)


def _pulse_ioctl(chip: str, offset: int, hold_s: float) -> None:
    try:
        fd = os.open(chip, os.O_RDONLY | os.O_CLOEXEC)
    except PermissionError as e:
        raise PermissionError(
            f"Cannot open {chip}; need udev root:gpio 0660 and the service user in group gpio"
        ) from e

    req = gpiohandle_request()
    try:
        req.lineoffsets[0] = offset
        req.flags = GPIOHANDLE_REQUEST_OUTPUT
        req.default_values[0] = 0
        req.consumer_label = b"ark-os-fmu-reset"
        req.lines = 1
        try:
            fcntl.ioctl(fd, GPIO_GET_LINEHANDLE_IOCTL, req, True)
        except OSError as e:
            if e.errno == errno.EBUSY:
                raise RuntimeError(
                    f"{chip} line {offset} is busy -- still hogged in DT? The carrier "
                    f"overlay must name {FMU_RST_LINE_NAME} without a gpio-hog."
                ) from e
            raise
    finally:
        os.close(fd)

    if req.fd < 0:
        raise RuntimeError(f"{chip} linehandle ioctl returned fd {req.fd}")
    try:
        _set_value(req.fd, True)
        time.sleep(hold_s)
        _set_value(req.fd, False)
    finally:
        os.close(req.fd)


def pulse_fmu_reset(hold_s: float = 0.1) -> str:
    """Assert FMU_RST_REQ for hold_s, then release. Returns "<chip> line <n>"."""
    chip, offset = resolve_fmu_reset_line()
    backend = os.environ.get("ARK_GPIO_BACKEND", "")
    if backend != "ioctl" and _pulse_gpioset(chip, offset, hold_s):
        return f"{chip} line {offset} (gpioset)"
    if backend == "gpiod":
        raise RuntimeError("ARK_GPIO_BACKEND=gpiod but gpioset could not drive the line")
    _pulse_ioctl(chip, offset, hold_s)
    return f"{chip} line {offset} (ioctl)"


if __name__ == "__main__":
    print(pulse_fmu_reset())
