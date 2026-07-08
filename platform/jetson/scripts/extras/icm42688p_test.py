#!/usr/bin/env python3
"""icm42688p_test.py — read the ICM-42688-P IMU over SPI (spi1.0) and watch it live.

With no arguments it draws — full-screen, over SSH — live time-series of the three
accelerometer and gyroscope axes plus the die temperature (needs rich + plotext).
With --raw it streams one JSON object per sample to stdout, so the data can be
consumed programmatically. Units: accel m/s^2, gyro rad/s, temp degC.

    icm42688p_test.py                    # live full-screen view; q or Ctrl-C quits
    icm42688p_test.py --raw              # {"timestamp":..., "accel_m_s2":[x,y,z], "gyro_rad_s":[x,y,z], "temp_c":...}
    icm42688p_test.py --raw --count 100  # exactly 100 samples, then exit
    icm42688p_test.py --rate 200         # sample at 200 Hz (either mode)
"""
from __future__ import annotations

import argparse
import contextlib
import json
import sys
import time
from collections import deque

try:
    import spidev
except ImportError as error:
    raise SystemExit(f"icm42688p_test needs spidev: pip3 install spidev  [{error}]")

# The live view is optional — --raw must work without rich/plotext installed.
try:
    import plotext
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
except ImportError as error:
    GUI_IMPORT_ERROR: ImportError | None = error
else:
    GUI_IMPORT_ERROR = None

# SPI Configuration
SPI_BUS = 1     # SPI1
SPI_DEVICE = 0  # CSN0

# Register Constants
WHO_AM_I = 0x75
DEVICE_ID = 0x47

DEVICE_CONFIG = 0x11
SOFT_RESET = 0x01

REG_BANK_SEL = 0x76

# Register Bank 0 (default)
PWR_MGMT0 = 0x4E
GYRO_CONFIG0 = 0x4F
ACCEL_CONFIG0 = 0x50
INT_STATUS = 0x2D
ACCEL_XOUT_H = 0x1F

ACCEL_SCALE = 9.80665 / 2048  # m/s^2 per LSB at +/-16g
GYRO_SCALE = (3.141592653589793 / 180) / 16.4  # rad/s per LSB at +/-2000 dps
TEMP_SCALE = 1 / 132.48  # degC per LSB
TEMP_OFFSET = 25.0

DEFAULT_RATE_HZ = 50.0
DEFAULT_WINDOW_SECONDS = 10.0
REFRESH_PER_SECOND = 10
ACCEL_Y_FLOOR = 12.0  # keeps 1 g at rest well inside the plot
GYRO_Y_FLOOR = 0.5


class ICM42688P:
    def __init__(self):
        self.spi = spidev.SpiDev()
        self.spi.open(SPI_BUS, SPI_DEVICE)
        self.spi.max_speed_hz = 1000000
        self.spi.mode = 0b00
        self._initialize_device()

    def _write_register(self, reg, value):
        self.spi.xfer2([reg & 0x7F, value])  # MSB=0 for write

    def _read_register(self, reg, length=1):
        result = self.spi.xfer2([reg | 0x80] + [0x00] * length)
        return result[1:] if length > 1 else result[1]

    def _select_register_bank(self, bank):
        self._write_register(REG_BANK_SEL, bank << 4)

    def _initialize_device(self):
        self._write_register(DEVICE_CONFIG, SOFT_RESET)
        time.sleep(0.1)
        whoami = self._read_register(WHO_AM_I)
        if whoami != DEVICE_ID:
            raise RuntimeError(f"ICM-42688-P not found! WHO_AM_I={whoami:#x}")

        self._write_register(PWR_MGMT0, 0x0F)  # Enable accel & gyro, low-noise mode
        self._write_register(GYRO_CONFIG0, 0x06)   # 1kHz ODR, +/-2000 dps
        self._write_register(ACCEL_CONFIG0, 0x06)  # 1kHz ODR, +/-16g

    def read(self):
        data = self._read_register(ACCEL_XOUT_H, 14)
        ax = self._combine(data[0], data[1]) * ACCEL_SCALE
        ay = self._combine(data[2], data[3]) * ACCEL_SCALE
        az = self._combine(data[4], data[5]) * ACCEL_SCALE

        gx = self._combine(data[6], data[7]) * GYRO_SCALE
        gy = self._combine(data[8], data[9]) * GYRO_SCALE
        gz = self._combine(data[10], data[11]) * GYRO_SCALE

        temp_c = self._combine(data[12], data[13]) * TEMP_SCALE + TEMP_OFFSET

        return {
            'accel': (ax, ay, az),   # m/s^2
            'gyro': (gx, gy, gz),    # rad/s
            'temp': temp_c,          # degC
        }

    def _combine(self, high, low):
        val = (high << 8) | low
        return val - 65536 if val & 0x8000 else val

    def close(self):
        self.spi.close()


def paced(rate_hz: float):
    """Yield forever at rate_hz, sleeping between iterations; after a stall, resume
    from now rather than bursting to catch up."""
    interval = 1.0 / rate_hz
    next_time = time.monotonic()
    while True:
        yield
        next_time += interval
        delay = next_time - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            next_time = time.monotonic()


# --- raw mode --------------------------------------------------------------------------------------

def run_raw(imu: ICM42688P, rate_hz: float, count: int | None) -> None:
    """Stream one JSON object per line to stdout until Ctrl-C (or count samples)."""
    emitted = 0
    for _ in paced(rate_hz):
        sample = imu.read()
        print(json.dumps({
            "timestamp": time.time(),
            "accel_m_s2": sample['accel'],
            "gyro_rad_s": sample['gyro'],
            "temp_c": sample['temp'],
        }), flush=True)
        emitted += 1
        if count is not None and emitted >= count:
            break


# --- live view -------------------------------------------------------------------------------------

class TriAxisPlot:
    """A rich renderable that draws the x/y/z time-series with plotext, sized to its region."""

    AXIS_COLORS = ("red", "green", "blue")

    def __init__(self, series: list, window_seconds: float, y_max: float):
        self.series = series  # per axis: [(seconds_ago <= 0, value), ...]
        self.window_seconds = window_seconds
        self.y_max = y_max

    def __rich_console__(self, console, options):
        width = max(int(options.max_width), 20)
        height = max(int(options.height or 8), 4)
        plotext.clf()
        plotext.theme("clear")
        plotext.plotsize(width, height)
        plotext.xlim(-self.window_seconds, 0)
        plotext.ylim(-self.y_max, self.y_max)
        for points, axis, color in zip(self.series, "xyz", self.AXIS_COLORS):
            if points:
                plotext.plot([p[0] for p in points], [p[1] for p in points], marker="braille", color=color, label=axis)
        yield Text.from_ansi(plotext.build())


def clock(seconds: float) -> str:
    seconds = int(seconds)
    minutes, secs = divmod(seconds, 60)
    return f"{minutes:02d}:{secs:02d}"


def header(rate_hz: float, temp_c: float, elapsed: float, sample_count: int) -> Panel:
    text = Text()
    text.append(" ICM-42688-P ", style="bold white on blue")
    text.append(f"  spi{SPI_BUS}.{SPI_DEVICE} @ {rate_hz:g} Hz    ")
    text.append(f"{temp_c:5.1f} °C", style="bold cyan")
    text.append(f"    up {clock(elapsed)}    {sample_count} samples")
    text.append("     q quit", style="dim")
    return Panel(text, border_style="blue", padding=(0, 1), title="icm42688p", title_align="left")


def sensor_panel(name: str, unit: str, samples: deque, first_index: int, y_floor: float,
                 window_seconds: float, now: float, border: str) -> Panel:
    series = []
    peak = 0.0
    for offset in range(3):
        points = [(sample[0] - now, sample[first_index + offset]) for sample in samples]
        peak = max(peak, max((abs(value) for _, value in points), default=0.0))
        series.append(points)
    title = f"{name} [{unit}]"
    if samples:
        latest = samples[-1]
        title += "".join(f"   {axis} {latest[first_index + i]:+8.3f}" for i, axis in enumerate("xyz"))
    plot = TriAxisPlot(series, window_seconds, max(y_floor, peak * 1.2))
    # Text, not str: a str title would be parsed as rich markup and eat the [unit]
    return Panel(plot, title=Text(title), title_align="left", border_style=border, padding=0)


def render(samples: deque, rate_hz: float, window_seconds: float, now: float, start: float) -> Layout:
    temp_c = samples[-1][7] if samples else 0.0
    layout = Layout()
    layout.split_column(
        Layout(header(rate_hz, temp_c, now - start, len(samples)), name="header", size=3),
        Layout(sensor_panel("accel", "m/s²", samples, 1, ACCEL_Y_FLOOR, window_seconds, now, "cyan"), name="accel", ratio=1, minimum_size=6),
        Layout(sensor_panel("gyro", "rad/s", samples, 4, GYRO_Y_FLOOR, window_seconds, now, "green"), name="gyro", ratio=1, minimum_size=6),
    )
    return layout


@contextlib.contextmanager
def raw_keyboard():
    """Put the TTY in cbreak so ``q`` is read without Enter; Ctrl-C still interrupts. No-op off a TTY."""
    if not sys.stdin.isatty():
        yield
        return
    import termios
    import tty
    descriptor = sys.stdin.fileno()
    saved = termios.tcgetattr(descriptor)
    try:
        tty.setcbreak(descriptor)
        yield
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, saved)


def quit_requested() -> bool:
    if not sys.stdin.isatty():
        return False
    import select
    ready, _, _ = select.select([sys.stdin], [], [], 0)
    return bool(ready) and sys.stdin.read(1) in ("q", "Q")


def run_gui(imu: ICM42688P, rate_hz: float, window_seconds: float) -> None:
    samples = deque()  # (monotonic, ax, ay, az, gx, gy, gz, temp), trimmed to the plot window
    render_interval = 1.0 / REFRESH_PER_SECOND
    start = time.monotonic()
    last_render = 0.0
    with raw_keyboard(), Live(render(samples, rate_hz, window_seconds, start, start), screen=True, auto_refresh=False) as live:
        for _ in paced(rate_hz):
            data = imu.read()
            now = time.monotonic()
            samples.append((now, *data['accel'], *data['gyro'], data['temp']))
            while samples and samples[0][0] < now - window_seconds:
                samples.popleft()
            if now - last_render >= render_interval:
                live.update(render(samples, rate_hz, window_seconds, now, start), refresh=True)
                last_render = now
                if quit_requested():
                    break


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read the ICM-42688-P IMU over SPI: full-screen live view by default, or a JSON stream with --raw.")
    parser.add_argument("--raw", action="store_true", help="print one JSON object per sample to stdout (no UI), for programmatic use")
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE_HZ, help="sample rate in Hz (default: %(default)s)")
    parser.add_argument("--count", type=int, help="with --raw, exit after this many samples (default: run until Ctrl-C)")
    parser.add_argument("--window", type=float, default=DEFAULT_WINDOW_SECONDS, help="live-view plot window in seconds (default: %(default)s)")
    arguments = parser.parse_args()
    if arguments.rate <= 0:
        parser.error("--rate must be positive")
    if arguments.count is not None and not arguments.raw:
        parser.error("--count only applies to --raw")
    return arguments


def main() -> int:
    arguments = parse_arguments()
    if not arguments.raw and GUI_IMPORT_ERROR is not None:
        print(f"the live view needs rich + plotext (pip3 install rich plotext); use --raw for plain JSON output.  [{GUI_IMPORT_ERROR}]", file=sys.stderr)
        return 1
    try:
        imu = ICM42688P()
    except (RuntimeError, OSError) as error:
        print(f"cannot open the ICM-42688-P on spi{SPI_BUS}.{SPI_DEVICE}: {error}", file=sys.stderr)
        return 1
    try:
        if arguments.raw:
            run_raw(imu, arguments.rate, arguments.count)
        else:
            run_gui(imu, arguments.rate, arguments.window)
    except KeyboardInterrupt:
        pass
    finally:
        imu.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
