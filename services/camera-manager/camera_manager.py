#!/usr/bin/env python3
"""ARK-OS Camera Manager — FastAPI service for the RTSP server's camera selection.

The Video page in the web UI talks to this service to discover which cameras are
connected and to choose which one the RTSP server streams. The rtsp-server.toml file
is only the persistence layer (the value the rtsp-server reads on startup); this API is
the data channel, mirroring the other *-manager services.

The HTTP contract is the pydantic models below (CameraList, ActionResponse, ...). Every
handler CONSTRUCTS its response model, so the type checker (`mypy`, run from the CLI or
CI) rejects any drift between the producer and the contract before the service ever runs
on a device. FastAPI generates the OpenAPI spec from the same models (served at
/openapi.json, Swagger UI at /docs).

Capabilities:
- Enumerating connected V4L2 capture devices (CSI / USB), classified the same way the
  rtsp-server classifies them, so the UI list matches what will actually stream.
- Reading and writing the selected camera in rtsp-server.toml, then restarting the
  rtsp-server unit so the new device takes effect.
"""

import os
import ctypes
import fcntl
import logging
import subprocess

from fastapi import FastAPI
from pydantic import BaseModel
import toml  # type: ignore[import-untyped]  # runtime dep (build_venv.sh); no stubs shipped
import uvicorn


def setup_logging() -> logging.Logger:
    """Setup simple logging that will be captured by journald via stdout"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger('camera-manager')


logger = setup_logging()


# ── HTTP contract: the single source of truth ────────────────────────────────

class Camera(BaseModel):
    path: str       # "/dev/video0"
    index: int      # 0 for /dev/video0 — also the auto-select ordering key
    name: str       # V4L2 card name, e.g. "vi-output, imx219 9-0010" or "HD Webcam"
    type: str       # "csi" | "usb" | "other"
    selected: bool  # the device the rtsp-server will actually stream right now


class CameraList(BaseModel):
    cameras: list[Camera]
    # The configured device from rtsp-server.toml: "" means auto-select (lowest index).
    configured: str


class SelectRequest(BaseModel):
    # Device path to stream (e.g. "/dev/video1"), or "" to revert to auto-select.
    device: str


class ActionResponse(BaseModel):
    status: str            # "success" | "fail"
    message: str | None = None
    configured: str | None = None


app = FastAPI(title="ARK-OS Camera Manager", version="1.0.0")

# rtsp-server.toml lives flat under the shared ARK-OS config dir, like every other
# service config the web UI edits. Overridable for off-device testing.
RTSP_CONFIG = os.environ.get("RTSP_CONFIG", "/etc/ark-os/rtsp-server.toml")
RTSP_SERVICE = "rtsp-server.service"


# ── V4L2 capability probe (VIDIOC_QUERYCAP) ──────────────────────────────────
# Identify and classify /dev/video* nodes via ioctl rather than shelling out to
# v4l2-ctl, so the manager has no external tool dependency and matches the
# rtsp-server's own classification byte-for-byte.

class _v4l2_capability(ctypes.Structure):
    _fields_ = [
        ("driver", ctypes.c_char * 16),
        ("card", ctypes.c_char * 32),
        ("bus_info", ctypes.c_char * 32),
        ("version", ctypes.c_uint32),
        ("capabilities", ctypes.c_uint32),
        ("device_caps", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32 * 3),
    ]


# _IOR('V', 0, struct v4l2_capability); sizeof == 104. Same value on arm64/x86_64.
_VIDIOC_QUERYCAP = 0x80685600
_V4L2_CAP_VIDEO_CAPTURE = 0x00000001
_V4L2_CAP_DEVICE_CAPS = 0x80000000


def _classify(driver: str) -> str:
    """Map a V4L2 driver name to a camera type (kept in sync with CameraProbe.cpp)."""
    if "tegra" in driver or driver == "vi-output":
        return "csi"
    if driver == "uvcvideo":
        return "usb"
    return "other"


def enumerate_cameras() -> list[Camera]:
    """Return every /dev/video* node that can capture video, sorted by index.

    UVC webcams expose extra metadata-only nodes; VIDIOC_QUERYCAP's device_caps reports
    Metadata Capture (not Video Capture) for those, so they are filtered out and never
    offered as a selectable camera.
    """
    cameras: list[Camera] = []

    try:
        entries = os.listdir("/dev")
    except OSError as e:
        logger.error(f"Cannot list /dev: {e}")
        return cameras

    for name in entries:
        if not name.startswith("video"):
            continue
        digits = name[len("video"):]
        if not digits.isdigit():
            continue

        path = f"/dev/{name}"
        cap = _v4l2_capability()
        fd = -1
        try:
            # O_NONBLOCK so a busy CSI sensor still answers QUERYCAP (it needs no
            # streaming access); a node we can't open (permissions) is simply skipped.
            fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
            fcntl.ioctl(fd, _VIDIOC_QUERYCAP, cap)
        except OSError:
            continue
        finally:
            if fd >= 0:
                os.close(fd)

        caps = cap.device_caps if (cap.capabilities & _V4L2_CAP_DEVICE_CAPS) else cap.capabilities
        if not (caps & _V4L2_CAP_VIDEO_CAPTURE):
            continue

        driver = cap.driver.decode("utf-8", "replace")
        cameras.append(Camera(
            path=path,
            index=int(digits),
            name=cap.card.decode("utf-8", "replace"),
            type=_classify(driver),
            selected=False,
        ))

    cameras.sort(key=lambda c: c.index)
    return cameras


# ── config read / write ──────────────────────────────────────────────────────

def read_configured_device() -> str:
    """The [camera].device value from rtsp-server.toml, or "" if unset/unreadable."""
    try:
        with open(RTSP_CONFIG, "r") as f:
            data = toml.load(f)
    except (OSError, toml.TomlDecodeError) as e:
        logger.warning(f"Could not read {RTSP_CONFIG}: {e}")
        return ""
    device = data.get("camera", {}).get("device", "")
    return device if isinstance(device, str) else ""


def write_configured_device(device: str) -> None:
    """Persist [camera].device into rtsp-server.toml, preserving every other field.

    Re-dumps the whole table (comments are not preserved — the same trade-off the web
    UI's TOML editor already makes), so options arrays and other settings survive.
    """
    with open(RTSP_CONFIG, "r") as f:
        data = toml.load(f)
    data.setdefault("camera", {})["device"] = device
    with open(RTSP_CONFIG, "w") as f:
        toml.dump(data, f)


def mark_selected(cameras: list[Camera], configured: str) -> None:
    """Flag the camera the rtsp-server will actually stream, mirroring its selection:
    the configured device if it's connected, otherwise the lowest-numbered camera."""
    if not cameras:
        return
    chosen = next((c for c in cameras if c.path == configured), None) if configured else None
    if chosen is None:
        chosen = cameras[0]  # auto-select: lowest index (already sorted)
    chosen.selected = True


class CameraManager:

    @staticmethod
    def list_cameras() -> CameraList:
        configured = read_configured_device()
        cameras = enumerate_cameras()
        mark_selected(cameras, configured)
        return CameraList(cameras=cameras, configured=configured)

    @staticmethod
    def select_camera(device: str) -> ActionResponse:
        # "" is allowed (revert to auto); a non-empty value must name a connected,
        # capture-capable camera so the UI can't point the stream at a dead node.
        if device:
            if not any(c.path == device for c in enumerate_cameras()):
                return ActionResponse(
                    status="fail",
                    message=f"{device} is not a connected camera",
                )

        try:
            write_configured_device(device)
        except (OSError, toml.TomlDecodeError) as e:
            return ActionResponse(status="fail", message=f"Could not write config: {e}")

        # Restart so the rtsp-server rebuilds its pipeline for the new device. Relies on
        # the same polkit grant the service-manager uses; the unit name is hard-coded, so
        # there is no injection surface here.
        try:
            proc = subprocess.run(
                ["systemctl", "restart", RTSP_SERVICE],
                capture_output=True, text=True, timeout=15,
            )
        except Exception as e:
            return ActionResponse(status="fail", message=f"Saved, but restart failed: {e}",
                                  configured=device)

        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout).strip() or f"exit code {proc.returncode}"
            return ActionResponse(status="fail", message=f"Saved, but restart failed: {msg}",
                                  configured=device)

        return ActionResponse(status="success", configured=device)


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.get("/cameras")
def get_cameras() -> CameraList:
    logger.debug("GET /cameras called")
    return CameraManager.list_cameras()


@app.post("/select", response_model_exclude_none=True)
def select_camera(body: SelectRequest) -> ActionResponse:
    logger.info(f"POST /select called for '{body.device or 'auto'}'")
    return CameraManager.select_camera(body.device)


if __name__ == '__main__':
    host = '127.0.0.1'
    port = int(os.environ.get("PORT", 3005))

    logger.info(f"Starting Camera Manager on {host}:{port}")
    uvicorn.run(app, host=host, port=port, access_log=False)
