"""ARK-OS Autopilot Manager — FastAPI service for autopilot MAVLink interactions.

The HTTP contract is the pydantic models below (AutopilotDetails, FlashProgress, ...).
get_autopilot_details() CONSTRUCTS an AutopilotDetails, so the type checker (`mypy`,
run from the CLI or CI) rejects any drift between the producer and the contract
before the service ever runs on a device. FastAPI generates the OpenAPI spec from
the same models (served at /openapi.json, Swagger UI at /docs).

Firmware-flash progress is a one-way server→client stream, served as Server-Sent
Events at /firmware-upload/stream (events: progress, completed, failed). The flash
itself runs in a worker thread; ProgressBroker fans its events out to subscribers.
The pymavlink message loop stays on its own daemon thread; handlers are plain `def`
so FastAPI runs them in a threadpool and blocking subprocess calls never stall the
event loop.
"""

import os
import json
import subprocess
import glob
import threading
import time
import argparse
import logging
import asyncio
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any
import socket

from fastapi import FastAPI, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ValidationError
import uvicorn
import pymavlink.mavutil as mavutil
from pymavlink.dialects.v20 import common as mavlink


def setup_logging():
    """Setup logging configuration that outputs to stdout"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger('autopilot-manager')


# Initialize logger
logger = setup_logging()


# ── HTTP contract: the single source of truth ────────────────────────────────

class AutopilotDetails(BaseModel):
    autopilot_type: str
    version: str
    git_hash: str
    voltage: float
    current: float
    remaining: int
    mavlink_connected: bool
    device_connected: bool
    in_bootloader: bool
    device_name: str | None
    last_heartbeat: str | None
    timestamp: str


class MessageResponse(BaseModel):
    success: bool
    message: str


class UploadResponse(BaseModel):
    status: str  # "success" | "fail"
    message: str


class FlashProgress(BaseModel):
    """Payload of the SSE 'progress' event. px_uploader.py's --json-progress
    lines are validated against this model before they are published."""
    status: str
    message: str | None = None
    percent: float


class FlashMessage(BaseModel):
    """Payload of the SSE 'completed' and 'failed' events."""
    message: str


app = FastAPI(title="ARK-OS Autopilot Manager", version="1.0.0")


FlashEvent = tuple[str, dict[str, Any]]


class ProgressBroker:
    """Fans firmware-flash events out to the SSE subscribers.

    The flash runs in a worker thread while each subscriber awaits an
    asyncio.Queue on the event loop, so publish hops onto that loop via
    call_soon_threadsafe — subscribers block on get() instead of polling.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: dict[asyncio.Queue[FlashEvent], asyncio.AbstractEventLoop] = {}

    def subscribe(self) -> asyncio.Queue[FlashEvent]:
        """Must be called from the event loop (it captures the running loop)."""
        q: asyncio.Queue[FlashEvent] = asyncio.Queue()
        with self._lock:
            self._subscribers[q] = asyncio.get_running_loop()
        return q

    def unsubscribe(self, q: asyncio.Queue[FlashEvent]) -> None:
        with self._lock:
            self._subscribers.pop(q, None)

    def publish(self, event: str, data: dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers.items())
        for q, loop in subscribers:
            try:
                loop.call_soon_threadsafe(q.put_nowait, (event, data))
            except RuntimeError:
                # Subscriber's loop already shut down.
                pass


broker = ProgressBroker()


class DeviceDetector:
    """Handles USB device detection for ARK autopilots"""

    @staticmethod
    def check_device_status():
        """Check if ARK device is connected and determine its mode"""
        try:
            for product_file in glob.glob('/sys/bus/usb/devices/*/product'):
                with open(product_file, 'r') as f:
                    product = f.read().strip()
                if "ARK BL" in product:
                    logger.debug(f"Detected bootloader: {product}")
                    return {"device_connected": True, "in_bootloader": True, "device_name": "ARK Bootloader"}
                elif "ARK" in product:
                    logger.debug(f"Detected ARK device: {product}")
                    return {"device_connected": True, "in_bootloader": False, "device_name": "ARK Flight Controller"}
        except Exception as e:
            logger.error(f"Error checking device status: {e}")
        return {"device_connected": False, "in_bootloader": False, "device_name": None}


class MAVLinkConnection:
    # Reconnect backoff bounds (seconds) for when the autopilot heartbeat is
    # absent: rebuild the link on a growing delay instead of churning the socket
    # every few seconds on a board with no flight controller.
    _INITIAL_RESET_BACKOFF = 1.0
    _MAX_RESET_BACKOFF = 30.0

    def __init__(self, connection_string='udpin:localhost:14571', source_system=254):
        self.connection_string = connection_string
        self.source_system = source_system
        self.mav_connection = None
        self.running = False
        self.thread = None
        self.heartbeat_timeout = 3  # seconds
        self.last_heartbeat = None
        self.device_detector = DeviceDetector()
        self._lock = threading.Lock()

        # Store the latest autopilot data
        self.autopilot_data: dict[str, Any] = {
            "autopilot_type": "Unknown",
            "version": "Unknown",
            "git_hash": "Unknown",
            "voltage": 0.0,
            "current": 0.0,
            "remaining": 0,
            "mavlink_connected": False,
            "device_connected": False,
            "in_bootloader": False,
            "device_name": None,
            "last_heartbeat": None
        }

    def connect(self):
        """Start the connection process to the MAVLink stream (non-blocking)"""
        if self.mav_connection:
            return True

        try:
            logger.info(f"Connecting to MAVLink at {self.connection_string}")
            # This part is non-blocking, just creates the connection object
            self.mav_connection = mavutil.mavlink_connection(self.connection_string,
                                                            autoreconnect=True,
                                                            source_system=self.source_system)

            self.mav_connection.target_component = mavlink.MAV_COMP_ID_AUTOPILOT1

            # Start the message loop which will also handle detecting the connection
            self.start_message_loop()
            return True
        except Exception as e:
            logger.error(f"Error initializing MAVLink connection: {e}")
            return False

    def disconnect(self):
        """Disconnect from the MAVLink stream"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)

        if self.mav_connection:
            try:
                self.mav_connection.close()
            except Exception as e:
                logger.error(f"Error closing MAVLink connection: {e}")
            finally:
                self.mav_connection = None
                with self._lock:
                    self.autopilot_data["mavlink_connected"] = False

    def _reset_connection(self):
        """Close and re-create the MAVLink connection"""
        with self._lock:
            self.autopilot_data["mavlink_connected"] = False
        if self.mav_connection:
            self.mav_connection.close()
        self.mav_connection = mavutil.mavlink_connection(
            self.connection_string,
            autoreconnect=True,
            source_system=self.source_system)

    def _reconnect_helps(self) -> bool:
        """Whether rebuilding the connection can actually recover the link.

        A udpin/udp listener has no peer to dial, so recreating its socket while
        the FC is gone only churns it — the existing socket still receives a
        returning autopilot. Client/serial links (udpout, tcp, serial) do
        benefit from a rebuild.
        """
        return not self.connection_string.startswith(('udpin:', 'udp:'))

    def update_heartbeat_time(self):
        """Update the last heartbeat timestamp"""
        self.last_heartbeat = datetime.now()
        with self._lock:
            self.autopilot_data["last_heartbeat"] = self.last_heartbeat.isoformat()

    def is_mavlink_connected(self):
        """Check if the MAVLink connection is active based on recent heartbeats"""
        if not self.last_heartbeat:
            return False

        time_since_heartbeat = (datetime.now() - self.last_heartbeat).total_seconds()
        return time_since_heartbeat < self.heartbeat_timeout

    def request_autopilot_version(self):
        """Request the autopilot version information"""
        if not self.mav_connection:
            return False

        try:
            logger.debug("Requesting autopilot version")
            # Use MAVLink command to request version information
            self.mav_connection.mav.command_long_send(
                self.mav_connection.target_system,
                self.mav_connection.target_component,
                mavlink.MAV_CMD_REQUEST_MESSAGE,
                0,  # Confirmation
                mavlink.MAVLINK_MSG_ID_AUTOPILOT_VERSION,  # Message ID for AUTOPILOT_VERSION
                0, 0, 0, 0, 0, 0  # Empty parameters
            )
            return True
        except Exception as e:
            logger.error(f"Error requesting autopilot version: {e}")
            return False

    def send_system_time(self, current_time):
        if not self.mav_connection:
            return False

        try:
            logger.debug(f"Sending system time {int(current_time * 1e6)}")
            time_unix_usec = int(current_time * 1e6)
            time_boot_ms = 0  # unused in PX4
            self.mav_connection.mav.system_time_send(
                time_unix_usec,
                time_boot_ms
            )
            return True
        except Exception as e:
            logger.error(f"Error sending system time: {e}")
            return False

    def update_device_status(self):
        """Update device connection status via USB detection"""
        device_status = self.device_detector.check_device_status()
        with self._lock:
            self.autopilot_data["device_connected"] = device_status["device_connected"]
            self.autopilot_data["in_bootloader"] = device_status["in_bootloader"]
            self.autopilot_data["device_name"] = device_status["device_name"]

            # If in bootloader, set appropriate autopilot type
            if device_status["in_bootloader"]:
                self.autopilot_data["autopilot_type"] = "Bootloader"

    def process_messages(self):
        """Process incoming MAVLink messages in a loop"""
        self.running = True
        last_version_request_time = 0.0
        last_system_time_update_time = 0.0
        last_device_check_time = 0.0
        last_probe_time = 0.0
        # Reconnect/episode state: back off rebuilding the link, and log the
        # disconnect only once per episode (not every loop) so an FC-less board
        # doesn't churn the socket or flood the journal.
        reset_backoff = self._INITIAL_RESET_BACKOFF
        next_reset_time = 0.0
        disconnect_logged = False

        while self.running:
            try:
                current_time = time.time()

                # Periodically check device status (every 2 seconds)
                if current_time - last_device_check_time > 2:
                    self.update_device_status()
                    last_device_check_time = current_time

                if self.mav_connection is None:
                    time.sleep(1)
                    continue

                # Use blocking mode with a timeout - this is more efficient than sleep
                # as it will wake up immediately when a message arrives
                msg = self.mav_connection.recv_match(blocking=True, timeout=0.5)

                if msg:
                    # Ignore messages that do not originate from the autopilot
                    if msg.get_srcComponent() != mavlink.MAV_COMP_ID_AUTOPILOT1:
                        continue

                    # Process different message types
                    if msg.get_type() == 'HEARTBEAT':
                        self.update_heartbeat_time()
                        with self._lock:
                            self.autopilot_data["autopilot_type"] = self.get_autopilot_type(msg.autopilot)
                            self.autopilot_data["mavlink_connected"] = True

                        # Recovered: log once and reset the backoff so the next
                        # drop is reported promptly and probed without delay.
                        if disconnect_logged:
                            logger.info("Autopilot heartbeat received; MAVLink connected")
                            disconnect_logged = False
                        reset_backoff = self._INITIAL_RESET_BACKOFF
                        next_reset_time = 0.0

                        # Periodically request version information if needed
                        if current_time - last_version_request_time > 5:
                            with self._lock:
                                version_unknown = self.autopilot_data["version"] == "Unknown"
                            if version_unknown:
                                self.request_autopilot_version()
                                last_version_request_time = current_time

                        # Periodically send system time
                        if current_time - last_system_time_update_time > 5:
                            self.send_system_time(current_time)
                            last_system_time_update_time = current_time

                    elif msg.get_type() == 'AUTOPILOT_VERSION':
                        # Extract version and git hash
                        flight_sw_version = msg.flight_sw_version
                        major = (flight_sw_version >> 24) & 0xFF
                        minor = (flight_sw_version >> 16) & 0xFF
                        patch = (flight_sw_version >> 8) & 0xFF
                        with self._lock:
                            self.autopilot_data["version"] = f"{major}.{minor}.{patch}"

                            # Convert git hash bytes to hex string
                            if hasattr(msg, 'flight_custom_version'):
                                # take first 8 bytes, reverse to MSB-first, take only first 5 bytes (PX4 only uses 5)
                                hash_bytes = msg.flight_custom_version[:8][::-1][:5]
                                hex_hash = ''.join(f'{b:02x}' for b in hash_bytes)
                                self.autopilot_data["git_hash"] = hex_hash

                    elif msg.get_type() == 'SYS_STATUS':
                        # Extract battery information
                        with self._lock:
                            if hasattr(msg, 'voltage_battery'):
                                # Convert from millivolts to volts
                                self.autopilot_data["voltage"] = msg.voltage_battery / 1000.0

                            if hasattr(msg, 'current_battery'):
                                # Convert from 10*milliamps to amps
                                self.autopilot_data["current"] = msg.current_battery / 100.0

                            if hasattr(msg, 'battery_remaining'):
                                self.autopilot_data["remaining"] = msg.battery_remaining

                # No message, and the autopilot heartbeat is missing or stale.
                elif (self.last_heartbeat is None or
                      (datetime.now() - self.last_heartbeat).total_seconds() > 5):

                    with self._lock:
                        self.autopilot_data["mavlink_connected"] = False

                    # Log the disconnect once per episode, not every cycle — a
                    # board with no FC would otherwise WARN every few seconds.
                    if not disconnect_logged:
                        logger.warning("No autopilot heartbeat; probing and reconnecting in the background")
                        disconnect_logged = True

                    # Probe with a GCS heartbeat at ~1 Hz to elicit a response.
                    if current_time - last_probe_time >= 1.0:
                        try:
                            self.mav_connection.mav.heartbeat_send(
                                mavlink.MAV_TYPE_GCS,
                                mavlink.MAV_AUTOPILOT_INVALID,
                                0, 0, 0)
                        except Exception as e:
                            logger.error(f"Error sending heartbeat: {e}")
                        last_probe_time = current_time

                    # Rebuild the link on a capped exponential backoff so a
                    # permanently absent FC can't churn the socket (or journal)
                    # every few seconds. Skipped entirely for a udpin listener,
                    # which has no peer to reconnect to.
                    if current_time >= next_reset_time:
                        if self._reconnect_helps():
                            try:
                                self._reset_connection()
                            except Exception as reset_error:
                                logger.error(f"Error resetting MAVLink connection: {reset_error}")
                                self.mav_connection = None
                                time.sleep(1)
                        next_reset_time = current_time + reset_backoff
                        reset_backoff = min(reset_backoff * 2, self._MAX_RESET_BACKOFF)

            except socket.timeout:
                # This is expected when using blocking mode with timeout
                # No action needed as we'll loop back and try again
                pass
            except ConnectionResetError as cre:
                logger.warning(f"Connection reset: {cre}")
                # Give a short pause before attempting reconnection
                time.sleep(1)
                try:
                    self._reset_connection()
                    reset_backoff = self._INITIAL_RESET_BACKOFF
                    next_reset_time = current_time + reset_backoff
                except Exception as reset_error:
                    logger.error(f"Error resetting MAVLink connection: {reset_error}")
                    self.mav_connection = None
            except Exception as e:
                logger.error(f"Error processing MAVLink messages: {e}")
                time.sleep(0.5)  # Brief pause before retrying

    def get_autopilot_type(self, autopilot_type):
        types = {
            mavlink.MAV_AUTOPILOT_GENERIC: "Generic",
            mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA: "ArduPilot",
            mavlink.MAV_AUTOPILOT_PX4: "PX4",
        }
        return types.get(autopilot_type, f"Unknown({autopilot_type})")

    def start_message_loop(self):
        if self.thread and self.thread.is_alive():
            return

        self.running = True
        self.thread = threading.Thread(target=self.process_messages)
        self.thread.daemon = True
        self.thread.start()
        logger.info("MAVLink message processing thread started")

    def get_autopilot_details(self) -> AutopilotDetails:
        """The typed boundary: the message loop fills a loose dict; this builds
        the AutopilotDetails explicitly, so the type checker verifies every
        field against the contract."""
        with self._lock:
            data = dict(self.autopilot_data)
        return AutopilotDetails(
            autopilot_type=data["autopilot_type"],
            version=data["version"],
            git_hash=data["git_hash"],
            voltage=data["voltage"],
            current=data["current"],
            remaining=data["remaining"],
            mavlink_connected=data["mavlink_connected"],
            device_connected=data["device_connected"],
            in_bootloader=data["in_bootloader"],
            device_name=data["device_name"],
            last_heartbeat=data["last_heartbeat"],
            timestamp=datetime.now().isoformat(),
        )


class AutopilotManager:
    def __init__(self, connection_string='udpin:localhost:14571', source_system=254):
        self.mavlink = MAVLinkConnection(connection_string=connection_string, source_system=source_system)
        self._flash_lock = threading.Lock()
        self._flashing = False
        # Start the connection process (non-blocking)
        self.mavlink.connect()
        # The message loop is started automatically in connect()

    def get_autopilot_details(self) -> AutopilotDetails:
        """Get details about the connected autopilot via MAVLink"""
        # This is now non-blocking as connection management happens in the background
        return self.mavlink.get_autopilot_details()

    def find_serial_device(self):
        """Find the ARKV6X serial device"""
        try:
            devices = glob.glob('/dev/serial/by-id/*ARK*')
            for device in devices:
                if 'if00' in device:
                    return os.path.realpath(device)
            return None
        except Exception as e:
            logger.error(f"Error finding serial device: {e}")
            return None

    def is_service_active(self, service_name):
        """Check if a systemd service is active"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                text=True
            )
            return result.stdout.strip() == "active"
        except Exception as e:
            logger.error(f"Error checking service status: {e}")
            return False

    def stop_mavlink_router(self):
        try:
            logger.debug("Stopping mavlink-router service")
            result = subprocess.run(["systemctl", "stop", "mavlink-router"],
                                    check=False,
                                    capture_output=True,
                                    text=True)
            if result.returncode == 0:
                logger.debug("Successfully stopped mavlink-router")
                return True
            else:
                logger.warning(f"Failed to stop mavlink-router: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error stopping mavlink-router: {e}")
            return False

    def restart_mavlink_router(self):
        try:
            logger.debug("Restarting mavlink-router service")
            result = subprocess.run(["systemctl", "restart", "mavlink-router"],
                                    check=False,
                                    capture_output=True,
                                    text=True)
            if result.returncode == 0:
                logger.debug("Successfully restarted mavlink-router")
                return True
            else:
                logger.warning(f"Failed to restart mavlink-router: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error restarting mavlink-router: {e}")
            return False

    def reset_fmu(self, mode="wait_bl") -> tuple[bool, str]:
        """Reset the flight management unit

        Args:
            mode: Either "wait_bl" to wait for bootloader or "fast" for quick reset
        """
        script = "reset_fmu_wait_bl.py" if mode == "wait_bl" else "reset_fmu_fast.py"
        try:
            logger.debug(f"Resetting FMU using {script}")
            result = subprocess.run(["/usr/lib/ark-os/venv/bin/python3", f"/usr/lib/ark-os/scripts/{script}"],
                                   check=False,
                                   capture_output=True,
                                   text=True)
            if result.returncode == 0:
                logger.debug(f"Successfully reset FMU with {script}")
                return True, "Reset successful"
            else:
                logger.warning(f"Failed to reset FMU with {script}: {result.stderr}")
                return False, f"Reset failed: {result.stderr}"
        except Exception as e:
            logger.error(f"Error resetting FMU with {script}: {e}")
            return False, f"Reset error: {str(e)}"

    def try_claim_flash(self) -> bool:
        """Claim the single flash slot, so a concurrent upload can be rejected
        in the HTTP response instead of broadcasting a failure to every SSE
        subscriber (which would also reach the client whose flash is running).
        Released by flash_firmware when the flash finishes."""
        with self._flash_lock:
            if self._flashing:
                return False
            self._flashing = True
            return True

    def release_flash(self) -> None:
        with self._flash_lock:
            self._flashing = False

    def flash_firmware(self, firmware_path: str) -> bool:
        """Flash firmware to the autopilot, publishing progress to SSE
        subscribers. The caller must hold the flash slot (try_claim_flash);
        it is released here when the flash finishes."""
        logger.info(f"Starting firmware flash process for {firmware_path}")

        try:
            # Check if firmware file exists
            if not os.path.isfile(firmware_path):
                error_msg = "Firmware file does not exist"
                logger.error(f"Error: {error_msg}")
                broker.publish('failed', FlashMessage(message=error_msg).model_dump())
                return False

            # Find the ARKV6X device
            logger.debug("Looking for ARKV6X device")
            serial_device = self.find_serial_device()
            if not serial_device:
                error_msg = "ARKV6X not found"
                logger.error(f"Error: {error_msg}")
                broker.publish('failed', FlashMessage(message=error_msg).model_dump())
                return False
            logger.debug(f"Found ARKV6X device at {serial_device}")

            # Disconnect from MAVLink first to avoid conflicts
            logger.debug("Disconnecting MAVLink connection")
            self.mavlink.disconnect()

            # Stop mavlink router service if it's running
            logger.debug("Checking if mavlink-router is active")
            router_was_active = self.is_service_active("mavlink-router")
            if router_was_active:
                logger.debug("mavlink-router is active, stopping it")
                if not self.stop_mavlink_router():
                    error_msg = ("Could not stop mavlink-router; it still holds the autopilot "
                                 "serial port, so the bootloader erase would stall. This usually "
                                 "means the service user lacks polkit authorization to run "
                                 "systemctl (the 99-ark-service-manager.pkla grant is missing).")
                    logger.error(error_msg)
                    broker.publish('failed', FlashMessage(message=error_msg).model_dump())
                    return False
            else:
                logger.debug("mavlink-router is not active")

            # Reset FMU to enter bootloader mode
            logger.debug("Resetting FMU to enter bootloader mode")
            reset_ok, reset_msg = self.reset_fmu(mode="wait_bl")
            if not reset_ok:
                error_msg = f"Failed to reset FMU into bootloader mode: {reset_msg}"
                logger.error(error_msg)
                broker.publish('failed', FlashMessage(message=error_msg).model_dump())
                if router_was_active:
                    self.restart_mavlink_router()
                    self.mavlink.connect()
                return False

            # Run px_uploader.py with JSON progress output
            logger.debug("Starting firmware upload using px_uploader.py")
            command = [
                "/usr/lib/ark-os/venv/bin/python3", "-u",
                "/usr/lib/ark-os/scripts/px_uploader.py",
                "--json-progress", "--port", serial_device, firmware_path
            ]

            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )

                logger.debug(f"Started upload process with PID: {process.pid}")

                # Process output line by line to capture JSON progress updates
                assert process.stdout is not None
                for line in process.stdout:
                    logger.debug(f"Uploader output: {line.strip()}")
                    if line is not None:
                        try:
                            # Only lines matching the contract reach subscribers;
                            # anything else is uploader chatter.
                            progress = FlashProgress.model_validate(json.loads(line.strip()))
                            broker.publish('progress', progress.model_dump(exclude_none=True))
                        except (json.JSONDecodeError, ValidationError):
                            logger.debug(f"Non-progress output: {line.strip()}")

                # Wait for process to complete
                return_code = process.wait()
                logger.debug(f"Upload process completed with return code: {return_code}")

                # Get stderr output if there was an error
                stderr_output = ""
                if return_code != 0:
                    assert process.stderr is not None
                    stderr_output = process.stderr.read()
                    logger.error(f"Error output from uploader: {stderr_output}")

                # Reset FMU quickly after flashing
                logger.debug("Performing fast reset of FMU")
                self.reset_fmu(mode="fast")

                # Wait for the reset to complete
                logger.debug("Waiting for reset to complete")
                time.sleep(3)

                # Restart mavlink router service only if it was active before
                if router_was_active:
                    logger.debug("Restarting mavlink-router service")
                    self.restart_mavlink_router()

                    # Wait for mavlink-router to start up
                    logger.debug("Waiting for mavlink-router to initialize")
                    time.sleep(2)

                # Reconnect MAVLink
                logger.debug("Reconnecting to MAVLink")
                self.mavlink.connect()

                if return_code == 0:
                    success_msg = "Firmware update completed successfully."
                    logger.info(success_msg)
                    broker.publish('completed', FlashMessage(message=success_msg).model_dump())
                    return True
                else:
                    error_msg = f"Firmware update failed with code {return_code}: {stderr_output}"
                    logger.error(error_msg)
                    broker.publish('failed', FlashMessage(message=error_msg).model_dump())
                    return False

            except Exception as e:
                error_msg = f"Exception during firmware update: {str(e)}"
                logger.error(error_msg)
                broker.publish('failed', FlashMessage(message=error_msg).model_dump())

                # Try to restart mavlink-router if it was active
                if router_was_active:
                    logger.debug("Attempting to restart mavlink-router after exception")
                    self.restart_mavlink_router()
                    time.sleep(2)
                    self.mavlink.connect()

                return False
        finally:
            self.release_flash()
            # Clean up temp firmware file
            try:
                if os.path.isfile(firmware_path):
                    os.unlink(firmware_path)
            except OSError:
                pass


# Set in __main__ before uvicorn starts.
autopilot_manager: AutopilotManager | None = None


def get_manager() -> AutopilotManager:
    assert autopilot_manager is not None
    return autopilot_manager


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.get("/details")
def get_autopilot_details() -> AutopilotDetails:
    """Get details about the connected autopilot"""
    logger.debug("GET /details called")
    return get_manager().get_autopilot_details()


@app.post("/firmware-upload")
def upload_firmware(firmware: UploadFile, response: Response) -> UploadResponse:
    """Upload firmware and start flashing in the background. Progress is
    streamed to /firmware-upload/stream subscribers."""
    logger.info("POST /firmware-upload called")

    # Check if the file has an allowed extension
    allowed_extensions = ['.px4', '.apj']
    filename = os.path.basename(firmware.filename or "")
    file_ext = os.path.splitext(filename)[1].lower()

    if file_ext not in allowed_extensions:
        logger.warning(f"Invalid file type: {file_ext}")
        response.status_code = 400
        return UploadResponse(
            status="fail",
            message=f"Invalid file type. Only {', '.join(allowed_extensions)} files are allowed.",
        )

    # Claim the flash slot before touching the temp file: a concurrent upload
    # is rejected here, and can't overwrite a file the running flash is reading.
    if not get_manager().try_claim_flash():
        logger.warning("Rejected firmware upload: flash already in progress")
        response.status_code = 409
        return UploadResponse(status="fail", message="Firmware flash already in progress")

    try:
        # Save the firmware to a temporary file
        temp_path = os.path.join('/tmp', filename)
        with open(temp_path, 'wb') as f:
            while chunk := firmware.file.read(1024 * 1024):
                f.write(chunk)
        logger.info(f"Firmware file saved to {temp_path}")

        # Start the flashing process in a background thread
        threading.Thread(
            target=get_manager().flash_firmware,
            args=(temp_path,),
            daemon=True,
        ).start()
    except Exception:
        get_manager().release_flash()
        raise

    return UploadResponse(status="success", message="Firmware upload started")


@app.get("/firmware-upload/stream")
async def firmware_upload_stream() -> StreamingResponse:
    """Server-Sent Events stream of firmware-flash progress.

    Events: 'progress' (FlashProgress), 'completed' / 'failed' (FlashMessage).
    One-way server→client push, so SSE rides the same /api HTTP proxy chain as
    the REST endpoints — no websocket layer involved.
    """

    async def event_stream() -> AsyncIterator[str]:
        q = broker.subscribe()
        try:
            yield ": connected\n\n"
            while True:
                try:
                    event, data = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    # Periodic comment keeps intermediate proxies from timing
                    # out the connection while no flash is running.
                    yield ": keepalive\n\n"
                    continue
                yield f"event: {event}\ndata: {json.dumps(data)}\n\n"
        finally:
            broker.unsubscribe(q)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/reset-fmu")
def reset_fmu(response: Response) -> MessageResponse:
    """Reset the flight controller"""
    logger.info("POST /reset-fmu called")

    success, message = get_manager().reset_fmu(mode="fast")
    if not success:
        response.status_code = 500
    return MessageResponse(success=success, message=message)


@app.post("/reset-fmu-bootloader")
def reset_fmu_bootloader(response: Response) -> MessageResponse:
    """Reset the flight controller into bootloader mode"""
    logger.info("POST /reset-fmu-bootloader called")

    success, message = get_manager().reset_fmu(mode="wait_bl")
    if not success:
        response.status_code = 500
    return MessageResponse(success=success, message=message)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='ARKV6X Autopilot Manager')
    parser.add_argument('--connection-string',
                        default='udpin:localhost:14571',
                        help='MAVLink connection string (default: udpin:localhost:14571)')
    parser.add_argument('--host',
                        # localhost only: reached via the nginx gateway (localhost:3003),
                        # never a public surface — matches the other managers.
                        default='127.0.0.1',
                        help='Host address to bind (default: 127.0.0.1)')
    parser.add_argument('--port',
                        type=int,
                        default=int(os.environ.get('PORT', 3003)),
                        help='Port to listen on (default: 3003)')
    parser.add_argument('--source-system',
                        type=int,
                        default=254,
                        help='MAVLink source system ID (default: 254)')
    parser.add_argument('--log-level',
                        default='info',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Logging level (default: info)')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()

    # Set log level from command line argument
    log_level = getattr(logging, args.log_level.upper())
    logger.setLevel(log_level)
    logger.info(f"Log level set to {args.log_level.upper()}")

    # Create the AutopilotManager instance with command line arguments
    autopilot_manager = AutopilotManager(
        connection_string=args.connection_string,
        source_system=args.source_system
    )

    logger.info(f"Starting Autopilot Manager on {args.host}:{args.port}")
    # access_log off: /details is polled at 1 Hz by the UI (this replaces the
    # werkzeug log suppression the Flask version used).
    uvicorn.run(app, host=args.host, port=args.port, access_log=False)
