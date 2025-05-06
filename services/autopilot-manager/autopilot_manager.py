import os
import json
import subprocess
import tempfile
import glob
import threading
import time
import argparse
import logging
from datetime import datetime
import socket
import re
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
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

# Explicitly set async_mode to threading to avoid eventlet issues
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", path='/socket.io/autopilot-firmware-upload', async_mode='threading')


class MAVLinkConnection:
    def __init__(self, connection_string='udpin:localhost:14571', source_system=254):
        self.connection_string = connection_string
        self.source_system = source_system
        self.mav_connection = None
        self.running = False
        self.thread = None
        self.heartbeat_timeout = 3  # seconds
        self.last_heartbeat = None

        # Store the latest autopilot data
        self.autopilot_data = {
            "autopilot_type": "Unknown",
            "version": "Unknown",
            "git_hash": "Unknown",
            "voltage": 0.0,
            "current": 0.0,
            "remaining": 0,
            "connected": False,
            "in_bootloader": False,
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
                self.autopilot_data["connected"] = False

    def update_heartbeat_time(self):
        """Update the last heartbeat timestamp"""
        self.last_heartbeat = datetime.now()
        self.autopilot_data["last_heartbeat"] = self.last_heartbeat.isoformat()

    def is_connected(self):
        """Check if the MAVLink connection is active based on recent heartbeats"""
        if not self.last_heartbeat:
            return False

        time_since_heartbeat = (datetime.now() - self.last_heartbeat).total_seconds()
        return time_since_heartbeat < self.heartbeat_timeout

    def check_bootloader_mode(self):
        """Check if the autopilot is in bootloader mode using lsusb"""
        try:
            result = subprocess.run(
                "lsusb",
                shell=True,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                # Look for the ARK BL FPV.x pattern in lsusb output
                for line in result.stdout.splitlines():
                    if "ARK BL" in line:
                        logger.info(f"Detected bootloader: {line.strip()}")
                        return True

            return False
        except Exception as e:
            logger.error(f"Error checking bootloader mode: {e}")
            return False

    def request_autopilot_version(self):
        """Request the autopilot version information"""
        if not self.mav_connection:
            return False

        try:
            logger.info("Requesting autopilot version")
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
            logger.info(f"Sending system time {int(current_time * 1e6)}")
            time_unix_usec = int(current_time * 1e6);
            time_boot_ms = 0; # unused in PX4
            self.mav_connection.mav.system_time_send(
                time_unix_usec,
                time_boot_ms
            )
            return True
        except Exception as e:
            logger.error(f"Error sending system time: {e}")
            return False

    def process_messages(self):
        """Process incoming MAVLink messages in a loop"""
        self.running = True
        connection_attempts = 0
        last_version_request_time = 0
        last_system_time_update_time = 0
        waiting_for_heartbeat = True

        while self.running:
            try:
                if self.mav_connection is None:
                    time.sleep(1)
                    continue

                # Use blocking mode with a timeout - this is more efficient than sleep
                # as it will wake up immediately when a message arrives
                msg = self.mav_connection.recv_match(blocking=True, timeout=0.5)

                # Send periodic heartbeats if we're waiting for initial connection
                current_time = time.time()

                if msg:
                    # Ignore messages that do not originate from the autopilot
                    if msg.get_srcComponent() != mavlink.MAV_COMP_ID_AUTOPILOT1:
                        continue

                    # We received a message, connection is working
                    waiting_for_heartbeat = False

                    # Process different message types
                    if msg.get_type() == 'HEARTBEAT':
                        self.update_heartbeat_time()
                        self.autopilot_data["autopilot_type"] = self.get_autopilot_type(msg.autopilot)
                        self.autopilot_data["connected"] = True
                        self.autopilot_data["in_bootloader"] = False  # If we get a heartbeat, we're not in bootloader

                        # Reset connection attempts on successful heartbeat
                        connection_attempts = 0

                        # Periodically request version information if needed
                        if current_time - last_version_request_time > 5:
                            if self.autopilot_data["version"] == "Unknown":
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
                        self.autopilot_data["version"] = f"{major}.{minor}.{patch}"

                        # Convert git hash bytes to hex string
                        if hasattr(msg, 'flight_custom_version'):
                            hash_bytes = msg.flight_custom_version[:8]  # First 8 bytes
                            hex_hash = ''.join(f'{b:02x}' for b in hash_bytes if b != 0)
                            self.autopilot_data["git_hash"] = hex_hash

                    elif msg.get_type() == 'SYS_STATUS':
                        # Extract battery information
                        if hasattr(msg, 'voltage_battery'):
                            # Convert from millivolts to volts
                            self.autopilot_data["voltage"] = msg.voltage_battery / 1000.0

                        if hasattr(msg, 'current_battery'):
                            # Convert from 10*milliamps to amps
                            self.autopilot_data["current"] = msg.current_battery / 100.0

                        if hasattr(msg, 'battery_remaining'):
                            self.autopilot_data["remaining"] = msg.battery_remaining

                # If no message or heartbeat timeout occurred, check connection status
                elif (self.last_heartbeat is None or
                      (datetime.now() - self.last_heartbeat).total_seconds() > 5):

                    if self.check_bootloader_mode():
                        self.autopilot_data["in_bootloader"] = True
                        self.autopilot_data["autopilot_type"] = "Bootloader"
                        continue

                    # No recent heartbeat, try to send one to elicit a response
                    if waiting_for_heartbeat and connection_attempts < 5:
                        try:
                            logger.info(f"Sending heartbeat attempt {connection_attempts+1}/5")
                            self.mav_connection.mav.heartbeat_send(
                                mavlink.MAV_TYPE_GCS,
                                mavlink.MAV_AUTOPILOT_INVALID,
                                0, 0, 0)
                            connection_attempts += 1
                        except Exception as e:
                            logger.error(f"Error sending heartbeat: {e}")
                    # If we've tried several times, reset the connection
                    elif connection_attempts >= 5:
                        try:
                            logger.warning("Connection issues detected, attempting to reset MAVLink connection")
                            self.autopilot_data["connected"] = False
                            if self.mav_connection:
                                self.mav_connection.close()
                            self.mav_connection = mavutil.mavlink_connection(
                                self.connection_string,
                                autoreconnect=True,
                                source_system=self.source_system)
                            waiting_for_heartbeat = True
                            connection_attempts = 0
                        except Exception as reset_error:
                            logger.error(f"Error resetting MAVLink connection: {reset_error}")
                            self.mav_connection = None
                            time.sleep(1)

            except socket.timeout:
                # This is expected when using blocking mode with timeout
                # No action needed as we'll loop back and try again
                pass
            except ConnectionResetError as cre:
                logger.warning(f"Connection reset: {cre}")
                self.autopilot_data["connected"] = False
                # Give a short pause before attempting reconnection
                time.sleep(1)
                try:
                    if self.mav_connection:
                        self.mav_connection.close()
                    self.mav_connection = mavutil.mavlink_connection(
                        self.connection_string,
                        autoreconnect=True,
                        source_system=self.source_system)
                    waiting_for_heartbeat = True
                    connection_attempts = 0
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

    def get_autopilot_details(self):
        self.autopilot_data["connected"] = self.is_connected()
        self.autopilot_data["timestamp"] = datetime.now().isoformat()
        return self.autopilot_data


class AutopilotManager:
    def __init__(self, connection_string='udpin:localhost:14571', source_system=254):
        self.mavlink = MAVLinkConnection(connection_string=connection_string, source_system=source_system)
        # Start the connection process (non-blocking)
        self.mavlink.connect()
        # The message loop is started automatically in connect()

    def execute_process(self, command, shell=True, timeout=30):
        """Execute a command and return the result"""
        try:
            process = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if process.returncode == 0:
                return True, process.stdout
            else:
                return False, process.stderr
        except Exception as e:
            return False, str(e)

    def get_autopilot_details(self):
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
                f"systemctl --user is-active {service_name}",
                shell=True,
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
            result = subprocess.run("systemctl --user stop mavlink-router",
                                    shell=True,
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
            result = subprocess.run("systemctl --user restart mavlink-router",
                                    shell=True,
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

    def reset_fmu(self, mode="wait_bl"):
        """Reset the flight management unit

        Args:
            mode: Either "wait_bl" to wait for bootloader or "fast" for quick reset
        """
        script = "reset_fmu_wait_bl.py" if mode == "wait_bl" else "reset_fmu_fast.py"
        try:
            logger.debug(f"Resetting FMU using {script}")
            result = subprocess.run(f"python3 ~/.local/bin/{script}",
                                   shell=True,
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

    def flash_firmware(self, firmware_path, socket_id):
        """Flash firmware to the autopilot"""
        socket = socketio.server
        logger.info(f"Starting firmware flash process for {firmware_path}")

        # Check if firmware file exists
        if not os.path.isfile(firmware_path):
            error_msg = "Firmware file does not exist"
            logger.error(f"Error: {error_msg}")
            error_data = {
                "status": "failed",
                "message": error_msg,
                "percent": 0
            }
            socket.emit('progress', error_data, room=socket_id)
            return False

        # Find the ARKV6X device
        logger.debug("Looking for ARKV6X device")
        serial_device = self.find_serial_device()
        if not serial_device:
            error_msg = "ARKV6X not found"
            logger.error(f"Error: {error_msg}")
            error_data = {
                "status": "failed",
                "message": error_msg,
                "percent": 0
            }
            socket.emit('progress', error_data, room=socket_id)
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
            self.stop_mavlink_router()
        else:
            logger.debug("mavlink-router is not active")

        # Reset FMU to enter bootloader mode
        logger.debug("Resetting FMU to enter bootloader mode")
        self.reset_fmu(mode="wait_bl")

        # Run px_uploader.py with JSON progress output
        logger.debug(f"Starting firmware upload using px_uploader.py")
        command = f"python3 -u ~/.local/bin/px_uploader.py --json-progress --port {serial_device} {firmware_path}"

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            logger.debug(f"Started upload process with PID: {process.pid}")

            # Process output line by line to capture JSON progress updates
            for line in process.stdout:
                logger.debug(f"Uploader output: {line.strip()}")
                if line is not None:
                    try:
                        # Try to parse as JSON for progress updates
                        progress_data = json.loads(line.strip())
                        socket.emit('progress', progress_data, room=socket_id)
                    except json.JSONDecodeError:
                        # Not JSON, could be other output
                        logger.debug(f"Non-JSON output: {line.strip()}")

            # Wait for process to complete
            return_code = process.wait()
            logger.debug(f"Upload process completed with return code: {return_code}")

            # Get stderr output if there was an error
            stderr_output = ""
            if return_code != 0:
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
                socket.emit('completed', {"message": success_msg}, room=socket_id)
                return True
            else:
                error_msg = f"Firmware update failed with code {return_code}: {stderr_output}"
                logger.error(error_msg)
                socket.emit('error', {"message": error_msg}, room=socket_id)
                return False

        except Exception as e:
            error_msg = f"Exception during firmware update: {str(e)}"
            logger.error(error_msg)
            socket.emit('error', {"message": error_msg}, room=socket_id)

            # Try to restart mavlink-router if it was active
            if router_was_active:
                logger.debug("Attempting to restart mavlink-router after exception")
                self.restart_mavlink_router()
                time.sleep(2)
                self.mavlink.connect()

            return False


# Store autopilot_manager as Flask app context
app.autopilot_manager = None


# API endpoints
@app.route('/details', methods=['GET'])
def get_autopilot_details():
    """Get details about the connected autopilot"""
    logger.debug("GET /details called")
    details = app.autopilot_manager.get_autopilot_details()
    return jsonify(details)


@app.route('/firmware-upload', methods=['POST'])
def upload_firmware():
    """Upload and flash firmware to the autopilot"""
    logger.info("POST /firmware-upload called")

    if 'firmware' not in request.files:
        logger.warning("No firmware file provided in request")
        return jsonify({"status": "fail", "message": "No firmware file provided"}), 400

    firmware_file = request.files['firmware']
    socket_id = request.form.get('socketId')

    if not socket_id:
        logger.warning("No socket ID provided in request")
        return jsonify({"status": "fail", "message": "No socket ID provided"}), 400

    # Check if the file has an allowed extension
    allowed_extensions = ['.px4', '.apj']
    filename = firmware_file.filename
    file_ext = os.path.splitext(filename)[1].lower()

    if file_ext not in allowed_extensions:
        logger.warning(f"Invalid file type: {file_ext}")
        return jsonify({
            "status": "fail",
            "message": f"Invalid file type. Only {', '.join(allowed_extensions)} files are allowed."
        }), 400

    # Create a temporary file for the firmware
    temp_path = os.path.join('/tmp', filename)
    firmware_file.save(temp_path)
    logger.info(f"Firmware file saved to {temp_path}")

    # Start the flashing process in a background thread
    @socketio.on_error_default
    def default_error_handler(e):
        logger.error(f"SocketIO error: {str(e)}")

    socketio.start_background_task(
        app.autopilot_manager.flash_firmware,
        temp_path,
        socket_id
    )

    return jsonify({"status": "success", "message": "Firmware upload started"})


@app.route('/reset-fmu', methods=['POST'])
def reset_fmu():
    """Reset the flight controller"""
    logger.info("POST /reset-fmu called")

    success, message = app.autopilot_manager.reset_fmu(mode="fast")

    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 500


@app.route('/reset-fmu-bootloader', methods=['POST'])
def reset_fmu_bootloader():
    """Reset the flight controller into bootloader mode"""
    logger.info("POST /reset-fmu-bootloader called")

    success, message = app.autopilot_manager.reset_fmu(mode="wait_bl")

    if success:
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 500


@socketio.on('connect')
def test_connect():
    client_id = request.sid
    logger.info(f'Client connected: {client_id}')
    return {'status': 'connected'}


@socketio.on('disconnect')
def test_disconnect():
    logger.info('Client disconnected')


# Error handler for SocketIO
@socketio.on_error_default
def default_error_handler(e):
    logger.error(f'SocketIO error: {str(e)}')


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='ARKV6X Autopilot Manager')
    parser.add_argument('--connection-string',
                        default='udpin:localhost:14571',
                        help='MAVLink connection string (default: udpin:localhost:14571)')
    parser.add_argument('--host',
                        default='0.0.0.0',
                        help='Host address to bind (default: 0.0.0.0)')
    parser.add_argument('--port',
                        type=int,
                        default=3003,
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
    app.autopilot_manager = AutopilotManager(
        connection_string=args.connection_string,
        source_system=args.source_system
    )

    logger.info(f"Starting Autopilot Manager on {args.host}:{args.port}")
    try:
        # For newer versions of Flask-SocketIO
        socketio.run(app, host=args.host, port=args.port, debug=False, allow_unsafe_werkzeug=True)
    except TypeError:
        # For older versions that don't have allow_unsafe_werkzeug parameter
        socketio.run(app, host=args.host, port=args.port, debug=False)
