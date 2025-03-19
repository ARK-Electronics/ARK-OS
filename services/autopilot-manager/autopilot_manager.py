#!/usr/bin/env python3
"""
ARKV6X Autopilot Manager

This service provides a REST API for managing the flight controller, including:
- Retrieving autopilot details
- Uploading and flashing firmware
"""

import os
import json
import subprocess
import tempfile
import glob
import threading
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO

# Explicitly set async_mode to threading to avoid eventlet issues
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", path='/socket.io/vehicle-firmware-upload',
                   async_mode='threading')

class AutopilotManager:

    @staticmethod
    def execute_process(command, shell=True, timeout=30):
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

    @staticmethod
    def get_autopilot_details():
        """Get details about the connected autopilot"""
        command = "mavlink_autopilot_details.sh"
        success, output = AutopilotManager.execute_process(command)

        if success:
            try:
                data = json.loads(output)
                return data
            except json.JSONDecodeError:
                return {"error": "Invalid response format"}
        else:
            return {"error": f"Command failed: {output}"}

    @staticmethod
    def find_serial_device():
        """Find the ARKV6X serial device"""
        try:
            devices = glob.glob('/dev/serial/by-id/*ARK*')
            for device in devices:
                if 'if00' in device:
                    return os.path.realpath(device)
            return None
        except Exception as e:
            print(f"Error finding serial device: {e}")
            return None

    @staticmethod
    def is_service_active(service_name):
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
            print(f"Error checking service status: {e}")
            return False

    @staticmethod
    def stop_mavlink_router():
        try:
            print("Stopping mavlink-router service")
            subprocess.run("systemctl --user stop mavlink-router", shell=True, check=False)
            return True
        except Exception as e:
            print(f"Error stopping mavlink-router: {e}")
            return False


    @staticmethod
    def restart_mavlink_router():
        try:
            print("Restarting mavlink-router service")
            subprocess.run("systemctl --user restart mavlink-router", shell=True, check=False)
            return True
        except Exception as e:
            print(f"Error restarting mavlink-router: {e}")
            return False


    @staticmethod
    def reset_fmu(mode="wait_bl"):
        """Reset the flight management unit

        Args:
            mode: Either "wait_bl" to wait for bootloader or "fast" for quick reset
        """
        script = "reset_fmu_wait_bl.py" if mode == "wait_bl" else "reset_fmu_fast.py"
        try:
            subprocess.run(f"python3 ~/.local/bin/{script}", shell=True, check=False)
            return True
        except Exception as e:
            print(f"Error resetting FMU: {e}")
            return False

    @staticmethod
    def flash_firmware(firmware_path, socket_id):
        """Flash firmware to the autopilot"""
        socket = socketio.server

        # Check if firmware file exists
        if not os.path.isfile(firmware_path):
            error_data = {
                "status": "failed",
                "message": "Firmware file does not exist",
                "percent": 0
            }
            socket.emit('progress', error_data, room=socket_id)
            return False

        # Find the ARKV6X device
        serial_device = AutopilotManager.find_serial_device()
        if not serial_device:
            error_data = {
                "status": "failed",
                "message": "ARKV6X not found",
                "percent": 0
            }
            socket.emit('progress', error_data, room=socket_id)
            return False

        # Stop mavlink router service if it's running
        router_was_active = AutopilotManager.is_service_active("mavlink-router")
        if router_was_active:
            AutopilotManager.stop_mavlink_router()

        # Reset FMU to enter bootloader mode
        AutopilotManager.reset_fmu(mode="wait_bl")

        # Run px_uploader.py with JSON progress output
        command = f"python3 -u ~/.local/bin/px_uploader.py --json-progress --port {serial_device} {firmware_path}"
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        # Process output line by line to capture JSON progress updates
        for line in process.stdout:
            try:
                # Try to parse as JSON for progress updates
                progress_data = json.loads(line.strip())
                socket.emit('progress', progress_data, room=socket_id)
            except json.JSONDecodeError:
                # Not JSON, could be other output
                pass

        # Wait for process to complete
        return_code = process.wait()

        # Reset FMU quickly after flashing
        AutopilotManager.reset_fmu(mode="fast")

        # Wait for the reset to complete
        import time
        time.sleep(3)

        # Restart mavlink router service only if it was active before
        if router_was_active:
            AutopilotManager.restart_mavlink_router()

        if return_code == 0:
            socket.emit('completed', {"message": "Firmware update completed successfully."}, room=socket_id)
            return True
        else:
            error_output = process.stderr.read()
            socket.emit('error', {"message": f"Firmware update failed: {error_output}"}, room=socket_id)
            return False

# API endpoints
@app.route('/autopilot-details', methods=['GET'])
def get_autopilot_details():
    """Get details about the connected autopilot"""
    print("GET /autopilot-details called")
    details = AutopilotManager.get_autopilot_details()
    return jsonify(details)

@app.route('/firmware-upload', methods=['POST'])
def upload_firmware():
    """Upload and flash firmware to the autopilot"""
    print("POST /firmware-upload called")

    if 'firmware' not in request.files:
        return jsonify({"status": "fail", "message": "No firmware file provided"}), 400

    firmware_file = request.files['firmware']
    socket_id = request.form.get('socketId')

    if not socket_id:
        return jsonify({"status": "fail", "message": "No socket ID provided"}), 400

    # Check if the file has an allowed extension
    allowed_extensions = ['.px4', '.apj']
    filename = firmware_file.filename
    file_ext = os.path.splitext(filename)[1].lower()

    if file_ext not in allowed_extensions:
        return jsonify({
            "status": "fail",
            "message": f"Invalid file type. Only {', '.join(allowed_extensions)} files are allowed."
        }), 400

    # Create a temporary file for the firmware
    temp_path = os.path.join('/tmp', filename)
    firmware_file.save(temp_path)

    # Start the flashing process in a background thread
    @socketio.on_error_default
    def default_error_handler(e):
        print(f"SocketIO error: {str(e)}")

    socketio.start_background_task(
        AutopilotManager.flash_firmware,
        temp_path,
        socket_id
    )

    return jsonify({"status": "success", "message": "Firmware upload started"})

@socketio.on('connect')
def test_connect():
    client_id = request.sid
    print(f'Client connected: {client_id}')
    return {'status': 'connected'}

@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')

# Error handler for SocketIO
@socketio.on_error_default
def default_error_handler(e):
    print(f'SocketIO error: {str(e)}')

if __name__ == '__main__':
    host = '0.0.0.0'
    port = 3003

    print(f"Starting Autopilot Manager on {host}:{port}")
    try:
        # For newer versions of Flask-SocketIO
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    except TypeError:
        # For older versions that don't have allow_unsafe_werkzeug parameter
        socketio.run(app, host=host, port=port, debug=False)
