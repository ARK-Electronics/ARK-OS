#!/usr/bin/env python3
"""
ARK-OS Service Manager

This service provides a REST API for managing system services, including:
- Retrieving service statuses
- Starting and stopping services
- Enabling and disabling services
- Managing service configurations
- Viewing service logs

It's designed to replace the existing bash script implementations with a unified Python service.
"""

import os
import json
import subprocess
import re
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Input validation
_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
_SERVICE_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$')
_VALID_SYSTEMCTL_OPS = frozenset({"start", "stop", "restart", "enable", "disable"})
_VALID_STATUS_TYPES = frozenset({"active", "enabled"})


def validate_service_name(name):
    if not name or not _SERVICE_NAME_RE.match(name):
        raise ValueError(f"Invalid service name: {name}")
    return name


def validate_positive_int(value, max_val=10000):
    n = int(value)
    if n < 1 or n > max_val:
        raise ValueError(f"Value out of range: {n}")
    return n


class ServiceManager:

    @staticmethod
    def run_systemctl(operation, service_name):
        if operation not in _VALID_SYSTEMCTL_OPS:
            return False, f"Invalid operation: {operation}"
        service_name = validate_service_name(service_name)
        try:
            process = subprocess.run(
                ["systemctl", "--user", operation, service_name],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = _ANSI_RE.sub('', process.stdout + process.stderr).strip()

            if process.returncode == 0:
                return True, ""
            else:
                return False, output or f"Failed to {operation} service (exit code {process.returncode})"

        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_service_status(service_name, status_type="active"):
        if status_type not in _VALID_STATUS_TYPES:
            return "unknown"
        service_name = validate_service_name(service_name)
        try:
            process = subprocess.run(
                ["systemctl", "--user", f"is-{status_type}", service_name],
                capture_output=True,
                text=True
            )

            return _ANSI_RE.sub('', process.stdout).strip() or process.stderr.strip()
        except:
            return "unknown"

    @staticmethod
    def get_service_config_file(service_name):
        share_dir = f"/opt/ark/share/{service_name}"

        config_file_name = "config.toml"

        manifest_file = os.path.join(share_dir, f"{service_name}.manifest.json")
        if os.path.isfile(manifest_file):
            try:
                with open(manifest_file, 'r') as f:
                    manifest_data = json.load(f)
                    manifest_config = manifest_data.get("configFile", "")
                    if manifest_config:
                        config_file_name = manifest_config
            except Exception as e:
                print(f"Error reading manifest file for {service_name}: {e}")

        # Check user config override first, then fall back to installed default
        user_config = os.path.expanduser(f"~/.config/ark/{service_name}/{config_file_name}")
        if os.path.isfile(user_config):
            return user_config

        return os.path.join(share_dir, config_file_name)

    @staticmethod
    def is_service_visible(service_name):
        manifest_file = f"/opt/ark/share/{service_name}/{service_name}.manifest.json"

        if os.path.isfile(manifest_file):
            try:
                with open(manifest_file, 'r') as f:
                    manifest_data = json.load(f)
                    return str(manifest_data.get("visible", True)).lower() == "true"
            except:
                pass

        return True

    @staticmethod
    def get_service_statuses():
        services = []

        service_dir = "/etc/systemd/user"

        if not os.path.isdir(service_dir):
            return {"services": []}

        service_files = [f for f in os.listdir(service_dir) if f.endswith('.service')]

        for service_file in service_files:
            service_name = service_file.replace('.service', '')

            enabled_status = ServiceManager.get_service_status(service_name, "enabled")
            active_status = ServiceManager.get_service_status(service_name, "active")

            config_file = ServiceManager.get_service_config_file(service_name)
            config_file_name = os.path.basename(config_file) if os.path.isfile(config_file) else ""

            visible = "true" if ServiceManager.is_service_visible(service_name) else "false"

            services.append({
                "name": service_name,
                "enabled": enabled_status,
                "active": active_status,
                "config_file": config_file_name,
                "visible": visible
            })

        return {"services": services}

    @staticmethod
    def start_service(service_name):
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}

        success, message = ServiceManager.run_systemctl("start", service_name)

        if success:
            status = ServiceManager.get_service_status(service_name)
            if status == "active":
                return {"status": "success", "service": service_name, "active": status}
            else:
                return {"status": "fail", "service": service_name,
                        "message": f"Service started but status is '{status}' instead of 'active'"}
        else:
            return {"status": "fail", "service": service_name, "message": message}

    @staticmethod
    def stop_service(service_name):
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}

        success, message = ServiceManager.run_systemctl("stop", service_name)

        if success:
            status = ServiceManager.get_service_status(service_name)
            if status == "inactive":
                return {"status": "success", "service": service_name, "active": status}
            else:
                return {"status": "fail", "service": service_name,
                        "message": f"Service stopped but status is '{status}' instead of 'inactive'"}
        else:
            return {"status": "fail", "service": service_name, "message": message}

    @staticmethod
    def restart_service(service_name):
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}

        success, message = ServiceManager.run_systemctl("restart", service_name)

        if success:
            status = ServiceManager.get_service_status(service_name)
            return {"status": "success", "service": service_name, "active": status}
        else:
            return {"status": "fail", "service": service_name, "message": message}

    @staticmethod
    def enable_service(service_name):
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}

        success, message = ServiceManager.run_systemctl("enable", service_name)

        if success:
            return {"status": "success", "service": service_name, "enabled": "enabled"}
        else:
            return {"status": "fail", "service": service_name, "message": message}

    @staticmethod
    def disable_service(service_name):
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}

        success, message = ServiceManager.run_systemctl("disable", service_name)

        if success:
            return {"status": "success", "service": service_name, "enabled": "disabled"}
        else:
            return {"status": "fail", "service": service_name, "message": message}

    @staticmethod
    def get_logs(service_name, num_lines=50):
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}

        try:
            service_name = validate_service_name(service_name)
            num_lines = validate_positive_int(num_lines, max_val=10000)
            process = subprocess.run(
                ["journalctl", "--user", "-u", service_name, "-n", str(num_lines), "--no-pager", "-o", "cat"],
                capture_output=True,
                text=True,
                timeout=10
            )

            logs = _ANSI_RE.sub('', process.stdout).strip()

            return {"status": "success", "service": service_name, "logs": logs}
        except ValueError as e:
            return {"status": "fail", "service": service_name, "message": str(e)}
        except Exception as e:
            return {"status": "fail", "service": service_name, "message": str(e)}

    @staticmethod
    def get_config(service_name):
        if not service_name:
            return {"status": "fail", "data": "No service name provided"}

        config_file = ServiceManager.get_service_config_file(service_name)

        if not os.path.isfile(config_file):
            config_file_name = os.path.basename(config_file)
            service_dir = os.path.dirname(config_file)
            return {"status": "fail", "data": f"{config_file_name} not found in {service_dir}"}

        try:
            with open(config_file, 'r') as f:
                config_data = f.read()
                return {"status": "success", "data": config_data}
        except Exception as e:
            return {"status": "fail", "data": f"Error reading config file: {str(e)}"}

    @staticmethod
    def save_config(service_name, config_data):
        if not service_name:
            return {"status": "fail", "data": "No service name provided"}

        try:
            service_name = validate_service_name(service_name)
        except ValueError as e:
            return {"status": "fail", "data": str(e)}

        # Validate config content size
        if len(config_data) > 65536:
            return {"status": "fail", "data": f"Config too large: {len(config_data)} bytes (max 65536)"}

        config_file = ServiceManager.get_service_config_file(service_name)
        config_file_name = os.path.basename(config_file)

        if not os.path.isfile(config_file):
            service_dir = os.path.dirname(config_file)
            return {"status": "fail", "data": f"{config_file_name} not found in {service_dir}"}

        # Always save to user-writable location (~/.config/ark/<service>/)
        user_config_dir = os.path.expanduser(f"~/.config/ark/{service_name}")
        user_config_file = os.path.join(user_config_dir, config_file_name)

        # Prevent path traversal
        allowed_base = os.path.realpath(os.path.expanduser("~/.config/ark"))
        if not os.path.realpath(user_config_file).startswith(allowed_base + os.sep):
            return {"status": "fail", "data": "Invalid config path"}

        try:
            os.makedirs(user_config_dir, exist_ok=True)
            with open(user_config_file, 'w') as f:
                f.write(config_data)
                return {"status": "success", "data": "Configuration saved successfully"}
        except Exception as e:
            return {"status": "fail", "data": f"Error saving config file: {str(e)}"}

# API endpoints
def _get_validated_service_name():
    """Extract and validate service name from request args. Returns (name, error_response)."""
    service_name = request.args.get('serviceName')
    if not service_name:
        return None, (jsonify({"status": "fail", "message": "No service name provided"}), 400)
    try:
        validate_service_name(service_name)
    except ValueError:
        return None, (jsonify({"status": "fail", "message": f"Invalid service name: {service_name}"}), 400)
    return service_name, None


@app.route('/statuses', methods=['GET'])
def get_service_statuses():
    print("GET /statuses called")
    return jsonify(ServiceManager.get_service_statuses())

@app.route('/start', methods=['POST'])
def start_service():
    service_name, err = _get_validated_service_name()
    if err:
        return err
    print(f"POST /start called for {service_name}")
    result = ServiceManager.start_service(service_name)
    return jsonify(result)

@app.route('/stop', methods=['POST'])
def stop_service():
    service_name, err = _get_validated_service_name()
    if err:
        return err
    print(f"POST /stop called for {service_name}")
    result = ServiceManager.stop_service(service_name)
    return jsonify(result)

@app.route('/restart', methods=['POST'])
def restart_service():
    service_name, err = _get_validated_service_name()
    if err:
        return err
    print(f"POST /restart called for {service_name}")
    result = ServiceManager.restart_service(service_name)
    return jsonify(result)

@app.route('/enable', methods=['POST'])
def enable_service():
    service_name, err = _get_validated_service_name()
    if err:
        return err
    print(f"POST /enable called for {service_name}")
    result = ServiceManager.enable_service(service_name)
    return jsonify(result)

@app.route('/disable', methods=['POST'])
def disable_service():
    service_name, err = _get_validated_service_name()
    if err:
        return err
    print(f"POST /disable called for {service_name}")
    result = ServiceManager.disable_service(service_name)
    return jsonify(result)

@app.route('/logs', methods=['GET'])
def get_service_logs():
    service_name, err = _get_validated_service_name()
    if err:
        return err
    print(f"GET /logs called for {service_name}")
    result = ServiceManager.get_logs(service_name)
    return jsonify(result)

@app.route('/config', methods=['GET'])
def get_service_config():
    service_name, err = _get_validated_service_name()
    if err:
        return err
    print(f"GET /config called for {service_name}")
    result = ServiceManager.get_config(service_name)
    return jsonify(result)

@app.route('/config', methods=['POST'])
def save_service_config():
    service_name, err = _get_validated_service_name()
    if err:
        return err
    config_data = request.json.get('config')
    print(f"POST /config called for {service_name}")

    if not config_data:
        return jsonify({"status": "fail", "data": "No configuration data provided"})

    result = ServiceManager.save_config(service_name, config_data)
    return jsonify(result)

if __name__ == '__main__':
    host = '127.0.0.1'
    port = 3002

    print(f"Starting Service Manager on {host}:{port}")
    app.run(host=host, port=port, threaded=True)
