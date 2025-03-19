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
import sys
import json
import subprocess
import re
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

class ServiceManager:
    
    @staticmethod
    def run_systemctl(operation, service_name):
        command = f"systemctl --user {operation} {service_name}"
        try:
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            output = ansi_escape.sub('', process.stdout + process.stderr).strip()
            
            if process.returncode == 0:
                return True, ""
            else:
                return False, output or f"Failed to {operation} service (exit code {process.returncode})"
                
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def get_service_status(service_name, status_type="active"):
        command = f"systemctl --user is-{status_type} {service_name}"
        try:
            process = subprocess.run(
                command, 
                shell=True,
                capture_output=True, 
                text=True
            )

            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return ansi_escape.sub('', process.stdout).strip() or process.stderr.strip()
        except:
            return "unknown"
    
    @staticmethod
    def get_service_config_file(service_name):
        base_dir = os.path.expanduser("~/.local/share")
        service_dir = os.path.join(base_dir, service_name)
        
        config_file_name = "config.toml"
        
        manifest_file = os.path.join(service_dir, f"{service_name}.manifest.json")
        if os.path.isfile(manifest_file):
            try:
                with open(manifest_file, 'r') as f:
                    manifest_data = json.load(f)
                    manifest_config = manifest_data.get("configFile", "")
                    if manifest_config:
                        config_file_name = manifest_config
            except Exception as e:
                print(f"Error reading manifest file for {service_name}: {e}")
        
        return os.path.join(service_dir, config_file_name)
    
    @staticmethod
    def is_service_visible(service_name):
        base_dir = os.path.expanduser("~/.local/share")
        manifest_file = os.path.join(base_dir, service_name, f"{service_name}.manifest.json")
        
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
        
        service_dir = os.path.expanduser("~/.config/systemd/user")
        base_dir = os.path.expanduser("~/.local/share")
        
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
            command = f"journalctl --user -u {service_name} -n {num_lines} --no-pager -o cat"
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            logs = ansi_escape.sub('', process.stdout).strip()
            
            return {"status": "success", "service": service_name, "logs": logs}
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
        
        config_file = ServiceManager.get_service_config_file(service_name)
        
        if not os.path.isfile(config_file):
            config_file_name = os.path.basename(config_file)
            service_dir = os.path.dirname(config_file)
            return {"status": "fail", "data": f"{config_file_name} not found in {service_dir}"}
        
        try:
            with open(config_file, 'w') as f:
                f.write(config_data)
                return {"status": "success", "data": "Configuration saved successfully"}
        except Exception as e:
            return {"status": "fail", "data": f"Error saving config file: {str(e)}"}

# API endpoints
@app.route('/statuses', methods=['GET'])
def get_service_statuses():
    print("GET /statuses called")
    return jsonify(ServiceManager.get_service_statuses())

@app.route('/start', methods=['POST'])
def start_service():
    service_name = request.args.get('serviceName')
    print(f"POST /start called for {service_name}")
    result = ServiceManager.start_service(service_name)
    return jsonify(result)

@app.route('/stop', methods=['POST'])
def stop_service():
    service_name = request.args.get('serviceName')
    print(f"POST /stop called for {service_name}")
    result = ServiceManager.stop_service(service_name)
    return jsonify(result)

@app.route('/restart', methods=['POST'])
def restart_service():
    service_name = request.args.get('serviceName')
    print(f"POST /restart called for {service_name}")
    result = ServiceManager.restart_service(service_name)
    return jsonify(result)

@app.route('/enable', methods=['POST'])
def enable_service():
    service_name = request.args.get('serviceName')
    print(f"POST /enable called for {service_name}")
    result = ServiceManager.enable_service(service_name)
    return jsonify(result)

@app.route('/disable', methods=['POST'])
def disable_service():
    service_name = request.args.get('serviceName')
    print(f"POST /disable called for {service_name}")
    result = ServiceManager.disable_service(service_name)
    return jsonify(result)

@app.route('/logs', methods=['GET'])
def get_service_logs():
    service_name = request.args.get('serviceName')
    print(f"GET /logs called for {service_name}")
    result = ServiceManager.get_logs(service_name)
    return jsonify(result)

@app.route('/config', methods=['GET'])
def get_service_config():
    service_name = request.args.get('serviceName')
    print(f"GET /config called for {service_name}")
    result = ServiceManager.get_config(service_name)
    return jsonify(result)

@app.route('/config', methods=['POST'])
def save_service_config():
    service_name = request.args.get('serviceName')
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
