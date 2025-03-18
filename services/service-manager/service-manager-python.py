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

# Initialize Flask
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

class ServiceManager:
    """Core class for managing system services"""
    
    @staticmethod
    def run_systemctl(operation, service_name):
        """Run a systemctl operation and return success/failure with appropriate message"""
        command = f"systemctl --user {operation} {service_name}"
        try:
            # Run the command
            print(f"Running: {command}")
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Strip color codes if present
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            output = ansi_escape.sub('', process.stdout + process.stderr).strip()
            
            # Return success for zero exit code, otherwise error with output
            if process.returncode == 0:
                return True, ""
            else:
                return False, output or f"Failed to {operation} service (exit code {process.returncode})"
                
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def get_service_status(service_name, status_type="active"):
        """
        Get the status of a service
        status_type can be "active" or "enabled"
        """
        command = f"systemctl --user is-{status_type} {service_name}"
        try:
            process = subprocess.run(
                command, 
                shell=True,
                capture_output=True, 
                text=True
            )
            # Strip color codes if present
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return ansi_escape.sub('', process.stdout).strip() or process.stderr.strip()
        except:
            return "unknown"
    
    @staticmethod
    def get_service_config_file(service_name):
        """Get the configuration file path for a service"""
        base_dir = os.path.expanduser("~/.local/share")
        service_dir = os.path.join(base_dir, service_name)
        
        # Default config file name
        config_file_name = "config.toml"
        
        # Check for manifest file
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
        
        # Return full path to config file
        return os.path.join(service_dir, config_file_name)
    
    @staticmethod
    def is_service_visible(service_name):
        """Check if a service should be visible in the UI"""
        base_dir = os.path.expanduser("~/.local/share")
        manifest_file = os.path.join(base_dir, service_name, f"{service_name}.manifest.json")
        
        if os.path.isfile(manifest_file):
            try:
                with open(manifest_file, 'r') as f:
                    manifest_data = json.load(f)
                    return str(manifest_data.get("visible", True)).lower() == "true"
            except:
                pass
        
        # Default to visible if no manifest exists or error occurs
        return True
    
    @staticmethod
    def get_service_statuses():
        """Get statuses of all user services"""
        print("Getting service statuses")
        services = []
        
        # Get the user's systemd service directory
        service_dir = os.path.expanduser("~/.config/systemd/user")
        base_dir = os.path.expanduser("~/.local/share")
        
        # Check if the directory exists
        if not os.path.isdir(service_dir):
            print(f"Service directory not found: {service_dir}")
            return {"services": []}
        
        # Find all service files
        service_files = [f for f in os.listdir(service_dir) if f.endswith('.service')]
        
        for service_file in service_files:
            service_name = service_file.replace('.service', '')
            
            # Get enabled and active status
            enabled_status = ServiceManager.get_service_status(service_name, "enabled")
            active_status = ServiceManager.get_service_status(service_name, "active")
            
            # Check for config file
            config_file = ServiceManager.get_service_config_file(service_name)
            config_file_name = os.path.basename(config_file) if os.path.isfile(config_file) else ""
            
            # Check if service should be visible
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
        """Start a user service"""
        print(f"Starting service: {service_name}")
        
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}
        
        # Try to start the service
        success, message = ServiceManager.run_systemctl("start", service_name)
        
        if success:
            # Check if service is now active
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
        """Stop a user service"""
        print(f"Stopping service: {service_name}")
        
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}
        
        # Try to stop the service
        success, message = ServiceManager.run_systemctl("stop", service_name)
        
        if success:
            # Check if service is now inactive
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
        """Restart a user service"""
        print(f"Restarting service: {service_name}")
        
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}
        
        # Try to restart the service
        success, message = ServiceManager.run_systemctl("restart", service_name)
        
        if success:
            # Get current status
            status = ServiceManager.get_service_status(service_name)
            return {"status": "success", "service": service_name, "active": status}
        else:
            return {"status": "fail", "service": service_name, "message": message}
    
    @staticmethod
    def enable_service(service_name):
        """Enable a user service"""
        print(f"Enabling service: {service_name}")
        
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}
        
        # Try to enable the service
        success, message = ServiceManager.run_systemctl("enable", service_name)
        
        if success:
            return {"status": "success", "service": service_name, "enabled": "enabled"}
        else:
            return {"status": "fail", "service": service_name, "message": message}
    
    @staticmethod
    def disable_service(service_name):
        """Disable a user service"""
        print(f"Disabling service: {service_name}")
        
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}
        
        # Try to disable the service
        success, message = ServiceManager.run_systemctl("disable", service_name)
        
        if success:
            return {"status": "success", "service": service_name, "enabled": "disabled"}
        else:
            return {"status": "fail", "service": service_name, "message": message}
    
    @staticmethod
    def get_logs(service_name, num_lines=50):
        """Get logs for a service"""
        print(f"Getting logs for service: {service_name}")
        
        if not service_name:
            return {"status": "fail", "message": "No service name provided"}
        
        try:
            # Run journalctl command to get logs
            command = f"journalctl --user -u {service_name} -n {num_lines} --no-pager -o cat"
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Strip color codes if present
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            logs = ansi_escape.sub('', process.stdout).strip()
            
            return {"status": "success", "service": service_name, "logs": logs}
        except Exception as e:
            return {"status": "fail", "service": service_name, "message": str(e)}
    
    @staticmethod
    def get_config(service_name):
        """Get configuration for a service"""
        print(f"Getting config for service: {service_name}")
        
        if not service_name:
            return {"status": "fail", "data": "No service name provided"}
        
        # Get the config file path
        config_file = ServiceManager.get_service_config_file(service_name)
        
        # If file doesn't exist, return error
        if not os.path.isfile(config_file):
            config_file_name = os.path.basename(config_file)
            service_dir = os.path.dirname(config_file)
            return {"status": "fail", "data": f"{config_file_name} not found in {service_dir}"}
        
        try:
            # Read the config file
            with open(config_file, 'r') as f:
                config_data = f.read()
                return {"status": "success", "data": config_data}
        except Exception as e:
            return {"status": "fail", "data": f"Error reading config file: {str(e)}"}
    
    @staticmethod
    def save_config(service_name, config_data):
        """Save configuration for a service"""
        print(f"Saving config for service: {service_name}")
        
        if not service_name:
            return {"status": "fail", "data": "No service name provided"}
        
        # Get the config file path
        config_file = ServiceManager.get_service_config_file(service_name)
        
        # If file doesn't exist, return error
        if not os.path.isfile(config_file):
            config_file_name = os.path.basename(config_file)
            service_dir = os.path.dirname(config_file)
            return {"status": "fail", "data": f"{config_file_name} not found in {service_dir}"}
        
        try:
            # Write the config file
            with open(config_file, 'w') as f:
                f.write(config_data)
                return {"status": "success", "data": "Configuration saved successfully"}
        except Exception as e:
            return {"status": "fail", "data": f"Error saving config file: {str(e)}"}

# API endpoints
@app.route('/service/statuses', methods=['GET'])
def get_service_statuses():
    """API endpoint to get all service statuses"""
    print("GET /service/statuses called")
    return jsonify(ServiceManager.get_service_statuses())

@app.route('/service/start', methods=['POST'])
def start_service():
    """API endpoint to start a service"""
    service_name = request.args.get('serviceName')
    print(f"POST /service/start called for {service_name}")
    result = ServiceManager.start_service(service_name)
    return jsonify(result)

@app.route('/service/stop', methods=['POST'])
def stop_service():
    """API endpoint to stop a service"""
    service_name = request.args.get('serviceName')
    print(f"POST /service/stop called for {service_name}")
    result = ServiceManager.stop_service(service_name)
    return jsonify(result)

@app.route('/service/restart', methods=['POST'])
def restart_service():
    """API endpoint to restart a service"""
    service_name = request.args.get('serviceName')
    print(f"POST /service/restart called for {service_name}")
    result = ServiceManager.restart_service(service_name)
    return jsonify(result)

@app.route('/service/enable', methods=['POST'])
def enable_service():
    """API endpoint to enable a service"""
    service_name = request.args.get('serviceName')
    print(f"POST /service/enable called for {service_name}")
    result = ServiceManager.enable_service(service_name)
    return jsonify(result)

@app.route('/service/disable', methods=['POST'])
def disable_service():
    """API endpoint to disable a service"""
    service_name = request.args.get('serviceName')
    print(f"POST /service/disable called for {service_name}")
    result = ServiceManager.disable_service(service_name)
    return jsonify(result)

@app.route('/service/logs', methods=['GET'])
def get_service_logs():
    """API endpoint to get service logs"""
    service_name = request.args.get('serviceName')
    print(f"GET /service/logs called for {service_name}")
    result = ServiceManager.get_logs(service_name)
    return jsonify(result)

@app.route('/service/config', methods=['GET'])
def get_service_config():
    """API endpoint to get service configuration"""
    service_name = request.args.get('serviceName')
    print(f"GET /service/config called for {service_name}")
    result = ServiceManager.get_config(service_name)
    return jsonify(result)

@app.route('/service/config', methods=['POST'])
def save_service_config():
    """API endpoint to save service configuration"""
    service_name = request.args.get('serviceName')
    config_data = request.json.get('config')
    print(f"POST /service/config called for {service_name}")
    
    if not config_data:
        return jsonify({"status": "fail", "data": "No configuration data provided"})
    
    result = ServiceManager.save_config(service_name, config_data)
    return jsonify(result)

if __name__ == '__main__':
    # Hardcoded settings
    host = '0.0.0.0'
    port = 3000
    
    print(f"Starting Service Manager on {host}:{port}")
    app.run(host=host, port=port)
