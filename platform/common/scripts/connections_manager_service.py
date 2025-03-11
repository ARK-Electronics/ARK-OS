#!/usr/bin/env python3
"""
ARK-OS Connections Manager Service

This service provides a REST API for managing network connections, including:
- WiFi connections (both client and AP mode)
- Ethernet connections
- LTE/cellular connections (Jetson platform only)
- Connection priorities and routing

It's designed to work with NetworkManager and ModemManager.
"""

import os
import sys
import json
import time
import logging
import threading
import subprocess
import re
import toml
import collections
from flask import Flask, jsonify, request
from flask_cors import CORS
import psutil
import argparse
from flask_socketio import SocketIO, emit, disconnect
from pathlib import Path


# Configure logging
def setup_logging():
    """Setup logging configuration with fallback to local log file if needed"""
    try:
        # Try to use system log location
        log_handlers = [
            logging.StreamHandler(),
            logging.FileHandler('/var/log/connections_manager.log')
        ]
    except PermissionError:
        # Fall back to local file if permission denied
        print("Warning: Could not write to system log. Using local log file instead.")
        log_handlers = [
            logging.StreamHandler(),
            logging.FileHandler('connections_manager.log')
        ]

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=log_handlers
    )
    return logging.getLogger('connections_manager')


# Initialize logger
logger = setup_logging()


# Initialize Flask and SocketIO
def create_app():
    """Create and configure the Flask application with SocketIO"""
    app = Flask(__name__)

    # Enable CORS for development and production
    CORS(app, resources={r"/*": {"origins": "*"}})

    # Create SocketIO instance with simplified configuration
    logger.info("Initializing SocketIO...")
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",  # Allow all origins in development; production uses nginx
        async_mode='threading',
        logger=False,
        engineio_logger=False,
        path='/network/socket.io',  # Important: Custom path to avoid conflict with the Node.js socket.io
        wsgi_app=app.wsgi_app
    )
    logger.info("SocketIO initialized with path='/network/socket.io'")

    return app, socketio


# Create Flask app and SocketIO instance
app, socketio = create_app()

# Constants and configuration
class Config:
    # Default configuration
    DEFAULT_CONFIG = {
        "service": {
            "port": 3001,
            "host": "0.0.0.0",  # Listen on all interfaces for local development
            "debug": False
        },
        "network": {
            "priorities": [
                {"type": "ethernet", "priority": 1},
                {"type": "wifi", "priority": 2},
                {"type": "lte", "priority": 3}
            ],
            "ap": {
                "ssid": "ARK-AP",
                "password": "arkosdrone"
            }
        }
    }

    # Data usage tracking constants
    STATS_COLLECT_INTERVAL = 1.0  # Collect stats once per second
    STATS_REPORT_INTERVAL = 2.0   # Report to client every 2 seconds
    RATE_FILTER_ALPHA = 0.3       # Complementary filter coefficient (0-1, higher = more responsive)


# Global state
class State:
    config = Config.DEFAULT_CONFIG.copy()
    interface_stats = {}  # Store the latest stats for each interface
    last_stats_update = 0
    last_stats_report = 0
    stats_lock = threading.Lock()  # Thread safety for stats access

    # Websocket clients for real-time updates
    active_stats_clients = set()
    stats_thread_active = False
    stats_thread = None

class ConfigManager:
    @staticmethod
    def load_config(config_path):
        """Load configuration from TOML file"""
        try:
            if os.path.exists(config_path):
                loaded_config = toml.load(config_path)
                # Deep merge with default config
                ConfigManager._deep_merge(State.config, loaded_config)
                logger.info(f"Configuration loaded from {config_path}")
            else:
                logger.warning(f"Config file {config_path} not found, using default config")
                # Create the config file with default values
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, 'w') as f:
                    toml.dump(State.config, f)
                logger.info(f"Created default configuration file at {config_path}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")

    @staticmethod
    def _deep_merge(base, updates):
        """Deep merge two dictionaries, updating base with values from updates"""
        for key, value in updates.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                ConfigManager._deep_merge(base[key], value)
            else:
                base[key] = value


class CommandExecutor:
    @staticmethod
    def run_command(command, timeout=10):
        """Run a shell command and return its output"""
        try:
            # logger.debug(f"Running command: {command}")
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {command}")
            logger.error(f"Error: {e}")
            logger.error(f"stderr: {e.stderr}")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return None
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return None

    @staticmethod
    def safe_run_command(command, default=None, timeout=10):
        """Safely run a command and return the result or default value"""
        result = CommandExecutor.run_command(command, timeout)
        return result if result is not None else default


class NetworkConnectionManager:
    @staticmethod
    def get_network_connections():
        """Get all network connections managed by NetworkManager (WiFi and Ethernet only)"""
        connections = []

        # Get all NetworkManager connections
        output = CommandExecutor.safe_run_command("nmcli -t -f NAME,TYPE,DEVICE,UUID,STATE connection show")
        if not output:
            return connections

        # Parse network connections
        for line in output.strip().split('\n'):
            parts = line.split(':')
            if len(parts) >= 5:
                name, conn_type, device, uuid, state = parts[:5]

                # Only include WiFi and Ethernet connections
                if conn_type not in ['802-11-wireless', '802-3-ethernet']:
                    continue

                # Map connection types
                type_map = {
                    '802-11-wireless': 'wifi',
                    '802-3-ethernet': 'ethernet'
                }
                mapped_type = type_map.get(conn_type, conn_type)

                # Get connection details
                connection = {
                    'id': uuid,
                    'name': name,
                    'type': mapped_type,
                    'status': 'active' if state == 'activated' and device else 'inactive',
                    'device': device if device else '',
                    'signalStrength': 0,
                    'dataRate': 0,
                    'ipAddress': ''
                }

                # Get additional details based on type
                if connection['status'] == 'active':
                    NetworkConnectionManager._enhance_active_connection(connection, device, mapped_type, name)

                # Get connection priority
                connection['priority'] = NetworkConnectionManager.get_connection_priority(connection)

                connections.append(connection)

        return connections
    
    @staticmethod
    def _enhance_active_connection(connection, device, connection_type, name):
        """Add additional details to an active connection"""
        # Get IP address
        ip_output = CommandExecutor.safe_run_command(
            f"ip addr show {device} | grep 'inet ' | head -1 | awk '{{print $2}}' | cut -d/ -f1"
        )
        if ip_output:
            connection['ipAddress'] = ip_output

        # Get signal strength for WiFi
        if connection_type == 'wifi':
            signal_output = CommandExecutor.safe_run_command(
                f"nmcli -f SIGNAL device wifi list ifname {device} | grep -v SIGNAL | head -1 | awk '{{print $1}}'"
            )
            if signal_output and signal_output.isdigit():
                connection['signalStrength'] = int(signal_output)
            
            # Get SSID and additional WiFi details
            ssid_output = CommandExecutor.safe_run_command(f"nmcli -g 802-11-wireless.ssid connection show '{name}'")
            if ssid_output:
                connection['ssid'] = ssid_output
            
            # Get WiFi password (only include a boolean indicating if it exists, not the actual password)
            password = CommandExecutor.safe_run_command(f"nmcli -g 802-11-wireless-security.psk connection show '{name}' -s")
            connection['hasPassword'] = bool(password)
            
            mode_output = CommandExecutor.safe_run_command(f"nmcli -g 802-11-wireless.mode connection show '{name}'")
            if mode_output:
                connection['mode'] = mode_output

        # For ethernet, signal strength is always 100%
        if connection_type == 'ethernet':
            connection['signalStrength'] = 100

    @staticmethod
    def get_connection_priority(connection):
        """Get the priority for a connection based on type"""
        # Check routing table metrics for active connections
        if connection['status'] == 'active' and connection['device']:
            metric_output = CommandExecutor.safe_run_command(
                f"ip route show default | grep {connection['device']} | grep -o 'metric [0-9]\\+' | awk '{{print $2}}'"
            )
            if metric_output and metric_output.isdigit():
                return int(metric_output)

        # Fall back to default priorities from config
        for priority_entry in State.config['network']['priorities']:
            if priority_entry['type'] == connection['type']:
                return priority_entry['priority']

        # Default to lowest priority (highest number)
        return 99




class RoutingManager:
    @staticmethod
    def get_routing_priorities():
        """Get current routing priorities based on the routing table"""
        connections = NetworkConnectionManager.get_network_connections()
        active_connections = [conn for conn in connections if conn['status'] == 'active']

        # Sort by priority (routing metric)
        active_connections.sort(key=lambda x: x.get('priority', 99))

        # Assign sequential priorities
        for i, conn in enumerate(active_connections):
            conn['priority'] = i + 1

        return active_connections

    @staticmethod
    def update_routing_priorities(priorities):
        """Update routing priorities by changing route metrics"""
        success = True
        for priority_item in priorities:
            conn_id = priority_item.get('id')
            priority = priority_item.get('priority')
            
            # Find connection details
            connections = NetworkConnectionManager.get_network_connections()
            connection = next((c for c in connections if c['id'] == conn_id), None)

            if connection and connection['status'] == 'active' and connection['device']:
                # Set route metric for this connection
                metric = priority * 100  # Convert priority to metric (lower priority = lower metric = higher precedence)
                cmd = f"nmcli connection modify {conn_id} ipv4.route-metric {metric} ipv6.route-metric {metric}"
                if CommandExecutor.safe_run_command(cmd) is None:
                    success = False

                # Reactivate connection for changes to take effect
                CommandExecutor.safe_run_command(f"nmcli connection down {conn_id}")
                if CommandExecutor.safe_run_command(f"nmcli connection up {conn_id}") is None:
                    success = False

        return success




# API Routes
@app.route('/network/connections', methods=['GET'])
def api_get_connections():
    """Get all network connections"""
    logger.info("GET /network/connections called")
    return jsonify(NetworkConnectionManager.get_network_connections())


class ConnectionControl:
    @staticmethod
    def connect(connection_id):
        """Connect to a network by UUID"""
        result = CommandExecutor.safe_run_command(f"nmcli connection up uuid {connection_id}")
        return {'success': result is not None}

    @staticmethod
    def disconnect(connection_id):
        """Disconnect from a network by UUID"""
        result = CommandExecutor.safe_run_command(f"nmcli connection down uuid {connection_id}")
        return {'success': result is not None}


@app.route('/network/connections/<id>/connect', methods=['POST'])
def api_connect_to_network(id):
    """Connect to a network by UUID"""
    logger.info(f"POST /network/connections/{id}/connect called")
    return jsonify(ConnectionControl.connect(id))


@app.route('/network/connections/<id>/disconnect', methods=['POST'])
def api_disconnect_from_network(id):
    """Disconnect from a network by UUID"""
    logger.info(f"POST /network/connections/{id}/disconnect called")
    return jsonify(ConnectionControl.disconnect(id))




@app.route('/network/connections/<id>', methods=['PUT'])
def api_update_connection(id):
    """Update a connection configuration (WiFi and Ethernet only)"""
    logger.info(f"PUT /network/connections/{id} called")
    return jsonify(ConnectionManager.update_connection(id, request.json))


class ConnectionManager:
    @staticmethod
    def update_connection(connection_id, data):
        """Update a connection configuration (WiFi and Ethernet only)"""
        connection_type = data.get('type')

        if connection_type == 'wifi':
            return ConnectionManager._update_wifi_connection(connection_id, data)
        elif connection_type == 'ethernet':
            return ConnectionManager._update_ethernet_connection(connection_id, data)
        else:
            return {'success': False, 'error': 'Unsupported connection type'}
    
    @staticmethod
    def _update_wifi_connection(connection_id, data):
        """Update a WiFi connection configuration"""
        ssid = data.get('ssid')
        password = data.get('password')
        mode = data.get('mode', 'infrastructure')
        
        # Build the command based on the connection mode
        cmd = f"nmcli connection modify uuid {connection_id}"

        if ssid:
            cmd += f" 802-11-wireless.ssid '{ssid}'"
        if password:
            cmd += f" wifi-sec.psk '{password}'"

        # Add mode-specific parameters
        if mode == 'ap':
            # AP mode might need additional parameters here
            pass

        result = CommandExecutor.safe_run_command(cmd)
        return {'success': result is not None}
    
    @staticmethod
    def _update_ethernet_connection(connection_id, data):
        """Update an Ethernet connection configuration"""
        ip_method = data.get('ipMethod', 'auto')
        
        cmd = f"nmcli connection modify uuid {connection_id}"
        
        if ip_method == 'auto':
            cmd += " ipv4.method auto"
        elif ip_method == 'manual':
            ip_address = data.get('ipAddress')
            gateway = data.get('gateway')
            prefix = data.get('prefix', 24)
            dns1 = data.get('dns1')
            dns2 = data.get('dns2')
            
            if ip_address and gateway:
                cmd += f" ipv4.method manual ipv4.addresses '{ip_address}/{prefix}' ipv4.gateway '{gateway}'"
                
                if dns1:
                    dns_servers = dns1
                    if dns2:
                        dns_servers += f",{dns2}"
                    cmd += f" ipv4.dns '{dns_servers}'"
            
        result = CommandExecutor.safe_run_command(cmd)
        return {'success': result is not None}

    @staticmethod
    def create_connection(data):
        """Create a new connection (WiFi and Ethernet only)"""
        connection_type = data.get('type')

        if connection_type == 'wifi':
            return ConnectionManager._create_wifi_connection(data)
        elif connection_type == 'ethernet':
            return ConnectionManager._create_ethernet_connection(data)
        else:
            return {'success': False, 'error': 'Unsupported connection type'}
    
    @staticmethod
    def _create_wifi_connection(data):
        """Create a new WiFi connection"""
        ssid = data.get('ssid')
        password = data.get('password')
        mode = data.get('mode', 'infrastructure')
        
        if not ssid:
            return {'success': False, 'error': 'SSID is required'}
        
        if mode == 'infrastructure':
            # Create infrastructure WiFi connection
            cmd = f"nmcli device wifi connect '{ssid}'"
            if password:
                cmd += f" password '{password}'"
                
            result = CommandExecutor.safe_run_command(cmd)
            if result is None:
                return {'success': False, 'error': 'Failed to create WiFi connection'}
                
            # Get the UUID of the new connection
            uuid_output = CommandExecutor.safe_run_command(f"nmcli -t -f NAME,UUID connection show | grep '{ssid}' | cut -d: -f2")
            return {'success': True, 'id': uuid_output}
            
        elif mode == 'ap':
            # Create AP WiFi connection
            cmd = f"nmcli connection add type wifi ifname '*' con-name '{ssid}' autoconnect no ssid '{ssid}' 802-11-wireless.mode ap 802-11-wireless.band bg ipv4.method shared"
            result = CommandExecutor.safe_run_command(cmd)
            
            if result is None:
                return {'success': False, 'error': 'Failed to create AP connection'}
            
            # Set password
            if password:
                update_cmd = f"nmcli connection modify '{ssid}' wifi-sec.key-mgmt wpa-psk wifi-sec.psk '{password}' 802-11-wireless-security.pmf disable"
                CommandExecutor.safe_run_command(update_cmd)
            
            # Get the UUID of the new connection
            uuid_output = CommandExecutor.safe_run_command(f"nmcli -t -f NAME,UUID connection show | grep '{ssid}' | cut -d: -f2")
            return {'success': True, 'id': uuid_output}
    
    @staticmethod
    def _create_ethernet_connection(data):
        """Create a new Ethernet connection"""
        name = data.get('name', 'Ethernet Connection')
        ip_method = data.get('ipMethod', 'auto')
        
        # Create base ethernet connection
        cmd = f"nmcli connection add type ethernet con-name '{name}' ifname '*'"
        result = CommandExecutor.safe_run_command(cmd)
        
        if result is None:
            return {'success': False, 'error': 'Failed to create ethernet connection'}
        
        # Configure IP settings
        uuid_output = CommandExecutor.safe_run_command(f"nmcli -t -f NAME,UUID connection show | grep '{name}' | cut -d: -f2")
        
        if ip_method == 'manual':
            ip_address = data.get('ipAddress')
            gateway = data.get('gateway')
            prefix = data.get('prefix', 24)
            dns1 = data.get('dns1')
            dns2 = data.get('dns2')
            
            if ip_address and gateway:
                update_cmd = f"nmcli connection modify uuid {uuid_output} ipv4.method manual ipv4.addresses '{ip_address}/{prefix}' ipv4.gateway '{gateway}'"
                
                if dns1:
                    dns_servers = dns1
                    if dns2:
                        dns_servers += f",{dns2}"
                    update_cmd += f" ipv4.dns '{dns_servers}'"
                
                CommandExecutor.safe_run_command(update_cmd)
        
        return {'success': True, 'id': uuid_output}
    
    @staticmethod
    def delete_connection(connection_id):
        """Delete a connection by UUID"""
        result = CommandExecutor.safe_run_command(f"nmcli connection delete uuid {connection_id}")
        return {'success': result is not None}


@app.route('/network/connections', methods=['POST'])
def api_create_connection():
    """Create a new connection (WiFi and Ethernet only)"""
    logger.info("POST /network/connections called")
    return jsonify(ConnectionManager.create_connection(request.json))


@app.route('/network/connections/<id>', methods=['DELETE'])
def api_delete_connection(id):
    """Delete a connection by UUID (WiFi and Ethernet only)"""
    logger.info(f"DELETE /network/connections/{id} called")
    return jsonify(ConnectionManager.delete_connection(id))


@app.route('/network/wifi/scan', methods=['GET'])
def api_scan_wifi():
    logger.info("GET /network/wifi/scan called")
    return jsonify(WiFiNetworkManager.scan_wifi_networks())


class WiFiNetworkManager:
    @staticmethod
    def scan_wifi_networks():
        """Scan for available WiFi networks"""
        networks = []

        # Trigger a scan
        CommandExecutor.safe_run_command("nmcli device wifi rescan")

        # Wait for scan to complete
        time.sleep(2)

        # Get scan results
        output = CommandExecutor.safe_run_command("nmcli -f SSID,SIGNAL,SECURITY,CHAN device wifi list")
        if not output:
            return networks

        # Parse WiFi networks
        lines = output.strip().split('\n')
        if len(lines) <= 1:  # Only header
            return networks

        # Get current connections for checking which ones are connected
        current_connections = NetworkConnectionManager.get_network_connections()
        connected_ssids = [conn.get('ssid', '') for conn in current_connections if conn['type'] == 'wifi' and conn['status'] == 'active']

        # Process each network
        for line in lines[1:]:  # Skip header row
            fields = re.split(r'\s{2,}', line.strip())
            if len(fields) >= 3:
                ssid = fields[0]
                signal = fields[1]
                security = fields[2]

                # Skip if no SSID
                if not ssid:
                    continue

                # Create network entry
                network = {
                    'ssid': ssid,
                    'signalStrength': int(signal) if signal.isdigit() else 0,
                    'secured': security != '--',
                    'connected': ssid in connected_ssids
                }

                networks.append(network)

        return networks

    @staticmethod
    def connect_wifi(data):
        """Connect to WiFi network with the given SSID and password"""
        ssid = data.get('ssid')
        password = data.get('password')

        if not ssid:
            return {'success': False, 'error': 'SSID is required'}

        cmd = f"nmcli device wifi connect '{ssid}'"
        if password:
            cmd += f" password '{password}'"

        result = CommandExecutor.safe_run_command(cmd)
        return {'success': result is not None}


@app.route('/network/wifi/connect', methods=['POST'])
def api_connect_wifi():
    logger.info("POST /network/wifi/connect called")
    return jsonify(WiFiNetworkManager.connect_wifi(request.json))


@app.route('/network/routing', methods=['GET'])
def api_get_routing():
    logger.info("GET /network/routing called")
    return jsonify(RoutingManager.get_routing_priorities())


@app.route('/network/routing', methods=['PUT'])
def api_update_routing():
    logger.info("PUT /network/routing called")
    data = request.json
    priorities = data.get('priorities', [])
    
    success = RoutingManager.update_routing_priorities(priorities)
    return jsonify({'success': success})


class HostnameManager:
    @staticmethod
    def get_hostname():
        """Get the system hostname"""
        return CommandExecutor.safe_run_command("hostname")

    @staticmethod
    def set_hostname(new_hostname):
        """Set the system hostname"""
        if not new_hostname:
            return False, "No hostname provided"

        # Validate hostname format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', new_hostname):
            return False, "Invalid hostname format"

        # Change hostname using hostnamectl
        result = CommandExecutor.safe_run_command(f"sudo hostnamectl set-hostname {new_hostname}")
        if result is None:
            return False, "Failed to set hostname"

        return True, new_hostname


@app.route('/network/hostname', methods=['GET'])
def api_get_hostname():
    logger.info("GET /network/hostname called")
    hostname = HostnameManager.get_hostname()
    return jsonify({"hostname": hostname})


@app.route('/network/hostname', methods=['POST'])
def api_set_hostname():
    logger.info("POST /network/hostname called")
    data = request.json
    new_hostname = data.get('hostname')
    
    success, message = HostnameManager.set_hostname(new_hostname)
    
    if success:
        return jsonify({"status": "success", "hostname": message})
    else:
        return jsonify({"status": "error", "message": message}), 400


class CellularUtils:
    @staticmethod
    def detect_apn_from_carrier(operator_name):
        """Detect appropriate APN based on carrier/operator name"""
        if not operator_name:
            return None

        # Convert to lowercase for case-insensitive matching
        operator_lower = operator_name.lower()

        # Common US carriers
        if any(name in operator_lower for name in ['t-mobile', 'tmobile']):
            return 'fast.t-mobile.com'
        elif any(name in operator_lower for name in ['at&t', 'at and t', 'att']):
            return 'broadband'
        elif any(name in operator_lower for name in ['verizon']):
            return 'vzwinternet'
        elif any(name in operator_lower for name in ['sprint']):
            return 'sprint'
        elif any(name in operator_lower for name in ['h2o']):
            return 'h2o'
        elif any(name in operator_lower for name in ['visible']):
            return 'vsblinternet'

        # International carriers
        elif any(name in operator_lower for name in ['vodafone']):
            return 'internet'
        elif any(name in operator_lower for name in ['orange']):
            return 'orange'
        elif any(name in operator_lower for name in ['telefonica', 'movistar']):
            return 'movistar.es'
        elif any(name in operator_lower for name in ['telstra']):
            return 'telstra.internet'

        # No match found
        return None




@app.route('/network/lte/status', methods=['GET'])
def api_get_lte_status():
    """Get LTE modem status (Jetson platform only)"""
    logger.info("GET /network/lte/status called")
    return jsonify(LteManager.get_lte_status())


class LteManager:
    @staticmethod
    def get_lte_status():
        """Get LTE modem status (Jetson platform only)"""
        # Check if we're on a Jetson platform
        is_jetson = os.path.exists('/etc/nv_tegra_release')

        if not is_jetson:
            return {"status": "not_available", "message": "LTE functionality only available on Jetson platform"}

        # Check if ModemManager is installed and running
        if not CommandExecutor.safe_run_command("systemctl is-active --quiet ModemManager"):
            return {"status": "not_found", "message": "ModemManager is not running"}

        # Get modem index
        modem_index = CommandExecutor.safe_run_command("mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
        if not modem_index:
            return {"status": "not_found", "message": "No modem found"}

        try:
            # Get modem information
            modem_info = CommandExecutor.safe_run_command(f"mmcli -m {modem_index}")
            if not modem_info:
                return {"status": "error", "message": "Failed to get modem information"}

            # Parse modem information
            model = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} | grep -oP '(?<=model: ).*' || echo 'Unknown'")
            operator = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} | grep -oP '(?<=operator name: ).*' || echo 'Unknown'")
            state = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} | grep -oP '(?<=state: ).*' || echo 'Unknown'")
            signal = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} | grep 'signal quality' | awk '{{print $4}}' | sed 's/%//'")

            # Get bearer information if connected
            bearer_path = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} | grep -oP '/org/freedesktop/ModemManager1/Bearer/\\d+' | head -1 || echo ''")
            connected = bool(bearer_path)

            # Initialize interface details
            apn = ""
            ip_address = ""
            interface = ""
            gateway = ""
            dns = []

            if connected:
                bearer_index = re.search(r'/Bearer/(\d+)', bearer_path)
                if bearer_index:
                    bearer_info = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} --bearer={bearer_index.group(1)}")
                    if bearer_info:
                        # Extract all bearer details
                        apn_match = re.search(r'apn: ([\w\.-]+)', bearer_info)
                        if apn_match:
                            apn = apn_match.group(1)

                        interface_match = re.search(r'interface: (\w+)', bearer_info)
                        if interface_match:
                            interface = interface_match.group(1)

                        address_match = re.search(r'address: ([0-9.]+)', bearer_info)
                        if address_match:
                            ip_address = address_match.group(1)

                        gateway_match = re.search(r'gateway: ([0-9.]+)', bearer_info)
                        if gateway_match:
                            gateway = gateway_match.group(1)

                        dns_match = re.search(r'DNS: ([0-9., ]+)', bearer_info)
                        if dns_match:
                            dns = [s.strip() for s in dns_match.group(1).split(',') if s.strip()]

            # Get data usage (tx/rx) on the interface if it exists
            tx_bytes = 0
            rx_bytes = 0
            if interface:
                try:
                    io_counters = psutil.net_io_counters(pernic=True)
                    if interface in io_counters:
                        tx_bytes = io_counters[interface].bytes_sent
                        rx_bytes = io_counters[interface].bytes_recv
                except Exception as e:
                    logger.warning(f"Failed to get interface statistics: {e}")
                    
            # Detect appropriate APN from carrier if available
            detected_apn = None
            if operator.strip() and operator.strip() != "Unknown":
                detected_apn = CellularUtils.detect_apn_from_carrier(operator.strip())
                    
            # Build response
            response = {
                "status": "ok",
                "model": model.strip() if model else "Unknown",
                "operator": operator.strip() if operator else "Unknown",
                "state": state.strip() if state else "Unknown",
                "signal": int(signal) if signal and signal.isdigit() else 0,
                "connected": connected,
                "apn": apn,
                "detectedApn": detected_apn,
            }

            # Add connection details if connected
            if connected:
                response.update({
                    "interface": interface,
                    "ipAddress": ip_address,
                    "gateway": gateway,
                    "dns": dns,
                    "dataUsage": {
                        "txBytes": tx_bytes,
                        "rxBytes": rx_bytes
                    }
                })

            return response
        except Exception as e:
            logger.error(f"Error getting LTE status: {e}")
            return {"status": "error", "message": str(e)}

    @staticmethod
    def connect_lte(apn=None, request_data=None):
        """Connect to LTE network with specified APN (Jetson platform only)"""
        # Get APN from request data if provided
        if request_data:
            apn = request_data.get('apn', apn)

        # Check if we're on a Jetson platform
        is_jetson = os.path.exists('/etc/nv_tegra_release')
        
        if not is_jetson:
            return {"status": "error", "message": "LTE functionality only available on Jetson platform"}, 400

        # If no APN is provided, try to detect it from the carrier
        if not apn:
            # Get modem index
            modem_index = CommandExecutor.safe_run_command("mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
            if not modem_index:
                return {"status": "error", "message": "No modem found"}, 404
                
            # Get carrier/operator name
            operator = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} | grep -oP '(?<=operator name: ).*' || echo ''")
            if operator:
                detected_apn = CellularUtils.detect_apn_from_carrier(operator)
                if detected_apn:
                    logger.info(f"No APN provided, detected {detected_apn} from carrier {operator}")
                    apn = detected_apn
                else:
                    logger.error(f"No APN provided and couldn't detect from carrier: {operator}")
                    return {"status": "error", "message": "APN is required - couldn't auto-detect from carrier"}, 400
            else:
                logger.error("No APN provided and couldn't detect carrier")
                return {"status": "error", "message": "APN is required - no carrier detected"}, 400

        # Check prerequisites
        if not CommandExecutor.safe_run_command("modprobe qmi_wwan"):
            return {"status": "error", "message": "Failed to load qmi_wwan kernel module"}, 500

        if not CommandExecutor.safe_run_command("systemctl is-active --quiet ModemManager"):
            return {"status": "error", "message": "ModemManager is not running"}, 500
        
        try:
            # Wait for modem to be available
            logger.info("Waiting for modem to be available...")
            modem_index = None
            for _ in range(30):  # Wait up to 60 seconds
                result = CommandExecutor.safe_run_command("mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
                if result:
                    modem_index = result
                    break
                time.sleep(2)

            if not modem_index:
                return {"status": "error", "message": "No modem found after waiting"}, 404

            logger.info(f"Modem found with index {modem_index}")

            # Configure modem initial EPS bearer settings
            logger.info(f"Configuring modem with APN: {apn}")
            eps_cmd = f"mmcli -m {modem_index} --3gpp-set-initial-eps-bearer-settings=apn={apn}"
            if not CommandExecutor.safe_run_command(eps_cmd):
                return {"status": "error", "message": "Failed to configure modem EPS settings"}, 500

            # Connect modem to network
            logger.info("Connecting modem to network...")
            connect_cmd = f"mmcli -m {modem_index} --simple-connect=apn={apn},ip-type=ipv4v6"
            if not CommandExecutor.safe_run_command(connect_cmd):
                return {"status": "error", "message": "Failed to connect modem to network"}, 500

            # Wait for modem to connect to network
            logger.info("Waiting for modem to connect to network...")
            connected = False
            for _ in range(60):  # Wait up to 60 seconds
                modem_status = CommandExecutor.safe_run_command(f"mmcli -m {modem_index}")
                if modem_status and "state: connected" in modem_status and "packet service state: attached" in modem_status:
                    connected = True
                    break
                time.sleep(1)

            if not connected:
                return {"status": "error", "message": "Modem failed to connect within timeout period"}, 500

            # Get bearer information
            logger.info("Getting bearer information...")
            bearer_path = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} | grep -oP '/org/freedesktop/ModemManager1/Bearer/\\d+' | head -1")
            if not bearer_path:
                return {"status": "error", "message": "Failed to get bearer path"}, 500

            bearer_index = re.search(r'/Bearer/(\d+)', bearer_path)
            if not bearer_index:
                return {"status": "error", "message": "Failed to parse bearer index"}, 500

            # Get interface details
            bearer_info = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} --bearer={bearer_index.group(1)}")
            if not bearer_info:
                return {"status": "error", "message": "Failed to get bearer information"}, 500

            # Extract network details using regex
            interface_match = re.search(r'interface: (\w+)', bearer_info)
            address_match = re.search(r'address: ([0-9.]+)', bearer_info)
            prefix_match = re.search(r'prefix: (\d+)', bearer_info)
            gateway_match = re.search(r'gateway: ([0-9.]+)', bearer_info)
            dns_match = re.search(r'DNS: ([0-9., ]+)', bearer_info)
            mtu_match = re.search(r'MTU: (\d+)', bearer_info)

            if not interface_match or not address_match or not gateway_match:
                return {"status": "error", "message": "Failed to extract network information from bearer"}, 500

            # Configure the network interface
            interface = interface_match.group(1)
            address = address_match.group(1)
            prefix = prefix_match.group(1) if prefix_match else "24"
            gateway = gateway_match.group(1)

            # Flush existing IP and routes
            logger.info(f"Configuring interface {interface}...")
            if not CommandExecutor.safe_run_command(f"ip addr flush dev {interface}"):
                logger.warning("Failed to flush IP address")

            if not CommandExecutor.safe_run_command(f"ip route flush dev {interface}"):
                logger.warning("Failed to flush routes")

            # Configure interface
            if not CommandExecutor.safe_run_command(f"ip link set {interface} up"):
                return {"status": "error", "message": f"Failed to bring up interface {interface}"}, 500

            if not CommandExecutor.safe_run_command(f"ip addr add {address}/{prefix} dev {interface}"):
                return {"status": "error", "message": f"Failed to add IP address to interface {interface}"}, 500

            if mtu_match:
                CommandExecutor.safe_run_command(f"ip link set {interface} mtu {mtu_match.group(1)}")

            # Configure routing
            CommandExecutor.safe_run_command(f"ip link set dev {interface} arp off")

            if not CommandExecutor.safe_run_command(f"ip route add default via {gateway} dev {interface} metric 4294967295"):
                return {"status": "error", "message": "Failed to add default route"}, 500

            # Configure DNS if available
            if dns_match:
                dns_servers = dns_match.group(1).strip().split(",")
                if len(dns_servers) > 0:
                    dns1 = dns_servers[0].strip()
                    if dns1:
                        logger.info(f"Adding DNS server: {dns1}")
                        CommandExecutor.safe_run_command(f"sh -c \"echo 'nameserver {dns1}' >> /etc/resolv.conf\"")

                if len(dns_servers) > 1:
                    dns2 = dns_servers[1].strip()
                    if dns2:
                        logger.info(f"Adding DNS server: {dns2}")
                        CommandExecutor.safe_run_command(f"sh -c \"echo 'nameserver {dns2}' >> /etc/resolv.conf\"")

            # Test connection
            logger.info("Testing connection...")
            if not CommandExecutor.safe_run_command(f"ping -4 -c 1 -I {interface} 8.8.8.8", timeout=5):
                logger.warning("Ping test failed, but connection might still be working")

            return {
                "status": "success",
                "message": "LTE modem connected",
                "interface": interface,
                "ipAddress": address,
                "gateway": gateway
            }
        except Exception as e:
            logger.error(f"Error connecting to LTE: {e}")
            return {"status": "error", "message": str(e)}, 500

    @staticmethod
    def disconnect_lte():
        """Disconnect LTE modem"""
        # Check if we're on a Jetson platform
        is_jetson = os.path.exists('/etc/nv_tegra_release')

        if not is_jetson:
            return {"status": "error", "message": "LTE functionality only available on Jetson platform"}, 400
        
        # Check if ModemManager is installed and running
        if not CommandExecutor.safe_run_command("systemctl is-active --quiet ModemManager"):
            return {"status": "error", "message": "ModemManager is not running"}, 500

        # Get modem index
        modem_index = CommandExecutor.safe_run_command("mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
        if not modem_index:
            return {"status": "error", "message": "No modem found"}, 404

        try:
            # Get bearer information to identify the interface
            bearer_path = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} | grep -oP '/org/freedesktop/ModemManager1/Bearer/\\d+' | head -1")
            interface = None

            if bearer_path:
                bearer_index = re.search(r'/Bearer/(\d+)', bearer_path)
                if bearer_index:
                    bearer_info = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} --bearer={bearer_index.group(1)}")
                    if bearer_info:
                        interface_match = re.search(r'interface: (\w+)', bearer_info)
                        if interface_match:
                            interface = interface_match.group(1)

            # Disconnect the modem
            logger.info("Disconnecting modem...")
            if not CommandExecutor.safe_run_command(f"mmcli -m {modem_index} --simple-disconnect"):
                return {"status": "error", "message": "Failed to disconnect from LTE network"}, 500

            # Clean up the interface if found
            if interface:
                logger.info(f"Cleaning up interface {interface}...")
                CommandExecutor.safe_run_command(f"ip addr flush dev {interface}")
                CommandExecutor.safe_run_command(f"ip route flush dev {interface}")

            return {"status": "success", "message": "Disconnected from LTE network"}
        except Exception as e:
            logger.error(f"Error disconnecting from LTE: {e}")
            return {"status": "error", "message": str(e)}, 500


@app.route('/network/lte/connect', methods=['POST'])
def api_connect_lte():
    """Connect to LTE network with specified APN (Jetson platform only)"""
    logger.info("POST /network/lte/connect called")
    result, status_code = LteManager.connect_lte(request_data=request.json)
    
    if isinstance(status_code, int):
        return jsonify(result), status_code
    else:
        return jsonify(result)


@app.route('/network/lte/disconnect', methods=['POST'])
def api_disconnect_lte():
    """Disconnect from LTE network (Jetson platform only)"""
    logger.info("POST /network/lte/disconnect called")
    result, status_code = LteManager.disconnect_lte()
    
    if isinstance(status_code, int):
        return jsonify(result), status_code
    else:
        return jsonify(result)


class NetworkStatsCollector:
    @staticmethod
    def collect_interface_stats():
        """
        Collect network interface statistics from activated NetworkManager connections.
        Simplified to focus only on active connections and basic stats.
        Returns a dictionary of interface stats with rx/tx bytes, packets, errors, dropped.
        """
        stats = {}
        try:
            # Get all activated NetworkManager connections
            nm_output = CommandExecutor.safe_run_command("nmcli -t -f NAME,TYPE,DEVICE,UUID,STATE connection show")
            if not nm_output:
                logger.warning("Failed to get NetworkManager connections")
                return stats

            active_connections = {}
            
            # Parse NetworkManager connections and find active ones with devices
            for line in nm_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) >= 5:
                    name, conn_type, device, uuid, state = parts[:5]
                    
                    # Only process active connections with devices
                    if state == 'activated' and device and device != '--':
                        # Map connection types
                        if conn_type == '802-11-wireless':
                            interface_type = 'wifi'
                        elif conn_type == '802-3-ethernet':
                            interface_type = 'ethernet'
                        elif conn_type in ['gsm', 'cdma']:
                            interface_type = 'lte'
                        else:
                            interface_type = 'other'
                            
                        active_connections[device] = {
                            'name': name,
                            'type': interface_type,
                            'uuid': uuid
                        }
            
            logger.debug(f"Found {len(active_connections)} active NetworkManager connections")
            
            # Process each active connection
            for device, info in active_connections.items():
                # Get detailed stats using 'ip -s link show' command
                stats_output = CommandExecutor.safe_run_command(f"ip -s link show {device}")
                if not stats_output:
                    logger.warning(f"Failed to get stats for device {device}")
                    continue
                
                # Parse the stats output
                interface_stats = NetworkStatsCollector._parse_ip_stats(stats_output)
                if not interface_stats:
                    continue
                
                # Get IP address
                ip_output = CommandExecutor.safe_run_command(
                    f"ip addr show {device} | grep -w inet | head -1 | awk '{{print $2}}' | cut -d/ -f1"
                )
                
                # Create the stats entry with simplified data
                device_stats = {
                    'interface': device,
                    'name': info['name'],
                    'type': info['type'],
                    'active': True,  # Only active connections are included
                    'rx_bytes': interface_stats['rx_bytes'],
                    'rx_packets': interface_stats['rx_packets'],
                    'rx_errors': interface_stats['rx_errors'],
                    'rx_dropped': interface_stats['rx_dropped'],
                    'tx_bytes': interface_stats['tx_bytes'],
                    'tx_packets': interface_stats['tx_packets'],
                    'tx_errors': interface_stats['tx_errors'],
                    'tx_dropped': interface_stats['tx_dropped'],
                    'rx_rate': 0,  # Will be calculated by processor
                    'tx_rate': 0,  # Will be calculated by processor
                    'timestamp': time.time(),
                    'ip_address': ip_output if ip_output else ''
                }
                
                # Add WiFi-specific information if applicable
                if info['type'] == 'wifi':
                    # Get signal strength
                    signal_output = CommandExecutor.safe_run_command(
                        f"nmcli -f SIGNAL device wifi list ifname {device} | grep -v SIGNAL | head -1 | awk '{{print $1}}'"
                    )
                    if signal_output and signal_output.isdigit():
                        device_stats['signal_strength'] = int(signal_output)
                    
                    # Get SSID
                    ssid_output = CommandExecutor.safe_run_command(f"nmcli -g 802-11-wireless.ssid connection show '{info['name']}'")
                    if ssid_output:
                        device_stats['ssid'] = ssid_output
                
                stats[device] = device_stats
                logger.debug(f"Collected stats for {device} ({info['name']}): RX={device_stats['rx_bytes']}, TX={device_stats['tx_bytes']}")

        except Exception as e:
            logger.error(f"Error collecting interface stats: {e}")

        return stats

    @staticmethod
    def _parse_ip_stats(stats_output):
        """Parse the output of 'ip -s link show' command"""
        rx_bytes = 0
        rx_packets = 0
        rx_errors = 0
        rx_dropped = 0
        tx_bytes = 0
        tx_packets = 0
        tx_errors = 0
        tx_dropped = 0

        lines = stats_output.split('\n')
        for i, line in enumerate(lines):
            if 'RX:' in line and i+1 < len(lines):
                stats_line = lines[i+1].strip()
                parts = stats_line.split()
                if len(parts) >= 4:
                    rx_bytes = int(parts[0])
                    rx_packets = int(parts[1])
                    rx_errors = int(parts[2])
                    rx_dropped = int(parts[3])
            elif 'TX:' in line and i+1 < len(lines):
                stats_line = lines[i+1].strip()
                parts = stats_line.split()
                if len(parts) >= 4:
                    tx_bytes = int(parts[0])
                    tx_packets = int(parts[1])
                    tx_errors = int(parts[2])
                    tx_dropped = int(parts[3])

        return {
            'rx_bytes': rx_bytes,
            'rx_packets': rx_packets,
            'rx_errors': rx_errors,
            'rx_dropped': rx_dropped,
            'tx_bytes': tx_bytes,
            'tx_packets': tx_packets,
            'tx_errors': tx_errors,
            'tx_dropped': tx_dropped
        }



class NetworkStatsProcessor:
    @staticmethod
    def update_interface_stats():
        """
        Update interface statistics and calculate rates using a complementary filter for smoothing.
        Simplified implementation focused on active interfaces only.
        """
        current_time = time.time()

        # Check if enough time has passed since the last update
        if (State.interface_stats and
            current_time - State.last_stats_update < Config.STATS_COLLECT_INTERVAL):
            # Not enough time has passed since last update
            logger.debug("Skipping stats update - not enough time elapsed")
            return State.interface_stats

        # Get current stats for active network interfaces
        current_stats = NetworkStatsCollector.collect_interface_stats()
        if not current_stats:
            logger.debug("No active network interfaces found")
            return State.interface_stats

        with State.stats_lock:
            # Calculate rates for interfaces that have previous data
            for interface, stats in current_stats.items():
                NetworkStatsProcessor._calculate_interface_rates(interface, stats)

            # Update our stored stats with the new values
            State.interface_stats = current_stats
            State.last_stats_update = current_time

        return State.interface_stats

    @staticmethod
    def _calculate_interface_rates(interface, stats):
        """Calculate data rates for a network interface with simplified smoothing filter"""
        # Calculate rates if we have previous data for this interface
        if interface in State.interface_stats:
            previous = State.interface_stats[interface]
            time_diff = stats['timestamp'] - previous['timestamp']

            if time_diff > 0:
                # Calculate bytes per second
                rx_bytes_diff = stats['rx_bytes'] - previous['rx_bytes']
                tx_bytes_diff = stats['tx_bytes'] - previous['tx_bytes']

                # Check for counter reset (e.g., interface restarted)
                if rx_bytes_diff < 0:
                    logger.warning(f"RX counter reset detected for {interface}")
                    rx_bytes_diff = stats['rx_bytes']

                if tx_bytes_diff < 0:
                    logger.warning(f"TX counter reset detected for {interface}")
                    tx_bytes_diff = stats['tx_bytes']

                # Calculate current rates in bytes per second
                current_rx_rate = rx_bytes_diff / time_diff
                current_tx_rate = tx_bytes_diff / time_diff

                # Apply complementary filter for smooth rate transition
                # new_value = α * current_measurement + (1-α) * previous_value
                # Using Config.RATE_FILTER_ALPHA (default 0.3)
                if 'rx_rate' in previous:
                    # Apply complementary filter
                    alpha = Config.RATE_FILTER_ALPHA
                    rx_rate = (alpha * current_rx_rate) + ((1 - alpha) * previous['rx_rate'])
                    tx_rate = (alpha * current_tx_rate) + ((1 - alpha) * previous['tx_rate'])
                else:
                    # First calculation for this interface
                    rx_rate = current_rx_rate
                    tx_rate = current_tx_rate

                # Convert to Mbps for display (bytes/sec * 8 / 1,000,000)
                rx_rate_mbps = rx_rate * 8 / 1_000_000
                tx_rate_mbps = tx_rate * 8 / 1_000_000

                # Zero out rates when no actual traffic
                if rx_bytes_diff == 0:
                    rx_rate_mbps = 0
                if tx_bytes_diff == 0:
                    tx_rate_mbps = 0

                # Store the calculated rates
                stats['rx_rate'] = rx_rate
                stats['tx_rate'] = tx_rate
                stats['rx_rate_mbps'] = rx_rate_mbps
                stats['tx_rate_mbps'] = tx_rate_mbps

                logger.debug(f"Interface {interface} rates: RX={rx_rate_mbps:.2f} Mbps, TX={tx_rate_mbps:.2f} Mbps")
            else:
                # No time elapsed, copy previous values
                if 'rx_rate' in previous:
                    stats['rx_rate'] = previous['rx_rate']
                    stats['tx_rate'] = previous['tx_rate']
                    stats['rx_rate_mbps'] = previous.get('rx_rate_mbps', 0)
                    stats['tx_rate_mbps'] = previous.get('tx_rate_mbps', 0)
        else:
            # First time seeing this interface, initialize rate values
            logger.info(f"First collection for {interface} - initializing rate values")
            stats['rx_rate'] = 0
            stats['tx_rate'] = 0
            stats['rx_rate_mbps'] = 0
            stats['tx_rate_mbps'] = 0




class NetworkReporting:
    @staticmethod
    def get_interface_usage_summary():
        """
        Get simplified usage summary for active network interfaces.
        Returns a list of interface summaries with essential stats.
        """
        with State.stats_lock:
            summary = []

            # Check if we have any stats, if not try to collect them
            if not State.interface_stats:
                logger.debug("No interface stats available, collecting now")
                NetworkStatsProcessor.update_interface_stats()
                
                if not State.interface_stats:
                    logger.debug("No active network interfaces found")
                    return []

            # Process each interface to create a simplified summary
            for interface, stats in State.interface_stats.items():
                # Skip loopback interface
                if interface == 'lo':
                    continue

                # Create a simplified summary with just the essentials
                # IMPORTANT: Using UI naming conventions for compatibility
                interface_summary = {
                    'interface': interface,
                    'type': stats.get('type', 'other'),
                    'name': stats.get('name', interface),
                    'ipAddress': stats.get('ip_address', ''),  # camelCase for UI
                    'active': True,  # Only active interfaces are included
                    'isUp': True,    # Legacy field for UI compatibility
                    
                    # Basic traffic stats
                    'rxBytes': stats.get('rx_bytes', 0),
                    'txBytes': stats.get('tx_bytes', 0),
                    'totalBytes': stats.get('rx_bytes', 0) + stats.get('tx_bytes', 0),
                    
                    # Rates in Mbps - CRITICAL: match exactly what the Vue component expects
                    'dataDown': stats.get('rx_rate_mbps', 0),
                    'dataUp': stats.get('tx_rate_mbps', 0),
                    'current_rx_rate_mbps': stats.get('rx_rate_mbps', 0),  # Snake case version 
                    'current_tx_rate_mbps': stats.get('tx_rate_mbps', 0),  # Snake case version
                    'currentRxRateMbps': stats.get('rx_rate_mbps', 0),     # Camel case version
                    'currentTxRateMbps': stats.get('tx_rate_mbps', 0),     # Camel case version
                    
                    # Error and packet counts with camelCase for UI
                    'rxErrors': stats.get('rx_errors', 0),
                    'rxDropped': stats.get('rx_dropped', 0),
                    'txErrors': stats.get('tx_errors', 0),
                    'txDropped': stats.get('tx_dropped', 0),
                    'rxPackets': stats.get('rx_packets', 0),
                    'txPackets': stats.get('tx_packets', 0)
                }
                
                # Add WiFi-specific fields if applicable
                if stats.get('type') == 'wifi':
                    interface_summary['signalStrength'] = stats.get('signal_strength', 0)
                    interface_summary['ssid'] = stats.get('ssid', '')
                
                summary.append(interface_summary)

            # Sort by total bytes (most traffic first)
            summary.sort(key=lambda x: -x.get('totalBytes', 0))
            
            logger.debug(f"Generated summary for {len(summary)} active interfaces")
            return summary




class StatsThread:
    """
    Manages the background thread for network statistics collection and reporting.
    Thread starts when the first client connects and stops when the last client disconnects.
    """

    @staticmethod
    def start_collection_thread():
        """Create and start the stats collection thread if not already running"""
        if not State.stats_thread_active and State.active_stats_clients:
            logger.info("Starting network stats collection thread")
            State.stats_thread_active = True
            State.stats_thread = threading.Thread(
                target=StatsThread.stats_collection_thread,
                daemon=True
            )
            State.stats_thread.start()
            return True
        return False

    @staticmethod
    def stop_collection_thread():
        """Signal the stats collection thread to stop"""
        if State.stats_thread_active:
            logger.info("Stopping network stats collection thread")
            State.stats_thread_active = False
            return True
        return False

    @staticmethod
    def stats_collection_thread():
        """
        Thread function to collect and report network statistics to connected clients.
        Only runs while there are active clients connected to the websocket.
        """
        logger.info("Network stats collection thread started")
        count = 0

        try:
            # Main collection loop - runs as long as there are active clients
            while State.stats_thread_active and len(State.active_stats_clients) > 0:
                try:
                    # Collect interface stats at the configured interval
                    stats = NetworkStatsProcessor.update_interface_stats()
                    count += 1

                    # Log occasionally to avoid filling logs
                    if count <= 2 or count % 30 == 0:
                        active_interfaces = list(stats.keys()) if stats else []
                        logger.info(f"Stats update #{count}. Active interfaces: {active_interfaces}")
                        
                        # Log interfaces with significant traffic
                        StatsThread._log_traffic_stats(stats)

                    # Send updates to clients at the report interval
                    StatsThread._send_stats_to_clients()

                except Exception as e:
                    logger.error(f"Error in stats collection thread: {e}")
                    # Continue the thread despite errors

                # Sleep before next collection
                time.sleep(Config.STATS_COLLECT_INTERVAL)

            logger.info("Network stats collection thread stopping - no active clients")

        except Exception as e:
            logger.error(f"Fatal error in stats collection thread: {e}")
        finally:
            # Always mark the thread as inactive when exiting
            State.stats_thread_active = False

    @staticmethod
    def _log_traffic_stats(stats):
        """Log information about interfaces with meaningful traffic"""
        if not stats:
            return
            
        # Only log interfaces with significant traffic (> 0.1 Mbps)
        active_interfaces = []
        for interface, data in stats.items():
            rx_rate = data.get('rx_rate_mbps', 0)
            tx_rate = data.get('tx_rate_mbps', 0)
            if rx_rate > 0.1 or tx_rate > 0.1:
                active_interfaces.append(f"{interface}: ↓{rx_rate:.2f}/↑{tx_rate:.2f} Mbps")

        if active_interfaces:
            logger.info(f"Interfaces with traffic: {', '.join(active_interfaces)}")

    @staticmethod
    def _send_stats_to_clients():
        """Send collected stats to all connected clients at the configured interval"""
        current_time = time.time()

        # Only send updates at the configured interval
        if (current_time - State.last_stats_report >= Config.STATS_REPORT_INTERVAL) and State.active_stats_clients:
            try:
                # Generate the summary to send to clients
                summary = NetworkReporting.get_interface_usage_summary()
                
                # Make sure we have data to send
                if not summary:
                    logger.warning("No network interfaces found to report stats")
                    return
                    
                # Send update to all connected clients
                if State.active_stats_clients:
                    # Log data we're sending periodically
                    if current_time - State.last_stats_update > 10:
                        logger.info(f"Sending stats update: {summary}")
                        
                    socketio.emit('network_stats_update', summary)
                    logger.info(f"Sent stats update to {len(State.active_stats_clients)} clients")
                    State.last_stats_report = current_time
            except Exception as e:
                logger.error(f"Failed to send stats update: {e}")




class SocketEventHandler:
    """
    Handles Socket.IO events for real-time network statistics communication.
    Manages client connections and the lifecycle of the stats collection thread.
    """

    @staticmethod
    @socketio.on('connect')
    def handle_stats_connect():
        """
        Handle new websocket connection for network stats.
        Starts the stats collection thread if this is the first client.
        """
        try:
            client_id = request.sid
            logger.info(f"Network stats client connected: {client_id}")

            # Add to active clients
            State.active_stats_clients.add(client_id)
            logger.info(f"Client added. Total active clients: {len(State.active_stats_clients)}")

            # Start collection thread if this is the first client
            if not State.stats_thread_active:
                logger.info("First client connected, starting stats collection thread")
                StatsThread.start_collection_thread()

            # Make sure we have some initial stats
            NetworkStatsProcessor.update_interface_stats()

            # Send initial data to this client immediately
            try:
                summary = NetworkReporting.get_interface_usage_summary()
                if summary:
                    logger.info(f"Sending initial stats to client: {client_id}")
                    logger.info(f"Initial data: {summary}")
                    socketio.emit('network_stats_update', summary, room=client_id)
                else:
                    logger.warning("No network interfaces found for initial stats")
            except Exception as e:
                logger.error(f"Error sending initial stats: {e}")

            return True  # Acknowledge the connection

        except Exception as e:
            logger.error(f"Error handling client connection: {e}")
            return False  # Reject connection if there's an error

    @staticmethod
    @socketio.on('disconnect')
    def handle_stats_disconnect(reason=None):
        """
        Handle websocket disconnection.
        Stops the stats collection thread if this was the last client.
        """
        try:
            client_id = request.sid
            logger.info(f"Network stats client disconnected: {client_id}, reason: {reason}")

            # Remove from active clients
            if client_id in State.active_stats_clients:
                State.active_stats_clients.remove(client_id)
                remaining = len(State.active_stats_clients)
                logger.info(f"Client removed. Remaining active clients: {remaining}")

                # Stop thread if no clients remain
                if remaining == 0 and State.stats_thread_active:
                    logger.info("Last client disconnected, stopping stats collection thread")
                    StatsThread.stop_collection_thread()
                    
        except Exception as e:
            logger.error(f"Error handling client disconnect: {e}")

    @staticmethod
    @socketio.on_error()
    def handle_error(e):
        """Handle Socket.IO errors"""
        try:
            client_id = request.sid if hasattr(request, 'sid') else "unknown"
            logger.error(f"SocketIO error for client {client_id}: {str(e)}")
        except Exception as inner_error:
            # Emergency fallback for errors in error handler
            logger.error(f"Error in error handler: {inner_error}")

        # Return False to prevent the error from propagating
        return False


class ApplicationRunner:
    """Application entry point and initialization"""
    
    @staticmethod
    def main():
        """Main entry point for the application"""
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='ARK-OS Connections Manager Service')
        parser.add_argument(
            '--config',
            default='/etc/ark/network/connections_manager.toml',
            help='Path to config file'
        )
        args = parser.parse_args()

        # Load configuration from file
        ConfigManager.load_config(args.config)

        # Start the server
        ApplicationRunner.start_server()
    
    @staticmethod
    def start_server():
        """Start the Flask SocketIO server"""
        logger.info(f"Starting SocketIO server on {State.config['service']['host']}:{State.config['service']['port']}")
        try:
            socketio.run(
                app,
                host=State.config['service']['host'],
                port=State.config['service']['port'],
                debug=State.config['service']['debug'],
                allow_unsafe_werkzeug=True
            )
        except Exception as e:
            logger.error(f"Error starting SocketIO server: {e}")
            logger.exception(e)


# Entry point
if __name__ == '__main__':
    ApplicationRunner.main()
