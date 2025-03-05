#!/usr/bin/env python3
"""
ARK-OS Connections Manager Service

This service provides a REST API for managing network connections, including:
- WiFi connections (both client and AP mode)
- Ethernet connections
- LTE/cellular connections (Jetson platform only)
- Connection priorities and routing
- Network statistics

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
from flask import Flask, jsonify, request
from flask_cors import CORS
import psutil
import argparse
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/connections_manager.log')
    ]
)
logger = logging.getLogger('connections_manager')

# Create Flask app
app = Flask(__name__)
CORS(app)  # Enable cross-origin requests

# Default configuration
DEFAULT_CONFIG = {
    "service": {
        "port": 5000,
        "host": "0.0.0.0",
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

# Global variables
config = DEFAULT_CONFIG.copy()

def load_config(config_path):
    """Load configuration from TOML file"""
    global config
    try:
        if os.path.exists(config_path):
            loaded_config = toml.load(config_path)
            # Deep merge with default config
            deep_merge(config, loaded_config)
            logger.info(f"Configuration loaded from {config_path}")
        else:
            logger.warning(f"Config file {config_path} not found, using default config")
            # Create the config file with default values
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                toml.dump(config, f)
            logger.info(f"Created default configuration file at {config_path}")
    except Exception as e:
        logger.error(f"Error loading config: {e}")

def deep_merge(base, updates):
    """Deep merge two dictionaries, updating base with values from updates"""
    for key, value in updates.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value

def run_command(command, timeout=10):
    """Run a shell command and return its output"""
    try:
        logger.debug(f"Running command: {command}")
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

def safe_run_command(command, default=None, timeout=10):
    """Safely run a command and return the result or default value"""
    result = run_command(command, timeout)
    return result if result is not None else default

def get_network_connections():
    """Get all network connections managed by NetworkManager (WiFi and Ethernet only)"""
    connections = []
    
    # Get all NetworkManager connections
    output = safe_run_command("nmcli -t -f NAME,TYPE,DEVICE,UUID,STATE connection show")
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
                # Get IP address
                ip_output = safe_run_command(f"ip addr show {device} | grep 'inet ' | head -1 | awk '{{print $2}}' | cut -d/ -f1")
                if ip_output:
                    connection['ipAddress'] = ip_output
                
                # Get signal strength for WiFi
                if mapped_type == 'wifi':
                    signal_output = safe_run_command(f"nmcli -f SIGNAL device wifi list ifname {device} | grep -v SIGNAL | head -1 | awk '{{print $1}}'")
                    if signal_output and signal_output.isdigit():
                        connection['signalStrength'] = int(signal_output)
                    
                    # Get SSID and additional WiFi details
                    ssid_output = safe_run_command(f"nmcli -g 802-11-wireless.ssid connection show '{name}'")
                    if ssid_output:
                        connection['ssid'] = ssid_output
                    
                    # Get WiFi password (only include a boolean indicating if it exists, not the actual password)
                    password = safe_run_command(f"nmcli -g 802-11-wireless-security.psk connection show '{name}' -s")
                    connection['hasPassword'] = bool(password)
                    
                    mode_output = safe_run_command(f"nmcli -g 802-11-wireless.mode connection show '{name}'")
                    if mode_output:
                        connection['mode'] = mode_output
                
                # For ethernet, signal strength is always 100%
                if mapped_type == 'ethernet':
                    connection['signalStrength'] = 100
            
            # Get connection priority
            connection['priority'] = get_connection_priority(connection)
            
            connections.append(connection)
    
    return connections

def get_connection_priority(connection):
    """Get the priority for a connection based on type"""
    # Check routing table metrics for active connections
    if connection['status'] == 'active' and connection['device']:
        metric_output = safe_run_command(f"ip route show default | grep {connection['device']} | grep -o 'metric [0-9]\\+' | awk '{{print $2}}'")
        if metric_output and metric_output.isdigit():
            return int(metric_output)
    
    # Fall back to default priorities from config
    for priority_entry in config['network']['priorities']:
        if priority_entry['type'] == connection['type']:
            return priority_entry['priority']
    
    # Default to lowest priority (highest number)
    return 99

def scan_wifi_networks():
    """Scan for available WiFi networks"""
    networks = []
    
    # Trigger a scan
    safe_run_command("nmcli device wifi rescan")
    
    # Wait for scan to complete
    time.sleep(2)
    
    # Get scan results
    output = safe_run_command("nmcli -f SSID,SIGNAL,SECURITY,CHAN device wifi list")
    if not output:
        return networks
    
    # Parse WiFi networks
    lines = output.strip().split('\n')
    if len(lines) <= 1:  # Only header
        return networks
    
    # Get current connections for checking which ones are connected
    current_connections = get_network_connections()
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

def get_routing_priorities():
    """Get current routing priorities based on the routing table"""
    connections = get_network_connections()
    active_connections = [conn for conn in connections if conn['status'] == 'active']
    
    # Sort by priority (routing metric)
    active_connections.sort(key=lambda x: x.get('priority', 99))
    
    # Assign sequential priorities
    for i, conn in enumerate(active_connections):
        conn['priority'] = i + 1
    
    return active_connections

def update_routing_priorities(priorities):
    """Update routing priorities by changing route metrics"""
    success = True
    for priority_item in priorities:
        conn_id = priority_item.get('id')
        priority = priority_item.get('priority')
        
        # Find connection details
        connections = get_network_connections()
        connection = next((c for c in connections if c['id'] == conn_id), None)
        
        if connection and connection['status'] == 'active' and connection['device']:
            # Set route metric for this connection
            metric = priority * 100  # Convert priority to metric (lower priority = lower metric = higher precedence)
            cmd = f"nmcli connection modify {conn_id} ipv4.route-metric {metric} ipv6.route-metric {metric}"
            if safe_run_command(cmd) is None:
                success = False
            
            # Reactivate connection for changes to take effect
            safe_run_command(f"nmcli connection down {conn_id}")
            if safe_run_command(f"nmcli connection up {conn_id}") is None:
                success = False
    
    return success

# API Routes
@app.route('/api/connections', methods=['GET'])
def api_get_connections():
    """Get all network connections"""
    return jsonify(get_network_connections())

@app.route('/api/connections/<id>/connect', methods=['POST'])
def api_connect_to_network(id):
    """Connect to a network by UUID"""
    result = safe_run_command(f"nmcli connection up uuid {id}")
    return jsonify({'success': result is not None})

@app.route('/api/connections/<id>/disconnect', methods=['POST'])
def api_disconnect_from_network(id):
    """Disconnect from a network by UUID"""
    result = safe_run_command(f"nmcli connection down uuid {id}")
    return jsonify({'success': result is not None})

@app.route('/api/connections/<id>', methods=['PUT'])
def api_update_connection(id):
    """Update a connection configuration (WiFi and Ethernet only)"""
    data = request.json
    connection_type = data.get('type')
    
    if connection_type == 'wifi':
        ssid = data.get('ssid')
        password = data.get('password')
        mode = data.get('mode', 'infrastructure')
        
        if mode == 'infrastructure':
            # Update infrastructure WiFi connection
            cmd = f"nmcli connection modify uuid {id}"
            if ssid:
                cmd += f" 802-11-wireless.ssid '{ssid}'"
            if password:
                cmd += f" wifi-sec.psk '{password}'"
            
            result = safe_run_command(cmd)
            return jsonify({'success': result is not None})
            
        elif mode == 'ap':
            # Update AP WiFi connection
            cmd = f"nmcli connection modify uuid {id}"
            if ssid:
                cmd += f" 802-11-wireless.ssid '{ssid}'"
            if password:
                cmd += f" wifi-sec.psk '{password}'"
            
            result = safe_run_command(cmd)
            return jsonify({'success': result is not None})
    
    elif connection_type == 'ethernet':
        ip_method = data.get('ipMethod', 'auto')
        
        cmd = f"nmcli connection modify uuid {id}"
        
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
            
        result = safe_run_command(cmd)
        return jsonify({'success': result is not None})
    
    return jsonify({'success': False, 'error': 'Unsupported connection type'})

@app.route('/api/connections', methods=['POST'])
def api_create_connection():
    """Create a new connection (WiFi and Ethernet only)"""
    data = request.json
    connection_type = data.get('type')
    
    if connection_type == 'wifi':
        ssid = data.get('ssid')
        password = data.get('password')
        mode = data.get('mode', 'infrastructure')
        
        if not ssid:
            return jsonify({'success': False, 'error': 'SSID is required'})
        
        if mode == 'infrastructure':
            # Create infrastructure WiFi connection
            cmd = f"nmcli device wifi connect '{ssid}'"
            if password:
                cmd += f" password '{password}'"
                
            result = safe_run_command(cmd)
            if result is None:
                return jsonify({'success': False, 'error': 'Failed to create WiFi connection'})
                
            # Get the UUID of the new connection
            uuid_output = safe_run_command(f"nmcli -t -f NAME,UUID connection show | grep '{ssid}' | cut -d: -f2")
            return jsonify({'success': True, 'id': uuid_output})
            
        elif mode == 'ap':
            # Create AP WiFi connection
            cmd = f"nmcli connection add type wifi ifname '*' con-name '{ssid}' autoconnect no ssid '{ssid}' 802-11-wireless.mode ap 802-11-wireless.band bg ipv4.method shared"
            result = safe_run_command(cmd)
            
            if result is None:
                return jsonify({'success': False, 'error': 'Failed to create AP connection'})
            
            # Set password
            if password:
                update_cmd = f"nmcli connection modify '{ssid}' wifi-sec.key-mgmt wpa-psk wifi-sec.psk '{password}' 802-11-wireless-security.pmf disable"
                safe_run_command(update_cmd)
            
            # Get the UUID of the new connection
            uuid_output = safe_run_command(f"nmcli -t -f NAME,UUID connection show | grep '{ssid}' | cut -d: -f2")
            return jsonify({'success': True, 'id': uuid_output})
    
    elif connection_type == 'ethernet':
        name = data.get('name', 'Ethernet Connection')
        ip_method = data.get('ipMethod', 'auto')
        
        # Create base ethernet connection
        cmd = f"nmcli connection add type ethernet con-name '{name}' ifname '*'"
        result = safe_run_command(cmd)
        
        if result is None:
            return jsonify({'success': False, 'error': 'Failed to create ethernet connection'})
        
        # Configure IP settings
        uuid_output = safe_run_command(f"nmcli -t -f NAME,UUID connection show | grep '{name}' | cut -d: -f2")
        
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
                
                safe_run_command(update_cmd)
        
        return jsonify({'success': True, 'id': uuid_output})
    
    return jsonify({'success': False, 'error': 'Unsupported connection type'})

@app.route('/api/connections/<id>', methods=['DELETE'])
def api_delete_connection(id):
    """Delete a connection by UUID (WiFi and Ethernet only)"""    
    result = safe_run_command(f"nmcli connection delete uuid {id}")
    return jsonify({'success': result is not None})

@app.route('/api/wifi/scan', methods=['GET'])
def api_scan_wifi():
    """Scan for available WiFi networks"""
    return jsonify(scan_wifi_networks())

@app.route('/api/wifi/connect', methods=['POST'])
def api_connect_wifi():
    """Connect to a WiFi network"""
    data = request.json
    ssid = data.get('ssid')
    password = data.get('password')
    
    if not ssid:
        return jsonify({'success': False, 'error': 'SSID is required'})
    
    cmd = f"nmcli device wifi connect '{ssid}'"
    if password:
        cmd += f" password '{password}'"
    
    result = safe_run_command(cmd)
    return jsonify({'success': result is not None})

@app.route('/api/routing', methods=['GET'])
def api_get_routing():
    """Get current routing priorities"""
    return jsonify(get_routing_priorities())

@app.route('/api/routing', methods=['PUT'])
def api_update_routing():
    """Update routing priorities"""
    data = request.json
    priorities = data.get('priorities', [])
    
    success = update_routing_priorities(priorities)
    return jsonify({'success': success})

@app.route('/api/statistics', methods=['GET'])
def api_get_statistics():
    """Get connection statistics"""
    return jsonify(get_connection_statistics())

@app.route('/api/hostname', methods=['GET'])
def api_get_hostname():
    """Get the current hostname"""
    hostname = safe_run_command("hostname")
    return jsonify({"hostname": hostname})

@app.route('/api/hostname', methods=['POST'])
def api_set_hostname():
    """Set a new hostname"""
    data = request.json
    new_hostname = data.get('hostname')
    
    if not new_hostname:
        return jsonify({"status": "error", "message": "No hostname provided"}), 400
    
    # Validate hostname format
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$', new_hostname):$', new_hostname):
        return jsonify({"status": "error", "message": "Invalid hostname format"}), 400
    
    # Change hostname using hostnamectl
    result = safe_run_command(f"sudo hostnamectl set-hostname {new_hostname}")
    if result is None:
        return jsonify({"status": "error", "message": "Failed to set hostname"}), 500
    
    return jsonify({"status": "success", "hostname": new_hostname})

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

@app.route('/api/lte/status', methods=['GET'])
def api_get_lte_status():
    """Get LTE modem status (Jetson platform only)"""
    # Check if we're on a Jetson platform
    is_jetson = os.path.exists('/etc/nv_tegra_release')
    
    if not is_jetson:
        return jsonify({"status": "not_available", "message": "LTE functionality only available on Jetson platform"})
    
    # Check if ModemManager is installed and running
    if not run_command("systemctl is-active --quiet ModemManager"):
        return jsonify({"status": "not_found", "message": "ModemManager is not running"})
    
    # Get modem index
    modem_index = safe_run_command("mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
    if not modem_index:
        return jsonify({"status": "not_found", "message": "No modem found"})
    
    try:
        # Get modem information
        modem_info = safe_run_command(f"mmcli -m {modem_index}")
        if not modem_info:
            return jsonify({"status": "error", "message": "Failed to get modem information"})
        
        # Parse modem information
        model = safe_run_command(f"mmcli -m {modem_index} | grep -oP '(?<=model: ).*' || echo 'Unknown'")
        operator = safe_run_command(f"mmcli -m {modem_index} | grep -oP '(?<=operator name: ).*' || echo 'Unknown'")
        state = safe_run_command(f"mmcli -m {modem_index} | grep -oP '(?<=state: ).*' || echo 'Unknown'")
        signal = safe_run_command(f"mmcli -m {modem_index} | grep 'signal quality' | awk '{{print $4}}' | sed 's/%//'")
        
        # Get bearer information if connected
        bearer_path = safe_run_command(f"mmcli -m {modem_index} | grep -oP '/org/freedesktop/ModemManager1/Bearer/\\d+' | head -1 || echo ''")
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
                bearer_info = safe_run_command(f"mmcli -m {modem_index} --bearer={bearer_index.group(1)}")
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
            detected_apn = detect_apn_from_carrier(operator.strip())
                
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
        
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error getting LTE status: {e}")
        return jsonify({"status": "error", "message": str(e)})


@app.route('/api/lte/connect', methods=['POST'])
def api_connect_lte():
    """Connect to LTE network with specified APN (Jetson platform only)"""
    # Check if we're on a Jetson platform
    is_jetson = os.path.exists('/etc/nv_tegra_release')
    
    if not is_jetson:
        return jsonify({"status": "error", "message": "LTE functionality only available on Jetson platform"}), 400
    
    data = request.json
    apn = data.get('apn')
    
    # If no APN is provided, try to detect it from the carrier
    if not apn:
        # Get modem index
        modem_index = safe_run_command("mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
        if not modem_index:
            return jsonify({"status": "error", "message": "No modem found"}), 404
            
        # Get carrier/operator name
        operator = safe_run_command(f"mmcli -m {modem_index} | grep -oP '(?<=operator name: ).*' || echo ''")
        if operator:
            detected_apn = detect_apn_from_carrier(operator)
            if detected_apn:
                logger.info(f"No APN provided, detected {detected_apn} from carrier {operator}")
                apn = detected_apn
            else:
                logger.error(f"No APN provided and couldn't detect from carrier: {operator}")
                return jsonify({"status": "error", "message": "APN is required - couldn't auto-detect from carrier"}), 400
        else:
            logger.error("No APN provided and couldn't detect carrier")
            return jsonify({"status": "error", "message": "APN is required - no carrier detected"}), 400
    
    # Check prerequisites
    if not run_command("modprobe qmi_wwan"):
        return jsonify({"status": "error", "message": "Failed to load qmi_wwan kernel module"}), 500
        
    if not run_command("systemctl is-active --quiet ModemManager"):
        return jsonify({"status": "error", "message": "ModemManager is not running"}), 500
    
    try:
        # Wait for modem to be available
        logger.info("Waiting for modem to be available...")
        modem_index = None
        for _ in range(30):  # Wait up to 60 seconds
            result = safe_run_command("mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
            if result:
                modem_index = result
                break
            time.sleep(2)
        
        if not modem_index:
            return jsonify({"status": "error", "message": "No modem found after waiting"}), 404
        
        logger.info(f"Modem found with index {modem_index}")
        
        # Configure modem initial EPS bearer settings
        logger.info(f"Configuring modem with APN: {apn}")
        eps_cmd = f"mmcli -m {modem_index} --3gpp-set-initial-eps-bearer-settings=apn={apn}"
        if not run_command(eps_cmd):
            return jsonify({"status": "error", "message": "Failed to configure modem EPS settings"}), 500
        
        # Connect modem to network
        logger.info("Connecting modem to network...")
        connect_cmd = f"mmcli -m {modem_index} --simple-connect=apn={apn},ip-type=ipv4v6"
        if not run_command(connect_cmd):
            return jsonify({"status": "error", "message": "Failed to connect modem to network"}), 500
        
        # Wait for modem to connect to network
        logger.info("Waiting for modem to connect to network...")
        connected = False
        for _ in range(60):  # Wait up to 60 seconds
            modem_status = safe_run_command(f"mmcli -m {modem_index}")
            if modem_status and "state: connected" in modem_status and "packet service state: attached" in modem_status:
                connected = True
                break
            time.sleep(1)
        
        if not connected:
            return jsonify({"status": "error", "message": "Modem failed to connect within timeout period"}), 500
        
        # Get bearer information
        logger.info("Getting bearer information...")
        bearer_path = safe_run_command(f"mmcli -m {modem_index} | grep -oP '/org/freedesktop/ModemManager1/Bearer/\\d+' | head -1")
        if not bearer_path:
            return jsonify({"status": "error", "message": "Failed to get bearer path"}), 500
            
        bearer_index = re.search(r'/Bearer/(\d+)', bearer_path)
        if not bearer_index:
            return jsonify({"status": "error", "message": "Failed to parse bearer index"}), 500
            
        # Get interface details
        bearer_info = safe_run_command(f"mmcli -m {modem_index} --bearer={bearer_index.group(1)}")
        if not bearer_info:
            return jsonify({"status": "error", "message": "Failed to get bearer information"}), 500
            
        # Extract network details using regex
        interface_match = re.search(r'interface: (\w+)', bearer_info)
        address_match = re.search(r'address: ([0-9.]+)', bearer_info)
        prefix_match = re.search(r'prefix: (\d+)', bearer_info)
        gateway_match = re.search(r'gateway: ([0-9.]+)', bearer_info)
        dns_match = re.search(r'DNS: ([0-9., ]+)', bearer_info)
        mtu_match = re.search(r'MTU: (\d+)', bearer_info)
        
        if not interface_match or not address_match or not gateway_match:
            return jsonify({"status": "error", "message": "Failed to extract network information from bearer"}), 500
            
        # Configure the network interface
        interface = interface_match.group(1)
        address = address_match.group(1)
        prefix = prefix_match.group(1) if prefix_match else "24"
        gateway = gateway_match.group(1)
        
        # Flush existing IP and routes
        logger.info(f"Configuring interface {interface}...")
        if not run_command(f"ip addr flush dev {interface}"):
            logger.warning("Failed to flush IP address")
            
        if not run_command(f"ip route flush dev {interface}"):
            logger.warning("Failed to flush routes")
            
        # Configure interface
        if not run_command(f"ip link set {interface} up"):
            return jsonify({"status": "error", "message": f"Failed to bring up interface {interface}"}), 500
            
        if not run_command(f"ip addr add {address}/{prefix} dev {interface}"):
            return jsonify({"status": "error", "message": f"Failed to add IP address to interface {interface}"}), 500
            
        if mtu_match:
            run_command(f"ip link set {interface} mtu {mtu_match.group(1)}")
            
        # Configure routing
        run_command(f"ip link set dev {interface} arp off")
        
        if not run_command(f"ip route add default via {gateway} dev {interface} metric 4294967295"):
            return jsonify({"status": "error", "message": "Failed to add default route"}), 500
            
        # Configure DNS if available
        if dns_match:
            dns_servers = dns_match.group(1).strip().split(",")
            if len(dns_servers) > 0:
                dns1 = dns_servers[0].strip()
                if dns1:
                    logger.info(f"Adding DNS server: {dns1}")
                    run_command(f"sh -c \"echo 'nameserver {dns1}' >> /etc/resolv.conf\"")
                    
            if len(dns_servers) > 1:
                dns2 = dns_servers[1].strip()
                if dns2:
                    logger.info(f"Adding DNS server: {dns2}")
                    run_command(f"sh -c \"echo 'nameserver {dns2}' >> /etc/resolv.conf\"")
        
        # Test connection
        logger.info("Testing connection...")
        if not run_command(f"ping -4 -c 1 -I {interface} 8.8.8.8", timeout=5):
            logger.warning("Ping test failed, but connection might still be working")
        
        return jsonify({
            "status": "success", 
            "message": "LTE modem connected",
            "interface": interface,
            "ipAddress": address,
            "gateway": gateway
        })
    except Exception as e:
        logger.error(f"Error connecting to LTE: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/lte/disconnect', methods=['POST'])
def api_disconnect_lte():
    """Disconnect from LTE network (Jetson platform only)"""
    # Check if we're on a Jetson platform
    is_jetson = os.path.exists('/etc/nv_tegra_release')
    
    if not is_jetson:
        return jsonify({"status": "error", "message": "LTE functionality only available on Jetson platform"}), 400
    
    # Check if ModemManager is installed and running
    if not run_command("systemctl is-active --quiet ModemManager"):
        return jsonify({"status": "error", "message": "ModemManager is not running"}), 500
    
    # Get modem index
    modem_index = safe_run_command("mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
    if not modem_index:
        return jsonify({"status": "error", "message": "No modem found"}), 404
    
    try:
        # Get bearer information to identify the interface
        bearer_path = safe_run_command(f"mmcli -m {modem_index} | grep -oP '/org/freedesktop/ModemManager1/Bearer/\\d+' | head -1")
        interface = None
        
        if bearer_path:
            bearer_index = re.search(r'/Bearer/(\d+)', bearer_path)
            if bearer_index:
                bearer_info = safe_run_command(f"mmcli -m {modem_index} --bearer={bearer_index.group(1)}")
                if bearer_info:
                    interface_match = re.search(r'interface: (\w+)', bearer_info)
                    if interface_match:
                        interface = interface_match.group(1)
                        
        # Disconnect the modem
        logger.info("Disconnecting modem...")
        if not run_command(f"mmcli -m {modem_index} --simple-disconnect"):
            return jsonify({"status": "error", "message": "Failed to disconnect from LTE network"}), 500
        
        # Clean up the interface if found
        if interface:
            logger.info(f"Cleaning up interface {interface}...")
            run_command(f"ip addr flush dev {interface}")
            run_command(f"ip route flush dev {interface}")
        
        return jsonify({"status": "success", "message": "Disconnected from LTE network"})
    except Exception as e:
        logger.error(f"Error disconnecting from LTE: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='ARK-OS Connections Manager Service')
    parser.add_argument('--config', default='/etc/ark/network/connections_manager.toml', help='Path to config file')
    args = parser.parse_args()
    
    # Load configuration
    load_config(args.config)
    
    # Run Flask app
    app.run(
        host=config['service']['host'],
        port=config['service']['port'],
        debug=config['service']['debug']
    )

if __name__ == '__main__':
    main()
