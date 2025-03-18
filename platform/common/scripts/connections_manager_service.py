#!/usr/bin/env python3
"""
ARK-OS Connections Manager Service

This service provides a REST API for managing network connections, including:
- WiFi connections (both client and AP mode)
- Ethernet connections
- LTE/cellular connections (Jetson platform only)

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

# Global state
class State:
    interface_stats = {}  # Store the latest stats for each interface
    last_stats_update = 0
    last_stats_report = 0
    stats_lock = threading.Lock()  # Thread safety for stats access

    # Websocket clients for real-time updates
    active_stats_clients = set()
    stats_thread_active = False
    stats_thread = None

def strip_ansi_colors(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

class CommandExecutor:
    @staticmethod
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

    @staticmethod
    def safe_run_command(command, default=None, timeout=10):
        """Safely run a command and return the result or default value"""
        result = CommandExecutor.run_command(command, timeout)
        return result if result is not None else default


class NetworkConnectionManager:
    @staticmethod
    def get_network_connections():
        connections = []

        output = CommandExecutor.safe_run_command("nmcli -t -f NAME,TYPE,DEVICE,AUTOCONNECT,ACTIVE connection show")
        if not output:
            return connections

        # Parse network connections
        for line in output.strip().split('\n'):
            parts = line.split(':')
            if len(parts) >= 5:
                name, type, device, autoconnect, active = parts[:5]

                if type == '802-11-wireless':
                    type = 'wifi'
                elif type == '802-3-ethernet':
                    type = 'ethernet'
                elif type == 'gsm':
                    type = 'lte'

                # Get connection details
                connection = {
                    'name': name,
                    'type': type,
                    'device': device,
                    'autoconnect': autoconnect,
                    'active': active,
                    'ipAddress': '',
                    # Wifi only
                    'ssid': '',
                    'mode': '',
                    'signal': '',
                }

                # Get interface specific properties
                if type == 'wifi':
                    connection['mode'] = CommandExecutor.safe_run_command(f"nmcli -g 802-11-wireless.mode con show \"{name}\"")
                    connection['ssid'] = CommandExecutor.safe_run_command(f"nmcli -g 802-11-wireless.ssid con show \"{name}\"")
                    connection['ipAddress'] = CommandExecutor.safe_run_command(f"nmcli -g IP4.ADDRESS con show \"{name}\"")
                elif type == 'ethernet':
                    connection['ipAddress'] = CommandExecutor.safe_run_command(f"nmcli -g ipv4.addresses con show  \"{name}\"")
                    connection['ipMethod'] = CommandExecutor.safe_run_command(f"nmcli -g ipv4.method con show  \"{name}\"")
                if type == 'lte':
                    connection['apn'] = CommandExecutor.safe_run_command(f"nmcli -g gsm.apn con show \"{name}\"")

                connections.append(connection)

        # Get all Wifi signal strengths
        wifi_signals = {}
        output = CommandExecutor.safe_run_command("nmcli -t -f SSID,SIGNAL device wifi")
        for line in output.strip().split('\n'):
            parts = line.split(':')
            if len(parts) >= 2:
                ssid, signal = parts[:2]
                wifi_signals[ssid] = signal

        # Add signal strength to all matching wifi connections
        for connection in connections:
            if connection['type'] == 'wifi' and connection['ssid'] in wifi_signals:
                connection['signal'] = wifi_signals[connection['ssid']]
            elif connection['type'] == 'lte':
                connection['signal'] = LteManager.get_lte_status().get('signal', 0)

        return connections


class ConnectionManager:
    @staticmethod
    def create_connection(data):
        type = data.get('type')

        if type == 'wifi':
            return ConnectionManager._create_wifi_connection(data)

        elif type == 'ethernet':
            return ConnectionManager._create_ethernet_connection(data)

        elif type == 'lte':
            return ConnectionManager._create_lte_connection(data)

        else:
            return {'success': False, 'error': 'Unsupported connection type'}

    @staticmethod
    def _create_wifi_connection(data):
        ssid = data.get('ssid')
        password = data.get('password')
        mode = data.get('mode')
        autoconnect = data.get('autoconnect', 'yes')

        if not ssid:
            return {'success': False, 'error': 'SSID is required'}

        if len(password) < 8 or len(password) > 63:
            return {'success': False, 'error': 'Invalid password'}

        if not mode:
            return {'success': False, 'error': 'Mode is required'}

        # Check if connection with this name already exists
        command = f"nmcli -t -f NAME con show"
        result = CommandExecutor.safe_run_command(command)

        if re.search(rf"^{re.escape(ssid)}$", result, re.MULTILINE):
            return {'success': False, 'error': 'Connection already exists'}

        # Create the connection
        command = f"nmcli con add type wifi ifname '*' con-name \"{ssid}\" autoconnect {autoconnect} ssid \"{ssid}\""

        if mode == 'ap':
            command += f" 802-11-wireless.mode ap 802-11-wireless.band bg ipv4.method shared"

        result = CommandExecutor.safe_run_command(command)

        if result is None:
            return {f"success': False, 'error': 'Failed to create {mode} connection"}

        # Add password to connection
        command = f"nmcli con modify \"{ssid}\" wifi-sec.key-mgmt wpa-psk wifi-sec.psk \"{password}\""
        if mode == 'ap':
            command += f" 802-11-wireless-security.pmf disable connection.autoconnect-priority -1"

        result = CommandExecutor.safe_run_command(command)
        if result is None:
            return {'success': False, 'error': 'Failed to set password'}

        # Query SSID to confirm creation
        command = f"nmcli -g 802-11-wireless.ssid con show \"{ssid}\""
        ssid = CommandExecutor.safe_run_command(command)

        return {'success': True, 'ssid': ssid, 'mode': mode}

    @staticmethod
    def _create_ethernet_connection(data):
        """Create a new Ethernet connection"""
        name = data.get('name', 'Ethernet Connection')
        ipMethod = data.get('ipMethod', 'auto')
        ipAddress = data.get('ipAddress')
        autoconnect = data.get('autoconnect', 'yes')

        if not name:
            return {'success': False, 'error': 'Name is required'}

        if ipMethod == 'manual' and not ipAddress:
            return {'success': False, 'error': 'IP address required for static IP'}

        # Check if connection with this name already exists
        command = f"nmcli -t -f NAME con show"
        result = CommandExecutor.safe_run_command(command)

        if re.search(rf"^{re.escape(name)}$", result, re.MULTILINE):
            return {'success': False, 'error': 'Connection already exists'}

        # Create base ethernet connection
        cmd = f"nmcli connection add type ethernet con-name \"{name}\" ifname '*' autoconnect {autoconnect}"
        result = CommandExecutor.safe_run_command(cmd)
        
        if result is None:
            return {'success': False, 'error': 'Failed to create ethernet connection'}
        
        if ipMethod == 'manual' and ipAddress:
            command = f"nmcli connection modify \"{name}\" ipv4.method manual ipv4.addresses {ipAddress}"
            CommandExecutor.safe_run_command(command)
        
        return {'success': True, 'name': name}

    @staticmethod
    def _create_lte_connection(data):
        """Create a new LTE connection"""
        name = data.get('name', 'LTE Connection')
        autoconnect = data.get('autoconnect', 'yes')
        apn = data.get('apn', '')

        if not name:
            return {'success': False, 'error': 'Name is required'}

        # Check if any LTE connection already exists. We can only allow 1.
        command = f"nmcli -t -f TYPE con show"
        result = CommandExecutor.safe_run_command(command)

        if result is None:
            return {'success': False, 'error': 'Failed to query connections'}

        if 'gsm' in result:
            return {'success': False, 'error': 'An LTE connection already exists'}

        # Create LTE connection
        cmd = f"nmcli connection add type gsm con-name \"{name}\" gsm.apn \"{apn}\" autoconnect {autoconnect}"
        result = CommandExecutor.safe_run_command(cmd)

        if result is None:
            return {'success': False, 'error': 'Failed to create LTE connection'}

        # TODO: do we need to modify any settings?

        return {'success': True, 'name': name}


    @staticmethod
    def update_connection(name, data):
        """Update a connection configuration (WiFi and Ethernet only)"""
        connection_type = data.get('type')

        if connection_type == 'wifi':
            return ConnectionManager._update_wifi_connection(name, data)
        elif connection_type == 'ethernet':
            return ConnectionManager._update_ethernet_connection(name, data)
        elif connection_type == 'lte':
            return ConnectionManager._update_lte_connection(name, data)
        else:
            return {'success': False, 'error': 'Unsupported connection type'}

    @staticmethod
    def _update_wifi_connection(name, data):
        ssid = data.get('ssid')
        password = data.get('password')
        autoconnect = data.get('autoconnect', 'yes')
        mode = data.get('mode', 'infrastructure')

        command = f"nmcli connection modify \"{name}\""

        if ssid:
            command += f" 802-11-wireless.ssid \"{ssid}\""
        if autoconnect:
            command +=f" autoconnect {autoconnect}"
        if password:
            command += f" wifi-sec.key-mgmt wpa-psk wifi-sec.psk \"{password}\""

        result = CommandExecutor.safe_run_command(command)
        return {'success': result is not None}

    @staticmethod
    def _update_ethernet_connection(name, data):
        ipMethod = data.get('ipMethod', 'auto')
        autoconnect = data.get('autoconnect', 'yes')
        ipAddress = data.get('ipAddress')

        command = f"nmcli connection modify \"{name}\""

        if autoconnect:
            command +=f" autoconnect {autoconnect}"
        if ipMethod == 'auto':
            command += " ipv4.method auto"
        elif ipMethod == 'manual' and ipAddress:
            command += f" ipv4.method manual ipv4.addresses {ipAddress}"
        else:
            return {'success': False, 'error': 'Missing ipAddress'}

        result = CommandExecutor.safe_run_command(command)
        return {'success': result is not None}

    @staticmethod
    def _update_lte_connection(name, data):
        """Update an LTE connection with new settings"""
        apn = data.get('apn')
        autoconnect = data.get('autoconnect', 'yes')

        cmd = f"nmcli connection modify \"{name}\""

        if apn:
            cmd += f" gsm.apn \"{apn}\""
        if autoconnect:
            cmd += f" autoconnect {autoconnect}"

        logger.info(f"Updating LTE connection {name}")
        logger.info(f"apn {apn}")
        logger.info(f"autoconnect {autoconnect}")

        result = CommandExecutor.safe_run_command(cmd)
        return {'success': result is not None}



class WiFiNetworkManager:
    @staticmethod
    def scan_wifi_networks():
        networks = []

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
                    'signal': int(signal) if signal.isdigit() else 0,
                    'secured': security != '--',
                }

                networks.append(network)

        return networks


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




class LteManager:
    @staticmethod
    def get_lte_status():
        """
        Get detailed status information for the LTE modem

        Returns a dictionary with all modem status information
        """

        if not CommandExecutor.safe_run_command("systemctl is-active ModemManager"):
            return {"status": "not_found", "message": "ModemManager is not running"}

        # Initialize comprehensive status structure with all possible fields
        status = {
            # Basic modem hardware info
            "manufacturer": "",
            "model": "",
            "firmwareRevision": "",
            "equipmentId": "",

            # Connection state
            "state": "",              # Raw state from modem
            "failedReason": "",       # If state is "failed"

            # Signal information
            "signal": 0,

            # Identity information
            "imei": "",

            # Network information
            "operatorId": "",
            "operatorName": "",
            "registration": "",      # Registration status (home, roaming, etc.)

            # SIM information
            "simActive": "",
            "simOperatorName": "",
            "simOperatorId": "",
            "simImsi": "",

            # Bearer/APN information
            "initialApn": "",
            "apn": "",
            "bearerConnected": False,
            "suggestedApn": "",       # Suggested default APN based on SIM operator

            # Interface information
            "interface": "",         # wwan0, etc
            "interfaceState": "",    # up, down, unknown

            # IP configuration
            "ipMethod": "",         # static, dhcp, etc.
            "ipAddress": "",
            "prefix": "",
            "gateway": "",
            "dns": [],
            "mtu": ""
        }

        try:
            # Get modem index
            modem_index = CommandExecutor.safe_run_command("mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
            if not modem_index:
                logger.warning("No modem found")
                return status

            # Get modem information
            modem_info = CommandExecutor.safe_run_command(f"mmcli -m {modem_index}")
            if not modem_info:
                logger.warning(f"Failed to get information for modem {modem_index}")
                return status

            # Parse each line for basic modem information
            bearer_path = None
            sim_path = None

            for line in modem_info.split('\n'):
                line = line.strip()

                # Hardware info
                if 'manufacturer:' in line:
                    status["manufacturer"] = line.split('manufacturer:')[1].strip()
                elif 'model:' in line:
                    status["model"] = line.split('model:')[1].strip()
                elif 'firmware revision:' in line:
                    status["firmwareRevision"] = line.split('firmware revision:')[1].strip()
                elif 'equipment id:' in line:
                    status["equipmentId"] = line.split('equipment id:')[1].strip()

                # Status info
                elif 'signal quality:' in line:
                    signal_parts = line.split('signal quality:')[1].strip().split()
                    # Parse "60% (recent)" format
                    if signal_parts and '%' in signal_parts[0]:
                        status["signal"] = int(signal_parts[0].replace('%', ''))
                elif '  state:' in line:  # Using two spaces to differentiate from other state fields (power state:)
                    status["state"] = strip_ansi_colors(line.split('state:')[1].strip())

                # 3GPP info
                elif 'imei:' in line:
                    status["imei"] = line.split('imei:')[1].strip()
                elif 'operator id:' in line:
                    status["operatorId"] = line.split('operator id:')[1].strip()
                elif 'operator name:' in line:
                    status["operatorName"] = line.split('operator name:')[1].strip()
                elif 'registration:' in line:
                    status["registration"] = line.split('registration:')[1].strip()

                # EPS / Bearer info
                elif 'initial bearer apn:' in line:
                    status["initialApn"] = line.split('initial bearer apn:')[1].strip()
                # elif 'initial bearer path:' in line:
                #     bearer_path_full = line.split('initial bearer path:')[1].strip()
                #     match = re.search(r'/org/freedesktop/ModemManager1/Bearer/(\d+)', bearer_path_full)
                #     if match:
                #         logger.info(f"FOUND INITIAL BEARER PATH: {bearer_path}")
                #         bearer_path = match.group(1)

                # SIM info
                elif 'primary sim path:' in line:
                    sim_path_full = line.split('primary sim path:')[1].strip()
                    match = re.search(r'/org/freedesktop/ModemManager1/SIM/(\d+)', sim_path_full)
                    if match:
                        sim_path = match.group(1)

                # Bearer section (might be at the bottom of output)
                elif 'Bearer' in line and 'paths:' in line:
                    bearer_match = re.search(r'/org/freedesktop/ModemManager1/Bearer/(\d+)', line)
                    if bearer_match:
                        bearer_path = bearer_match.group(1)

            if status["state"] == "failed":
                for line in modem_info.split('\n'):
                    if 'failed reason:' in line:
                        status["failedReason"] = strip_ansi_colors(line.split('failed reason:')[1].strip())

            # If we have a SIM path, get SIM info
            if sim_path:
                sim_info = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} --sim {sim_path}")
                if sim_info:
                    for line in sim_info.split('\n'):
                        line = line.strip()
                        if 'operator name:' in line:
                            status["simOperatorName"] = line.split('operator name:')[1].strip()
                        elif 'operator id:' in line:
                            status["simOperatorId"] = line.split('operator id:')[1].strip()
                        elif 'imsi:' in line:
                            status["simImsi"] = line.split('imsi:')[1].strip()
                        elif 'active:' in line:
                            status["simActive"] = line.split('active:')[1].strip()

            # If we have a bearer path, get bearer info for interface and IP details
            if bearer_path:
                bearer_info = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} --bearer={bearer_path}")
                if bearer_info:
                    for line in bearer_info.split('\n'):
                        line = line.strip()
                        if 'connected:' in line:
                            status["bearerConnected"] = "yes" in line.split('connected:')[1].strip()
                        elif 'interface:' in line:
                            status["interface"] = line.split('interface:')[1].strip()
                        elif 'apn:' in line:
                            status["apn"] = line.split('apn:')[1].strip()
                        elif 'method:' in line:
                            status["ipMethod"] = line.split('method:')[1].strip()
                        elif 'address:' in line:
                            status["ipAddress"] = line.split('address:')[1].strip()
                        elif 'prefix:' in line:
                            status["prefix"] = line.split('prefix:')[1].strip()
                        elif 'gateway:' in line:
                            status["gateway"] = line.split('gateway:')[1].strip()
                        elif 'dns:' in line:
                            dns_servers = line.split('dns:')[1].strip().split(',')
                            status["dns"] = [server.strip() for server in dns_servers]
                        elif 'mtu:' in line:
                            status["mtu"] = line.split('mtu:')[1].strip()

                    # Check interface status if we have one
                    if status["interface"]:
                        interface_status = CommandExecutor.safe_run_command(f"ip link show {status['interface']} | grep 'state'")
                        if interface_status:
                            if "UP" in interface_status:
                                status["interfaceState"] = "up"
                            else:
                                status["interfaceState"] = "down"

            # Suggest APN depending on SIM operator
            if status["simOperatorName"]:
                operator = status["simOperatorName"].lower()
                if "t-mobile" in operator:
                    status["suggestedApn"] = "fast.t-mobile.com"
                elif "at&t" in operator or "att" in operator:
                    status["suggestedApn"] = "broadband"
                elif "verizon" in operator:
                    status["suggestedApn"] = "vzwinternet"

        except Exception as e:
            logger.error(f"Error getting modem status: {e}")
            logger.exception(e)  # Log full traceback for debugging

        return status



class NetworkStatsCollector:
    @staticmethod
    def collect_interface_stats():
        """
        Collect network interface statistics from activated NetworkManager connections.
        Uses GENERAL.IP-IFACE property to identify the actual data interface for all connection types.
        Returns a dictionary of interface stats with rx/tx bytes, packets, errors, dropped.
        """
        stats = {}
        try:
            # Get all activated NetworkManager connections
            nm_output = CommandExecutor.safe_run_command("nmcli -t -f NAME,TYPE,STATE connection show")
            if not nm_output:
                logger.warning("Failed to get NetworkManager connections")
                return stats

            active_connections = {}

            # Parse NetworkManager connections and find active ones
            for line in nm_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) >= 3:
                    name, conn_type, state = parts[:3]

                    # Only process active connections
                    if state == 'activated':
                        # Map connection types
                        if conn_type == '802-11-wireless':
                            interface_type = 'wifi'
                        elif conn_type == '802-3-ethernet':
                            interface_type = 'ethernet'
                        elif conn_type == 'gsm':
                            interface_type = 'lte'
                        else:
                            interface_type = 'other'

                        # Get the actual IP interface for this connection
                        ip_iface = CommandExecutor.safe_run_command(f"nmcli -g GENERAL.IP-IFACE connection show \"{name}\"")

                        if ip_iface and ip_iface.strip():
                            device = ip_iface.strip()
                            logger.debug(f"Connection '{name}' using IP interface: {device}")

                            # Store connection info keyed by the actual interface
                            active_connections[device] = {
                                'name': name,
                                'type': interface_type
                            }
                        else:
                            logger.warning(f"Could not find IP interface for connection '{name}'")

            logger.debug(f"Found {len(active_connections)} active NetworkManager connections")

            # Process each active connection to collect statistics
            for device, info in active_connections.items():
                # Get detailed stats using 'ip -s link show' command
                stats_output = CommandExecutor.safe_run_command(f"ip -s link show {device}")
                if not stats_output:
                    logger.warning(f"Failed to get stats for device {device}")
                    continue

                # Parse the stats output
                interface_stats = NetworkStatsCollector._parse_ip_stats(stats_output)
                if not interface_stats:
                    logger.warning(f"Failed to parse stats for device {device}")
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

                # Add connection-type specific information
                if info['type'] == 'wifi':
                    # Get signal strength for WiFi
                    signal_output = CommandExecutor.safe_run_command(
                        f"nmcli -f SIGNAL device wifi list ifname {device} | grep -v SIGNAL | head -1 | awk '{{print $1}}'"
                    )
                    if signal_output and signal_output.isdigit():
                        device_stats['signal_strength'] = int(signal_output)

                    # Get SSID for WiFi
                    ssid_output = CommandExecutor.safe_run_command(f"nmcli -g 802-11-wireless.ssid connection show '{info['name']}'")
                    if ssid_output:
                        device_stats['ssid'] = ssid_output

                elif info['type'] == 'lte':
                    # For LTE connections, try to get signal strength from ModemManager
                    # This is optional and only works if ModemManager is available
                    signal_output = CommandExecutor.safe_run_command(
                        "mmcli -m 0 | grep 'signal quality' | awk -F': ' '{print $2}' | awk '{print $1}' | tr -d '%'"
                    )
                    if signal_output and signal_output.isdigit():
                        device_stats['signal_strength'] = int(signal_output)

                stats[device] = device_stats
                logger.debug(f"Collected stats for {device} ({info['name']}): RX={device_stats['rx_bytes']}, TX={device_stats['tx_bytes']}")

        except Exception as e:
            logger.error(f"Error collecting interface stats: {e}")
            logger.exception(e)  # Log full traceback for debugging

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
            current_time - State.last_stats_update < 1.0):
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
                if 'rx_rate' in previous:
                    # Apply complementary filter
                    alpha = 1
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
                interface_summary = {
                    'name': stats.get('name', interface),
                    'interface': interface,
                    'type': stats.get('type', 'other'),
                    'ipAddress': stats.get('ip_address', ''),
                    'active': True,
                    'rxBytes': stats.get('rx_bytes', 0),
                    'txBytes': stats.get('tx_bytes', 0),
                    'rxRateMbps': stats.get('rx_rate_mbps', 0),
                    'txRateMbps': stats.get('tx_rate_mbps', 0),
                    'rxErrors': stats.get('rx_errors', 0),
                    'rxDropped': stats.get('rx_dropped', 0),
                    'txErrors': stats.get('tx_errors', 0),
                    'txDropped': stats.get('tx_dropped', 0),
                    'rxPackets': stats.get('rx_packets', 0),
                    'txPackets': stats.get('tx_packets', 0)
                }
                
                if stats.get('type') == 'wifi':
                    interface_summary['signal'] = stats.get('signal_strength', 0)
                
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

        try:
            # Main collection loop - runs as long as there are active clients
            while State.stats_thread_active and len(State.active_stats_clients) > 0:
                try:
                    # Collect interface stats at the configured interval
                    stats = NetworkStatsProcessor.update_interface_stats()

                    # Send updates to clients at the report interval
                    StatsThread._send_stats_to_clients()

                except Exception as e:
                    logger.error(f"Error in stats collection thread: {e}")
                    # Continue the thread despite errors

                # Sleep before next collection
                time.sleep(1.0)

            logger.info("Network stats collection thread stopping - no active clients")

        except Exception as e:
            logger.error(f"Fatal error in stats collection thread: {e}")
        finally:
            # Always mark the thread as inactive when exiting
            State.stats_thread_active = False

    @staticmethod
    def _send_stats_to_clients():
        """Send collected stats to all connected clients at the configured interval"""
        current_time = time.time()

        # Only send updates at the configured interval
        if (current_time - State.last_stats_report >= 2.0) and State.active_stats_clients:
            try:
                # Generate the summary to send to clients
                summary = NetworkReporting.get_interface_usage_summary()
                
                # Make sure we have data to send
                if not summary:
                    logger.warning("No network interfaces found to report stats")
                    return
                    
                # Send update to all connected clients
                if State.active_stats_clients:
                    socketio.emit('network_stats_update', summary)
                    # logger.info(f"Sent stats update to {len(State.active_stats_clients)} clients")
                    # pretty_json = json.dumps(summary, indent=2, sort_keys=True)
                    # logger.info(f"stats: \n{pretty_json}")
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
        try:
            client_id = request.sid if hasattr(request, 'sid') else "unknown"
            logger.error(f"SocketIO error for client {client_id}: {str(e)}")
        except Exception as inner_error:
            # Emergency fallback for errors in error handler
            logger.error(f"Error in error handler: {inner_error}")

        # Return False to prevent the error from propagating
        return False


# API Routes

# Get connections
@app.route('/network/connections', methods=['GET'])
def api_get_connections():
    logger.info("GET /network/connections called")
    return jsonify(NetworkConnectionManager.get_network_connections())

# Create connection
@app.route('/network/connections', methods=['POST'])
def api_create_connection():
    logger.info("POST /network/connections called")
    return jsonify(ConnectionManager.create_connection(request.json))

# Delete connection
@app.route('/network/connections/<name>', methods=['DELETE'])
def api_delete_connection(name):
    logger.info(f"DELETE /network/connections/{name} called")
    result = CommandExecutor.safe_run_command(f"nmcli connection delete \"{name}\"")
    return jsonify({'success': result is not None})

# Update connection
@app.route('/network/connections/<name>', methods=['PUT'])
def api_update_connection(name):
    logger.info(f"PUT /network/connections/{name} called")
    return jsonify(ConnectionManager.update_connection(name, request.json))

# Connect to connection
@app.route('/network/connections/<name>/connect', methods=['POST'])
def api_connect_to_network(name):
    logger.info(f"POST /network/connections/{name}/connect called")
    result = CommandExecutor.safe_run_command(f"nmcli con up \"{name}\"")
    return jsonify({'success': result is not None})

# Disconnect from connection
@app.route('/network/connections/<name>/disconnect', methods=['POST'])
def api_disconnect_from_network(name):
    logger.info(f"POST /network/connections/{name}/disconnect called")
    result = CommandExecutor.safe_run_command(f"nmcli con down \"{name}\"")
    return jsonify({'success': result is not None})

# Scan for wifi networks
@app.route('/network/wifi/scan', methods=['GET'])
def api_scan_wifi():
    logger.info("GET /network/wifi/scan called")
    return jsonify(WiFiNetworkManager.scan_wifi_networks())

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

@app.route('/network/lte/status', methods=['GET'])
def api_get_lte_status():
    """Get LTE modem status (Jetson platform only)"""
    logger.info("GET /network/lte/status called")
    return jsonify(LteManager.get_lte_status())

class ApplicationRunner:
    @staticmethod
    def main():
        parser = argparse.ArgumentParser(description='ARK-OS Connections Manager Service')
        parser.add_argument(
            '--example',
            default='/this/is/an/example',
            help='Example arg'
        )
        args = parser.parse_args()

        ApplicationRunner.start_server()
    
    @staticmethod
    def start_server():
        host = '0.0.0.0'
        port = '3001'
        debug = False;

        logger.info(f"Starting SocketIO server on {host}:{port}")
        try:
            socketio.run(
                app,
                host=host,
                port=port,
                debug=debug,
                allow_unsafe_werkzeug=True
            )
        except Exception as e:
            logger.error(f"Error starting SocketIO server: {e}")
            logger.exception(e)


if __name__ == '__main__':
    ApplicationRunner.main()
