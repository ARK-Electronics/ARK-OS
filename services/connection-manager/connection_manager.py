#!/usr/bin/env python3
"""ARK-OS Connections Manager — FastAPI service for managing network connections.

The HTTP contract is the pydantic models below (Connection, LteStatus, ...).
Every handler CONSTRUCTS its response model, so the type checker (`mypy`, run from
the CLI or CI) rejects any drift between the producer and the contract before the
service ever runs on a device. FastAPI generates the OpenAPI spec from the same
models (served at /openapi.json, Swagger UI at /docs).

Capabilities (via NetworkManager and ModemManager):
- WiFi connections (both client and AP mode)
- Ethernet connections
- LTE/cellular connections (Jetson platform only)

Network statistics are a one-way server→client stream, served as Server-Sent
Events at /stats/stream (event: network_stats_update, every 2 s). Each subscriber
is an async generator that offloads the blocking nmcli/ip collection to a thread;
collection itself is rate-limited and shared through State, so this replaces the
eventlet/Socket.IO client-tracking thread machinery the Flask version needed.
"""

import os
import json
import time
import logging
import threading
import subprocess
import re
import asyncio
import ipaddress
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import uvicorn


def setup_logging():
    """Setup simple logging that will be captured by journald via stdout"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger('connection-manager')

# Initialize logger
logger = setup_logging()


# ── HTTP contract: the single source of truth ────────────────────────────────

class Connection(BaseModel):
    name: str
    type: str
    device: str
    autoconnect: str
    active: str
    ipAddress: str = ''
    # WiFi only
    ssid: str = ''
    mode: str = ''
    signal: int | str = ''
    # Ethernet only (omitted for other types)
    ipMethod: str | None = None
    gateway: str | None = None
    dns: str | None = None
    # LTE only (omitted for other types)
    apn: str | None = None


class ConnectionRequest(BaseModel):
    """Create/update payload for all three connection types. Per-type required
    fields are validated in the managers so the error messages match the UI."""
    type: str
    name: str | None = None
    autoconnect: str = 'yes'
    # WiFi
    ssid: str | None = None
    password: str | None = None
    mode: str | None = None
    # Ethernet
    ipMethod: str = 'auto'
    ipAddress: str | None = None
    gateway: str | None = None
    dns: str | list[str] | None = None
    # LTE
    apn: str | None = None


class OpResult(BaseModel):
    success: bool
    error: str | None = None
    applied: bool | None = None
    # Create echoes back the identifying fields
    name: str | None = None
    ssid: str | None = None
    mode: str | None = None


class WifiNetwork(BaseModel):
    ssid: str
    signal: int
    secured: bool


class HostnameResponse(BaseModel):
    hostname: str | None


class SetHostnameRequest(BaseModel):
    # The acceptable input is enforced by the type itself: a malformed hostname
    # is rejected at the boundary (422) before any handler code runs.
    hostname: str = Field(
        max_length=63,
        pattern=r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
    )


class SetHostnameResult(BaseModel):
    status: str  # "success" | "error"
    hostname: str | None = None
    message: str | None = None


class LteStatus(BaseModel):
    """Detailed LTE modem status. Empty/zero defaults are the not-available
    values the UI expects; `status` is only set when ModemManager is missing."""
    status: str = ""        # "not_found" when ModemManager is not running
    message: str = ""

    # Basic modem hardware info
    manufacturer: str = ""
    model: str = ""
    firmwareRevision: str = ""
    equipmentId: str = ""

    # Connection state
    state: str = ""         # Raw state from modem
    failedReason: str = ""  # If state is "failed"

    # Signal information
    signal: int = 0

    # Identity information
    imei: str = ""

    # Network information
    operatorId: str = ""
    operatorName: str = ""
    registration: str = ""  # Registration status (home, roaming, etc.)

    # SIM information
    simActive: str = ""
    simOperatorName: str = ""
    simOperatorId: str = ""
    simImsi: str = ""
    simIccid: str = ""

    # Bearer/APN information
    initialApn: str = ""
    apn: str = ""
    bearerConnected: bool = False
    suggestedApn: str = ""  # Suggested default APN based on SIM operator

    # Interface information
    interface: str = ""       # wwan0, etc
    interfaceState: str = ""  # up, down, unknown

    # IP configuration
    ipMethod: str = ""        # static, dhcp, etc.
    ipAddress: str = ""
    prefix: str = ""
    gateway: str = ""
    dns: list[str] = Field(default_factory=list)
    mtu: str = ""


class InterfaceSummary(BaseModel):
    """One entry of the network_stats_update SSE payload."""
    name: str
    interface: str
    type: str
    ipAddress: str
    active: bool
    rxBytes: int
    txBytes: int
    rxRateMbps: float
    txRateMbps: float
    rxErrors: int
    rxDropped: int
    txErrors: int
    txDropped: int
    rxPackets: int
    txPackets: int
    signal: int | None = None  # WiFi only


app = FastAPI(title="ARK-OS Connection Manager", version="1.0.0")


# Global state
class State:
    interface_stats: dict[str, dict[str, Any]] = {}  # Latest stats per interface
    last_stats_update: float = 0

    # Each accessor acquires this exactly once; collection happens outside
    # the lock (see get_interface_usage_summary), so a plain Lock suffices.
    stats_lock = threading.Lock()  # Thread safety for stats access


def strip_ansi_colors(text: str) -> str:
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def _clean_nmcli_error(stderr: str) -> str:
    """Turn nmcli stderr into a short, user-facing message."""
    lines = (stderr or "").strip().splitlines()
    msg = lines[-1].strip() if lines else ""
    msg = re.sub(r'^Error:\s*', '', msg)
    return msg or "operation failed"


def _normalize_ipv4_cidr(value: str | None) -> str | None:
    """
    Validate a static IPv4 address and return it in 'addr/prefix' form.

    The UI exposes a single address field, so a bare address such as
    '192.168.1.50' is accepted and defaulted to a /24 prefix. (A bare
    address would otherwise be stored by nmcli as /32, which leaves the
    host with no usable subnet route.) Returns None for invalid IPv4.
    """
    value = (value or "").strip()
    if not value:
        return None
    if '/' not in value:
        value = f"{value}/24"
    try:
        iface = ipaddress.ip_interface(value)
    except ValueError:
        return None
    if iface.version != 4:
        return None
    return iface.with_prefixlen


def _validate_ipv4(value: str | None) -> str | None:
    """Return a bare valid IPv4 host address, or None if invalid."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(addr) if addr.version == 4 else None


def _normalize_dns_list(value: str | list[str] | tuple | None) -> tuple[str, list[str]]:
    """
    Parse IPv4 DNS servers from a string (comma/space/semicolon separated)
    or a list. Returns (csv_for_nmcli, invalid_tokens).
    """
    if not value:
        return "", []
    if isinstance(value, (list, tuple)):
        tokens = [str(v) for v in value]
    else:
        tokens = re.split(r'[\s,;]+', str(value).strip())
    servers, invalid = [], []
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        valid = _validate_ipv4(token)
        if valid is None:
            invalid.append(token)
        else:
            servers.append(valid)
    return ",".join(servers), invalid


def _split_nmcli_terse(line: str) -> list[str]:
    """Split an `nmcli -t` line on ':' separators, honoring '\\:' escapes."""
    return [field.replace('\\:', ':') for field in re.split(r'(?<!\\):', line)]


def _redact_args(args: list[str]) -> str:
    """Render an argv list for logging, masking secret values."""
    rendered = []
    redact_next = False
    for arg in args:
        if redact_next:
            rendered.append("***")
            redact_next = False
            continue
        rendered.append(arg)
        if arg in ("wifi-sec.psk", "802-11-wireless-security.psk"):
            redact_next = True
    return ' '.join(rendered)


class CommandExecutor:
    @staticmethod
    def run_command(command: str, timeout: int = 30) -> str | None:
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
    def safe_run_command(command: str, default: str | None = None, timeout: int = 30) -> str | None:
        """Safely run a command and return the result or default value"""
        result = CommandExecutor.run_command(command, timeout)
        return result if result is not None else default

    @staticmethod
    def run_argv(args: list[str], timeout: int = 30) -> tuple[bool, str, str]:
        """
        Run a command given as an argv list (no shell) and return a
        (success, stdout, stderr) tuple.

        The argv form keeps user-supplied values (connection names, SSIDs,
        IP addresses, passwords, APNs) out of the shell, so they can't be
        word-split or interpreted as shell metacharacters, and it lets
        callers surface the real error message instead of just None.
        """
        try:
            logger.debug(f"Running: {_redact_args(args)}")
            result = subprocess.run(
                args,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            if result.returncode != 0:
                logger.error(f"Command failed ({result.returncode}): {_redact_args(args)}")
                logger.error(f"stderr: {stderr}")
                return False, stdout, stderr or f"exited with status {result.returncode}"
            return True, stdout, ""
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {_redact_args(args)}")
            return False, "", "command timed out"
        except FileNotFoundError as e:
            logger.error(f"Command not found: {args[0] if args else ''}")
            return False, "", str(e)
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return False, "", str(e)

    @staticmethod
    def run_argv_output(args: list[str], default: str | None = None, timeout: int = 30) -> str | None:
        """
        Run an argv command (no shell) and return its stdout, or `default`
        on failure -- the read/stats equivalent of safe_run_command.

        The read and stats paths use this instead of interpolating a
        connection name or interface into a shell string, so a name created
        with embedded shell metacharacters can't be executed when it is
        later read back.
        """
        ok, out, _err = CommandExecutor.run_argv(args, timeout)
        return out if ok else default


class NetworkConnectionManager:
    @staticmethod
    def get_network_connections() -> list[Connection]:
        connections: list[Connection] = []

        output = CommandExecutor.safe_run_command("nmcli -t -f NAME,TYPE,DEVICE,AUTOCONNECT,ACTIVE connection show")
        if not output:
            return connections

        # Parse network connections
        for line in output.strip().split('\n'):
            parts = line.split(':')
            if len(parts) >= 5:
                name, conn_type, device, autoconnect, active = parts[:5]

                if conn_type == '802-11-wireless':
                    conn_type = 'wifi'
                elif conn_type == '802-3-ethernet':
                    conn_type = 'ethernet'
                elif conn_type == 'gsm':
                    conn_type = 'lte'

                connection = Connection(
                    name=name,
                    type=conn_type,
                    device=device,
                    autoconnect=autoconnect,
                    active=active,
                )

                # Get interface specific properties
                if conn_type == 'wifi':
                    connection.mode = CommandExecutor.run_argv_output(["nmcli", "-g", "802-11-wireless.mode", "connection", "show", "id", name]) or ''
                    connection.ssid = CommandExecutor.run_argv_output(["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", "id", name]) or ''
                    connection.ipAddress = CommandExecutor.run_argv_output(["nmcli", "-g", "IP4.ADDRESS", "connection", "show", "id", name]) or ''
                elif conn_type == 'ethernet':
                    # Prefer the live address (DHCP-assigned or static) and fall
                    # back to the configured static address, so the list still
                    # shows an IP for a DHCP connection (whose ipv4.addresses is
                    # empty) as well as a configured-but-inactive static one.
                    live = CommandExecutor.run_argv_output(["nmcli", "-g", "IP4.ADDRESS", "connection", "show", "id", name])
                    profile = CommandExecutor.run_argv_output(["nmcli", "-g", "ipv4.addresses", "connection", "show", "id", name])
                    connection.ipAddress = live or profile or ''
                    connection.ipMethod = CommandExecutor.run_argv_output(["nmcli", "-g", "ipv4.method", "connection", "show", "id", name])
                    connection.gateway = CommandExecutor.run_argv_output(["nmcli", "-g", "ipv4.gateway", "connection", "show", "id", name]) or ''
                    connection.dns = CommandExecutor.run_argv_output(["nmcli", "-g", "ipv4.dns", "connection", "show", "id", name]) or ''
                if conn_type == 'lte':
                    connection.apn = CommandExecutor.run_argv_output(["nmcli", "-g", "gsm.apn", "connection", "show", "id", name])

                connections.append(connection)

        # Get all Wifi signal strengths
        wifi_signals: dict[str, str] = {}
        output = CommandExecutor.safe_run_command("nmcli -t -f SSID,SIGNAL device wifi")
        if output:
            for line in output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) >= 2:
                    ssid, signal = parts[:2]
                    wifi_signals[ssid] = signal

        # Add signal strength to all matching wifi connections
        for connection in connections:
            if connection.type == 'wifi' and connection.ssid in wifi_signals:
                connection.signal = wifi_signals[connection.ssid]
            elif connection.type == 'lte':
                connection.signal = LteManager.get_lte_status().signal

        return connections


class ConnectionManager:
    @staticmethod
    def create_connection(req: ConnectionRequest) -> tuple[OpResult, int]:
        if req.type == 'wifi':
            return ConnectionManager._create_wifi_connection(req)
        elif req.type == 'ethernet':
            return ConnectionManager._create_ethernet_connection(req)
        elif req.type == 'lte':
            return ConnectionManager._create_lte_connection(req)

        return OpResult(success=False, error='Unsupported connection type'), 400

    @staticmethod
    def _connection_exists(name: str) -> tuple[bool, str | None]:
        """Return (exists, error_message). Matches the connection NAME exactly."""
        ok, out, err = CommandExecutor.run_argv(["nmcli", "-t", "-f", "NAME", "connection", "show"])
        if not ok:
            return False, _clean_nmcli_error(err)
        # -f NAME yields one field per line; _split_nmcli_terse un-escapes the
        # '\:' that nmcli uses for a literal ':' within the name.
        existing = {_split_nmcli_terse(line)[0] for line in out.split('\n') if line}
        return name in existing, None

    @staticmethod
    def _apply_changes(name: str) -> tuple[OpResult, int]:
        """
        Make a saved profile change take effect on the live connection.

        'nmcli connection modify' only rewrites the stored profile; an
        already-active connection keeps running with its previous settings
        until it is brought back up. Re-activate the connection -- but only
        when it is currently active, so we don't start connections the user
        didn't ask to bring up -- and report any activation failure instead
        of silently succeeding.
        """
        _ok, state, _err = CommandExecutor.run_argv(
            ["nmcli", "-g", "GENERAL.STATE", "connection", "show", "id", name]
        )
        if state.strip() != 'activated':
            # Inactive profile: the new settings apply next time it comes up.
            return OpResult(success=True, applied=False), 200

        ok, _out, err = CommandExecutor.run_argv(
            ["nmcli", "--wait", "20", "connection", "up", "id", name], timeout=30
        )
        if not ok:
            return OpResult(
                success=False,
                applied=False,
                error=f"Settings were saved but could not be applied: {_clean_nmcli_error(err)}",
            ), 500
        return OpResult(success=True, applied=True), 200

    @staticmethod
    def _build_gateway_dns_args(cidr: str | None, req: ConnectionRequest,
                                clear_empty: bool = True) -> tuple[list[str] | None, str | None]:
        """
        Build the ipv4.gateway / ipv4.dns arguments for a static connection.

        Both fields are optional. On update (clear_empty=True) an empty value
        is emitted as "" so clearing a field in the form clears it in the
        stored profile; on create (clear_empty=False) empty fields are simply
        omitted. Returns (args, error_message); args is None on validation
        failure.
        """
        args: list[str] = []

        gateway = (req.gateway or '').strip()
        if gateway:
            gw = _validate_ipv4(gateway)
            if gw is None:
                return None, f'Invalid gateway address: {gateway}'
            # A default route only works if the gateway is on the local subnet.
            if cidr is not None:
                network = ipaddress.ip_interface(cidr).network
                if ipaddress.ip_address(gw) not in network:
                    return None, f'Gateway {gw} is not in the subnet {network.with_prefixlen}'
            args += ["ipv4.gateway", gw]
        elif clear_empty:
            args += ["ipv4.gateway", ""]

        dns_csv, invalid = _normalize_dns_list(req.dns)
        if invalid:
            return None, f"Invalid DNS server(s): {', '.join(invalid)}"
        if dns_csv or clear_empty:
            args += ["ipv4.dns", dns_csv]

        return args, None

    @staticmethod
    def _create_wifi_connection(req: ConnectionRequest) -> tuple[OpResult, int]:
        ssid = req.ssid
        password = req.password or ''
        mode = req.mode
        autoconnect = req.autoconnect

        if not ssid:
            return OpResult(success=False, error='SSID is required'), 400
        if not mode:
            return OpResult(success=False, error='Mode is required'), 400

        # A password makes the network secured; an empty one means an open
        # network (valid for a station, but a hotspot must be secured).
        secured = bool(password)
        if mode == 'ap' and not secured:
            return OpResult(success=False, error='A password is required for hotspot mode'), 400
        if secured and not (8 <= len(password) <= 63):
            return OpResult(success=False, error='Password must be 8-63 characters'), 400

        exists, err = ConnectionManager._connection_exists(ssid)
        if err is not None:
            return OpResult(success=False, error=err), 500
        if exists:
            return OpResult(success=False, error='Connection already exists'), 409

        args = [
            "nmcli", "connection", "add", "type", "wifi", "ifname", "*",
            "con-name", ssid, "autoconnect", autoconnect, "ssid", ssid,
        ]
        if mode == 'ap':
            args += ["802-11-wireless.mode", "ap", "802-11-wireless.band", "bg",
                     "ipv4.method", "shared"]
        if secured:
            args += ["wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", password]
            if mode == 'ap':
                args += ["802-11-wireless-security.pmf", "disable",
                         "connection.autoconnect-priority", "-1"]

        ok, _out, err_out = CommandExecutor.run_argv(args)
        if not ok:
            return OpResult(success=False, error=_clean_nmcli_error(err_out)), 500

        return OpResult(success=True, ssid=ssid, mode=mode), 201

    @staticmethod
    def _create_ethernet_connection(req: ConnectionRequest) -> tuple[OpResult, int]:
        """Create a new Ethernet connection"""
        name = req.name if req.name is not None else 'Ethernet Connection'
        ipMethod = req.ipMethod
        ipAddress = req.ipAddress
        autoconnect = req.autoconnect

        if not name:
            return OpResult(success=False, error='Name is required'), 400

        ipv4_extra: list[str] = []
        if ipMethod == 'manual':
            if not ipAddress:
                return OpResult(success=False, error='An IP address is required for static IP'), 400
            cidr = _normalize_ipv4_cidr(ipAddress)
            if cidr is None:
                return OpResult(success=False, error=f'Invalid IP address: {ipAddress}'), 400
            gw_dns, gw_err = ConnectionManager._build_gateway_dns_args(cidr, req, clear_empty=False)
            if gw_dns is None:
                return OpResult(success=False, error=gw_err), 400
            ipv4_extra = ["ipv4.method", "manual", "ipv4.addresses", cidr] + gw_dns

        exists, err = ConnectionManager._connection_exists(name)
        if err is not None:
            return OpResult(success=False, error=err), 500
        if exists:
            return OpResult(success=False, error='Connection already exists'), 409

        # Build the whole profile in a single command so a static address
        # can't be left half-applied by a failing follow-up modify.
        args = [
            "nmcli", "connection", "add", "type", "ethernet",
            "con-name", name, "ifname", "*", "autoconnect", autoconnect,
        ] + ipv4_extra

        ok, _out, err_out = CommandExecutor.run_argv(args)
        if not ok:
            return OpResult(success=False, error=_clean_nmcli_error(err_out)), 500

        return OpResult(success=True, name=name), 201

    @staticmethod
    def _create_lte_connection(req: ConnectionRequest) -> tuple[OpResult, int]:
        """Create a new LTE connection"""
        name = req.name if req.name is not None else 'LTE Connection'
        autoconnect = req.autoconnect
        apn = req.apn or ''

        if not name:
            return OpResult(success=False, error='Name is required'), 400

        # Only a single gsm/LTE connection is supported.
        ok, out, err = CommandExecutor.run_argv(["nmcli", "-t", "-f", "TYPE", "connection", "show"])
        if not ok:
            return OpResult(success=False, error=_clean_nmcli_error(err)), 500
        if 'gsm' in out.split('\n'):
            return OpResult(success=False, error='An LTE connection already exists'), 409

        args = [
            "nmcli", "connection", "add", "type", "gsm",
            "con-name", name, "gsm.apn", apn, "autoconnect", autoconnect,
        ]
        ok, _out, err = CommandExecutor.run_argv(args)
        if not ok:
            return OpResult(success=False, error=_clean_nmcli_error(err)), 500

        return OpResult(success=True, name=name), 201

    @staticmethod
    def update_connection(name: str, req: ConnectionRequest) -> tuple[OpResult, int]:
        """Update a connection configuration (WiFi, Ethernet, and LTE)"""
        if req.type == 'wifi':
            return ConnectionManager._update_wifi_connection(name, req)
        elif req.type == 'ethernet':
            return ConnectionManager._update_ethernet_connection(name, req)
        elif req.type == 'lte':
            return ConnectionManager._update_lte_connection(name, req)

        return OpResult(success=False, error='Unsupported connection type'), 400

    @staticmethod
    def _update_wifi_connection(name: str, req: ConnectionRequest) -> tuple[OpResult, int]:
        args = ["nmcli", "connection", "modify", "id", name]
        if req.ssid:
            args += ["802-11-wireless.ssid", req.ssid]
        if req.autoconnect:
            args += ["autoconnect", req.autoconnect]
        if req.password:
            if not (8 <= len(req.password) <= 63):
                return OpResult(success=False, error='Password must be 8-63 characters'), 400
            args += ["wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", req.password]

        ok, _out, err = CommandExecutor.run_argv(args)
        if not ok:
            return OpResult(success=False, error=_clean_nmcli_error(err)), 500

        return ConnectionManager._apply_changes(name)

    @staticmethod
    def _update_ethernet_connection(name: str, req: ConnectionRequest) -> tuple[OpResult, int]:
        args = ["nmcli", "connection", "modify", "id", name]
        if req.autoconnect:
            args += ["autoconnect", req.autoconnect]

        if req.ipMethod == 'auto':
            # Switch to DHCP and clear any leftover static configuration so it
            # doesn't linger in the profile.
            args += ["ipv4.method", "auto", "ipv4.addresses", "",
                     "ipv4.gateway", "", "ipv4.dns", ""]
        elif req.ipMethod == 'manual':
            if not req.ipAddress:
                return OpResult(success=False, error='An IP address is required for static IP'), 400
            cidr = _normalize_ipv4_cidr(req.ipAddress)
            if cidr is None:
                return OpResult(success=False, error=f'Invalid IP address: {req.ipAddress}'), 400
            gw_dns, gw_err = ConnectionManager._build_gateway_dns_args(cidr, req)
            if gw_dns is None:
                return OpResult(success=False, error=gw_err), 400
            args += ["ipv4.method", "manual", "ipv4.addresses", cidr] + gw_dns
        else:
            return OpResult(success=False, error=f'Invalid IP method: {req.ipMethod}'), 400

        ok, _out, err = CommandExecutor.run_argv(args)
        if not ok:
            return OpResult(success=False, error=_clean_nmcli_error(err)), 500

        # nmcli only wrote the stored profile; re-activate so an already-active
        # connection actually picks up the change (this is the fix for the
        # "modify did not take, no error shown" report).
        return ConnectionManager._apply_changes(name)

    @staticmethod
    def _update_lte_connection(name: str, req: ConnectionRequest) -> tuple[OpResult, int]:
        """Update an LTE connection with new settings"""
        args = ["nmcli", "connection", "modify", "id", name]
        if req.apn:
            args += ["gsm.apn", req.apn]
        if req.autoconnect:
            args += ["autoconnect", req.autoconnect]

        logger.info(f"Updating LTE connection {name} (apn={req.apn}, autoconnect={req.autoconnect})")

        ok, _out, err = CommandExecutor.run_argv(args)
        if not ok:
            return OpResult(success=False, error=_clean_nmcli_error(err)), 500

        return ConnectionManager._apply_changes(name)


class WiFiNetworkManager:
    # Monotonic timestamp of the last rescan we asked NetworkManager for.
    _last_rescan = 0.0
    _rescan_lock = threading.Lock()

    @staticmethod
    def request_rescan_async(min_interval: float = 10.0) -> None:
        """
        Ask NetworkManager to rescan, off the request path.

        NetworkManager keeps a continuously-updated scan cache and rate-limits
        explicit rescans, so we nudge it at most once per min_interval seconds
        and never block on it: the fresh results land in the cache and are
        picked up by a subsequent list call (the UI polls).
        """
        now = time.monotonic()
        with WiFiNetworkManager._rescan_lock:
            if now - WiFiNetworkManager._last_rescan < min_interval:
                return
            WiFiNetworkManager._last_rescan = now

        # Fire and forget in a background thread; nmcli can block briefly
        # while the scan runs and we don't want the HTTP response to wait.
        threading.Thread(
            target=CommandExecutor.safe_run_command,
            args=("nmcli device wifi rescan", None, 20),
            daemon=True,
        ).start()

    @staticmethod
    def list_cached_networks() -> list[WifiNetwork]:
        """
        Return WiFi networks from NetworkManager's scan cache *without*
        triggering a (blocking) rescan -- `--rescan no` is the key: the default
        `auto` makes `device wifi list` itself scan when the cache is stale.

        Results are deduplicated by SSID (keeping the strongest signal, since
        one SSID spans multiple APs/bands), hidden networks are dropped, and
        the list is sorted strongest-first.
        """
        output = CommandExecutor.safe_run_command(
            "nmcli -t -f SSID,SIGNAL,SECURITY device wifi list --rescan no"
        )
        if not output:
            return []

        networks: dict[str, WifiNetwork] = {}
        for line in output.strip().split('\n'):
            if not line:
                continue
            fields = _split_nmcli_terse(line)
            if len(fields) < 3:
                continue
            ssid, signal, security = fields[0], fields[1], fields[2]
            if not ssid:  # hidden network
                continue
            signal_val = int(signal) if signal.isdigit() else 0
            existing = networks.get(ssid)
            if existing is None or signal_val > existing.signal:
                networks[ssid] = WifiNetwork(
                    ssid=ssid,
                    signal=signal_val,
                    secured=bool(security) and security != '--',
                )

        return sorted(networks.values(), key=lambda n: (-n.signal, n.ssid.lower()))

    @staticmethod
    def scan_wifi_networks() -> list[WifiNetwork]:
        """Nudge a background rescan and return the current cached list."""
        WiFiNetworkManager.request_rescan_async()
        return WiFiNetworkManager.list_cached_networks()


class HostnameManager:
    @staticmethod
    def get_hostname() -> str | None:
        """Get the system hostname"""
        return CommandExecutor.safe_run_command("hostname")

    @staticmethod
    def set_hostname(new_hostname: str) -> tuple[bool, str]:
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
    def get_lte_status() -> LteStatus:
        """
        Get detailed status information for the LTE modem.

        The mmcli output is parsed straight into the LteStatus contract model,
        so the type checker verifies every field assignment.
        """

        if not CommandExecutor.safe_run_command("systemctl is-active ModemManager"):
            return LteStatus(status="not_found", message="ModemManager is not running")

        status = LteStatus()

        try:
            # Get modem index
            modem_index = CommandExecutor.safe_run_command(r"mmcli -L | grep -oP '(?<=/Modem/)\d+' || echo ''")
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
                    status.manufacturer = line.split('manufacturer:')[1].strip()
                elif 'model:' in line:
                    status.model = line.split('model:')[1].strip()
                elif 'firmware revision:' in line:
                    status.firmwareRevision = line.split('firmware revision:')[1].strip()
                elif 'equipment id:' in line:
                    status.equipmentId = line.split('equipment id:')[1].strip()

                # Status info
                elif 'signal quality:' in line:
                    signal_parts = line.split('signal quality:')[1].strip().split()
                    # Parse "60% (recent)" format
                    if signal_parts and '%' in signal_parts[0]:
                        status.signal = int(signal_parts[0].replace('%', ''))
                elif '  state:' in line:  # Using two spaces to differentiate from other state fields (power state:)
                    status.state = strip_ansi_colors(line.split('state:')[1].strip())

                # 3GPP info
                elif 'imei:' in line:
                    status.imei = line.split('imei:')[1].strip()
                elif 'operator id:' in line:
                    status.operatorId = line.split('operator id:')[1].strip()
                elif 'operator name:' in line:
                    status.operatorName = line.split('operator name:')[1].strip()
                elif 'registration:' in line:
                    status.registration = line.split('registration:')[1].strip()

                # EPS / Bearer info
                elif 'initial bearer apn:' in line:
                    status.initialApn = line.split('initial bearer apn:')[1].strip()

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

            if status.state == "failed":
                for line in modem_info.split('\n'):
                    if 'failed reason:' in line:
                        status.failedReason = strip_ansi_colors(line.split('failed reason:')[1].strip())

            # If we have a SIM path, get SIM info
            if sim_path:
                sim_info = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} --sim {sim_path}")
                if sim_info:
                    for line in sim_info.split('\n'):
                        line = line.strip()
                        if 'operator name:' in line:
                            status.simOperatorName = line.split('operator name:')[1].strip()
                        elif 'operator id:' in line:
                            status.simOperatorId = line.split('operator id:')[1].strip()
                        elif 'imsi:' in line:
                            status.simImsi = line.split('imsi:')[1].strip()
                        elif 'iccid:' in line:
                            status.simIccid = line.split('iccid:')[1].strip()
                        elif 'active:' in line:
                            status.simActive = line.split('active:')[1].strip()

            # If we have a bearer path, get bearer info for interface and IP details
            if bearer_path:
                bearer_info = CommandExecutor.safe_run_command(f"mmcli -m {modem_index} --bearer={bearer_path}")
                if bearer_info:
                    for line in bearer_info.split('\n'):
                        line = line.strip()
                        if 'connected:' in line:
                            status.bearerConnected = "yes" in line.split('connected:')[1].strip()
                        elif 'interface:' in line:
                            status.interface = line.split('interface:')[1].strip()
                        elif 'apn:' in line:
                            status.apn = line.split('apn:')[1].strip()
                        elif 'method:' in line:
                            status.ipMethod = line.split('method:')[1].strip()
                        elif 'address:' in line:
                            status.ipAddress = line.split('address:')[1].strip()
                        elif 'prefix:' in line:
                            status.prefix = line.split('prefix:')[1].strip()
                        elif 'gateway:' in line:
                            status.gateway = line.split('gateway:')[1].strip()
                        elif 'dns:' in line:
                            dns_servers = line.split('dns:')[1].strip().split(',')
                            status.dns = [server.strip() for server in dns_servers]
                        elif 'mtu:' in line:
                            status.mtu = line.split('mtu:')[1].strip()

                    # Check interface status if we have one
                    if status.interface:
                        interface_status = CommandExecutor.safe_run_command(f"ip link show {status.interface} | grep 'state'")
                        if interface_status:
                            if "UP" in interface_status:
                                status.interfaceState = "up"
                            else:
                                status.interfaceState = "down"

            # Suggest APN depending on SIM operator
            if status.simOperatorName:
                operator = status.simOperatorName.lower()
                if "t-mobile" in operator:
                    status.suggestedApn = "fast.t-mobile.com"
                elif "at&t" in operator or "att" in operator:
                    status.suggestedApn = "broadband"
                elif "verizon" in operator:
                    status.suggestedApn = "vzwinternet"

        except Exception as e:
            logger.error(f"Error getting modem status: {e}")
            logger.exception(e)  # Log full traceback for debugging

        return status


class NetworkStatsCollector:
    @staticmethod
    def collect_interface_stats() -> dict[str, dict[str, Any]]:
        """
        Collect network interface statistics from activated NetworkManager connections.
        Uses GENERAL.IP-IFACE property to identify the actual data interface for all connection types.
        Returns a dictionary of interface stats with rx/tx bytes, packets, errors, dropped.
        """
        stats: dict[str, dict[str, Any]] = {}
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
                        ip_iface = CommandExecutor.run_argv_output(["nmcli", "-g", "GENERAL.IP-IFACE", "connection", "show", "id", name])

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
                stats_output = CommandExecutor.run_argv_output(["ip", "-s", "link", "show", device])
                if not stats_output:
                    logger.warning(f"Failed to get stats for device {device}")
                    continue

                # Parse the stats output
                interface_stats = NetworkStatsCollector._parse_ip_stats(stats_output)
                if not interface_stats:
                    logger.warning(f"Failed to parse stats for device {device}")
                    continue

                # Get IP address: first IPv4 'inet' line, address without prefix.
                ip_output = ''
                addr_out = CommandExecutor.run_argv_output(["ip", "-4", "addr", "show", device])
                if addr_out:
                    for addr_line in addr_out.split('\n'):
                        addr_fields = addr_line.split()
                        if addr_fields and addr_fields[0] == 'inet':
                            ip_output = addr_fields[1].split('/')[0]
                            break

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
                    # Get signal strength for WiFi: first row of the terse list
                    # (strongest network on this interface).
                    signal_out = CommandExecutor.run_argv_output(
                        ["nmcli", "-t", "-f", "SIGNAL", "device", "wifi", "list", "ifname", device]
                    )
                    signal_output = next((l.strip() for l in (signal_out or '').split('\n') if l.strip()), '')
                    if signal_output and signal_output.isdigit():
                        device_stats['signal_strength'] = int(signal_output)

                    # Get SSID for WiFi
                    ssid_output = CommandExecutor.run_argv_output(["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", "id", info['name']])
                    if ssid_output:
                        device_stats['ssid'] = ssid_output

                elif info['type'] == 'lte':
                    # For LTE connections, try to get signal strength from ModemManager
                    # This is optional and only works if ModemManager is available
                    signal_output = CommandExecutor.safe_run_command(
                        "mmcli -m 0 | grep 'signal quality' | awk -F': ' '{print $2}' | awk '{print $1}' | tr -d '%'"
                    ) or ''
                    if signal_output and signal_output.isdigit():
                        device_stats['signal_strength'] = int(signal_output)

                stats[device] = device_stats
                logger.debug(f"Collected stats for {device} ({info['name']}): RX={device_stats['rx_bytes']}, TX={device_stats['tx_bytes']}")

        except Exception as e:
            logger.error(f"Error collecting interface stats: {e}")
            logger.exception(e)  # Log full traceback for debugging

        return stats

    @staticmethod
    def _parse_ip_stats(stats_output: str) -> dict[str, int]:
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
    def update_interface_stats() -> dict[str, dict[str, Any]]:
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
    def _calculate_interface_rates(interface: str, stats: dict[str, Any]) -> None:
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
            stats['rx_rate'] = 0
            stats['tx_rate'] = 0
            stats['rx_rate_mbps'] = 0
            stats['tx_rate_mbps'] = 0


class NetworkReporting:
    @staticmethod
    def get_interface_usage_summary() -> list[InterfaceSummary]:
        """
        Get simplified usage summary for active network interfaces.
        Returns a list of interface summaries with essential stats.
        """
        # Fast path: build directly from already-collected stats.
        with State.stats_lock:
            if State.interface_stats:
                return NetworkReporting._build_summary()

        # No stats yet. Collect them WITHOUT holding the lock: collection
        # shells out to nmcli/ip and takes the lock itself only to store the
        # result, so holding it here would block other readers across slow
        # subprocess calls (and is what previously forced a reentrant lock).
        logger.debug("No interface stats available, collecting now")
        NetworkStatsProcessor.update_interface_stats()

        with State.stats_lock:
            if not State.interface_stats:
                logger.debug("No active network interfaces found")
                return []
            return NetworkReporting._build_summary()

    @staticmethod
    def _build_summary() -> list[InterfaceSummary]:
        """
        Build the interface summary list from State.interface_stats — the typed
        boundary between the loose collector dicts and the SSE contract.
        The caller must hold State.stats_lock.
        """
        summary: list[InterfaceSummary] = []

        # Process each interface to create a simplified summary
        for interface, stats in State.interface_stats.items():
            # Skip loopback interface
            if interface == 'lo':
                continue

            summary.append(InterfaceSummary(
                name=stats.get('name', interface),
                interface=interface,
                type=stats.get('type', 'other'),
                ipAddress=stats.get('ip_address', ''),
                active=True,
                rxBytes=stats.get('rx_bytes', 0),
                txBytes=stats.get('tx_bytes', 0),
                rxRateMbps=stats.get('rx_rate_mbps', 0),
                txRateMbps=stats.get('tx_rate_mbps', 0),
                rxErrors=stats.get('rx_errors', 0),
                rxDropped=stats.get('rx_dropped', 0),
                txErrors=stats.get('tx_errors', 0),
                txDropped=stats.get('tx_dropped', 0),
                rxPackets=stats.get('rx_packets', 0),
                txPackets=stats.get('tx_packets', 0),
                signal=stats.get('signal_strength', 0) if stats.get('type') == 'wifi' else None,
            ))

        # Sort by total bytes (most traffic first)
        summary.sort(key=lambda x: -(x.rxBytes + x.txBytes))

        logger.debug(f"Generated summary for {len(summary)} active interfaces")
        return summary


# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/connections", response_model_exclude_none=True)
def api_get_connections() -> list[Connection]:
    logger.info("GET /connections called")
    return NetworkConnectionManager.get_network_connections()


@app.post("/connections", response_model_exclude_none=True)
def api_create_connection(body: ConnectionRequest, response: Response) -> OpResult:
    logger.info("POST /connections called")
    result, code = ConnectionManager.create_connection(body)
    response.status_code = code
    return result


@app.delete("/connections/{name}", response_model_exclude_none=True)
def api_delete_connection(name: str, response: Response) -> OpResult:
    logger.info(f"DELETE /connections/{name} called")
    ok, _out, err = CommandExecutor.run_argv(["nmcli", "connection", "delete", "id", name])
    if not ok:
        response.status_code = 500
        return OpResult(success=False, error=_clean_nmcli_error(err))
    return OpResult(success=True)


@app.put("/connections/{name}", response_model_exclude_none=True)
def api_update_connection(name: str, body: ConnectionRequest, response: Response) -> OpResult:
    logger.info(f"PUT /connections/{name} called")
    result, code = ConnectionManager.update_connection(name, body)
    response.status_code = code
    return result


@app.post("/connections/{name}/connect", response_model_exclude_none=True)
def api_connect_to_network(name: str, response: Response) -> OpResult:
    logger.info(f"POST /connections/{name}/connect called")
    ok, _out, err = CommandExecutor.run_argv(
        ["nmcli", "--wait", "20", "connection", "up", "id", name], timeout=30
    )
    if not ok:
        response.status_code = 500
        return OpResult(success=False, error=_clean_nmcli_error(err))
    return OpResult(success=True)


@app.post("/connections/{name}/disconnect", response_model_exclude_none=True)
def api_disconnect_from_network(name: str, response: Response) -> OpResult:
    logger.info(f"POST /connections/{name}/disconnect called")
    ok, _out, err = CommandExecutor.run_argv(["nmcli", "connection", "down", "id", name])
    if not ok:
        response.status_code = 500
        return OpResult(success=False, error=_clean_nmcli_error(err))
    return OpResult(success=True)


@app.get("/wifi/scan")
def api_scan_wifi() -> list[WifiNetwork]:
    logger.info("GET /wifi/scan called")
    return WiFiNetworkManager.scan_wifi_networks()


@app.get("/hostname")
def api_get_hostname() -> HostnameResponse:
    logger.info("GET /hostname called")
    return HostnameResponse(hostname=HostnameManager.get_hostname())


@app.post("/hostname", response_model_exclude_none=True)
def api_set_hostname(body: SetHostnameRequest, response: Response) -> SetHostnameResult:
    logger.info("POST /hostname called")
    success, message = HostnameManager.set_hostname(body.hostname)

    if success:
        return SetHostnameResult(status="success", hostname=message)
    response.status_code = 400
    return SetHostnameResult(status="error", message=message)


@app.get("/lte/status")
def api_get_lte_status() -> LteStatus:
    logger.info("GET /lte/status called")
    return LteManager.get_lte_status()


@app.get("/stats/stream")
async def api_stats_stream() -> StreamingResponse:
    """Server-Sent Events stream of interface usage statistics.

    Emits a network_stats_update event (list[InterfaceSummary]) every 2 s.
    One-way server→client push, so SSE rides the same /api HTTP proxy chain
    as the REST endpoints — no websocket layer involved. Collection is
    blocking subprocess work, so it runs in a thread; the shared State plus
    the 1 s rate limit in update_interface_stats keep concurrent subscribers
    from over-collecting.
    """

    async def event_stream() -> AsyncIterator[str]:
        logger.info("Network stats stream client connected")

        def collect() -> list[InterfaceSummary]:
            NetworkStatsProcessor.update_interface_stats()
            return NetworkReporting.get_interface_usage_summary()

        try:
            while True:
                summary = await asyncio.to_thread(collect)
                if summary:
                    payload = json.dumps([i.model_dump(exclude_none=True) for i in summary])
                    yield f"event: network_stats_update\ndata: {payload}\n\n"
                else:
                    # Comment keeps the connection (and intermediate proxies)
                    # alive while there is nothing to report.
                    yield ": no-active-interfaces\n\n"
                await asyncio.sleep(2.0)
        finally:
            logger.info("Network stats stream client disconnected")

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == '__main__':
    host = '127.0.0.1'
    port = int(os.environ.get("PORT", 3001))

    logger.info(f"Starting Connection Manager on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
