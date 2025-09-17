from flask import Flask, jsonify, request
import platform
import os
import psutil
import subprocess
import re
import socket

app = Flask(__name__)

class SystemInfoCollector:
    """Base class for system information collection"""

    @staticmethod
    def get_common_info():
        """Get system information common to all devices"""
        info = {
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "total": psutil.virtual_memory().total / (1024**3),  # GB
                "used": psutil.virtual_memory().used / (1024**3),
                "available": psutil.virtual_memory().available / (1024**3),
                "percent": psutil.virtual_memory().percent
            },
            "disk": {
                "total": psutil.disk_usage('/').total / (1024**3),
                "used": psutil.disk_usage('/').used / (1024**3),
                "available": psutil.disk_usage('/').free / (1024**3),
                "percent": psutil.disk_usage('/').percent
            },
            "network_interfaces": {}
        }

        # Get network interfaces
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    info["network_interfaces"][iface] = addr.address
                    break

        # Get distribution info
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_info[key] = value.strip('"\'')

                info["distribution"] = os_info.get('PRETTY_NAME', 'Unknown Linux')
                info["release"] = os_info.get('VERSION_ID', 'unknown')
                info["codename"] = os_info.get('VERSION_CODENAME', 'unknown')
        except Exception:
            info["distribution"] = "Unknown Linux"
            info["release"] = "unknown"
            info["codename"] = "unknown"

        return info

    @staticmethod
    def get_temperature_info():
        """Try to get CPU temperature from various sources"""
        temp_info = {}

        # Try thermal zone (common on ARM devices)
        try:
            thermal_zones = [f for f in os.listdir('/sys/class/thermal/') if f.startswith('thermal_zone')]
            for zone in thermal_zones:
                temp_file = f'/sys/class/thermal/{zone}/temp'
                if os.path.exists(temp_file):
                    with open(temp_file, 'r') as f:
                        temp = int(f.read().strip()) / 1000.0  # Convert from millidegrees
                        temp_info[zone] = temp
                        if 'cpu' not in temp_info:
                            temp_info['cpu'] = temp  # Use first zone as CPU temp
        except Exception:
            pass

        # Try using psutil sensors (if available)
        try:
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        for entry in entries:
                            if 'cpu' in entry.label.lower() or 'core' in entry.label.lower():
                                temp_info['cpu'] = entry.current
                                break
        except Exception:
            pass

        return temp_info


class JetsonCollector(SystemInfoCollector):
    """Collector for NVIDIA Jetson devices"""

    @staticmethod
    def is_jetson():
        """Check if running on a Jetson device"""
        try:
            with open('/proc/device-tree/model', 'r') as f:
                model = f.read().lower()
                return 'nvidia' in model or 'jetson' in model
        except:
            return False

    @staticmethod
    def get_jetson_info():
        """Get Jetson-specific information using jtop"""
        try:
            from jtop import jtop

            with jtop() as jetson:
                if not jetson.ok():
                    return None

                # Collect Jetson-specific data
                data = {
                    "hardware": {
                        "type": "jetson",
                        "model": jetson.board.get("hardware", {}).get("Model", "Unknown"),
                        "module": jetson.board.get("hardware", {}).get("Module", "Unknown"),
                        "serial_number": jetson.board.get("hardware", {}).get("Serial Number", "Unknown"),
                        "l4t": jetson.board.get("hardware", {}).get("L4T", "Unknown"),
                        "jetpack": jetson.board.get("hardware", {}).get("Jetpack", "Unknown")
                    },
                    "libraries": {
                        "cuda": jetson.board.get("libraries", {}).get("CUDA", "Not available"),
                        "opencv": jetson.board.get("libraries", {}).get("OpenCV", "Not available"),
                        "opencv_cuda": jetson.board.get("libraries", {}).get("OpenCV-Cuda", False),
                        "cudnn": jetson.board.get("libraries", {}).get("cuDNN", "Not available"),
                        "tensorrt": jetson.board.get("libraries", {}).get("TensorRT", "Not available"),
                        "vpi": jetson.board.get("libraries", {}).get("VPI", "Not available"),
                        "vulkan": jetson.board.get("libraries", {}).get("Vulkan", "Not available")
                    },
                    "power": {
                        "nvpmodel": str(jetson.nvpmodel) if jetson.nvpmodel else "Unknown",
                        "jetson_clocks": "Active" if (hasattr(jetson, 'jetson_clocks') and jetson.jetson_clocks) else "Inactive" if hasattr(jetson, 'jetson_clocks') else None,
                        "total": jetson.power.get("tot", {}).get("power", 0) if hasattr(jetson, 'power') else 0,
                        "temperature": {
                            "cpu": jetson.temperature.get("cpu", {}).get("temp", 0) if hasattr(jetson, 'temperature') else 0,
                            "gpu": jetson.temperature.get("gpu", {}).get("temp", 0) if hasattr(jetson, 'temperature') else 0,
                            "tj": jetson.temperature.get("tj", {}).get("temp", 0) if hasattr(jetson, 'temperature') else 0
                        }
                    }
                }

                return data
        except (ImportError, ModuleNotFoundError):
            return None
        except Exception as e:
            print(f"Error collecting Jetson data: {e}")
            return None


class RaspberryPiCollector(SystemInfoCollector):
    """Collector for Raspberry Pi devices"""

    @staticmethod
    def is_raspberry_pi():
        """Check if running on a Raspberry Pi"""
        try:
            with open('/proc/device-tree/model', 'r') as f:
                model = f.read().lower()
                return 'raspberry pi' in model
        except:
            return False

    @staticmethod
    def get_pi_info():
        """Get Raspberry Pi specific information"""
        info = {}

        # Get Pi model
        try:
            with open('/proc/device-tree/model', 'r') as f:
                info['model'] = f.read().strip('\x00')
        except:
            info['model'] = "Unknown Raspberry Pi"

        # Get serial number
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('Serial'):
                        info['serial_number'] = line.split(':')[1].strip()
                        break
        except:
            info['serial_number'] = "Unknown"

        # Get CPU info
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('Hardware'):
                        info['hardware'] = line.split(':')[1].strip()
                    elif line.startswith('Revision'):
                        info['revision'] = line.split(':')[1].strip()
        except:
            pass

        # Get GPU memory split
        try:
            result = subprocess.run(['vcgencmd', 'get_mem', 'gpu'],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                info['gpu_memory'] = result.stdout.strip()
        except:
            pass

        # Get throttling status
        try:
            result = subprocess.run(['vcgencmd', 'get_throttled'],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                throttled = result.stdout.strip()
                info['throttled'] = throttled
                # Parse throttling flags
                if '0x' in throttled:
                    value = int(throttled.split('0x')[1], 16)
                    info['throttling_status'] = {
                        'under_voltage': bool(value & 0x1),
                        'frequency_capped': bool(value & 0x2),
                        'throttled': bool(value & 0x4),
                        'soft_temp_limit': bool(value & 0x8)
                    }
        except:
            pass

        return info


class GenericLinuxCollector(SystemInfoCollector):
    """Collector for generic Linux systems"""

    @staticmethod
    def get_info():
        """Get generic Linux system information"""
        info = {
            "type": "generic",
            "kernel_version": platform.release(),
            "processor": platform.processor() or "Unknown"
        }

        # Try to get CPU model
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if 'model name' in line.lower():
                        info['cpu_model'] = line.split(':')[1].strip()
                        break
        except:
            pass

        return info


def get_system_info():
    """Main function to collect all system information with unified structure"""
    # Start with common info
    system_info = SystemInfoCollector.get_common_info()

    # Get temperature info
    temp_info = SystemInfoCollector.get_temperature_info()

    # Initialize with default structure
    result = {
        "device_type": "unknown",
        "hardware": {
            "model": "Not available",
            "module": "Not available",
            "serial_number": "Not available",
            "l4t": "Not available",
            "jetpack": "Not available"
        },
        "platform": {
            "distribution": system_info["distribution"],
            "release": system_info["codename"],
            "kernel": platform.release(),
            "python": system_info["python_version"],
            "architecture": system_info["architecture"]
        },
        "libraries": {
            "cuda": "Not available",
            "opencv": "Not available",
            "opencv_cuda": False,
            "cudnn": "Not available",
            "tensorrt": "Not available",
            "vpi": "Not available",
            "vulkan": "Not available"
        },
        "power": {
            "nvpmodel": "Not available",
            "jetson_clocks": "Not available",
            "total": 0,
            "temperature": {}
        },
        "resources": {
            "memory": system_info["memory"],
            "disk": system_info["disk"],
            "cpu_count": system_info["cpu_count"]
        },
        "network": {
            "hostname": system_info["hostname"],
            "interfaces": system_info["network_interfaces"]
        },
        "temperature": temp_info if temp_info else {}
    }

    # Detect device type and update specific fields
    if JetsonCollector.is_jetson():
        result["device_type"] = "jetson"
        jetson_data = JetsonCollector.get_jetson_info()
        if jetson_data:
            # Update with Jetson-specific data
            if "hardware" in jetson_data:
                result["hardware"].update(jetson_data["hardware"])
            if "libraries" in jetson_data:
                result["libraries"] = jetson_data["libraries"]
            if "power" in jetson_data:
                result["power"] = jetson_data["power"]
                # Merge temperatures
                if "temperature" in jetson_data["power"]:
                    result["temperature"].update(jetson_data["power"]["temperature"])

    elif RaspberryPiCollector.is_raspberry_pi():
        result["device_type"] = "pi"
        pi_info = RaspberryPiCollector.get_pi_info()
        result["hardware"]["model"] = pi_info.get("model", "Raspberry Pi")
        result["hardware"]["serial_number"] = pi_info.get("serial_number", "Unknown")

    else:
        result["device_type"] = "generic"
        generic_info = GenericLinuxCollector.get_info()
        result["hardware"]["model"] = generic_info.get("cpu_model", "Generic Linux System")

    # Backward compatibility
    result["interfaces"] = result["network"]

    return result


def is_valid_hostname(hostname):
    """
    Validate hostname format according to RFC 1123 and RFC 952
    """
    if not hostname or len(hostname) > 63:
        return False

    pattern = r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
    return bool(re.match(pattern, hostname))


def set_hostname(new_hostname):
    """Set system hostname"""
    try:
        if not is_valid_hostname(new_hostname):
            return {
                "success": False,
                "message": "Invalid hostname format. Use only alphanumeric and hyphens, 63 chars max."
            }

        old_hostname = platform.node()

        # Try hostnamectl first (systemd systems)
        try:
            subprocess.run(["hostnamectl", "set-hostname", new_hostname],
                         check=True, capture_output=True, timeout=5)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to hostname command
            subprocess.run(["hostname", new_hostname], check=True, timeout=5)
            # Also update /etc/hostname
            with open('/etc/hostname', 'w') as f:
                f.write(new_hostname + '\n')

        return {
            "success": True,
            "message": f"Hostname changed from {old_hostname} to {new_hostname}. Reboot required."
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to change hostname: {str(e)}"
        }


@app.route('/info', methods=['GET'])
def system_info():
    """Get system information endpoint"""
    try:
        data = get_system_info()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e), "message": "Failed to collect system information"}), 500


@app.route('/hostname', methods=['POST'])
def update_hostname():
    """Update hostname endpoint"""
    try:
        data = request.get_json()

        if not data or 'hostname' not in data:
            return jsonify({
                "success": False,
                "message": "Missing hostname parameter"
            }), 400

        new_hostname = data['hostname']
        result = set_hostname(new_hostname)

        return jsonify(result), 200 if result['success'] else 400

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500


if __name__ == '__main__':
    host = '127.0.0.1'
    port = 3004
    print(f"Starting System Manager on {host}:{port}")
    print(f"Device type detection in progress...")

    # Quick device detection for startup message
    if JetsonCollector.is_jetson():
        print("Detected: NVIDIA Jetson")
    elif RaspberryPiCollector.is_raspberry_pi():
        print("Detected: Raspberry Pi")
    else:
        print("Detected: Generic Linux System")

    app.run(host=host, port=port, threaded=True)
