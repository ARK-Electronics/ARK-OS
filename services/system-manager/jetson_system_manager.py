from flask import Flask, jsonify, request
import time
import random
import platform
import os
import psutil
import subprocess
import re

app = Flask(__name__)

def get_mock_jetson_info():
    """Generate mock Jetson data for testing on non-Jetson devices"""
    # Get some real system data where possible
    hostname = platform.node()
    python_version = platform.python_version()

    # Get Linux distribution info from /etc/os-release
    distribution = "Unknown Linux"
    release = "unknown"
    codename = "unknown"

    try:
        with open('/etc/os-release', 'r') as f:
            os_info = {}
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    os_info[key] = value.strip('"\'')

            distribution = os_info.get('PRETTY_NAME', 'Unknown Linux')
            release = os_info.get('VERSION_ID', 'unknown')
            codename = os_info.get('VERSION_CODENAME', 'unknown')
    except Exception:
        pass

    # Get disk usage for the root filesystem
    disk = psutil.disk_usage('/')
    total_gb = disk.total / (1024**3)
    used_gb = disk.used / (1024**3)
    free_gb = disk.free / (1024**3)

    # Mock temperature (random values between 40-60°C)
    temp_cpu = random.uniform(40, 60)
    temp_gpu = random.uniform(40, 60)
    temp_tj = max(temp_cpu, temp_gpu) + random.uniform(0, 5)

    # Get network interfaces
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # AF_INET (IPv4)
                interfaces[iface] = addr.address
                break

    # Create mock data structure
    mock_data = {
        "hardware": {
            "type": "jetson",
            "model": "NVIDIA Jetson Mock Device",
            "module": "NVIDIA Jetson Nano (4GB ram)",
            "serial_number": "MOCK12345678",
            "l4t": "32.7.1",
            "jetpack": "4.6.1"
        },
        "platform": {
            "distribution": distribution,
            "release": codename,  # Use the codename (e.g., "jammy") as the release
            "python": python_version
        },
        "libraries": {
            "cuda": "10.2.300",
            "opencv": "4.5.1",
            "opencv_cuda": False,
            "cudnn": "8.2.1.32",
            "tensorrt": "8.0.1.6",
            "vpi": "1.1.0",
            "vulkan": "1.2.70"
        },
        "power": {
            "nvpmodel": "10W",
            "jetson_clocks": False,
            "total": random.randint(3000, 7000),
            "temperature": {
                "cpu": temp_cpu,
                "gpu": temp_gpu,
                "tj": temp_tj
            }
        },
        "interfaces": {
            "hostname": hostname,
            "interfaces": interfaces
        },
        "disk": {
            "total": total_gb,
            "used": used_gb,
            "available": free_gb
        }
    }

    return mock_data


def get_jetson_info():
    """Collect and return data from Jetson device or mock data if not available"""
    try:
        # Try to import jtop
        from jtop import jtop

        with jtop() as jetson:
            if not jetson.ok():
                print("Failed to connect to Jetson device, using mock data instead")
                return get_mock_jetson_info()

            # Wait for data collection
            time.sleep(0.5)

            # Collect data specified in the requirements
            data = {
                "hardware": {
                    "type": "jetson",
                    "model": jetson.board["hardware"]["Model"],
                    "module": jetson.board["hardware"]["Module"],
                    "serial_number": jetson.board["hardware"]["Serial Number"],
                    "l4t": jetson.board["hardware"]["L4T"],
                    "jetpack": jetson.board["hardware"]["Jetpack"]
                },
                "platform": {
                    "distribution": jetson.board["platform"]["Distribution"],
                    "release": jetson.board["platform"]["Release"],
                    "python": jetson.board["platform"]["Python"]
                },
                "libraries": {
                    "cuda": jetson.board["libraries"]["CUDA"],
                    "opencv": jetson.board["libraries"]["OpenCV"],
                    "opencv_cuda": jetson.board["libraries"]["OpenCV-Cuda"],
                    "cudnn": jetson.board["libraries"]["cuDNN"],
                    "tensorrt": jetson.board["libraries"]["TensorRT"],
                    "vpi": jetson.board["libraries"]["VPI"],
                    "vulkan": jetson.board["libraries"]["Vulkan"]
                },
                "power": {
                    "nvpmodel": str(jetson.nvpmodel),
                    "jetson_clocks": bool(jetson.jetson_clocks),
                    "total": jetson.power["tot"]["power"],
                    "temperature": {
                        "cpu": jetson.temperature["cpu"]["temp"],
                        "gpu": jetson.temperature["gpu"]["temp"],
                        "tj": jetson.temperature["tj"]["temp"]
                    }
                },
                "interfaces": {
                    "hostname": jetson.local_interfaces["hostname"],
                    "interfaces": jetson.local_interfaces["interfaces"]
                },
                "disk": {
                    "total": jetson.disk["total"],
                    "used": jetson.disk["used"],
                    "available": jetson.disk["available"]
                }
            }

            return data

    except (ImportError, ModuleNotFoundError):
        print("jtop module not found, using mock data instead")
        return get_mock_jetson_info()
    except Exception as e:
        print(f"Error: {str(e)}, using mock data instead")
        return get_mock_jetson_info()


def is_valid_hostname(hostname):
    """
    Validate hostname format according to RFC 1123 and RFC 952:
    - Can contain alphanumeric characters and hyphens
    - Cannot start or end with a hyphen
    - Maximum length of 63 characters
    """
    if not hostname or len(hostname) > 63:
        return False

    # Regex: start with alnum, then up to 61 alnum-or-hyphens, end with alnum
    pattern = r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
    return bool(re.match(pattern, hostname))


def set_hostname(new_hostname):
    try:
        if not is_valid_hostname(new_hostname):
            return {
                "success": False,
                "message": "Invalid hostname format. Hostname must contain only alphanumeric characters and hyphens, cannot start or end with a hyphen, and must be 63 characters or less."
            }
        old_hostname = platform.node()
        try:
            subprocess.run(["hostnamectl", "set-hostname", new_hostname], check=True)
            return {
                "success": True,
                "message": f"Hostname changed from {old_hostname} to {new_hostname}. A system reboot is required for the change to take effect."
            }
        except subprocess.CalledProcessError as e:
            return {
                "success": False,
                "message": f"Failed to set hostname: {str(e)}"
            }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to change hostname: {str(e)}"
        }

'''
Example usage:
curl -X GET http://localhost:3004/info | jq
'''
@app.route('/info', methods=['GET'])
def jetson_info():
    try:
        data = get_jetson_info()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

'''
Example usage:
curl -X POST http://localhost:3004/hostname -H "Content-Type: application/json" -d '{"hostname":"new-hostname"}'
'''
@app.route('/hostname', methods=['POST'])
def update_hostname():
    try:
        data = request.get_json()

        if not data or 'hostname' not in data:
            return jsonify({
                "success": False,
                "message": "Missing hostname parameter"
            }), 400

        new_hostname = data['hostname']
        result = set_hostname(new_hostname)

        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error: {str(e)}"
        }), 500


if __name__ == '__main__':
    host = '127.0.0.1'
    port = 3004
    print(f"Starting Jetson System Manager on {host}:{port}")
    app.run(host=host, port=port, threaded=True)
