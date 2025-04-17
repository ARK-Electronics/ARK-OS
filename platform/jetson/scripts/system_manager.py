from flask import Flask, jsonify
import time
import random
import platform
import os
import psutil

app = Flask(__name__)

def get_mock_jetson_stats():
    """Generate mock Jetson data for testing on non-Jetson devices"""
    # Get some real system data where possible
    hostname = platform.node()
    python_version = platform.python_version()
    system_platform = f"{platform.system()} {platform.release()}"

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
            "model": "NVIDIA Jetson Mock Device",
            "module": "NVIDIA Jetson Nano (4GB ram)",
            "serial_number": "MOCK12345678",
            "l4t": "32.7.1",
            "jetpack": "4.6.1"
        },
        "platform": {
            "distribution": system_platform,
            "release": "dummy",
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

def get_jetson_stats():
    """Collect and return data from Jetson device or mock data if not available"""
    try:
        # Try to import jtop
        from jtop import jtop

        with jtop() as jetson:
            if not jetson.ok():
                print("Failed to connect to Jetson device, using mock data instead")
                return get_mock_jetson_stats()

            # Wait for data collection
            time.sleep(0.5)

            # Collect data specified in the requirements
            data = {
                "hardware": {
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
        return get_mock_jetson_stats()
    except Exception as e:
        print(f"Error: {str(e)}, using mock data instead")
        return get_mock_jetson_stats()

'''
Example usage:
curl -X GET http://localhost:3004/stats | jq
'''
@app.route('/stats', methods=['GET'])
def jetson_stats():
    try:
        data = get_jetson_stats()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    host = '127.0.0.1'
    port = 3004
    print(f"Starting Jetson System Manager on {host}:{port}")
    app.run(host=host, port=port, threaded=True)
