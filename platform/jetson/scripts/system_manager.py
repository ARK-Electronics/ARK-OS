from flask import Flask, jsonify
from jtop import jtop
import time

app = Flask(__name__)

def get_jetson_stats():
    with jtop() as jetson:
        if not jetson.ok():
            return {"error": "Failed to connect to Jetson device"}

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
