from jtop import jtop

with jtop() as jetson:
    if jetson.ok():

        print("jetson.engine")
        print(jetson.engine)
        print("\n")

        print("jetson.board")
        print(jetson.board)
        print("\n")

        print("jetson.fan")
        print(jetson.fan)
        print("\n")

        print("jetson.nvpmodel")
        print(jetson.nvpmodel)
        print("\n")

        print("jetson.jetson_clocks")
        print(jetson.jetson_clocks)
        print("\n")

        print("jetson.stats")
        print(jetson.stats)
        print("\n")

        print("jetson.memory")
        print(jetson.memory)
        print("\n")

        print("jetson.cpu")
        print(jetson.cpu)
        print("\n")

        print("jetson.processes")
        print(jetson.processes)
        print("\n")

        print("jetson.gpu")
        print(jetson.gpu)
        print("\n")

        print("jetson.power")
        print(jetson.power)
        print("\n")

        print("jetson.temperature")
        print(jetson.temperature)
        print("\n")

        print("jetson.local_interfaces")
        print(jetson.local_interfaces)
        print("\n")

        print("jetson.disk")
        print(jetson.disk)
        print("\n")

        print("jetson.uptime")
        print(jetson.uptime)
        print("\n")

        print("jetson.interval")
        print(jetson.interval)
        print("\n")


## We want to publish this data via the API

## Hardware
# jetson.board.hardware.model
# jetson.board.hardware.module
# jetson.board.hardware.serial number
# jetson.board.hardware.L4T
# jetson.board.hardware.Jetpack

## Platform
# jetson.board.platform.distribution
# jetson.board.platform.release
# jetson.board.platform.python

## Libraries
# jetson.board.libraries.cuda
# jetson.board.libraries.opencv
# jetson.board.libraries.opencv-cuda
# jetson.board.libraries.cuDNN
# jetson.board.libraries.TensorRT
# jetson.board.libraries.VPI
# jetson.board.libraries.Vulkan

## Power
# jetson.nvpmodel
# jetson.jetson_clocks
# jetson.power.tot
# jetson.temperature.cpu
# jetson.temperature.gpu
# jetson.temperature.tj

## Interfaces
# jetson.local_interfaces.hostname
# jetson.local_interfaces.interfaces

## Disk
# jetson.disk.total
# jetson.disk.used
# jetson.disk.available




#### Example output below. We want to provide the data via the API in JSON format.


# jetson.engine
# {'APE': {'APE': {'online': False, 'cur': 200000}}, 'NVDEC': {'NVDEC': {'online': False, 'cur': 524800}}, 'NVJPG': {'NVJPG': {'online': False, 'cur': 499200}, 'NVJPG1': {'online': False, 'cur': 499200}}, 'OFA': {'OFA': {'online': False, 'cur': 537600}}, 'SE': {'SE': {'online': False, 'cur': 307200}}, 'VIC': {'VIC': {'online': False, 'cur': 435200}}}


# jetson.board
# {'hardware': {'Model': 'NVIDIA Jetson Orin Nano Engineering Reference Developer Kit Super', '699-level Part Number': '699-13767-0004-300 N.2', 'P-Number': 'p3767-0004', 'Module': 'NVIDIA Jetson Orin Nano (4GB ram)', 'SoC': 'tegra234', 'CUDA Arch BIN': '8.7', 'Serial Number': '1421123049835', 'L4T': '36.4.3', 'Jetpack': '6.2'}, 'platform': {'Machine': 'aarch64', 'System': 'Linux', 'Distribution': 'Ubuntu 22.04 Jammy Jellyfish', 'Release': '5.15.148-tegra', 'Python': '3.10.12'}, 'libraries': {'CUDA': '12.6.68', 'OpenCV': '4.8.0', 'OpenCV-Cuda': False, 'cuDNN': '9.3.0.75', 'TensorRT': '10.3.0.30', 'VPI': '3.2.4', 'Vulkan': '1.3.204'}}


# jetson.fan
# {'pwmfan': {'speed': [26.274509803921568], 'rpm': [1145], 'profile': 'quiet', 'governor': 'cont', 'control': 'close_loop'}}


# jetson.nvpmodel
# 25W


# jetson.jetson_clocks
# False


# jetson.stats
# {'time': datetime.datetime(2025, 4, 16, 23, 6, 5, 398586), 'uptime': datetime.timedelta(seconds=931, microseconds=410000), 'CPU1': 18, 'CPU2': 39, 'CPU3': 9, 'CPU4': 9, 'CPU5': 5, 'CPU6': 3, 'RAM': 0.4574121443512036, 'SWAP': 0.0, 'EMC': 0, 'GPU': 4.8, 'APE': 'OFF', 'NVDEC': 'OFF', 'NVJPG': 'OFF', 'NVJPG1': 'OFF', 'OFA': 'OFF', 'SE': 'OFF', 'VIC': 'OFF', 'Fan pwmfan0': 26.274509803921568, 'Temp cpu': 46.062, 'Temp cv0': -256, 'Temp cv1': -256, 'Temp cv2': -256, 'Temp gpu': 46.406, 'Temp soc0': 45.875, 'Temp soc1': 47.906, 'Temp soc2': 45.25, 'Temp tj': 47.906, 'Power VDD_CPU_GPU_CV': 1064, 'Power VDD_SOC': 1540, 'Power TOT': 5133, 'jetson_clocks': 'OFF', 'nvp model': '25W'}


# jetson.memory
# {'RAM': {'tot': 3688892, 'used': 1687344, 'free': 737636, 'buffers': 99660, 'cached': 1258132, 'shared': 36904, 'lfb': 28}, 'SWAP': {'tot': 1844424, 'used': 0, 'cached': 0, 'table': {'/dev/zram0': {'type': 'zram', 'prio': 5, 'size': 307404, 'used': 0, 'boot': False}, '/dev/zram1': {'type': 'zram', 'prio': 5, 'size': 307404, 'used': 0, 'boot': False}, '/dev/zram2': {'type': 'zram', 'prio': 5, 'size': 307404, 'used': 0, 'boot': False}, '/dev/zram3': {'type': 'zram', 'prio': 5, 'size': 307404, 'used': 0, 'boot': False}, '/dev/zram4': {'type': 'zram', 'prio': 5, 'size': 307404, 'used': 0, 'boot': False}, '/dev/zram5': {'type': 'zram', 'prio': 5, 'size': 307404, 'used': 0, 'boot': False}}}, 'EMC': {'cur': 2133000, 'max': 3199000, 'min': 204000, 'override': 0, 'val': 0, 'online': True}}


# jetson.cpu
# {'total': {'user': 3.314632497861299, 'nice': 0.0, 'system': 2.113178653634374, 'idle': 93.61272728132076}, 'cpu': [{'online': True, 'governor': 'schedutil', 'freq': {'min': 729600, 'max': 1728000, 'cur': 1344000}, 'info_freq': {'min': 115200, 'max': 1728000, 'cur': 1344000}, 'idle_state': {'WFI': 0, 'c7': 0}, 'model': 'ARMv8 Processor rev 1 (v8l)', 'user': 8.24742268041237, 'nice': 0.0, 'system': 6.185567010309279, 'idle': 82.4742268041237}, {'online': True, 'governor': 'schedutil', 'freq': {'min': 729600, 'max': 1728000, 'cur': 1344000}, 'info_freq': {'min': 115200, 'max': 1728000, 'cur': 1344000}, 'idle_state': {'WFI': 0, 'c7': 0}, 'model': 'ARMv8 Processor rev 1 (v8l)', 'user': 25.252525252525253, 'nice': 0.0, 'system': 12.121212121212121, 'idle': 61.61616161616161}, {'online': True, 'governor': 'schedutil', 'freq': {'min': 729600, 'max': 1728000, 'cur': 1344000}, 'info_freq': {'min': 115200, 'max': 1728000, 'cur': 1344000}, 'idle_state': {'WFI': 0, 'c7': 0}, 'model': 'ARMv8 Processor rev 1 (v8l)', 'user': 5.1020408163265305, 'nice': 0.0, 'system': 1.0204081632653061, 'idle': 91.83673469387756}, {'online': True, 'governor': 'schedutil', 'freq': {'min': 729600, 'max': 1728000, 'cur': 1344000}, 'info_freq': {'min': 115200, 'max': 1728000, 'cur': 1344000}, 'idle_state': {'WFI': 0, 'c7': 0}, 'model': 'ARMv8 Processor rev 1 (v8l)', 'user': 5.1020408163265305, 'nice': 0.0, 'system': 2.0408163265306123, 'idle': 91.83673469387756}, {'online': True, 'governor': 'schedutil', 'freq': {'min': 729600, 'max': 1728000, 'cur': 729600}, 'info_freq': {'min': 115200, 'max': 1728000, 'cur': 729600}, 'idle_state': {'WFI': 0, 'c7': 0}, 'model': 'ARMv8 Processor rev 1 (v8l)', 'user': 1.0204081632653061, 'nice': 0.0, 'system': 3.061224489795918, 'idle': 95.91836734693877}, {'online': True, 'governor': 'schedutil', 'freq': {'min': 729600, 'max': 1728000, 'cur': 729600}, 'info_freq': {'min': 115200, 'max': 1728000, 'cur': 729600}, 'idle_state': {'WFI': 0, 'c7': 0}, 'model': 'ARMv8 Processor rev 1 (v8l)', 'user': 0.0, 'nice': 0.0, 'system': 3.0, 'idle': 97.0}]}


# jetson.processes
# [[10764, 'jetson', 'I', 'Graphic', 20, 'R', 12.0, 4368, 0, 'vulkaninfo'], [2646, 'jetson', 'I', 'Graphic', 20, 'S', 0.14593894704501065, 41188, 3816, 'gnome-initial-s'], [2564, 'jetson', 'I', 'Graphic', 20, 'S', 0.028517214526230357, 11372, 320, 'xdg-desktop-por'], [1907, 'jetson', 'I', 'Graphic', 20, 'S', 0.528509995732528, 50308, 5704, 'gnome-shell'], [1358, 'jetson', 'I', 'Graphic', 20, 'S', 0.0556914475408404, 15643, 27064, 'Xorg']]


# jetson.gpu
# {'gpu': {'type': 'integrated', 'status': {'railgate': False, 'tpc_pg_mask': False, '3d_scaling': True, 'load': 4.8}, 'freq': {'governor': 'nvhost_podgov', 'cur': 306000, 'max': 1020000, 'min': 306000, 'GPC': [305981]}, 'power_control': 'auto'}}


# jetson.power
# {'rail': {'VDD_CPU_GPU_CV': {'volt': 4928, 'curr': 216, 'warn': 32760, 'crit': 32760, 'power': 1064, 'online': True, 'avg': 806}, 'VDD_SOC': {'volt': 4936, 'curr': 312, 'warn': 32760, 'crit': 32760, 'power': 1540, 'online': True, 'avg': 1524}}, 'tot': {'volt': 4936, 'curr': 1040, 'warn': 5232, 'crit': 5232, 'power': 5133, 'online': True, 'avg': 4800, 'name': 'VDD_IN'}}


# jetson.temperature
# {'cpu': {'temp': 46.062, 'online': True}, 'cv0': {'temp': -256, 'online': False}, 'cv1': {'temp': -256, 'online': False}, 'cv2': {'temp': -256, 'online': False}, 'gpu': {'temp': 46.406, 'online': True}, 'soc0': {'temp': 45.875, 'online': True}, 'soc1': {'temp': 47.906, 'online': True}, 'soc2': {'temp': 45.25, 'online': True}, 'tj': {'temp': 47.906, 'online': True}}


# jetson.local_interfaces
# {'hostname': 'jetson', 'interfaces': {'wlP1p1s0': '192.168.0.33'}}


# jetson.disk
# {'total': 232.2406234741211, 'used': 25.741069793701172, 'available': 206.49955368041992, 'available_no_root': 194.63290405273438, 'unit': 'G'}


# jetson.uptime
# 0:15:31.410000


# jetson.interval
# 1.0
