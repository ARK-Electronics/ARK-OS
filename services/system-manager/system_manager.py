#!/usr/bin/env python3
"""ARK-OS System Manager — FastAPI service exposing device system information.

The HTTP contract is the pydantic models below (SystemInfo, HostnameRequest, ...).
get_system_info() CONSTRUCTS a SystemInfo, so the type checker (`mypy`, run from
the CLI or CI) rejects any drift between the producer and the contract before the
service ever runs on a device. FastAPI generates the OpenAPI spec from the same
models (served at /openapi.json, Swagger UI at /docs).
"""

from typing import Any

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field
import platform
import os
import psutil
import subprocess
import re
import socket
import threading
import atexit
import time
import uvicorn


# ── HTTP contract: the single source of truth ────────────────────────────────

class Hardware(BaseModel):
    model: str
    module: str
    serial_number: str
    l4t: str
    jetpack: str
    type: str | None = None  # only populated on Jetson


class Platform(BaseModel):
    distribution: str
    release: str
    kernel: str
    python: str
    architecture: str


class Libraries(BaseModel):
    cuda: str
    opencv: str
    opencv_cuda: bool
    cudnn: str
    tensorrt: str
    vpi: str
    vulkan: str


class Power(BaseModel):
    nvpmodel: str
    jetson_clocks: str | None
    total: float
    temperature: dict[str, float] = Field(default_factory=dict)
    # Optional rail measurements (Modalix INA238); volts / amps when known
    voltage: float | None = None
    current: float | None = None


class Usage(BaseModel):
    total: float
    used: float
    available: float
    percent: float


class DiskVolume(BaseModel):
    """One physical disk or mounted volume for the Memory/storage card."""
    name: str          # short label, e.g. eMMC, NVMe, mmcblk0
    device: str        # /dev/mmcblk0 or /dev/nvme0n1
    mountpoint: str    # e.g. / or empty if not mounted
    total: float       # GiB
    used: float
    available: float
    percent: float
    model: str = ""    # optional drive model string


class Resources(BaseModel):
    memory: Usage
    disk: Usage  # root filesystem (backward compatible)
    disks: list[DiskVolume] = Field(default_factory=list)
    cpu_count: int


class Network(BaseModel):
    hostname: str
    interfaces: dict[str, str] = Field(default_factory=dict)


class SystemInfo(BaseModel):
    device_type: str
    hardware: Hardware
    platform: Platform
    libraries: Libraries
    power: Power
    resources: Resources
    network: Network
    temperature: dict[str, float] = Field(default_factory=dict)
    interfaces: Network  # backward-compat alias for `network`


class HostnameRequest(BaseModel):
    # The acceptable input is enforced by the type itself: a malformed hostname
    # is rejected at the boundary (422) before any handler code runs.
    hostname: str = Field(
        max_length=63,
        pattern=r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
    )


class MessageResponse(BaseModel):
    success: bool
    message: str


app = FastAPI(title="ARK-OS System Manager", version="1.0.0")


# ── System information collectors (loose dicts in, typed model out) ───────────

class SystemInfoCollector:
    """Base class for system information collection"""

    @staticmethod
    def get_common_info() -> dict[str, Any]:
        """Get system information common to all devices"""
        # Sample each source once; virtual_memory()/disk_usage() each shell into
        # the kernel, so calling them per-field was four redundant probes apiece.
        vm = psutil.virtual_memory()
        du = psutil.disk_usage('/')
        info: dict[str, Any] = {
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "total": vm.total / (1024**3),  # GB
                "used": vm.used / (1024**3),
                "available": vm.available / (1024**3),
                "percent": vm.percent
            },
            "disk": {
                "total": du.total / (1024**3),
                "used": du.used / (1024**3),
                "available": du.free / (1024**3),
                "percent": du.percent
            },
            "disks": SystemInfoCollector.get_disk_volumes(),
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
                os_info: dict[str, str] = {}
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
    def _parent_disk(dev: str) -> str:
        """/dev/mmcblk0p4 -> mmcblk0; /dev/nvme0n1p1 -> nvme0n1; /dev/sda1 -> sda."""
        base = os.path.basename(dev)
        if base.startswith("nvme") and "p" in base[4:]:
            return re.sub(r"p\d+$", "", base)
        if re.match(r".*p\d+$", base) and (
            base.startswith("mmcblk") or base.startswith("sd") or base.startswith("vd")
        ):
            return re.sub(r"p\d+$", "", base)
        m = re.match(r"^(sd[a-z]+|vd[a-z]+|hd[a-z]+)\d+$", base)
        if m:
            return m.group(1)
        return base

    @staticmethod
    def _disk_label(disk: str, model: str = "") -> str:
        if disk.startswith("mmcblk"):
            return "eMMC" if not model else f"eMMC ({model})"
        if disk.startswith("nvme"):
            return "NVMe" if not model else f"NVMe ({model.strip()})"
        if disk.startswith("sd") or disk.startswith("vd"):
            return model.strip() if model.strip() else disk
        return disk

    @staticmethod
    def get_disk_volumes() -> list[dict[str, Any]]:
        """List physical disks: root usage + any other whole disks (e.g. unmounted NVMe)."""
        gib = 1024.0 ** 3
        # parent_disk -> aggregated stats
        by_disk: dict[str, dict[str, Any]] = {}

        # Mounted real filesystems
        try:
            partitions = psutil.disk_partitions(all=False)
        except Exception:
            partitions = []

        for part in partitions:
            dev = part.device or ""
            if not dev.startswith("/dev/"):
                continue
            if any(
                x in dev
                for x in ("/loop", "/ram", "/zram", "/dm-", "/mapper/")
            ):
                continue
            fstype = (part.fstype or "").lower()
            if fstype in ("", "tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs"):
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except OSError:
                continue
            parent = SystemInfoCollector._parent_disk(dev)
            entry = by_disk.setdefault(
                parent,
                {
                    "name": parent,
                    "device": f"/dev/{parent}",
                    "mountpoint": "",
                    "total": 0.0,
                    "used": 0.0,
                    "available": 0.0,
                    "percent": 0.0,
                    "model": "",
                    "_root_usage": None,
                },
            )
            # Prefer filesystem stats from "/" for the root disk
            if part.mountpoint == "/":
                entry["mountpoint"] = "/"
                entry["_root_usage"] = usage
            elif not entry["mountpoint"]:
                entry["mountpoint"] = part.mountpoint
                if entry["_root_usage"] is None:
                    entry["_root_usage"] = usage

        # Whole-disk sizes from sysfs (covers unmounted NVMe etc.)
        sys_block = "/sys/block"
        try:
            block_devs = os.listdir(sys_block)
        except OSError:
            block_devs = []

        for disk in sorted(block_devs):
            if disk.startswith(("loop", "ram", "zram", "dm-", "sr", "fd")):
                continue
            if "boot" in disk:  # mmcblk0boot0
                continue
            size_path = f"{sys_block}/{disk}/size"
            try:
                with open(size_path, "r") as f:
                    sectors = int(f.read().strip())
            except (OSError, ValueError):
                continue
            total_gib = (sectors * 512) / gib
            if total_gib < 0.1:
                continue

            model = ""
            for mp in (
                f"{sys_block}/{disk}/device/model",
                f"{sys_block}/{disk}/device/name",
            ):
                try:
                    with open(mp, "r") as f:
                        model = f.read().strip()
                    if model:
                        break
                except OSError:
                    pass

            if disk not in by_disk:
                by_disk[disk] = {
                    "name": disk,
                    "device": f"/dev/{disk}",
                    "mountpoint": "",
                    "total": total_gib,
                    "used": 0.0,
                    "available": total_gib,
                    "percent": 0.0,
                    "model": model,
                    "_root_usage": None,
                }
            else:
                by_disk[disk]["total"] = total_gib
                by_disk[disk]["model"] = model or by_disk[disk].get("model", "")

        # Build sorted list: root disk first, then others by name
        volumes: list[dict[str, Any]] = []
        for disk, e in by_disk.items():
            total = float(e.get("total") or 0)
            usage = e.get("_root_usage")
            if usage is not None:
                # Show the mounted filesystem usage (root partition on eMMC)
                used = usage.used / gib
                avail = usage.free / gib
                # Keep device capacity as total when larger (whole eMMC)
                fs_total = usage.total / gib
                if total < fs_total:
                    total = fs_total
                pct = float(usage.percent)
                mount = e.get("mountpoint") or ""
            else:
                # Unmounted whole disk (e.g. NVMe with old partition table)
                used = 0.0
                avail = total
                pct = 0.0
                mount = ""
            if total <= 0:
                continue
            volumes.append(
                {
                    "name": SystemInfoCollector._disk_label(disk, e.get("model", "")),
                    "device": e["device"],
                    "mountpoint": mount,
                    "total": total,
                    "used": used,
                    "available": avail,
                    "percent": pct,
                    "model": e.get("model") or "",
                }
            )

        def sort_key(v: dict[str, Any]) -> tuple:
            # Root-bearing disk first
            is_root = 0 if v.get("mountpoint") == "/" else 1
            return (is_root, v.get("device") or "")

        volumes.sort(key=sort_key)
        return volumes

    @staticmethod
    def get_temperature_info() -> dict[str, Any]:
        """Try to get CPU temperature from various sources"""
        temp_info: dict[str, Any] = {}

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


class JtopManager:
    _RECONNECT_COOLDOWN = 10  # seconds

    def __init__(self):
        self._lock = threading.Lock()
        self._jetson = None
        self._available = None  # None=unknown, True/False=determined
        self._last_attempt = 0.0

    def _start_instance(self):
        try:
            from jtop import jtop
            instance = jtop()
            instance.start()
            self._jetson = instance
            self._available = True
            return True
        except (ImportError, ModuleNotFoundError):
            self._available = False
            return False
        except Exception as e:
            print(f"Failed to start jtop: {e}")
            return False

    def get_instance(self):
        if self._available is False:
            return None
        with self._lock:
            if self._available is False:
                return None
            if self._jetson is not None:
                if self._jetson.is_alive():
                    return self._jetson
                print("jtop instance died, attempting reconnect...")
                try:
                    self._jetson.close()
                except Exception:
                    pass
                self._jetson = None
            now = time.monotonic()
            if now - self._last_attempt < self._RECONNECT_COOLDOWN:
                return None
            self._last_attempt = now
            if self._start_instance():
                return self._jetson
            return None

    def shutdown(self):
        with self._lock:
            if self._jetson is not None:
                try:
                    self._jetson.close()
                except Exception:
                    pass
                self._jetson = None


_jtop_manager = JtopManager()
atexit.register(_jtop_manager.shutdown)


class JetsonCollector(SystemInfoCollector):
    """Collector for NVIDIA Jetson devices"""

    @staticmethod
    def is_jetson() -> bool:
        """Check if running on an NVIDIA Jetson (not ARK JAJ + Modalix).

        Note: the carrier product name "Just a Jetson" also contains "jetson";
        require NVIDIA/Tegra identity so Modalix eLxr is not mis-detected.
        """
        if os.path.isfile("/etc/nv_tegra_release"):
            return True
        try:
            with open("/proc/device-tree/compatible", "r") as f:
                compat = f.read().lower()
            if "simaai" in compat or "modalix" in compat:
                return False
            if "nvidia" in compat or "tegra" in compat:
                return True
        except OSError:
            pass
        try:
            with open("/proc/device-tree/model", "r") as f:
                model = f.read().lower()
            if "modalix" in model or "simaai" in model:
                return False
            # Do not match bare "jetson" (carrier product name on Modalix JAJ)
            return "nvidia" in model or "tegra" in model
        except OSError:
            return False

    @staticmethod
    def get_jetson_info() -> dict[str, Any] | None:
        """Get Jetson-specific information using jtop"""
        try:
            jetson = _jtop_manager.get_instance()
            if jetson is None:
                return None

            if not jetson.ok(spin=True):
                return None

            # Collect all temperature data
            temperatures: dict[str, Any] = {}
            if hasattr(jetson, 'temperature') and jetson.temperature:
                for sensor_name, sensor_data in jetson.temperature.items():
                    # Only include online sensors with valid temperatures
                    if isinstance(sensor_data, dict):
                        temp = sensor_data.get('temp', 0)
                        online = sensor_data.get('online', False)
                        # Include if online and temperature is valid (not -256)
                        if online and temp > -100:
                            temperatures[sensor_name] = temp
                    elif isinstance(sensor_data, (int, float)):
                        # Handle case where it might just be a number
                        if sensor_data > -100:
                            temperatures[sensor_name] = sensor_data

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
                    "temperature": temperatures  # Use all collected temperatures
                }
            }

            return data
        except Exception as e:
            print(f"Error collecting Jetson data: {e}")
            return None


class RaspberryPiCollector(SystemInfoCollector):
    """Collector for Raspberry Pi devices"""

    @staticmethod
    def is_raspberry_pi() -> bool:
        """Check if running on a Raspberry Pi"""
        try:
            with open('/proc/device-tree/model', 'r') as f:
                model = f.read().lower()
                return 'raspberry pi' in model
        except:
            return False

    @staticmethod
    def get_pi_info() -> dict[str, Any]:
        """Get Raspberry Pi specific information"""
        info: dict[str, Any] = {}

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
    def get_info() -> dict[str, Any]:
        """Get generic Linux system information"""
        info: dict[str, Any] = {
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


class ModalixCollector(SystemInfoCollector):
    """Collector for SiMa Modalix (eLxr) on ARK Just a Jetson / Modalix carriers."""

    _POWER_DIR = "/run/ark-jaj/sys-power"
    _BOARD_DIR = "/run/ark-jaj/board"

    @staticmethod
    def is_modalix() -> bool:
        """Detect Modalix SoM / eLxr (not Jetson, not Pi)."""
        try:
            if os.path.isfile("/etc/os-release"):
                with open("/etc/os-release", "r") as f:
                    osrel = f.read()
                if re.search(r"^ID=elxr\b", osrel, re.M) or "elxr" in osrel.lower():
                    return True
        except OSError:
            pass
        try:
            with open("/proc/device-tree/model", "r") as f:
                model = f.read().lower()
            if "modalix" in model:
                return True
            # ARK JAJ carrier with Modalix still says "Just a Jetson" in model
            if "just a jetson" in model and "nvidia" not in model:
                # Prefer compatible string to avoid false positives
                try:
                    with open("/proc/device-tree/compatible", "r") as f:
                        compat = f.read().lower()
                    if "modalix" in compat or "simaai" in compat:
                        return True
                except OSError:
                    pass
        except OSError:
            pass
        try:
            with open("/proc/device-tree/compatible", "r") as f:
                compat = f.read().lower()
            if "modalix" in compat or "simaai,modalix" in compat:
                return True
        except OSError:
            pass
        return False

    @staticmethod
    def _read_dt_string(path: str) -> str | None:
        """First NUL-terminated string (model is a single string)."""
        try:
            with open(path, "rb") as f:
                return f.read().split(b"\x00")[0].decode("utf-8", errors="replace").strip()
        except OSError:
            return None

    @staticmethod
    def _read_dt_strings(path: str) -> list[str]:
        """All NUL-separated strings (compatible is a list)."""
        try:
            with open(path, "rb") as f:
                raw = f.read()
            return [
                p.decode("utf-8", errors="replace").strip()
                for p in raw.split(b"\x00")
                if p.strip()
            ]
        except OSError:
            return []

    @staticmethod
    def _read_file(path: str) -> str | None:
        try:
            with open(path, "r") as f:
                return f.read().strip()
        except OSError:
            return None

    @staticmethod
    def _read_at24csw_unique_id(bus_num: int) -> str | None:
        """128-bit factory ID from AT24CSW010 security window (addr 0x58, word 0x80).

        Modalix SoM has no /proc/device-tree/serial-number; the on-module 24c128
        is blank. Carrier EEPROM is I2C1 (PAB V3 / JAJ). Same protocol as
        platform/jetson/scripts/jetson_serial_number.py (bus 7 on Jetson).
        """
        try:
            from smbus2 import SMBus
        except ImportError:
            return None
        try:
            bus = SMBus(bus_num)
            try:
                bus.write_byte(0x58, 0x80)
                data = bus.read_i2c_block_data(0x58, 0x80, 16)
            finally:
                bus.close()
        except OSError:
            return None
        if not data or len(data) < 16:
            return None
        if all(b == 0xFF for b in data) or all(b == 0 for b in data):
            return None
        return "".join(f"{b:02x}" for b in data)

    @classmethod
    def get_modalix_info(cls) -> dict[str, Any]:
        """Model/module/serial from DT + AT24CSW unique ID; power from INA238 publisher."""
        model = cls._read_dt_string("/proc/device-tree/model") or "Modalix"
        compat_list = cls._read_dt_strings("/proc/device-tree/compatible")

        # Module: prefer SoM token from compatible (e.g. simaai,modalix-som)
        module = "Modalix SoM"
        for p in compat_list:
            if "modalix-som" in p:
                module = p  # e.g. simaai,modalix-som
                break
            if p.startswith("simaai,") and "modalix" in p:
                module = p

        # Serial: carrier AT24CSW unique ID (PAB V3 / JAJ I2C1). Optional
        # ark-jaj-sys-power publisher, then live I2C, then DT (usually absent).
        serial = (
            cls._read_file(f"{cls._BOARD_DIR}/unique_id")
            or cls._read_file(f"{cls._BOARD_DIR}/unique_id_text")
            or cls._read_at24csw_unique_id(1)
            or cls._read_at24csw_unique_id(7)
            or cls._read_dt_string("/proc/device-tree/serial-number")
            or "Not available"
        )

        # Power: /run/ark-jaj/sys-power from INA238 userspace (or future hwmon)
        # Frontend expects power.total in milliwatts (Jetson jtop convention).
        power_total_mw = 0.0
        voltage_V: float | None = None
        current_A: float | None = None

        def _num(s: str | None) -> float | None:
            if s is None:
                return None
            s = s.strip()
            try:
                return float(s)
            except ValueError:
                return None

        power_uW = _num(cls._read_file(f"{cls._POWER_DIR}/power_uW"))
        voltage_uV = _num(cls._read_file(f"{cls._POWER_DIR}/voltage_uV"))
        current_uA = _num(cls._read_file(f"{cls._POWER_DIR}/current_uA"))
        if power_uW is not None:
            power_total_mw = power_uW / 1000.0
        if voltage_uV is not None:
            voltage_V = voltage_uV / 1e6
        if current_uA is not None:
            current_A = current_uA / 1e6

        if power_uW is None and voltage_V is None:
            # Fallback: in-kernel hwmon ina238 (power1 µW, in1 mV, curr1 mA)
            try:
                for name in os.listdir("/sys/class/hwmon"):
                    base = f"/sys/class/hwmon/{name}"
                    hwname = (cls._read_file(f"{base}/name") or "").lower()
                    if hwname not in ("ina238", "ina2xx"):
                        continue
                    pw = _num(cls._read_file(f"{base}/power1_input"))
                    if pw is not None:
                        power_total_mw = pw / 1000.0
                    vin = _num(cls._read_file(f"{base}/in1_input"))
                    if vin is not None:
                        voltage_V = vin / 1000.0  # mV → V
                    cur = _num(cls._read_file(f"{base}/curr1_input"))
                    if cur is not None:
                        current_A = cur / 1000.0  # mA → A
                    break
            except OSError:
                pass

        # Die temp from INA238 publisher if available (millidegC → °C)
        temperatures: dict[str, float] = {}
        temp_mC = _num(cls._read_file(f"{cls._POWER_DIR}/temp_mC"))
        if temp_mC is not None:
            temperatures["ina238"] = temp_mC / 1000.0

        return {
            "hardware": {
                "type": "modalix",
                "model": model,
                "module": module,
                "serial_number": serial,
            },
            "power": {
                "total": power_total_mw,
                "voltage": voltage_V,
                "current": current_A,
                "temperature": temperatures,
            },
        }


def get_system_info() -> SystemInfo:
    """Collect all system information as a validated SystemInfo model.

    The collectors above return loose dicts (device probes via psutil/jtop);
    this function is the typed boundary — it builds the SystemInfo explicitly,
    so the type checker verifies every field against the contract.
    """
    common = SystemInfoCollector.get_common_info()
    temp_info = SystemInfoCollector.get_temperature_info()

    # Device-agnostic defaults; device detection overrides these below.
    hardware = Hardware(
        model="Not available",
        module="Not available",
        serial_number="Not available",
        l4t="Not available",
        jetpack="Not available",
    )
    libraries = Libraries(
        cuda="Not available",
        opencv="Not available",
        opencv_cuda=False,
        cudnn="Not available",
        tensorrt="Not available",
        vpi="Not available",
        vulkan="Not available",
    )
    power = Power(
        nvpmodel="Not available",
        jetson_clocks="Not available",
        total=0,
        temperature={},
    )

    # Modalix first: carrier DT model may include "Just a Jetson" without NVIDIA.
    if ModalixCollector.is_modalix():
        device_type = "modalix"
        mx = ModalixCollector.get_modalix_info()
        hw = mx.get("hardware", {})
        hardware = Hardware(
            type=hw.get("type", "modalix"),
            model=hw.get("model", "Modalix"),
            module=hw.get("module", "Modalix SoM"),
            serial_number=hw.get("serial_number", "Not available"),
            l4t="",
            jetpack="",
        )
        libraries = Libraries(
            cuda="",
            opencv="",
            opencv_cuda=False,
            cudnn="",
            tensorrt="",
            vpi="",
            vulkan="",
        )
        pw = mx.get("power", {})
        power = Power(
            nvpmodel="",
            jetson_clocks=None,
            total=float(pw.get("total", 0) or 0),
            temperature=pw.get("temperature") or {},
            voltage=pw.get("voltage"),
            current=pw.get("current"),
        )
    elif JetsonCollector.is_jetson():
        device_type = "jetson"
        jetson_data = JetsonCollector.get_jetson_info()
        if jetson_data:
            hw = jetson_data.get("hardware", {})
            hardware = Hardware(
                type=hw.get("type", "jetson"),
                model=hw.get("model", "Not available"),
                module=hw.get("module", "Not available"),
                serial_number=hw.get("serial_number", "Not available"),
                l4t=hw.get("l4t", "Not available"),
                jetpack=hw.get("jetpack", "Not available"),
            )
            libs = jetson_data.get("libraries")
            if libs:
                libraries = Libraries(
                    cuda=libs.get("cuda", "Not available"),
                    opencv=libs.get("opencv", "Not available"),
                    opencv_cuda=libs.get("opencv_cuda", False),
                    cudnn=libs.get("cudnn", "Not available"),
                    tensorrt=libs.get("tensorrt", "Not available"),
                    vpi=libs.get("vpi", "Not available"),
                    vulkan=libs.get("vulkan", "Not available"),
                )
            pw = jetson_data.get("power")
            if pw:
                power = Power(
                    nvpmodel=pw.get("nvpmodel", "Unknown"),
                    jetson_clocks=pw.get("jetson_clocks"),
                    total=pw.get("total", 0),
                    temperature=pw.get("temperature", {}),
                )
    elif RaspberryPiCollector.is_raspberry_pi():
        device_type = "pi"
        pi_info = RaspberryPiCollector.get_pi_info()
        hardware = Hardware(
            model=pi_info.get("model", "Raspberry Pi"),
            module="Not available",
            serial_number=pi_info.get("serial_number", "Unknown"),
            l4t="",
            jetpack="",
        )
        libraries = Libraries(
            cuda="",
            opencv="",
            opencv_cuda=False,
            cudnn="",
            tensorrt="",
            vpi="",
            vulkan="",
        )
        power = Power(
            nvpmodel="",
            jetson_clocks=None,
            total=0,
            temperature={},
        )
    else:
        device_type = "generic"
        generic_info = GenericLinuxCollector.get_info()
        hardware = Hardware(
            model=generic_info.get("cpu_model", "Generic Linux System"),
            module="Not available",
            serial_number="Not available",
            l4t="",
            jetpack="",
        )
        libraries = Libraries(
            cuda="",
            opencv="",
            opencv_cuda=False,
            cudnn="",
            tensorrt="",
            vpi="",
            vulkan="",
        )
        power = Power(
            nvpmodel="",
            jetson_clocks=None,
            total=0,
            temperature={},
        )

    network = Network(
        hostname=common["hostname"],
        interfaces=common["network_interfaces"],
    )

    return SystemInfo(
        device_type=device_type,
        hardware=hardware,
        platform=Platform(
            distribution=common["distribution"],
            release=common["codename"],
            kernel=platform.release(),
            python=common["python_version"],
            architecture=common["architecture"],
        ),
        libraries=libraries,
        power=power,
        resources=Resources(
            memory=Usage(
                total=common["memory"]["total"],
                used=common["memory"]["used"],
                available=common["memory"]["available"],
                percent=common["memory"]["percent"],
            ),
            disk=Usage(
                total=common["disk"]["total"],
                used=common["disk"]["used"],
                available=common["disk"]["available"],
                percent=common["disk"]["percent"],
            ),
            disks=[
                DiskVolume(
                    name=d["name"],
                    device=d["device"],
                    mountpoint=d.get("mountpoint") or "",
                    total=float(d["total"]),
                    used=float(d["used"]),
                    available=float(d["available"]),
                    percent=float(d["percent"]),
                    model=d.get("model") or "",
                )
                for d in (common.get("disks") or [])
            ],
            cpu_count=common["cpu_count"],
        ),
        network=network,
        temperature=temp_info or {},
        interfaces=network,
    )


def is_valid_hostname(hostname: str) -> bool:
    """Validate hostname format according to RFC 1123 and RFC 952"""
    if not hostname or len(hostname) > 63:
        return False

    pattern = r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
    return bool(re.match(pattern, hostname))


def set_hostname(new_hostname: str) -> dict[str, Any]:
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


@app.get("/info")
def system_info() -> SystemInfo:
    """Get system information. The return type IS the response contract."""
    try:
        return get_system_info()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to collect system information: {e}")


@app.post("/hostname")
def update_hostname(body: HostnameRequest, response: Response) -> MessageResponse:
    """Set the system hostname. `body` is validated against HostnameRequest
    before this runs, so an invalid hostname never reaches here."""
    result = set_hostname(body.hostname)
    if not result["success"]:
        response.status_code = 400
    return MessageResponse(success=result["success"], message=result["message"])


if __name__ == '__main__':
    host = '127.0.0.1'
    port = int(os.environ.get("PORT", 3004))
    print(f"Starting System Manager on {host}:{port}")
    print("Device type detection in progress...")

    # Quick device detection for startup message
    if ModalixCollector.is_modalix():
        print("Detected: SiMa Modalix")
    elif JetsonCollector.is_jetson():
        print("Detected: NVIDIA Jetson")
    elif RaspberryPiCollector.is_raspberry_pi():
        print("Detected: Raspberry Pi")
    else:
        print("Detected: Generic Linux System")

    # access_log off: the UI polls /info.
    uvicorn.run(app, host=host, port=port, access_log=False)
