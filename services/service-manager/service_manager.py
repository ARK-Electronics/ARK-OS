#!/usr/bin/env python3
"""ARK-OS Service Manager — FastAPI service for managing ARK-OS systemd services.

The HTTP contract is the pydantic models below (ServiceList, ActionResponse, ...).
Every handler CONSTRUCTS its response model, so the type checker (`mypy`, run from
the CLI or CI) rejects any drift between the producer and the contract before the
service ever runs on a device. FastAPI generates the OpenAPI spec from the same
models (served at /openapi.json, Swagger UI at /docs).

Capabilities:
- Retrieving service statuses
- Starting and stopping services
- Enabling and disabling services
- Managing service configurations
- Viewing service logs
"""

import os
import json
import subprocess
import re

from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn


# ── HTTP contract: the single source of truth ────────────────────────────────

class ServiceStatus(BaseModel):
    name: str
    enabled: str
    active: str
    config_file: str
    visible: str  # "true"/"false" — the UI compares against the string


class ServiceList(BaseModel):
    services: list[ServiceStatus]


class ActionResponse(BaseModel):
    status: str  # "success" | "fail"
    service: str | None = None
    active: str | None = None
    enabled: str | None = None
    message: str | None = None


class LogsResponse(BaseModel):
    status: str
    service: str
    logs: str | None = None
    message: str | None = None


class ConfigResponse(BaseModel):
    status: str  # "success" | "fail"
    data: str


class SaveConfigRequest(BaseModel):
    config: str


app = FastAPI(title="ARK-OS Service Manager", version="1.0.0")

# The deb is the source of truth for what is installed: manifests are dropped at
# MANIFEST_DIR (one <svc>.manifest.json per <svc>.service), and the per-service
# configs the web UI edits live flat under CONFIG_DIR.
MANIFEST_DIR = "/usr/lib/ark-os/manifests"
CONFIG_DIR = "/etc/ark-os"

_ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub('', text)


class ServiceManager:

    @staticmethod
    def is_known_service(service_name: str) -> bool:
        """Only services the package installed a manifest for may be managed.

        Guards the systemctl / journalctl / config operations below against
        arbitrary unit names from the web UI. The Jetson polkit .pkla grant is not
        unit-scoped, so without this check a request could reach any system unit.
        """
        if not service_name or "/" in service_name or service_name in (".", ".."):
            return False
        manifest_file = os.path.join(MANIFEST_DIR, f"{service_name}.manifest.json")
        return os.path.isfile(manifest_file)

    @staticmethod
    def run_systemctl(operation: str, service_name: str) -> tuple[bool, str]:
        if not ServiceManager.is_known_service(service_name):
            return False, f"Unknown or unmanaged service: {service_name}"
        try:
            process = subprocess.run(
                ["systemctl", operation, service_name],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = strip_ansi(process.stdout + process.stderr).strip()

            if process.returncode == 0:
                return True, ""
            else:
                return False, output or f"Failed to {operation} service (exit code {process.returncode})"

        except Exception as e:
            return False, str(e)

    @staticmethod
    def get_service_status(service_name: str, status_type: str = "active") -> str:
        try:
            process = subprocess.run(
                ["systemctl", f"is-{status_type}", service_name],
                capture_output=True,
                text=True
            )

            return strip_ansi(process.stdout).strip() or process.stderr.strip()
        except Exception:
            return "unknown"

    @staticmethod
    def get_service_config_file(service_name: str) -> str:
        config_file_name = ""

        manifest_file = os.path.join(MANIFEST_DIR, f"{service_name}.manifest.json")
        if os.path.isfile(manifest_file):
            try:
                with open(manifest_file, 'r') as f:
                    manifest_data = json.load(f)
                    config_file_name = manifest_data.get("configFile", "") or ""
            except Exception as e:
                print(f"Error reading manifest file for {service_name}: {e}")

        return os.path.join(CONFIG_DIR, config_file_name)

    @staticmethod
    def is_service_visible(service_name: str) -> bool:
        manifest_file = os.path.join(MANIFEST_DIR, f"{service_name}.manifest.json")

        if os.path.isfile(manifest_file):
            try:
                with open(manifest_file, 'r') as f:
                    manifest_data = json.load(f)
                    return str(manifest_data.get("visible", True)).lower() == "true"
            except Exception:
                pass

        return True

    @staticmethod
    def get_service_statuses() -> ServiceList:
        services = []

        if not os.path.isdir(MANIFEST_DIR):
            return ServiceList(services=[])

        manifest_files = [f for f in os.listdir(MANIFEST_DIR) if f.endswith('.manifest.json')]

        for manifest_file in manifest_files:
            service_name = manifest_file[:-len('.manifest.json')]

            enabled_status = ServiceManager.get_service_status(service_name, "enabled")
            active_status = ServiceManager.get_service_status(service_name, "active")

            config_file = ServiceManager.get_service_config_file(service_name)
            config_file_name = os.path.basename(config_file) if os.path.isfile(config_file) else ""

            services.append(ServiceStatus(
                name=service_name,
                enabled=enabled_status,
                active=active_status,
                config_file=config_file_name,
                visible="true" if ServiceManager.is_service_visible(service_name) else "false",
            ))

        return ServiceList(services=services)

    @staticmethod
    def start_service(service_name: str) -> ActionResponse:
        success, message = ServiceManager.run_systemctl("start", service_name)

        if success:
            status = ServiceManager.get_service_status(service_name)
            if status == "active":
                return ActionResponse(status="success", service=service_name, active=status)
            else:
                return ActionResponse(status="fail", service=service_name,
                                      message=f"Service started but status is '{status}' instead of 'active'")
        else:
            return ActionResponse(status="fail", service=service_name, message=message)

    @staticmethod
    def stop_service(service_name: str) -> ActionResponse:
        success, message = ServiceManager.run_systemctl("stop", service_name)

        if success:
            status = ServiceManager.get_service_status(service_name)
            if status == "inactive":
                return ActionResponse(status="success", service=service_name, active=status)
            else:
                return ActionResponse(status="fail", service=service_name,
                                      message=f"Service stopped but status is '{status}' instead of 'inactive'")
        else:
            return ActionResponse(status="fail", service=service_name, message=message)

    @staticmethod
    def restart_service(service_name: str) -> ActionResponse:
        success, message = ServiceManager.run_systemctl("restart", service_name)

        if success:
            status = ServiceManager.get_service_status(service_name)
            return ActionResponse(status="success", service=service_name, active=status)
        else:
            return ActionResponse(status="fail", service=service_name, message=message)

    @staticmethod
    def enable_service(service_name: str) -> ActionResponse:
        success, message = ServiceManager.run_systemctl("enable", service_name)

        if success:
            return ActionResponse(status="success", service=service_name, enabled="enabled")
        else:
            return ActionResponse(status="fail", service=service_name, message=message)

    @staticmethod
    def disable_service(service_name: str) -> ActionResponse:
        success, message = ServiceManager.run_systemctl("disable", service_name)

        if success:
            return ActionResponse(status="success", service=service_name, enabled="disabled")
        else:
            return ActionResponse(status="fail", service=service_name, message=message)

    @staticmethod
    def get_logs(service_name: str, num_lines: int = 50) -> LogsResponse:
        if not ServiceManager.is_known_service(service_name):
            return LogsResponse(status="fail", service=service_name,
                                message=f"Unknown or unmanaged service: {service_name}")

        try:
            process = subprocess.run(
                ["journalctl", "-u", service_name, "-n", str(num_lines), "--no-pager", "-o", "cat"],
                capture_output=True,
                text=True,
                timeout=10
            )

            logs = strip_ansi(process.stdout).strip()

            return LogsResponse(status="success", service=service_name, logs=logs)
        except Exception as e:
            return LogsResponse(status="fail", service=service_name, message=str(e))

    @staticmethod
    def get_config(service_name: str) -> ConfigResponse:
        if not ServiceManager.is_known_service(service_name):
            return ConfigResponse(status="fail", data=f"Unknown or unmanaged service: {service_name}")

        config_file = ServiceManager.get_service_config_file(service_name)

        if not os.path.isfile(config_file):
            config_file_name = os.path.basename(config_file)
            service_dir = os.path.dirname(config_file)
            return ConfigResponse(status="fail", data=f"{config_file_name} not found in {service_dir}")

        try:
            with open(config_file, 'r') as f:
                return ConfigResponse(status="success", data=f.read())
        except Exception as e:
            return ConfigResponse(status="fail", data=f"Error reading config file: {str(e)}")

    @staticmethod
    def save_config(service_name: str, config_data: str) -> ConfigResponse:
        if not ServiceManager.is_known_service(service_name):
            return ConfigResponse(status="fail", data=f"Unknown or unmanaged service: {service_name}")

        config_file = ServiceManager.get_service_config_file(service_name)

        if not os.path.isfile(config_file):
            config_file_name = os.path.basename(config_file)
            service_dir = os.path.dirname(config_file)
            return ConfigResponse(status="fail", data=f"{config_file_name} not found in {service_dir}")

        try:
            with open(config_file, 'w') as f:
                f.write(config_data)
                return ConfigResponse(status="success", data="Configuration saved successfully")
        except Exception as e:
            return ConfigResponse(status="fail", data=f"Error saving config file: {str(e)}")


# ── API endpoints ─────────────────────────────────────────────────────────────
# `serviceName` is a required query parameter: a request without one is rejected
# at the boundary (422) before any handler code runs. Action results are always
# HTTP 200; the UI inspects the `status` field.

@app.get("/statuses")
def get_service_statuses() -> ServiceList:
    print("GET /statuses called")
    return ServiceManager.get_service_statuses()


@app.post("/start", response_model_exclude_none=True)
def start_service(serviceName: str) -> ActionResponse:
    print(f"POST /start called for {serviceName}")
    return ServiceManager.start_service(serviceName)


@app.post("/stop", response_model_exclude_none=True)
def stop_service(serviceName: str) -> ActionResponse:
    print(f"POST /stop called for {serviceName}")
    return ServiceManager.stop_service(serviceName)


@app.post("/restart", response_model_exclude_none=True)
def restart_service(serviceName: str) -> ActionResponse:
    print(f"POST /restart called for {serviceName}")
    return ServiceManager.restart_service(serviceName)


@app.post("/enable", response_model_exclude_none=True)
def enable_service(serviceName: str) -> ActionResponse:
    print(f"POST /enable called for {serviceName}")
    return ServiceManager.enable_service(serviceName)


@app.post("/disable", response_model_exclude_none=True)
def disable_service(serviceName: str) -> ActionResponse:
    print(f"POST /disable called for {serviceName}")
    return ServiceManager.disable_service(serviceName)


@app.get("/logs", response_model_exclude_none=True)
def get_service_logs(serviceName: str) -> LogsResponse:
    print(f"GET /logs called for {serviceName}")
    return ServiceManager.get_logs(serviceName)


@app.get("/config")
def get_service_config(serviceName: str) -> ConfigResponse:
    print(f"GET /config called for {serviceName}")
    return ServiceManager.get_config(serviceName)


@app.post("/config")
def save_service_config(serviceName: str, body: SaveConfigRequest) -> ConfigResponse:
    print(f"POST /config called for {serviceName}")

    if not body.config:
        return ConfigResponse(status="fail", data="No configuration data provided")

    return ServiceManager.save_config(serviceName, body.config)


if __name__ == '__main__':
    host = '127.0.0.1'
    port = int(os.environ.get("PORT", 3002))

    print(f"Starting Service Manager on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
