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
import logging
import asyncio
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import uvicorn


def setup_logging():
    """Setup simple logging that will be captured by journald via stdout"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )
    return logging.getLogger('service-manager')


logger = setup_logging()


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


class LogLine(BaseModel):
    """One journal entry pushed over the /logs/stream SSE channel."""
    ts: int | None = None  # epoch milliseconds (None if journald omitted it)
    priority: int = 6      # syslog severity 0..7; 6 = info, <=3 = error
    message: str


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


def parse_journal_line(raw: bytes) -> LogLine | None:
    """Turn one `journalctl -o json` line into a LogLine, or None if unusable.

    journald gives __REALTIME_TIMESTAMP as microseconds-since-epoch (a string),
    MESSAGE as a string or — for non-UTF-8 payloads — an array of byte values,
    and PRIORITY as a syslog level 0..7.
    """
    try:
        obj = json.loads(raw)
    except ValueError:
        return None

    if not isinstance(obj, dict):
        return None

    message = obj.get("MESSAGE")
    if isinstance(message, list):
        # journald encodes a non-UTF-8 message as an array of byte values.
        try:
            message = bytes(message).decode("utf-8", "replace")
        except (ValueError, TypeError):
            message = ""
    elif not isinstance(message, str):
        message = "" if message is None else str(message)

    ts: int | None
    try:
        ts = int(obj["__REALTIME_TIMESTAMP"]) // 1000
    except (KeyError, ValueError, TypeError):
        ts = None

    try:
        priority = int(obj.get("PRIORITY", 6))
    except (ValueError, TypeError):
        priority = 6

    return LogLine(ts=ts, priority=priority, message=strip_ansi(message))


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
                logger.error(f"Error reading manifest file for {service_name}: {e}")

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
    def _query_unit_states(service_names: list[str]) -> dict[str, tuple[str, str]]:
        """Return {service: (enabled_state, active_state)} for many units in a
        single `systemctl show` call.

        Replaces two `systemctl` spawns *per service*: with the UI polling
        /statuses at up to 1 Hz, that was ~2xN subprocess launches every second.
        UnitFileState/ActiveState carry the same vocabulary as is-enabled/
        is-active, so the values the UI sees are unchanged.
        """
        states: dict[str, tuple[str, str]] = {}
        if not service_names:
            return states

        units = [f"{name}.service" for name in service_names]
        try:
            process = subprocess.run(
                ["systemctl", "show", "-p", "Id", "-p", "UnitFileState", "-p", "ActiveState", *units],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception as e:
            logger.error(f"Error querying unit states: {e}")
            return states

        # One blank-line-separated block per unit, each a set of Key=Value lines.
        for block in process.stdout.strip().split("\n\n"):
            props: dict[str, str] = {}
            for line in block.splitlines():
                key, _, value = line.partition("=")
                props[key] = value
            unit_id = props.get("Id", "")
            if unit_id.endswith(".service"):
                name = unit_id[: -len(".service")]
                states[name] = (
                    props.get("UnitFileState") or "unknown",
                    props.get("ActiveState") or "unknown",
                )
        return states

    @staticmethod
    def get_service_statuses() -> ServiceList:
        services = []

        if not os.path.isdir(MANIFEST_DIR):
            return ServiceList(services=[])

        manifest_files = [f for f in os.listdir(MANIFEST_DIR) if f.endswith('.manifest.json')]
        service_names = [f[:-len('.manifest.json')] for f in manifest_files]

        # One batched systemctl call for all units instead of two spawns each.
        unit_states = ServiceManager._query_unit_states(service_names)

        for service_name in service_names:
            enabled_status, active_status = unit_states.get(service_name, ("unknown", "unknown"))

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
        # Clear any failed / start-limit-hit state first, so a unit that gave up
        # (e.g. mavlink-router hitting its StartLimit with no FC) starts from the UI.
        ServiceManager.run_systemctl("reset-failed", service_name)
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
    logger.debug("GET /statuses called")
    return ServiceManager.get_service_statuses()


@app.post("/start", response_model_exclude_none=True)
def start_service(serviceName: str) -> ActionResponse:
    logger.info(f"POST /start called for {serviceName}")
    return ServiceManager.start_service(serviceName)


@app.post("/stop", response_model_exclude_none=True)
def stop_service(serviceName: str) -> ActionResponse:
    logger.info(f"POST /stop called for {serviceName}")
    return ServiceManager.stop_service(serviceName)


@app.post("/restart", response_model_exclude_none=True)
def restart_service(serviceName: str) -> ActionResponse:
    logger.info(f"POST /restart called for {serviceName}")
    return ServiceManager.restart_service(serviceName)


@app.post("/enable", response_model_exclude_none=True)
def enable_service(serviceName: str) -> ActionResponse:
    logger.info(f"POST /enable called for {serviceName}")
    return ServiceManager.enable_service(serviceName)


@app.post("/disable", response_model_exclude_none=True)
def disable_service(serviceName: str) -> ActionResponse:
    logger.info(f"POST /disable called for {serviceName}")
    return ServiceManager.disable_service(serviceName)


@app.get("/logs/stream")
async def stream_service_logs(serviceName: str) -> StreamingResponse:
    """Server-Sent Events stream of a service's journal, tailing live.

    Runs `journalctl -u <svc> -b 0 -n 200 -f -o json` and pushes each entry as a
    `log_line` event (a LogLine: {ts, priority, message}). One-way server->client
    push, so it rides the same /api HTTP proxy chain as the REST endpoints — no
    websocket layer. The client appends each line and renders a timestamp column
    plus a severity colour, so there is no polling and no wholesale re-render.
    """
    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}

    # Guard the user-supplied unit name before it reaches journalctl (same gate
    # as every other systemctl/journalctl call). Can't return a 422 body the way
    # the REST routes do once we're a stream, so emit one error event and close.
    if not ServiceManager.is_known_service(serviceName):
        async def reject() -> AsyncIterator[str]:
            payload = json.dumps({"message": f"Unknown or unmanaged service: {serviceName}"})
            yield f"event: log_error\ndata: {payload}\n\n"

        return StreamingResponse(reject(), media_type="text/event-stream", headers=headers)

    async def event_stream() -> AsyncIterator[str]:
        logger.debug(f"Log stream connected for {serviceName}")
        # -b 0 scopes to the current boot, like `systemctl status` does. With no
        # NTP/RTC the wall clock restarts at the same value every boot, so without it
        # journalctl interleaves prior boots into the tail by timestamp and the pane
        # mixes old runs with the live one. -n 200 seeds history; -f follows; -o json
        # carries ts+severity; limit= keeps one long line from overrunning the buffer.
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-u", serviceName, "-b", "0", "-n", "200", "-f", "-o", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=2 ** 20,
        )

        try:
            assert proc.stdout is not None
            while True:
                try:
                    raw = await asyncio.wait_for(proc.stdout.readline(), timeout=30.0)
                except asyncio.TimeoutError:
                    # A quiet service writes nothing; a comment keeps the stream
                    # (and any intermediate proxy) from timing out the connection.
                    yield ": keepalive\n\n"
                    continue

                if not raw:
                    break  # journalctl exited

                line = parse_journal_line(raw)
                if line is None:
                    continue

                yield f"event: log_line\ndata: {json.dumps(line.model_dump())}\n\n"
        finally:
            # Runs on client disconnect (the generator is closed) as well as on a
            # normal exit, so the followed journalctl is never left orphaned.
            logger.debug(f"Log stream disconnected for {serviceName}")
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    proc.kill()

    return StreamingResponse(event_stream(), media_type="text/event-stream", headers=headers)


@app.get("/config")
def get_service_config(serviceName: str) -> ConfigResponse:
    logger.info(f"GET /config called for {serviceName}")
    return ServiceManager.get_config(serviceName)


@app.post("/config")
def save_service_config(serviceName: str, body: SaveConfigRequest) -> ConfigResponse:
    logger.info(f"POST /config called for {serviceName}")

    if not body.config:
        return ConfigResponse(status="fail", data="No configuration data provided")

    return ServiceManager.save_config(serviceName, body.config)


if __name__ == '__main__':
    host = '127.0.0.1'
    port = int(os.environ.get("PORT", 3002))

    logger.info(f"Starting Service Manager on {host}:{port}")
    # access_log off: the UI polls /statuses.
    uvicorn.run(app, host=host, port=port, access_log=False)
