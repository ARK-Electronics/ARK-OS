# P1: Migrate Python Services from Flask to FastAPI

## Problem

All four Python REST services use Flask, a synchronous WSGI framework. This works but has
limitations:
- No native async support (important for services that wait on subprocess/network calls)
- No automatic request validation or OpenAPI docs
- Manual JSON serialization
- Flask's development server is used in production (no gunicorn/uwsgi configured)

## Solution

Migrate each Python service from Flask to FastAPI. FastAPI provides:
- Automatic request/response validation via Pydantic models
- Auto-generated OpenAPI docs (useful for debugging on-device)
- Native async for subprocess calls
- Built-in CORS middleware
- Uvicorn as production ASGI server (lightweight, suitable for embedded)

### Migration Strategy

Migrate one service at a time, starting with the simplest (service-manager). Each migration
follows the same pattern: Flask routes → FastAPI routes, manual validation → Pydantic models.

## Files to Modify

### Per service (repeat for each):

| Service | Main file | Manifest |
|---------|-----------|----------|
| service-manager | `services/service-manager/service_manager.py` | `services/service-manager/service-manager.manifest.json` |
| connection-manager | `services/connection-manager/connection_manager.py` | `services/connection-manager/connection-manager.manifest.json` |
| system-manager | `services/system-manager/system_manager.py` | `services/system-manager/system-manager.manifest.json` |
| autopilot-manager | `services/autopilot-manager/autopilot_manager.py` | `services/autopilot-manager/autopilot-manager.manifest.json` |

### Packaging changes:

| File | Change |
|------|--------|
| `packaging/packages.yaml` | Update Python dependencies (flask → fastapi + uvicorn) |
| `packaging/generate.py` | Update exec_start template for uvicorn |
| `tests/test_*.py` | Update test clients (Flask test_client → FastAPI TestClient) |

## Implementation Steps

### Step 1: Migrate service-manager (simplest first)

```python
# Before (Flask):
from flask import Flask, jsonify, request
app = Flask(__name__)

@app.route("/services", methods=["GET"])
def get_services():
    services = discover_services()
    return jsonify(services)

@app.route("/restart/<service_name>", methods=["POST"])
def restart_service(service_name):
    validate_service_name(service_name)
    result = run_systemctl("restart", service_name)
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3002)
```

```python
# After (FastAPI):
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator
import uvicorn

app = FastAPI(title="ARK Service Manager")

class ServiceName(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$', v):
            raise ValueError("Invalid service name")
        return v

@app.get("/services")
async def get_services():
    services = await discover_services()
    return services

@app.post("/restart/{service_name}")
async def restart_service(service_name: str):
    ServiceName(name=service_name)  # Validates
    result = await run_systemctl("restart", service_name)
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=3002)
```

### Step 2: Update systemd exec_start

In `packaging/packages.yaml` or `generate.py`, the exec command changes from:
```
python3 /opt/ark/bin/service_manager.py
```
to:
```
python3 /opt/ark/bin/service_manager.py
```
(FastAPI's `uvicorn.run()` is called from the script itself, so no change needed if
the script uses `if __name__ == "__main__": uvicorn.run(...)`)

### Step 3: Update dependencies in packages.yaml

```yaml
# Add to each Python service or create a shared dependency
depends: [python3-fastapi, python3-uvicorn]
# Or if not available as system packages:
# Include a requirements.txt and pip install in postinst
```

Note: FastAPI and Uvicorn may need to be installed via pip on the target if not available
as system deb packages. Consider vendoring or adding a pip install step to postinst.

### Step 4: Make subprocess calls async

```python
import asyncio

async def run_systemctl(operation: str, service_name: str) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "systemctl", "--user", operation, service_name,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return {"returncode": proc.returncode, "stdout": stdout.decode(), "stderr": stderr.decode()}
```

### Step 5: Update tests

```python
# Before (Flask):
from service_manager import app
client = app.test_client()
response = client.get("/services")

# After (FastAPI):
from fastapi.testclient import TestClient
from service_manager import app
client = TestClient(app)
response = client.get("/services")
# Same assertions work — TestClient has the same interface
```

### Step 6: Update nginx proxy config

FastAPI/Uvicorn should work with the existing nginx proxy config since it still listens
on the same ports. No changes needed unless WebSocket endpoints are added.

### Step 7: Migrate remaining services

Repeat steps 1-5 for connection-manager, system-manager, and autopilot-manager.
Order by complexity:
1. service-manager (simplest, fewest endpoints)
2. system-manager (moderate)
3. autopilot-manager (moderate, has MAVLink-related logic)
4. connection-manager (most complex, nmcli interaction)

## Acceptance Criteria

- [ ] All four Python services use FastAPI + Uvicorn
- [ ] All existing API endpoints maintain the same URL structure and response format
- [ ] nginx reverse proxy still works without config changes
- [ ] OpenAPI docs accessible at `http://device.local/api/service/docs` (etc.)
- [ ] All subprocess calls use async (`asyncio.create_subprocess_exec`)
- [ ] Pydantic models validate all request inputs
- [ ] Tests updated and passing
- [ ] Services start and stop cleanly via systemd

## Dependencies

- **P0-path-migration-cleanup** — Complete first so we're not migrating code that will change
- **P0-security-hardening** — The validation logic from P0 should be built into Pydantic models

## Effort Estimate

Medium-large. Each service migration is ~1 session (mechanical translation). The main risk
is ensuring the nginx proxy and frontend still work correctly with the new backend. Testing
on-device is important. Total estimate: 4-5 sessions.
