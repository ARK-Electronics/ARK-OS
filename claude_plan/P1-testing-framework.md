# P1: Testing Framework

## Problem

ARK-OS has no automated tests. This makes refactoring risky, security fixes hard to verify,
and regressions easy to introduce. The CI pipeline lints but doesn't test.

A common concern: "How do you test drone software without hardware?" The answer is that
most of the codebase is standard software (HTTP APIs, config parsing, string formatting,
state machines) that has nothing to do with hardware. You test YOUR logic, not the hardware.

## Solution

Add pytest-based testing for Python services, with mocking for system calls. Integrate
into CI so tests run before package builds.

### What You're Actually Testing

| Layer | Example | Hardware needed? |
|-------|---------|-----------------|
| Input validation | Service name regex, hostname check | No |
| Config parsing | TOML loading, default values | No |
| API response shape | JSON structure, status codes | No |
| State machines | Service lifecycle transitions | No |
| Command construction | Correct systemctl arguments | No |
| Error handling | Graceful failure on bad input | No |
| Integration | Deb package contents, config generation | No |

### What You're NOT Testing (yet)

| Layer | Example | Approach |
|-------|---------|----------|
| MAVLink communication | Actual FC interaction | Hardware-in-the-loop (manual) |
| Camera streaming | RTSP pipeline | Device with camera (manual) |
| CAN bus | Jetson CAN interface | Jetson hardware (manual) |

## Files to Modify

| File | Change |
|------|--------|
| `.github/workflows/build.yml` | Add pytest job before build jobs |
| `pyproject.toml` | Add pytest config |
| New: `tests/conftest.py` | Shared fixtures |
| New: `tests/test_service_manager.py` | service-manager unit tests |
| New: `tests/test_connection_manager.py` | connection-manager unit tests |
| New: `tests/test_system_manager.py` | system-manager unit tests |
| New: `tests/test_autopilot_manager.py` | autopilot-manager unit tests |
| New: `tests/test_packaging.py` | Package generation integration tests |

## Implementation Steps

### Step 1: Set up pytest infrastructure

Update `pyproject.toml`:
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["services/service-manager", "services/connection-manager",
              "services/system-manager", "services/autopilot-manager"]
```

Create `tests/conftest.py` with shared fixtures:
```python
import pytest
from unittest.mock import patch

@pytest.fixture
def mock_subprocess():
    """Mock subprocess.run for all tests that need it."""
    with patch("subprocess.run") as mock:
        mock.return_value.returncode = 0
        mock.return_value.stdout = ""
        mock.return_value.stderr = ""
        yield mock
```

### Step 2: Write tests for P0-security fixes first

These tests validate that the security hardening from P0 actually works:

```python
# tests/test_service_manager.py

import pytest
from service_manager import app, validate_service_name

class TestServiceNameValidation:
    def test_valid_names(self):
        assert validate_service_name("logloader") == "logloader"
        assert validate_service_name("mavlink-router") == "mavlink-router"
        assert validate_service_name("dds-agent") == "dds-agent"

    def test_rejects_injection(self):
        with pytest.raises(ValueError):
            validate_service_name("; rm -rf /")
        with pytest.raises(ValueError):
            validate_service_name("foo$(whoami)")
        with pytest.raises(ValueError):
            validate_service_name("")

class TestServiceManagerAPI:
    @pytest.fixture
    def client(self):
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_get_services(self, client, mock_subprocess):
        response = client.get("/services")
        assert response.status_code == 200
        assert isinstance(response.json, list)

    def test_restart_invalid_service(self, client):
        response = client.post("/restart/; rm -rf /")
        assert response.status_code == 400

    def test_logs_invalid_service(self, client):
        response = client.get("/logs/$(whoami)")
        assert response.status_code == 400
```

### Step 3: Write API tests for each service

Use Flask's test client to test endpoints without running the server:

```python
# tests/test_connection_manager.py

class TestConnectionManagerAPI:
    @pytest.fixture
    def client(self):
        from connection_manager import app
        app.config["TESTING"] = True
        with app.test_client() as client:
            yield client

    def test_get_connections(self, client, mock_subprocess):
        mock_subprocess.return_value.stdout = "WiFi:wifi:wlan0\n"
        response = client.get("/connections")
        assert response.status_code == 200

    def test_set_hostname_rejects_invalid(self, client):
        response = client.post("/hostname", json={"hostname": "; whoami"})
        assert response.status_code == 400
```

### Step 4: Write config/packaging integration tests

```python
# tests/test_packaging.py

import yaml
import json
import os

def test_packages_yaml_valid():
    """Verify packages.yaml parses and has required fields."""
    with open("packaging/packages.yaml") as f:
        data = yaml.safe_load(f)
    assert "services" in data
    for name, svc in data["services"].items():
        assert "type" in svc, f"Service {name} missing type"
        assert "description" in svc, f"Service {name} missing description"

def test_manifests_valid():
    """Verify all manifest files parse and have required fields."""
    for root, dirs, files in os.walk("services"):
        for f in files:
            if f.endswith(".manifest.json"):
                path = os.path.join(root, f)
                with open(path) as fh:
                    manifest = json.load(fh)
                assert "displayName" in manifest, f"{path} missing displayName"
                assert "platform" in manifest, f"{path} missing platform"

def test_every_service_has_manifest():
    """Every service in packages.yaml has a corresponding manifest."""
    with open("packaging/packages.yaml") as f:
        data = yaml.safe_load(f)
    for name in data["services"]:
        manifest = f"services/{name}/{name}.manifest.json"
        assert os.path.exists(manifest), f"Missing manifest: {manifest}"
```

### Step 5: Add pytest to CI

Add to `.github/workflows/build.yml` before the build jobs:

```yaml
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
      with:
        submodules: recursive
    - uses: actions/setup-python@v5
      with:
        python-version: "3.11"
    - name: Install dependencies
      run: pip install pytest flask PyYAML
    - name: Run tests
      run: pytest tests/ -v
```

### Step 6: Add testing documentation

Add a section to the project README or a `tests/README.md` explaining:
- How to run tests locally: `pytest tests/ -v`
- How to add tests for a new service
- The mocking philosophy (test YOUR code, mock system boundaries)

## Acceptance Criteria

- [ ] `pytest tests/ -v` passes with zero failures
- [ ] CI runs tests before package builds
- [ ] Every Python service has at least basic API endpoint tests
- [ ] Input validation from P0-security is covered by tests
- [ ] Config parsing and manifest loading are tested
- [ ] `packages.yaml` structure is validated by tests
- [ ] Tests run in <30 seconds (no hardware, no network)

## Dependencies

- **P0-security-hardening** — Tests should validate the security fixes. Can be developed
  in parallel, but the validation functions being tested come from P0.

## Effort Estimate

Medium. Writing the test infrastructure (conftest.py, CI integration) is ~1 session.
Writing comprehensive tests for all 4 Python services is ~2-3 sessions. The packaging
tests are straightforward. Total estimate: 3-4 sessions.
