# P0: Security Hardening

## Problem

Several Python services use `subprocess.run(command, shell=True)` with string-interpolated
user input, creating command injection vulnerabilities. Service names and other parameters
from HTTP requests are inserted directly into shell commands without validation.

### Current Vulnerabilities

**service_manager.py** — 3 instances of `shell=True`:
- Line 33: `run_systemctl()` — `f"systemctl --user {operation} {service_name}"`
- Line 56: `get_service_status()` — `f"systemctl --user is-{status_type} {service_name}"`
- Line 213: `get_logs()` — `f"journalctl --user -u {service_name} -n {num_lines} --no-pager -o cat"`

**connection_manager.py** — 1 instance:
- Line 68: `CommandExecutor.run_command()` — Generic command executor with `shell=True`

An attacker with network access to the management ports could inject shell commands via
crafted service names (e.g., `; rm -rf /`) or connection parameters.

## Solution

1. Replace all `shell=True` with parameterized `subprocess.run([...])` (list form)
2. Add input validation for all external inputs
3. Validate service names, hostnames, and config content at API boundaries

## Files to Modify

| File | Changes |
|------|---------|
| `services/service-manager/service_manager.py` | Replace shell=True (3 sites), add service name validation |
| `services/connection-manager/connection_manager.py` | Replace shell=True (1 site), add hostname/SSID validation |
| `services/system-manager/system_manager.py` | Audit for injection, add input validation |
| `services/autopilot-manager/autopilot_manager.py` | Audit for injection, add input validation |

## Implementation Steps

### Step 1: Add input validation helpers

Add a validation module or inline validators for common inputs:

```python
import re

def validate_service_name(name: str) -> str:
    """Validate service name: alphanumeric, hyphens, underscores only."""
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$', name):
        raise ValueError(f"Invalid service name: {name}")
    return name

def validate_hostname(hostname: str) -> str:
    """Validate hostname per RFC 1123."""
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$', hostname):
        raise ValueError(f"Invalid hostname: {hostname}")
    return hostname

def validate_positive_int(value, max_val: int = 10000) -> int:
    """Validate positive integer within bounds."""
    n = int(value)
    if n < 1 or n > max_val:
        raise ValueError(f"Value out of range: {n}")
    return n
```

### Step 2: Fix service_manager.py

Replace shell=True with list-form subprocess calls:

```python
# Before (vulnerable):
command = f"systemctl --user {operation} {service_name}"
process = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)

# After (safe):
service_name = validate_service_name(service_name)
process = subprocess.run(
    ["systemctl", "--user", operation, service_name],
    capture_output=True, text=True, timeout=10
)
```

Apply same pattern to `get_service_status()` and `get_logs()`:

```python
# get_logs - before:
command = f"journalctl --user -u {service_name} -n {num_lines} --no-pager -o cat"

# get_logs - after:
service_name = validate_service_name(service_name)
num_lines = validate_positive_int(num_lines, max_val=10000)
process = subprocess.run(
    ["journalctl", "--user", "-u", service_name, "-n", str(num_lines), "--no-pager", "-o", "cat"],
    capture_output=True, text=True, timeout=10
)
```

### Step 3: Fix connection_manager.py

Replace the generic `CommandExecutor.run_command()` shell executor. Instead of passing
full command strings, use list-form for each specific nmcli operation:

```python
# Before (vulnerable):
result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)

# After (safe) — one method per operation:
def get_connections(self):
    return subprocess.run(
        ["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"],
        capture_output=True, text=True, check=True
    )

def connect_wifi(self, ssid: str, password: str):
    validate_ssid(ssid)
    return subprocess.run(
        ["nmcli", "device", "wifi", "connect", ssid, "password", password],
        capture_output=True, text=True, check=True, timeout=30
    )
```

### Step 4: Add config file validation

For any endpoint that accepts config file content:
- Enforce size limit (e.g., 64KB max)
- Prevent path traversal in filenames (reject `..`, absolute paths)
- Validate TOML syntax before writing

```python
def validate_config_content(content: str, max_size: int = 65536) -> str:
    if len(content) > max_size:
        raise ValueError(f"Config too large: {len(content)} bytes (max {max_size})")
    # Verify valid TOML
    import tomllib
    tomllib.loads(content)
    return content

def validate_config_path(path: str, allowed_dir: str) -> str:
    resolved = os.path.realpath(path)
    if not resolved.startswith(os.path.realpath(allowed_dir)):
        raise ValueError(f"Path traversal detected: {path}")
    return resolved
```

### Step 5: Audit remaining services

Review `system_manager.py` and `autopilot_manager.py` for similar patterns:
- Search for `subprocess.run`, `os.system`, `os.popen`
- Ensure all external input is validated before use
- Replace any remaining `shell=True` usage

## Acceptance Criteria

- [x] Zero instances of `shell=True` in Python services
- [x] All service names validated with `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`
- [x] All hostnames validated per RFC 1123
- [x] Config file writes enforce size limits and path traversal prevention
- [x] `grep -r 'shell=True' services/` returns zero hits (only upstream mavlink-router submodule)
- [ ] All existing API endpoints still work correctly after changes (needs runtime testing)
- [x] Invalid inputs return 400 status with descriptive error messages

## Dependencies

None — this is a standalone security fix. Should be done before P1-testing-framework
so tests can validate the security fixes.

## Effort Estimate

Small-medium. ~4 files to modify, mostly mechanical replacement of subprocess calls.
The connection_manager.py refactor is the most involved since it has a generic command
executor that needs to be split into specific methods. Estimate 1-2 focused sessions.

## Completion Notes

- **Date**: 2026-02-24
- **Session ID**: b906d938-9539-443c-b27c-bff4b9713b85
- **Transcript**: ~/.claude/projects/-home-jake-code-ark-ARK-OS/b906d938-9539-443c-b27c-bff4b9713b85.jsonl
- **Summary**: Eliminated all `shell=True` subprocess calls in ARK-OS Python services.
  Added input validation (service names, connection names, SSIDs, hostnames, IP addresses,
  APNs, interface names) at API boundaries. Added config file size limits and path traversal
  prevention. Converted ~40 string-form shell commands in connection_manager.py to list-form.
  Replaced piped shell commands with Python-native parsing. Audited system_manager.py and
  autopilot_manager.py (both already clean).
- **Deviations**: Kept `CommandExecutor` class structure in connection_manager.py rather than
  splitting into per-operation methods — the list-form approach is equally safe and minimizes
  code churn. Did not add TOML syntax validation to config writes (configs may not always be
  TOML format per manifest configFile).
- **Follow-up**: Runtime testing needed on target devices to confirm all API endpoints work
  correctly with the list-form subprocess calls.
