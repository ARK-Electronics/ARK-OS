# P3: MAVLink REST/WebSocket API Bridge

## Problem

Currently, the only way to interact with MAVLink data from the web UI is through the
Python services (autopilot-manager), which expose a limited set of MAVLink information
via custom REST endpoints. There is no general-purpose way to subscribe to arbitrary
MAVLink messages or send commands from the browser.

## Solution

Add a MAVLink-to-REST/WebSocket bridge that exposes the full MAVLink message set via
HTTP and WebSocket APIs. This enables:
- Real-time telemetry in the browser via WebSocket
- Sending MAVLink commands via REST
- Third-party integrations without custom service code

### Options

1. **mavlink2rest** (Rust) — Existing open-source project by Blue Robotics. Provides
   REST + WebSocket API for MAVLink. Well-tested, used in BlueOS.
   - Pro: Battle-tested, maintained, full MAVLink coverage
   - Con: Adds Rust dependency, another service to maintain

2. **Custom Python bridge** — Build on top of pymavlink in a new service
   - Pro: Same tech stack as existing services
   - Con: Significant effort to match mavlink2rest's feature set

3. **Extend autopilot-manager** — Add WebSocket support to existing service
   - Pro: No new service
   - Con: Mixes concerns, harder to maintain

**Recommended**: Option 1 (mavlink2rest) — it's proven and feature-complete.

## Files to Modify

| File | Change |
|------|--------|
| New: `services/mavlink2rest/` | Service directory with manifest |
| `packaging/packages.yaml` | Add mavlink2rest service definition |
| `frontend/ark-ui.nginx` | Add proxy for mavlink2rest API |

## Implementation Steps

### Step 1: Add mavlink2rest as a service

```yaml
# packages.yaml
mavlink2rest:
  type: custom
  description: "MAVLink REST/WebSocket API bridge"
  contents:
    - src: services/mavlink2rest/mavlink2rest
      dst: /opt/ark/bin/mavlink2rest
      mode: "0755"
  systemd:
    exec_start: /opt/ark/bin/mavlink2rest --connect udpin:0.0.0.0:14551
    after: [mavlink-router.service]
    wants: [mavlink-router.service]
```

### Step 2: Configure mavlink-router endpoint

Add a UDP endpoint in mavlink-router config for mavlink2rest:
```
[UdpEndpoint mavlink2rest]
Mode = Normal
Address = 127.0.0.1
Port = 14551
```

### Step 3: Add nginx proxy

```nginx
location /api/mavlink/ {
    proxy_pass http://127.0.0.1:8088/;
}
location /api/mavlink/ws {
    proxy_pass http://127.0.0.1:8088/ws;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

### Step 4: Frontend integration

Use WebSocket in Vue components for real-time telemetry:
```javascript
const ws = new WebSocket(`ws://${location.host}/api/mavlink/ws`);
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  // Update telemetry display
};
```

## Acceptance Criteria

- [ ] mavlink2rest runs as a systemd service
- [ ] REST API accessible at `/api/mavlink/`
- [ ] WebSocket provides real-time MAVLink messages
- [ ] Integrates with mavlink-router via UDP endpoint
- [ ] Service discoverable by service-manager

## Dependencies

- **P1-flask-to-fastapi** — Not strictly required, but good to modernize backend first

## Effort Estimate

Medium. Most of the work is integration (packaging, nginx config, mavlink-router config).
The mavlink2rest binary itself is pre-built. Estimate 2-3 sessions including testing.
