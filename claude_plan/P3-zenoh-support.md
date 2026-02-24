# P3: Zenoh Support Alongside DDS Agent

## Problem

The current PX4-ROS2 bridge uses Micro-XRCE-DDS-Agent, which works but has limitations:
- DDS discovery can be slow and resource-heavy on embedded systems
- No native pub/sub for non-ROS2 consumers
- Limited to the DDS ecosystem

Zenoh is a lightweight pub/sub protocol that can bridge DDS, MQTT, and REST. It's gaining
traction in the robotics community as a more efficient alternative to raw DDS for
resource-constrained systems.

## Solution

Add an optional Zenoh daemon that runs alongside the DDS agent, bridging DDS topics to
Zenoh's lightweight protocol. This enables:
- Efficient pub/sub for web clients and mobile apps
- Bridge to MQTT for IoT integrations
- Lower overhead than full DDS for companion computer use cases

**Important**: This does NOT replace the DDS agent. It adds Zenoh as an additional
transport option.

## Files to Modify

| File | Change |
|------|--------|
| New: `services/zenoh-daemon/` | Service directory with manifest and config |
| `packaging/packages.yaml` | Add zenoh-daemon service definition |

## Implementation Steps

### Step 1: Evaluate Zenoh-DDS bridge

Test the `zenoh-bridge-dds` binary:
```bash
# Run alongside DDS agent
zenoh-bridge-dds --scope /ark --dds-domain 0
```

Verify it correctly bridges PX4 uORB topics published by the DDS agent.

### Step 2: Add as an ARK-OS service

```yaml
# packages.yaml
zenoh-daemon:
  type: custom
  description: "Zenoh daemon with DDS bridge for lightweight pub/sub"
  contents:
    - src: services/zenoh-daemon/zenoh-bridge-dds
      dst: /opt/ark/bin/zenoh-bridge-dds
      mode: "0755"
    - src: services/zenoh-daemon/config.json5
      dst: /opt/ark/share/zenoh-daemon/config.json5
      type: config
  systemd:
    exec_start: /opt/ark/bin/zenoh-bridge-dds -c /opt/ark/share/zenoh-daemon/config.json5
    after: [dds-agent.service]
    wants: [dds-agent.service]
```

### Step 3: Configure Zenoh

```json5
// config.json5
{
  mode: "peer",
  listen: { endpoints: ["tcp/0.0.0.0:7447"] },
  plugins: {
    dds: {
      scope: "/ark",
      domain: 0,
      allow: "VehicleStatus|SensorCombined|VehicleGpsPosition"
    }
  }
}
```

### Step 4: Frontend integration (optional)

Zenoh has a JavaScript client that could connect directly from the browser:
```javascript
const z = await zenoh.open({ connect: { endpoints: [`tcp/${location.hostname}:7447`] } });
const sub = z.subscribe('/ark/**', (sample) => {
  console.log(sample.key, sample.value);
});
```

## Acceptance Criteria

- [ ] Zenoh daemon runs alongside DDS agent without conflicts
- [ ] PX4 uORB topics are accessible via Zenoh protocol
- [ ] Service is optional (not included in ark-companion meta-package)
- [ ] Configurable topic filtering
- [ ] Resource usage is acceptable on Jetson/Pi

## Dependencies

None — independent of other plans.

## Effort Estimate

Medium. Main effort is testing Zenoh-DDS bridge compatibility with the PX4 topic set
and measuring resource usage on embedded targets. Estimate 2-3 sessions.
