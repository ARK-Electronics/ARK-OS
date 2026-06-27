# Local test harness (x86, no hardware)

Run the ARK-OS userspace stack and web UI on your dev machine — in containers, with no camera, no flight controller, and no reflash. This is for iterating on the managers and the UI; it deliberately does **not** rebuild or install the arm64 `.deb` (see *Fidelity* below).

## What runs

One **`arkos`** container (like the real device, everything on shared localhost):

- the four FastAPI managers — `system` (3004), `service` (3002), `connection` (3001), `autopilot` (3003)
- the **ark-ui-backend** Express gateway (3000)
- **nginx** (:80) serving the built Vue UI and proxying `/api` → gateway, `/video/` → go2rtc
- a **fake flight controller** (`mavlink_stub.py`) feeding heartbeats + telemetry to the autopilot manager

…plus a **`go2rtc`** sidecar whose camera is a synthetic ffmpeg test pattern, so the Video page streams over the real WebRTC path with no `/dev/video*`.

## Run it

Only Docker is required — nothing else touches your host. The runner script uses plain `docker` (no Compose plugin or buildx needed):

```bash
bash test/run.sh up      # build + start; UI at http://localhost:8080
bash test/run.sh logs    # follow all service logs
bash test/run.sh down    # stop and remove
```

First run takes a few minutes (it builds the Vue UI and installs deps in the image); after that it's cached.

If you have the Compose plugin, `cd test && docker compose up --build` does the same thing (see `docker-compose.yml`).

## What works vs. what's faked

| Page | Status |
|------|--------|
| **System** | Real — system-manager's generic-Linux collector (CPU/mem/temp where the container can read it). |
| **Video** | Real WebRTC path; camera is a test pattern. Edit `go2rtc.test.yaml` (or via the Services page) and restart the `go2rtc` container to change the source. |
| **Autopilot** | Connected to the fake FC — heartbeat, battery, attitude, position move. No params/commands (those need SITL — see below). |
| **Services** | Driven by `manifests/`; status/start/stop/enable/logs work via the `systemctl`/`journalctl` shims (state is faked, in-container). |
| **Connections** | **Degraded** — connection-manager shells out to `nmcli`, which isn't present, so most actions error. This page is the one thing that really wants the systemd/NetworkManager tier. |

System-manager actions that write to the host (e.g. setting the hostname) will fail or no-op in the container — expected.

## Fast UI iteration

The image bakes the built UI, so a frontend change means a rebuild. For tight loops, run the Vue dev server on your host against the running backend instead:

```bash
cd frontend && npm run serve   # http://localhost:8081 with HMR
```

`frontend/vue.config.js` already proxies `/api` → `localhost:3000`; add a `/video` proxy to `localhost:8080` if you need the Video page in dev mode. (The gateway's `:3000` is internal to the `arkos` container — publish it in `docker-compose.yml` with `ports: ["3000:3000"]` if your dev server needs to reach it directly.)

## Upgrading the fake FC to PX4 SITL

The stub only emits telemetry. For real parameters/commands (so the Autopilot tabs are fully exercisable), drop in PX4 SITL and point the autopilot manager at it instead of the stub:

1. Add a SITL service to the compose file, e.g. `jonasvautherin/px4-gazebo-headless`, exposing its MAVLink UDP.
2. In `supervisord.conf`, change `autopilot-manager`'s `--connection-string` to the SITL endpoint, and disable the `mavlink-stub` program.

## Notes

- A repo-root `.dockerignore` keeps the build context lean (skips `.git`, `node_modules`, and the native-build service submodules the x86 harness doesn't use).
- **Fidelity:** this runs x86-native builds of the managers/gateway, not the arm64 artifact you ship. It's for behavior/UI iteration. To validate the actual package (install, systemd units, nginx wiring) before a release, run the real `.deb` in an arm64 systemd container under qemu — a separate, heavier harness we can add when needed.
