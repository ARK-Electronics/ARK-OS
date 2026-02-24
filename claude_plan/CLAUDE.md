# ARK-OS Improvement Plans

This directory contains prioritized, actionable improvement plans for ARK-OS. Each plan
follows a consistent template and contains enough detail for implementation.

## How This Works

1. **Read the plan** — Each `.md` file is a self-contained improvement plan
2. **Check dependencies** — Some plans depend on others being completed first
3. **Implement** — Follow the steps in the plan file
4. **Record completion** — Move the plan to `completed/` with a date prefix and add notes

### Recording Completed Work

When a plan is finished:
```bash
mv claude_plan/P0-path-migration-cleanup.md claude_plan/completed/2025-01-15-P0-path-migration-cleanup.md
```
Add a "Completion Notes" section at the bottom of the moved file documenting what was
done and any deviations from the original plan.

## Priority Matrix

### P0 — Critical (fix now)

These are bugs or security issues in the current codebase.

| Plan | Description | Dependencies |
|------|-------------|--------------|
| [P0-path-migration-cleanup.md](P0-path-migration-cleanup.md) | Complete `~/.local/` → `/opt/ark/` path migration | None |
| [P0-security-hardening.md](P0-security-hardening.md) | Fix command injection, add input validation | None |

### P1 — High (next quarter)

Important improvements that add significant value.

| Plan | Description | Dependencies |
|------|-------------|--------------|
| [P1-apt-repository.md](P1-apt-repository.md) | Hosted APT repo for OTA updates | None |
| [P1-testing-framework.md](P1-testing-framework.md) | Unit/integration testing strategy | P0-security (tests validate fixes) |
| [P1-flask-to-fastapi.md](P1-flask-to-fastapi.md) | Migrate Python services to FastAPI | P0-path-migration, P0-security |

### P2 — Medium (this half)

Feature improvements and modernization.

| Plan | Description | Dependencies |
|------|-------------|--------------|
| [P2-webrtc-video.md](P2-webrtc-video.md) | WebRTC video in UI + UVC camera support | None |
| [P2-vite-migration.md](P2-vite-migration.md) | Migrate vue-cli-service → Vite | None |

### P3 — Backburner

Future considerations, not actively planned.

| Plan | Description | Dependencies |
|------|-------------|--------------|
| [P3-mavlink2rest.md](P3-mavlink2rest.md) | MAVLink REST/WebSocket API bridge | P1-flask-to-fastapi |
| [P3-zenoh-support.md](P3-zenoh-support.md) | Zenoh daemon alongside DDS agent | None |

## Plan File Template

Every plan follows this structure:

```markdown
# Title
## Problem
## Solution
## Files to Modify (exact paths)
## Implementation Steps
## Acceptance Criteria
## Dependencies
## Effort Estimate
```
