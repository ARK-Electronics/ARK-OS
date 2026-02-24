# ARK-OS Improvement Plans

This directory contains prioritized, actionable improvement plans for ARK-OS. Each plan
follows a consistent template and contains enough detail for implementation.

## How This Works

1. **Read the plan** — Each `.md` file is a self-contained improvement plan
2. **Check dependencies** — Some plans depend on others being completed first
3. **Implement** — Follow the steps in the plan file
4. **Record completion** — Move the plan to `completed/` with a date prefix and notes
5. **Update docs** — Verify and update top-level docs to reflect the changes

### Recording Completed Work

When a plan (or a significant chunk of a plan) is finished:

```bash
mv claude_plan/P0-path-migration-cleanup.md claude_plan/completed/2025-01-15-P0-path-migration-cleanup.md
```

Add a **Completion Notes** section at the bottom of the moved file with:

```markdown
## Completion Notes

- **Date**: 2025-01-15
- **Session ID**: 098dc835-7d1e-467f-8ec5-8e34d6687f4b
- **Transcript**: ~/.claude/projects/-home-jake-code-ark-ARK-OS/<session-id>.jsonl
- **Planning session**: <session-id-of-planning-session>.jsonl (if different)
- **Summary**: <1-3 sentences on what was done>
- **Deviations**: <anything that differed from the original plan>
- **Follow-up**: <any new issues discovered, or "None">
```

The session ID is the UUID filename of the `.jsonl` transcript in
`~/.claude/projects/-home-jake-code-ark-ARK-OS/`. Use `ls -lt` to find the most recent
one, or check the plan's original text for a transcript reference.

### End-of-Session Checklist

**After every session that modifies code or completes a plan**, verify and update:

1. **`CLAUDE.md` (project root)** — Does it still accurately describe:
   - Install paths and conventions?
   - Migration status (remove the note once P0-path-migration is done)?
   - Services table (if services were added/removed/renamed)?
   - Submodule ownership table?
   - Install workflows?

2. **`ARCHITECTURE.md`** — Does it still accurately describe:
   - System architecture diagram?
   - Service table (ports, platforms)?
   - Packaging and deployment info?
   - "Adding a New Service" instructions?

3. **This file (`claude_plan/CLAUDE.md`)** — Update:
   - Move completed plans to `completed/`
   - Update priority matrix (remove completed rows, adjust dependencies)
   - Add any new plans discovered during implementation

4. **`~/.claude/projects/-home-jake-code-ark-ARK-OS/memory/MEMORY.md`** — Update:
   - Confirmed patterns and conventions
   - Any new architectural decisions
   - Remove outdated information

The goal: a future Claude session starting from `CLAUDE.md` should have an accurate,
up-to-date picture of the project without needing to re-discover anything.

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
