# P0: Complete Path Migration Cleanup

## Problem

The project recently migrated install paths from `~/.local/bin/` + `~/.local/share/` (XDG)
to `/opt/ark/bin/` + `/opt/ark/share/`. Packaging (`packages.yaml`) and systemd units are
correct, but **service source code still hardcodes old paths**. This is a runtime bug:
debs install configs to `/opt/ark/share/<service>/` but services look for them in
`~/.local/share/<service>/`.

Additionally, old per-service `install.sh` scripts remain in submodules, creating confusion
about how installation works.

## Solution

### Config Path Strategy (two-tier lookup)

Services need a two-tier config lookup:
1. **User config** at `~/.config/ark/<service>/config.toml` — writable, persists across upgrades
2. **Default config** at `/opt/ark/share/<service>/config.toml` — installed by deb, read-only

On startup, each service checks for user config first, falls back to default. Services that
write runtime state (logloader's SQLite DB, downloaded logs) use `~/.local/share/ark/<service>/`
as a writable data directory.

```
Read config:   ~/.config/ark/<service>/config.toml  →  /opt/ark/share/<service>/config.toml
Write data:    ~/.local/share/ark/<service>/
Binaries:      /opt/ark/bin/
```

## Files to Modify

### C++ submodules (ARK-owned, we can edit)

| File | Line(s) | Current Path | New Behavior |
|------|---------|-------------|--------------|
| `services/logloader/logloader/src/main.cpp` | 21, 38 | `$HOME/.local/share/logloader/` | Two-tier config + writable data dir |
| `services/polaris/polaris-client-mavlink/src/main.cpp` | 22 | `$HOME/.local/share/polaris/config.toml` | Two-tier config lookup |
| `services/rid-transmitter/RemoteIDTransmitter/src/main.cpp` | 23 | `$HOME/.local/share/rid-transmitter/config.toml` | Two-tier config lookup |
| `services/rtsp-server/rtsp-server/src/main.cpp` | 24 | `$HOME/.local/share/rtsp-server/config.toml` | Two-tier config lookup |

### Python services

| File | Line(s) | Issue |
|------|---------|-------|
| `services/service-manager/service_manager.py` | 68, 88, 105 | Hardcoded `~/.local/share` for manifest/config discovery and `~/.config/systemd/user` for unit files |
| `services/autopilot-manager/autopilot_manager.py` | 458, 538 | Hardcoded `~/.local/bin/` for `reset_fmu_*.py` and `px_uploader.py` |

### Shell scripts

| File | Line(s) | Issue |
|------|---------|-------|
| `platform/common/scripts/flash_firmware.sh` | 23, 28, 34 | Hardcoded `~/.local/bin/` for `reset_fmu_wait_bl.py`, `px_uploader.py`, `reset_fmu_fast.py` |
| `services/flight-review/start_flight_review.sh` | 5 | Hardcoded `~/.local/share/flight_review/app/serve.py` |

### Legacy files to delete

These old per-service install scripts are superseded by deb packaging:

- `services/logloader/logloader/install.sh`
- `services/rid-transmitter/RemoteIDTransmitter/install.sh`
- `services/polaris/polaris-client-mavlink/install.sh`
- `services/rtsp-server/rtsp-server/install.sh`

### Documentation to update

- `services/logloader/logloader/README.md` — Update path references
- `services/rid-transmitter/RemoteIDTransmitter/README.md` — Update config path
- `README.md` — Clarify deb as primary install method, `install.sh` as legacy/dev

## Implementation Steps

### Step 1: Create shared C++ config helper

Create a small header-only utility (or inline in each `main.cpp`) for two-tier config lookup:

```cpp
#include <filesystem>
#include <cstdlib>
#include <string>

namespace ark {

// Returns path to config file: user override > default
inline std::string find_config(const std::string& service_name,
                                const std::string& filename = "config.toml") {
    const char* home = std::getenv("HOME");
    if (!home) home = "/tmp";

    // User config (writable, survives upgrades)
    auto user_config = std::filesystem::path(home) / ".config/ark" / service_name / filename;
    if (std::filesystem::exists(user_config)) {
        return user_config.string();
    }

    // Default config (installed by deb)
    auto default_config = std::filesystem::path("/opt/ark/share") / service_name / filename;
    if (std::filesystem::exists(default_config)) {
        return default_config.string();
    }

    // Fallback to user location (will be created on first run)
    return user_config.string();
}

// Returns writable data directory for a service
inline std::string data_dir(const std::string& service_name) {
    const char* home = std::getenv("HOME");
    if (!home) home = "/tmp";
    auto dir = std::filesystem::path(home) / ".local/share/ark" / service_name;
    std::filesystem::create_directories(dir);
    return dir.string();
}

} // namespace ark
```

### Step 2: Update C++ services

For each C++ service (`logloader`, `polaris`, `rid-transmitter`, `rtsp-server`):
1. Replace hardcoded `$HOME/.local/share/<service>/config.toml` with `ark::find_config("<service>")`
2. For logloader: use `ark::data_dir("logloader")` for SQLite DB and log storage
3. Build and verify config is found correctly

### Step 3: Update Python services

**service_manager.py:**
- Change manifest discovery path from `~/.local/share` to `/opt/ark/share`
- Change config lookup to check `~/.config/ark/<service>/` then `/opt/ark/share/<service>/`
- Update systemd unit path: `/etc/systemd/user/` (debs install here, not `~/.config/systemd/user/`)

**autopilot_manager.py:**
- Change `~/.local/bin/` references to `/opt/ark/bin/`

### Step 4: Update shell scripts

**flash_firmware.sh:**
- Change `~/.local/bin/reset_fmu_wait_bl.py` → `/opt/ark/bin/reset_fmu_wait_bl.py`
- Change `~/.local/bin/px_uploader.py` → `/opt/ark/bin/px_uploader.py`
- Change `~/.local/bin/reset_fmu_fast.py` → `/opt/ark/bin/reset_fmu_fast.py`

**start_flight_review.sh:**
- Change `~/.local/share/flight_review/app/serve.py` → `/opt/ark/share/flight-review/app/serve.py`

### Step 5: Delete legacy install scripts

Remove the four `install.sh` files from submodules. These will need to be committed in
their respective submodule repos.

### Step 6: Update documentation

- Update `README.md` to clarify the three install workflows
- Update submodule READMEs with correct paths

## Acceptance Criteria

- [ ] All C++ services find config at `/opt/ark/share/<service>/config.toml` (default)
      or `~/.config/ark/<service>/config.toml` (user override)
- [ ] Logloader writes data to `~/.local/share/ark/logloader/` (not `~/.local/share/logloader/`)
- [ ] `service_manager.py` discovers manifests and configs from `/opt/ark/share/`
- [ ] `autopilot_manager.py` references scripts at `/opt/ark/bin/`
- [ ] `flash_firmware.sh` references scripts at `/opt/ark/bin/`
- [ ] `start_flight_review.sh` references the correct serve.py path
- [ ] No `install.sh` files remain in submodules
- [ ] `grep -r '~/.local' services/ platform/` returns zero hits (excluding git history)
- [ ] Services start correctly after a fresh `dpkg -i` install

## Dependencies

None — this is a foundational fix.

## Effort Estimate

Medium. ~15 files across 6 repos (main + 4 C++ submodules + flight-review wrapper).
The C++ changes are mechanical. The service_manager.py changes require care to maintain
backward compatibility during transition. Estimate 2-3 focused sessions.

## Completion Notes

- **Date**: 2026-02-24
- **Session ID**: fc9f2ca7-2003-48fe-b4f3-9213def9ca93
- **Transcript**: ~/.claude/projects/-home-jake-code-ark-ARK-OS/fc9f2ca7-2003-48fe-b4f3-9213def9ca93.jsonl
- **Planning session**: a0399aa8-6f9f-4357-8e39-c814c7e82711.jsonl
- **Summary**: Completed full path migration from `~/.local/` to `/opt/ark/`. Updated all 4 C++ submodules (logloader, polaris, rid-transmitter, rtsp-server) with two-tier config lookup. Fixed Python services (service_manager.py, autopilot_manager.py) and shell scripts (flash_firmware.sh, start_flight_review.sh). Added config.toml, manifest.json, and helper scripts to deb packages via packages.yaml + generate.py auto-include. Deleted 4 legacy install.sh files from submodules. Updated submodule READMEs.
- **Deviations**: Used inline two-tier config lookup in each main.cpp rather than a shared header, since the 4 submodules are separate repos and a shared header would need to be duplicated anyway. The `reset_fmu_*.py` scripts are not included in the autopilot-manager deb (platform-specific GPIO dependencies — noted in the plan as future work).
- **Follow-up**: Submodule changes need to be committed and pushed in their respective repos (logloader, polaris-client-mavlink, RemoteIDTransmitter, rtsp-server). The main repo needs the submodule pointers updated after those pushes.
