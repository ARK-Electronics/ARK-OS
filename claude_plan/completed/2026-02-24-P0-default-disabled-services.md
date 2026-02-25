# Default-disabled services + platform meta-packages

## Problem

Every service was `systemctl enable`d + `restart`ed on deb install. The old install flow
used interactive prompts and env vars (`default.env`) to selectively install services and
configure them. This was fragile, non-standard, and incompatible with a future apt repository.

## Solution

Install all services via platform meta-packages, but only enable core infrastructure by
default. Optional services are installed dormant — users enable them via the web UI.

## Changes Made

1. **`packaging/packages.yaml`** — Added `default_enabled: false` to 7 optional services;
   replaced single `ark-companion` meta-package with 4 platform-specific ones
   (ark-companion-base, ark-companion-jetson, ark-companion-pi, ark-companion-ubuntu)

2. **`packaging/generate.py`** — Modified postinst generators to accept `default_enabled`;
   when `False`, postinst only runs `daemon-reload`. Fixed content path prefix (`../../`)
   for correct resolution from `packaging/generated/`.

3. **`tools/service_control.sh`** — Removed `is_service_enabled()` and `configure_service()`;
   added explicit `systemctl enable+restart` after `dpkg -i` so dev workflow always starts.

4. **Submodule install.sh scripts** — Removed env var config substitution blocks from
   logloader, polaris, rid-transmitter.

5. **All 13 manifests** — Removed `env_var`, `install_script`, `install_files` fields;
   changed `jetson-can` to `visible: true`.

6. **`tools/install_software.sh`** — Removed `default.env` sourcing, `ask_yes_no()`,
   interactive prompts, installation summary, `INSTALL_JETPACK` conditional.

7. **`default.env`** — Deleted.

8. **`.github/workflows/build.yml`** — Updated all nfpm steps to run `generate.py` first
   and work from `packaging/generated/`; release builds 4 platform meta-packages.

## Completion Notes

- **Date**: 2026-02-24
- **Session ID**: 86152669-592c-43af-b1b9-11ceba788866
- **Transcript**: ~/.claude/projects/-home-jake-code-ark-ARK-OS/86152669-592c-43af-b1b9-11ceba788866.jsonl
- **Planning session**: fcbeabc2-9653-48b4-96d3-39cd0d5c1d4a.jsonl
- **Summary**: Implemented default-disabled services and platform meta-packages. Core services
  auto-enable on deb install; optional services install dormant. Removed all legacy env var
  config logic and interactive prompts. Fixed CI to generate packaging files before nfpm.
- **Deviations**: Also fixed pre-existing CI bug where nfpm config paths assumed `packaging/`
  but generated files are in `packaging/generated/`. Fixed content source paths from `../` to
  `../../` in generate.py for correct resolution.
- **Follow-up**: None
