# P1: APT Repository for OTA Updates

## Problem

Currently, users install ARK-OS by either:
1. Running `install.sh` on-device (legacy, builds from source)
2. Downloading `.deb` files from GitHub Releases and manually installing with `dpkg`

There is no `apt update && apt upgrade` workflow for end users. This means no automatic
dependency resolution, no easy rollback, and a manual update process.

## Solution

A hosted APT repository on GitHub Pages (gh-pages branch) managed by `reprepro`.
Devices can update with standard Debian tooling:

```bash
sudo apt update && sudo apt upgrade    # Updates all ARK packages
```

### Repository Structure

```
deb https://ark-electronics.github.io/ARK-OS stable main    # Release builds
```

**Hosting**: GitHub Pages on `gh-pages` branch of ARK-OS.
**Scope**: Stable releases only (tagged `v*`). Testing repo deferred.
**Tool**: `reprepro` (simple, file-based, maintains state on gh-pages).

## Files

| File | Purpose |
|------|---------|
| `packaging/apt/distributions` | reprepro distribution config (stable, arm64, main) |
| `packaging/apt/options` | reprepro options |
| `.github/workflows/publish-apt.yml` | CI workflow: on release, publish debs to gh-pages APT repo |
| `platform/common/scripts/setup_apt_repo.sh` | Device-side script to add the ARK APT source |

## How It Works

### CI Workflow (`publish-apt.yml`)

Triggered by `release` event (type: `published`):

1. Installs `reprepro` and imports GPG signing key from secrets
2. Checks out `gh-pages` branch (creates orphan branch on first run)
3. Copies reprepro config from `packaging/apt/` if not already initialized
4. Downloads all `.deb` assets from the GitHub Release
5. Runs `reprepro includedeb stable <each .deb>` to add packages
6. Exports the public GPG key as `ark-archive-keyring.gpg`
7. Commits and pushes to `gh-pages`

### Device Setup (`setup_apt_repo.sh`)

Run once per device to configure the APT source:

```bash
sudo bash platform/common/scripts/setup_apt_repo.sh
```

This downloads the GPG keyring, adds the source list entry, and runs `apt update`.

## Manual Steps Required

Before the workflow can run:

1. **Generate GPG signing key** (one-time):
   ```bash
   gpg --full-generate-key  # RSA 4096, "ARK Electronics <support@arkelectron.com>"
   ```

2. **Add GitHub Actions secrets** to the ARK-OS repo:
   - `APT_GPG_PRIVATE_KEY`: output of `gpg --armor --export-secret-keys <keyid>`
   - `APT_GPG_PASSPHRASE`: passphrase for the key (if set)

3. **Enable GitHub Pages** on the repo: Settings > Pages > Source: `gh-pages` branch

4. **(Optional)** Configure custom domain `apt.arkelectron.com` pointing to GitHub Pages.
   If using a custom domain, update `REPO_URL` in `setup_apt_repo.sh`.

## Acceptance Criteria

- [ ] `apt update` successfully fetches package list from the ARK repo
- [ ] `apt install ark-companion-base` installs all ARK-OS packages with dependencies
- [ ] `apt upgrade` updates installed packages to latest version
- [ ] Release tags in CI automatically publish to the stable repo
- [ ] Packages are GPG-signed and `apt` verifies signatures
- [ ] Setup script works on fresh Jetson and Pi devices

## Dependencies

None — all P0 prerequisites are complete.

## Effort Estimate

Small. The files are implemented; remaining work is manual setup (GPG key, secrets,
GitHub Pages) and verification on a real device.
