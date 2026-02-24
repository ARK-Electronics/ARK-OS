# P1: APT Repository for OTA Updates

## Problem

Currently, users install ARK-OS by either:
1. Running `install.sh` on-device (legacy, builds from source)
2. Downloading `.deb` files from GitHub Releases and manually installing with `dpkg`

There is no `apt update && apt upgrade` workflow for end users. This means no automatic
dependency resolution, no easy rollback, and a manual update process.

## Solution

Set up a hosted APT repository so devices can update with standard Debian tooling:

```bash
sudo apt update && sudo apt upgrade    # Updates all ARK packages
```

### Repository Structure

```
deb https://apt.arkelectron.com stable main       # Release builds
deb https://apt.arkelectron.com testing main       # PR/testing builds
```

## Files to Modify

| File | Change |
|------|--------|
| `.github/workflows/build.yml` | Add step to publish debs to APT repo after release |
| `packaging/build-packages.sh` | Add repo upload helper (optional) |
| New: `packaging/apt/` | GPG key management, repo config |
| New: `platform/common/scripts/setup_apt_repo.sh` | Add ARK repo to device sources |

## Implementation Steps

### Step 1: Choose hosting approach

Options (in order of simplicity):
1. **GitHub Pages + aptly** — Free, uses `gh-pages` branch as repo, `aptly` to manage
2. **S3 + CloudFront** — Scalable, standard for production APT repos
3. **Cloudsmith / Packagecloud** — Managed service, simplest but costs money

Recommended: Start with **GitHub Pages + aptly** for simplicity, migrate to S3 if needed.

### Step 2: Generate GPG signing key

```bash
gpg --full-generate-key    # RSA 4096, no expiry, "ARK Electronics <support@arkelectron.com>"
gpg --armor --export <keyid> > packaging/apt/ark-archive-keyring.gpg
```

Store the private key as a GitHub Actions secret (`APT_GPG_PRIVATE_KEY`).

### Step 3: Set up aptly repo structure

```bash
aptly repo create -distribution=stable -component=main ark-stable
aptly repo create -distribution=testing -component=main ark-testing
```

### Step 4: Update CI pipeline

Add a post-release job to `build.yml`:

```yaml
publish-apt:
  needs: [release]
  runs-on: ubuntu-latest
  if: startsWith(github.ref, 'refs/tags/v')
  steps:
    - name: Download release debs
      # ...
    - name: Add to aptly repo
      run: |
        aptly repo add ark-stable *.deb
        aptly publish update stable
    - name: Push to GitHub Pages
      # ...
```

### Step 5: Create device setup script

```bash
#!/bin/bash
# Add ARK APT repository to system
curl -fsSL https://apt.arkelectron.com/ark-archive-keyring.gpg | sudo tee /usr/share/keyrings/ark-archive-keyring.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/ark-archive-keyring.gpg] https://apt.arkelectron.com stable main" | sudo tee /etc/apt/sources.list.d/ark.list
sudo apt update
```

### Step 6: Add update check to system-manager

Optionally add an API endpoint in system-manager that checks for available updates:
```
GET /api/system/updates → {"available": true, "packages": [...]}
```

## Acceptance Criteria

- [ ] `apt update` successfully fetches package list from the ARK repo
- [ ] `apt install ark-companion` installs all ARK-OS packages with dependencies
- [ ] `apt upgrade` updates installed packages to latest version
- [ ] Release tags in CI automatically publish to the stable repo
- [ ] PR builds optionally publish to the testing repo
- [ ] Packages are GPG-signed and `apt` verifies signatures
- [ ] Setup script works on fresh Jetson and Pi devices

## Dependencies

None — can be done independently.

## Effort Estimate

Medium. The CI integration and GPG key management are the main effort. The aptly tool
handles most of the repo management complexity. Estimate 2-3 sessions for initial setup,
plus testing on actual devices.
