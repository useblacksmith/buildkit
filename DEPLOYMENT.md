# Deployment & Release Process

## Overview

This fork maintains patches on top of upstream BuildKit. We use a single automated workflow to create releases.

## Creating a Patched Release

### One Command

```bash
# Create a release based on upstream v0.17.0
gh workflow run create-patched-release.yml -f upstream_version=v0.17.0
```

The workflow will:
1. Cherry-pick all your patches from master onto v0.17.0
2. Create and push tag `v0.17.0-blacksmith`
3. Trigger `buildkit.yml` which automatically:
   - Builds multi-platform binaries (Linux/macOS, amd64/arm64)
   - Creates Docker images
   - Publishes a GitHub release with artifacts

### Monitor Progress

After running the workflow, monitor the release at:
- Actions: https://github.com/useblacksmith/buildkit/actions
- Releases: https://github.com/useblacksmith/buildkit/releases

## Manual Upstream Sync

To keep your patches rebased on upstream:

```bash
git checkout master
git fetch upstream
git rebase upstream/master
git push origin master --force-with-lease
```

## Tips

### See Your Patches
```bash
# View all patches not in upstream
git log upstream/master..origin/master --oneline
```

### Add New Patches
1. Create a feature branch from `master`
2. Make changes and commit
3. Open PR against `master`
4. After merge, the patch will be included in future releases

### Download Released Binaries
Releases are available at: https://github.com/useblacksmith/buildkit/releases