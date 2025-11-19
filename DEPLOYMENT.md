# Deployment & Release Process

## Overview

This fork maintains patches on top of upstream BuildKit. We use a simple two-step process to create releases:

1. **Prepare**: GitHub Actions cherry-picks patches onto an upstream release tag
2. **Release**: Push the tag locally to trigger BuildKit's existing release workflow

## Creating a Patched Release

### Step 1: Prepare the Release

```bash
# Run the workflow to prepare a release based on upstream v0.17.0
gh workflow run prepare-patched-release.yml -f upstream_version=v0.17.0
```

The workflow will:
- Cherry-pick all your patches from master onto v0.17.0
- Create a tag `v0.17.0-blacksmith`
- Show which patches succeeded/failed
- Provide exact commands to complete the release

### Step 2: Push the Tag

After reviewing the workflow output, run locally:

```bash
# Clone and fetch
git clone https://github.com/useblacksmith/buildkit.git
cd buildkit
git fetch --all --tags

# Push the tag - this triggers buildkit.yml
git push origin v0.17.0-blacksmith
```

The existing `buildkit.yml` workflow automatically:
- Builds multi-platform binaries (Linux/macOS, amd64/arm64)
- Creates Docker images
- Publishes a GitHub release with artifacts

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