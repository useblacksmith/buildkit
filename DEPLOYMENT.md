# Deployment & Release Process

## Overview

This fork maintains patches on top of upstream BuildKit using a rebase workflow. Our `master` branch contains upstream BuildKit plus our custom patches rebased on top.

## Release Strategy

We use BuildKit's existing `buildkit.yml` workflow to build and release our patched versions. This ensures consistency with upstream's build process.

### Process:
1. **Prepare**: Use `prepare-patched-release.yml` to cherry-pick patches onto an upstream tag
2. **Review**: Check which patches were applied successfully
3. **Push**: Manually push the tag to trigger BuildKit's release workflow
4. **Release**: The existing `buildkit.yml` automatically builds and publishes binaries

## Creating a Patched Release

### Step 1: Prepare the Release

```bash
# Run the prepare workflow to cherry-pick patches
gh workflow run prepare-patched-release.yml -f upstream_version=v0.17.0
```

This workflow will:
1. Cherry-pick all patches from master onto v0.17.0
2. Create a local tag `v0.17.0-blacksmith`
3. Show you which patches succeeded/failed
4. Give you the exact commands to complete the release

### Step 2: Review and Push

Check the workflow output, then run locally:

```bash
# Clone and setup
git clone https://github.com/useblacksmith/buildkit.git
cd buildkit
git fetch --all --tags

# Push the tag (this triggers buildkit.yml)
git push origin v0.17.0-blacksmith

# The existing buildkit.yml workflow will now:
# - Build multi-platform binaries
# - Create Docker images
# - Publish a GitHub release
```

### Why This Approach?

- **No PAT complexity**: If your patches don't modify workflows, you can use regular git push
- **Uses upstream's build**: The existing `buildkit.yml` handles all the complex build logic
- **Manual control**: You review patches before pushing the release
- **Cleaner**: We don't duplicate BuildKit's release logic

## Keeping Synced with Upstream

Run weekly or monthly:

```bash
gh workflow run rebase-upstream.yml
```

This rebases our patches on top of the latest upstream master. When upstream merges one of our patches, it automatically disappears from our stack during the rebase.

## Manual Operations

### See Current Patches
```bash
git log upstream/master..origin/master --oneline
```

### Manual Rebase
```bash
git checkout master
git fetch upstream
git rebase upstream/master
git push origin master --force-with-lease
```

### Download Released Binaries
```bash
# Linux AMD64
curl -L https://github.com/useblacksmith/buildkit/releases/download/v0.17.0-blacksmith/buildkit-v0.17.0-blacksmith-linux-amd64.tar.gz | tar xz
sudo mv buildkitd buildctl /usr/local/bin/
```

## Adding New Patches

1. Create a feature branch from `master`
2. Make changes and commit
3. Open PR against `master`
4. After merge, the patch will be automatically included in all future releases