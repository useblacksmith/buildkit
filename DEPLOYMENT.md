# Deployment & Release Process

## Overview

This fork maintains patches on top of upstream BuildKit using a rebase workflow. Our `master` branch contains upstream BuildKit plus our custom patches rebased on top.

## Creating a Patched Release

To deploy a patched version of BuildKit:

```bash
# Create release for v0.17.0 with all our patches
gh workflow run release-patched-version.yml -f upstream_version=v0.17.0
```

This workflow:
1. Finds all commits in `origin/master` that aren't in `upstream/master` (our patches)
2. Cherry-picks each patch onto the upstream version tag
3. Builds binaries for Linux and macOS (amd64/arm64)
4. Creates a GitHub release with downloadable artifacts

The release will be tagged as `v0.17.0-blacksmith`.

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