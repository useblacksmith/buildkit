# BuildKit Patches

This fork maintains production-ready patches on top of upstream BuildKit releases.

## Active Patches

### 1. History Database Corruption Recovery
- **Branch**: `fix-history-db-corruption`
- **Status**: Pending upstream review
- **PR**: [TBD - to be submitted]

**Description**: Adds automatic corruption recovery to `history.db` to match the existing recovery mechanism in `cache.db`. This prevents BuildKit from failing to start when the history database is corrupted, which commonly occurs with abrupt shutdowns or when using network block devices with snapshots.

**Files Modified**:
- `cmd/buildkitd/main.go` - Use SafeOpen for history.db
- `solver/bboltcachestorage/storage.go` - Switch to shared SafeOpen
- `util/db/boltutil/safe_open.go` - New shared recovery logic

## Patching Process

This repository uses GitHub Actions for manual patch and release:

1. **Trigger workflow** - Manually specify upstream version to patch
2. **Apply patches** - Cherry-picks patches onto the specified release
3. **Build binaries** - Multi-platform binaries for Linux and macOS (amd64, arm64)
4. **Create GitHub release** - With downloadable binaries and checksums

## Version Naming Convention

Patched versions use the suffix `-blacksmith`:
- Upstream: `v0.17.0`
- Patched: `v0.17.0-blacksmith`

## Using Patched Releases

### Download Binaries
```bash
# Linux AMD64
wget https://github.com/useblacksmith/buildkit/releases/download/v0.17.0-blacksmith/buildkit-v0.17.0-blacksmith-linux-amd64.tar.gz
tar -xzf buildkit-v0.17.0-blacksmith-linux-amd64.tar.gz
sudo mv buildkitd buildctl /usr/local/bin/

# macOS Apple Silicon
wget https://github.com/useblacksmith/buildkit/releases/download/v0.17.0-blacksmith/buildkit-v0.17.0-blacksmith-darwin-arm64.tar.gz
tar -xzf buildkit-v0.17.0-blacksmith-darwin-arm64.tar.gz
sudo mv buildctl /usr/local/bin/
```

## Creating a Patched Release

To patch a specific upstream version:

```bash
# Using GitHub CLI
gh workflow run patch-and-release.yml -f upstream_version=v0.17.0

# Or via GitHub UI
# Go to Actions → Patch and Release BuildKit → Run workflow
# Enter the upstream version (e.g., v0.17.0)
```

## Verification

All releases include SHA256 checksums:

```bash
# Download and verify
wget https://github.com/useblacksmith/buildkit/releases/download/v0.17.0-blacksmith/SHA256SUMS
sha256sum -c SHA256SUMS
```

## Contributing

When adding new patches:
1. Create a feature branch from master
2. Make your changes
3. Update this file with patch details
4. Update the `PATCH_BRANCH` in the workflow if creating a new patch type