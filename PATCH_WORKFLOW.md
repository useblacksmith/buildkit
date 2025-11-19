# Multi-Patch Workflow Guide

This guide explains how to manage multiple patches as your fork grows.

## Workflow Strategy

### 1. Single Patches Branch
Maintain all your patches in one branch (`production-patches`) that diverges from upstream master:

```bash
# Initial setup
git checkout master
git pull upstream master
git checkout -b production-patches

# Add your patches (one commit per patch)
git cherry-pick <history-db-fix-commit>
git cherry-pick <another-fix-commit>
# ... more patches

git push origin production-patches
```

### 2. Naming Convention for Patches
Use prefixed commit messages for easy identification:

```bash
# Format: [PATCH_ID] Description

git commit -m "[HISTORY_DB] Add corruption recovery to history.db"
git commit -m "[CACHE_FIX] Fix cache eviction race condition"
git commit -m "[NETWORK] Add retry logic for registry pulls"
git commit -m "[PERF] Optimize layer deduplication"
```

### 3. Applying Patches to Releases

The workflow automatically:
1. Finds all commits in `production-patches` that aren't in upstream
2. Cherry-picks them one by one onto the target release
3. Reports which succeeded/failed
4. Creates a release with all successful patches

```bash
# Apply all patches
gh workflow run patch-and-release.yml \
  -f upstream_version=v0.17.0

# Skip specific patches if they don't apply to older versions
gh workflow run patch-and-release.yml \
  -f upstream_version=v0.16.0 \
  -f skip_patches="PERF,NETWORK"

# Use a different patches branch for experimental patches
gh workflow run patch-and-release.yml \
  -f upstream_version=v0.17.0 \
  -f patches_branch=experimental-patches
```

## Managing Growing Patch Sets

### Option 1: Single Production Branch (Recommended)
Keep all production patches in one branch:

```
upstream/master ──┬──────────────────────> v0.17.0 ──> v0.18.0
                  │
                  └──> production-patches
                       ├── [HISTORY_DB] Fix
                       ├── [CACHE_FIX] Fix
                       ├── [NETWORK] Fix
                       └── [PERF] Fix
```

**Pros:**
- Simple to manage
- Clear history
- Easy to see all patches

**Cons:**
- All patches must be compatible

### Option 2: Categorized Branches
Separate patches by category:

```
upstream/master ──┬──> stability-patches (critical fixes)
                  ├──> performance-patches (optimizations)
                  └──> feature-patches (new features)
```

Usage:
```bash
# For production - only stability
gh workflow run patch-and-release.yml \
  -f upstream_version=v0.17.0 \
  -f patches_branch=stability-patches

# For staging - stability + performance
# Run workflow twice and create different tags
```

### Option 3: Version-Specific Patches
When patches become version-specific:

```bash
# Create version-specific branch
git checkout -b patches-v0.17 v0.17.0
git cherry-pick <commits-that-work-on-0.17>
git push origin patches-v0.17

git checkout -b patches-v0.18 v0.18.0
git cherry-pick <commits-that-work-on-0.18>
git push origin patches-v0.18

# Use appropriate branch for each version
gh workflow run patch-and-release.yml \
  -f upstream_version=v0.17.0 \
  -f patches_branch=patches-v0.17
```

## Patch Maintenance

### Adding a New Patch
```bash
# 1. Create the fix on a feature branch
git checkout -b fix-something upstream/master
# ... make changes ...
git commit -m "[FIX_ID] Description of fix"

# 2. Add to production-patches
git checkout production-patches
git cherry-pick <commit-from-feature-branch>
git push origin production-patches

# 3. Now it will be included in all future releases
```

### Removing a Patch (when merged upstream)
```bash
git checkout production-patches
git rebase -i HEAD~10  # interactive rebase
# Delete the line with the merged patch
git push origin production-patches --force-with-lease
```

### Testing Patch Compatibility
Before adding to production-patches, test against multiple versions:

```bash
# Test if patch applies cleanly to different versions
for VERSION in v0.16.0 v0.17.0 v0.18.0; do
  echo "Testing $VERSION..."
  git checkout $VERSION
  if git cherry-pick <patch-commit>; then
    echo "✅ $VERSION: Compatible"
    git cherry-pick --abort
  else
    echo "❌ $VERSION: Incompatible"
    git cherry-pick --abort
  fi
done
```

## Best Practices

1. **One Patch Per Commit**: Each commit should be one logical fix
2. **Use Patch IDs**: Prefix commits with `[PATCH_ID]` for easy filtering
3. **Document Patches**: Keep PATCHES.md updated with what each patch does
4. **Test Before Adding**: Ensure patches apply to recent upstream versions
5. **Clean History**: Rebase and squash as needed to keep history clean

## Example: Managing 5 Patches

```bash
# Your production-patches branch has:
# - [HISTORY_DB] Add corruption recovery
# - [CACHE_FIX] Fix cache race condition
# - [NETWORK] Add registry retry logic
# - [PERF_DEDUPE] Optimize layer deduplication
# - [PERF_GC] Improve garbage collection

# Release for production (stability only)
gh workflow run patch-and-release.yml \
  -f upstream_version=v0.17.0 \
  -f skip_patches="PERF_DEDUPE,PERF_GC"

# Release for staging (all patches)
gh workflow run patch-and-release.yml \
  -f upstream_version=v0.17.0

# Release for old version (where NETWORK doesn't apply)
gh workflow run patch-and-release.yml \
  -f upstream_version=v0.16.0 \
  -f skip_patches="NETWORK"
```

## Troubleshooting

### Patch Doesn't Apply
- The workflow reports failed patches but continues with others
- Check GitHub Actions logs for conflict details
- Create version-specific patches if needed

### Re-running for Same Version
Delete the existing tag first:
```bash
git push origin :refs/tags/v0.17.0-blacksmith
# Then run workflow again
```

### Finding What Patches Are Available
```bash
# See all patches
git log upstream/master..origin/production-patches --oneline

# See patch IDs only
git log upstream/master..origin/production-patches --pretty=format:"%s" | grep -oE '^\[([A-Z_]+)\]' | sort -u
```