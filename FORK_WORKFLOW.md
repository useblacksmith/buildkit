# Fork Workflow Guide

This document explains how we maintain our BuildKit fork with custom patches.

## Overview

We use a **rebase workflow** where:
- `master` branch = upstream BuildKit + our patches (always on top)
- Patches are automatically discovered (no manual tracking)
- Releases are created by cherry-picking our patches onto upstream tags

## Developer Workflow

### 1. Setting Up
```bash
# Clone the fork
git clone git@github.com:useblacksmith/buildkit.git
cd buildkit

# Add upstream remote
git remote add upstream https://github.com/moby/buildkit.git
```

### 2. Developing a Fix
```bash
# Start from master
git checkout master
git pull origin master

# Create your fix
git checkout -b fix/something-broken
# ... make changes ...
git commit -m "Fix something that was broken"

# Open PR against master
gh pr create --base master
```

### 3. After PR is Merged
Your fix is now part of `master` and will automatically be included in all future releases.

## Maintainer Workflow

### 1. Keep Master Updated (Weekly/Monthly)
```bash
# Option A: Run GitHub Action
gh workflow run rebase-upstream.yml

# Option B: Do it manually
git checkout master
git fetch upstream
git rebase upstream/master
git push origin master --force-with-lease
```

**What happens during rebase:**
- All our patches stay on top of upstream
- If upstream merged one of our fixes, it automatically disappears from our patch set
- If there are conflicts, you'll need to resolve them

### 2. Create a Patched Release
```bash
# Release v0.17.0 with all our patches
gh workflow run release-patched-version.yml -f upstream_version=v0.17.0
```

**What the workflow does:**
1. Checks out upstream `v0.17.0`
2. Finds all commits in `origin/master` that aren't in `upstream/master`
3. Cherry-picks each patch onto v0.17.0
4. Builds binaries for Linux/macOS (amd64/arm64)
5. Creates GitHub release with downloadable artifacts

## How It Works

### The Magic: Git Knows Your Patches
```bash
# These are YOUR patches (commits in origin/master but not upstream/master)
git log upstream/master..origin/master --oneline

# Example output:
abc123 Fix history.db corruption recovery
def456 Add retry logic for registry timeout
789012 Optimize cache eviction
```

When you run the release workflow for `v0.17.0`, it automatically:
- Takes these 3 commits
- Applies them to `v0.17.0`
- Creates `v0.17.0-blacksmith`

### Automatic Cleanup
When upstream merges one of your patches:
1. Next rebase detects the duplicate
2. Git automatically drops it from your stack
3. You don't need to do anything

## Example Scenario

### Day 1: You have 3 patches
```
upstream/master: A──B──C
origin/master:   A──B──C──X──Y──Z (your 3 patches)
```

### Day 30: Upstream merged patch X
```
upstream/master: A──B──C──D──E──X'
origin/master:   A──B──C──D──E──X'──Y──Z (only 2 patches now!)
```

After rebase, Git automatically detected X was merged and removed it from your stack.

### Creating v0.17.0-blacksmith
```
upstream/v0.17.0: A──B
v0.17.0-blacksmith: A──B──Y──Z (your remaining patches applied)
```

## FAQ

### Q: What if a patch doesn't apply to an old version?
The workflow continues with patches that do apply. The release notes show which patches were included.

### Q: How do I see what patches we're carrying?
```bash
git log upstream/master..origin/master --oneline
```

### Q: How do I remove a patch that's no longer needed?
```bash
git rebase -i upstream/master
# Delete the line with the patch you don't want
```

### Q: What if rebase has conflicts?
Resolve them normally:
```bash
git rebase upstream/master
# Fix conflicts in your editor
git add .
git rebase --continue
git push origin master --force-with-lease
```

## Benefits of This Approach

1. **No manual tracking** - Git tracks everything
2. **No special branches** - Just master + releases
3. **Automatic cleanup** - Merged patches disappear automatically
4. **Simple mental model** - "Our patches on top of upstream"
5. **Battle-tested** - Used by Chromium, Android, Linux distros

## Commands Summary

```bash
# Keep master updated
gh workflow run rebase-upstream.yml

# Create a release
gh workflow run release-patched-version.yml -f upstream_version=v0.17.0

# See your patches
git log upstream/master..origin/master --oneline

# Manual rebase
git rebase upstream/master && git push origin master --force-with-lease
```