# BuildKit Patches

This fork maintains production-ready patches on top of upstream BuildKit using a rebase workflow.

## How It Works

- **Master branch** = upstream BuildKit + our patches (always rebased on top)
- **Automatic discovery** = No manual tracking of patches
- **Releases** = Cherry-pick all our patches onto upstream release tags

## Current Patches

To see all patches we're carrying:
```bash
git log upstream/master..origin/master --oneline
```

### Example Patches
1. **History Database Corruption Recovery** - Prevents startup failures when history.db is corrupted
2. Additional patches added as needed via PRs to master

## Developer Workflow

1. Create fixes on feature branches
2. Open PRs against `master`
3. After merge, patches are automatically included in future releases

See [FORK_WORKFLOW.md](FORK_WORKFLOW.md) for detailed developer instructions.

## Creating a Release

```bash
# Create v0.17.0-blacksmith with all our patches
gh workflow run release-patched-version.yml -f upstream_version=v0.17.0

# Or via GitHub UI: Actions → Release Patched Version → Run workflow
```

The workflow automatically:
- Finds all commits in our master that aren't in upstream
- Cherry-picks them onto the upstream release
- Builds binaries for Linux/macOS (amd64/arm64)
- Creates GitHub release with artifacts

## Using Released Binaries

### Linux
```bash
# AMD64
curl -L https://github.com/useblacksmith/buildkit/releases/download/v0.17.0-blacksmith/buildkit-v0.17.0-blacksmith-linux-amd64.tar.gz | tar xz
sudo mv buildkitd buildctl /usr/local/bin/

# ARM64
curl -L https://github.com/useblacksmith/buildkit/releases/download/v0.17.0-blacksmith/buildkit-v0.17.0-blacksmith-linux-arm64.tar.gz | tar xz
sudo mv buildkitd buildctl /usr/local/bin/
```

### macOS
```bash
# Intel
curl -L https://github.com/useblacksmith/buildkit/releases/download/v0.17.0-blacksmith/buildkit-v0.17.0-blacksmith-darwin-amd64.tar.gz | tar xz
sudo mv buildctl /usr/local/bin/

# Apple Silicon
curl -L https://github.com/useblacksmith/buildkit/releases/download/v0.17.0-blacksmith/buildkit-v0.17.0-blacksmith-darwin-arm64.tar.gz | tar xz
sudo mv buildctl /usr/local/bin/
```

## Maintenance

### Keep master updated (weekly/monthly)
```bash
gh workflow run rebase-upstream.yml
```

This rebases our patches on top of latest upstream. When upstream merges one of our patches, it automatically disappears from our stack.

### Manual rebase if needed
```bash
git checkout master
git fetch upstream
git rebase upstream/master
git push origin master --force-with-lease
```