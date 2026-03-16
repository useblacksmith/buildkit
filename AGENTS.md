# Agent Guidelines for BuildKit

This document outlines conventions and hygiene practices for AI agents contributing to this repository.

## GitHub Operations

Prefer using the GitHub CLI (`gh`) for GitHub operations when possible:

- Use `gh pr create` for creating pull requests
- Use `gh issue list` for viewing issues
- Use `gh pr checkout` for checking out pull requests

## Commit and PR Conventions

### Commit Messages

- Use lowercase for commit message subjects
- Prefix with the package name: `package: one-line summary`
- Examples:
  - `boltutil: sync database on close to prevent corruption`
  - `solver: fix cache key computation for multi-platform builds`
  - `cmd/buildkitd: add graceful shutdown timeout flag`

### Pull Request Titles

- Follow the same format as commit messages
- Use lowercase
- Prefix with the package name: `package: one-line summary`

## Code Formatting

Before creating or updating commits:

1. Run `gofmt` on all modified Go files
2. Ensure imports are properly organized
3. Fix any linting issues

```bash
# Format all modified files
gofmt -w .

# Or format specific files
gofmt -w path/to/file.go
```

## Code Style

- **Comments**: Don't comment obvious code. Do add concise comments when the rationale (the "why") behind a decision isn't obvious from the code itself — e.g., non-obvious business rules, workarounds, performance trade-offs, or constraints that would require digging through history to understand

## Workflow Summary

1. Create a branch from `master`
2. Make changes
3. Run `gofmt -w .` to format code
4. Commit with proper message format: `package: description`
5. Push branch
6. Create PR with `gh pr create` using lowercase title
