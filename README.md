# gh-workflow-hardener

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

**Secure your GitHub Actions workflows against supply chain attacks.** Detects unpinned actions (the tj-actions attack vector), dangerous permissions, and script injection — all in one scan.

After the [tj-actions supply chain attack](https://www.crowd.dev/blog/github-actions-supply-chain-attack) compromised 23k+ repositories, teams realized: GitHub Actions workflows are a security blind spot. This tool fixes that.

## What It Detects

### 🔴 Critical Issues
- **Unpinned actions** — Actions without commit SHA pinning are vulnerable to malicious tag rewrites. Example:
  ```yaml
  - uses: actions/checkout@v3  # 🔴 VULNERABLE — pinned to tag, not SHA
  - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45aca646fdde3  # ✅ SAFE
  ```
- **Dangerous permissions** — Overly broad permissions (`permissions: write-all` or missing explicit deny). Example:
  ```yaml
  permissions:
    contents: write
    issues: write
    pull-requests: write  # Is this really needed?
  ```
- **Script injection** — Run steps with unsanitized inputs from PRs. Example:
  ```yaml
  - run: echo ${{ github.event.pull_request.title }}  # 🔴 VULNERABLE
  ```

### 🟡 High/Medium Issues
- Missing `permissions` block (defaults to broad access)
- Secrets passed as environment variables (use `secrets:` instead)
- Suspicious use of `github.token` in external actions

### 📋 Low Issues
- Deprecated action versions
- Missing checkout step before build
- Unreviewed third-party actions

## Installation

### As a CLI tool

**Option 1: Homebrew (macOS & Linux)**
```bash
brew tap indoor47/homebrew-gh-workflow-hardener
brew install gh-workflow-hardener
```

**Option 2: pip**
```bash
pip install gh-workflow-hardener
```

### As a GitHub Action (recommended)

Add to `.github/workflows/security-check.yml`:

```yaml
name: Workflow Security Check
on:
  pull_request:
    paths:
      - '.github/workflows/**'
  push:
    branches:
      - main
    paths:
      - '.github/workflows/**'

permissions:
  contents: read

jobs:
  hardener:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45aca646fdde3
      - uses: indoor47/gh-workflow-hardener@v1.0.0
        with:
          fail_on: critical
```

## Usage

### CLI

```bash
# Scan current repository (expects .github/workflows/)
gh-workflow-hardener

# Scan a specific repository
gh-workflow-hardener /path/to/repo

# Output as JSON (for CI integration)
gh-workflow-hardener --format json

# Output as SARIF (for GitHub Code Scanning)
gh-workflow-hardener --format sarif

# Auto-fix unpinned actions by resolving tags to commit SHAs
gh-workflow-hardener --fix --token $GITHUB_TOKEN

# Fail only on critical + high severity issues
gh-workflow-hardener --fail-on high
```

### Example Output

```
GitHub Actions Workflow Security Report
=========================================

.github/workflows/build.yml
  [CRITICAL] Line 12: Unpinned action: actions/checkout@v3
    → Pin to: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45aca646fdde3

  [HIGH] Line 45: Overly broad permissions
    → Found: permissions: write-all
    → Fix: Specify only needed permissions

.github/workflows/deploy.yml
  [MEDIUM] Line 8: Secrets passed as env var
    → Use: secrets: { AWS_KEY: ${{ secrets.AWS_KEY }} }

=========================================
Issues: 3 critical, 1 high, 1 medium
Status: FAIL (--fail-on critical)
```

## Why This Matters

The tj-actions attack showed that a single compromised action can:
- Steal repository secrets and tokens
- Modify code in pull requests
- Exfiltrate source code
- Inject malicious dependencies

By pinning actions to specific commit SHAs and validating permissions, you eliminate entire attack vectors.

## GitHub Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `fail_on` | `critical` | Exit with error if findings at this severity or above. Options: `critical`, `high`, `medium`, `low`, `none` |
| `format` | `text` | Output format: `text`, `json`, `markdown`, `sarif` |
| `fix` | `false` | Auto-fix unpinned actions by pinning to commit SHAs |
| `github_token` | `${{ github.token }}` | GitHub token for SHA resolution (needed for auto-fix) |

## Zero Dependencies (CLI)

The CLI requires only `pyyaml` and `click`. No heavy scanning frameworks, no bloat. Fast. Auditable.

## VS Code Extension

Prefer catching issues as you type? The companion [**GitHub Workflow Hardener**](https://github.com/indoor47/vscode-workflow-hardener) VS Code extension runs the same checks inline while you edit `.github/workflows/` files — no CLI needed.

## Contributing

Found a false positive? Have a better detection rule? Open an issue or PR.

## License

MIT
