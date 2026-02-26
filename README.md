# gh-workflow-hardener

GitHub Actions security scanner — pins actions to SHA hashes, detects permission issues, flags script injection.

Targets the supply chain attack surface of GitHub Actions workflows. Ensures actions are pinned to specific commit hashes instead of mutable tags, validates permission scopes, and detects script injection vulnerabilities in workflow files.

## Quick Start

```bash
gh-workflow-hardener --path .github/workflows
```

## License

MIT
