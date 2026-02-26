#!/usr/bin/env python3
"""gh-workflow-hardener - GitHub Actions Workflow Security Scanner

Finds and fixes security issues in your GitHub Actions workflows:
- Unpinned action references (supply chain risk)
- Missing or overly broad permissions
- Script injection vulnerabilities
- Insecure checkout configurations

Zero dependencies. Python 3.8+ stdlib only.
"""

import os
import sys
import re
import json
import glob as glob_mod
import urllib.request
import urllib.error
from pathlib import Path

__version__ = "1.0.0"

# ============================================================
# Patterns
# ============================================================

# Matches action references: uses: owner/repo@ref or uses: owner/repo/path@ref
USES_RE = re.compile(
    r'^(\s*-?\s*uses:\s*)'
    r'([a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)'
    r'@(\S+)',
)

# 40-char hex SHA
SHA_RE = re.compile(r'^[0-9a-f]{40}$')

# GitHub expression syntax
EXPR_RE = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')

# Untrusted GitHub context values that attackers can control
UNTRUSTED_CONTEXTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.commits",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages",
    "github.head_ref",
]

# Build regex from untrusted contexts (escape dots, handle array indexing)
UNTRUSTED_RE = re.compile(
    '|'.join(
        c.replace('.', r'\.').replace('[*]', r'\[\d+\]')
        for c in UNTRUSTED_CONTEXTS
    )
)


# ============================================================
# Scanners
# ============================================================

def scan_unpinned_actions(lines, filepath):
    """Find action references not pinned to a full commit SHA."""
    findings = []
    for line_num, line in enumerate(lines, 1):
        m = USES_RE.match(line)
        if not m:
            continue
        action = m.group(2)
        ref = m.group(3)
        # Strip inline comment
        if " #" in ref:
            ref = ref.split(" #")[0].strip()
        if "#" in ref and not ref.startswith("#"):
            ref = ref.split("#")[0].strip()
        # Skip local actions (./path)
        if action.startswith("."):
            continue
        # Skip Docker references
        if action.startswith("docker://"):
            continue
        if not SHA_RE.match(ref):
            findings.append({
                "file": filepath,
                "line": line_num,
                "check": "unpinned-action",
                "severity": "critical",
                "message": (
                    f"Action `{action}@{ref}` is not pinned to a commit SHA. "
                    f"Tags and branches can be moved to point to malicious code. "
                    f"See: tj-actions/changed-files supply chain attack (March 2025)."
                ),
                "fix": f"Pin to SHA: `uses: {action}@<commit-sha>  # {ref}`",
                "action": action,
                "ref": ref,
            })
    return findings


def scan_permissions(lines, filepath):
    """Check for missing or overly broad permissions."""
    findings = []
    has_top_level_perms = False
    in_jobs = False
    current_job = None
    job_indent = -1
    jobs_with_perms = set()

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        # Top-level permissions (0 or 1 indent)
        if indent == 0 and stripped.startswith("permissions"):
            has_top_level_perms = True
            if "write-all" in stripped:
                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "check": "broad-permissions",
                    "severity": "high",
                    "message": (
                        "Workflow uses `permissions: write-all`. "
                        "This grants the GITHUB_TOKEN full read-write access to all scopes. "
                        "Use least-privilege permissions instead."
                    ),
                    "fix": "Replace with specific permissions, e.g.:\npermissions:\n  contents: read\n  pull-requests: write",
                })

        # Track jobs section
        if indent == 0 and stripped.startswith("jobs"):
            in_jobs = True
            continue

        # Track individual jobs (indented under jobs:)
        if in_jobs and indent == 2 and stripped.endswith(":") and not stripped.startswith("-") and not stripped.startswith("#"):
            current_job = stripped.rstrip(":").strip()
            job_indent = indent

        # Track job-level permissions
        if current_job and indent == 4 and stripped.startswith("permissions"):
            jobs_with_perms.add(current_job)
            if "write-all" in stripped:
                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "check": "broad-permissions",
                    "severity": "high",
                    "message": (
                        f"Job `{current_job}` uses `permissions: write-all`. "
                        f"Use least-privilege permissions instead."
                    ),
                    "fix": "Replace with specific permissions for this job.",
                })

    # No permissions block at all
    if not has_top_level_perms:
        findings.append({
            "file": filepath,
            "line": 1,
            "check": "missing-permissions",
            "severity": "high",
            "message": (
                "No top-level `permissions` block defined. "
                "Without explicit permissions, the GITHUB_TOKEN gets the repository's default permissions "
                "(often read-write). Add a top-level permissions block."
            ),
            "fix": "Add at the top level:\npermissions:\n  contents: read",
        })

    return findings


def scan_script_injection(lines, filepath):
    """Find untrusted inputs used directly in run: blocks (shell injection risk)."""
    findings = []
    in_run = False
    run_indent = 0

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        # Detect start of run: block (handles both `run:` and `- run:`)
        run_match = re.match(r'^(\s*(?:-\s+)?)run\s*:\s*(.*)', line)
        if run_match:
            run_indent = len(run_match.group(1))
            inline_content = run_match.group(2).strip()
            # Single-line run (no | or >)
            if inline_content and inline_content not in ("|", "|+", "|-", ">", ">-", ">+"):
                _check_line_for_injection(inline_content, line_num, filepath, findings)
                in_run = False
            else:
                in_run = bool(inline_content)  # True if | or >
            continue

        # Inside multiline run block
        if in_run:
            if stripped == "" or indent > run_indent:
                _check_line_for_injection(line, line_num, filepath, findings)
            else:
                in_run = False

    return findings


def _check_line_for_injection(line, line_num, filepath, findings):
    """Check a single line for untrusted GitHub expression usage."""
    for expr_match in EXPR_RE.finditer(line):
        expr = expr_match.group(1).strip()
        if UNTRUSTED_RE.search(expr):
            findings.append({
                "file": filepath,
                "line": line_num,
                "check": "script-injection",
                "severity": "critical",
                "message": (
                    f"Untrusted input `${{{{ {expr} }}}}` used in a `run:` block. "
                    f"An attacker can inject arbitrary shell commands through this value. "
                    f"Assign to an environment variable and reference it as `$ENV_VAR` instead."
                ),
                "fix": (
                    f"Move to env block:\n"
                    f"  env:\n"
                    f"    UNTRUSTED_INPUT: ${{{{ {expr} }}}}\n"
                    f"  run: echo \"$UNTRUSTED_INPUT\""
                ),
            })


def scan_insecure_checkout(lines, filepath):
    """Find actions/checkout without persist-credentials: false."""
    findings = []

    for line_num, line in enumerate(lines, 1):
        if not re.match(r'^\s*-?\s*uses:\s*actions/checkout@', line):
            continue

        # Look ahead for persist-credentials in the with: block
        has_persist_false = False
        found_with = False
        step_indent = len(line) - len(line.lstrip())

        for i in range(line_num, min(line_num + 15, len(lines))):
            next_line = lines[i]
            next_stripped = next_line.strip()
            next_indent = len(next_line) - len(next_line.lstrip())

            # Hit next step or lower indent block
            if i > line_num - 1 and next_stripped.startswith("- ") and next_indent <= step_indent:
                break

            if "with:" in next_stripped:
                found_with = True

            if "persist-credentials" in next_stripped and "false" in next_stripped:
                has_persist_false = True
                break

        if not has_persist_false:
            findings.append({
                "file": filepath,
                "line": line_num,
                "check": "insecure-checkout",
                "severity": "medium",
                "message": (
                    "actions/checkout without `persist-credentials: false` leaves "
                    "the GITHUB_TOKEN in the git config. Subsequent steps "
                    "(including third-party actions) can read it."
                ),
                "fix": "Add to the checkout step:\n  with:\n    persist-credentials: false",
            })

    return findings


# ============================================================
# Scanner orchestrator
# ============================================================

def scan_file(content, filepath):
    """Run all checks on a single workflow file."""
    lines = content.splitlines()
    findings = []
    findings.extend(scan_unpinned_actions(lines, filepath))
    findings.extend(scan_permissions(lines, filepath))
    findings.extend(scan_script_injection(lines, filepath))
    findings.extend(scan_insecure_checkout(lines, filepath))
    return findings


def scan_directory(path):
    """Scan all workflow files in .github/workflows/."""
    workflow_dir = os.path.join(path, ".github", "workflows")

    if not os.path.isdir(workflow_dir):
        print(f"Error: No .github/workflows/ directory found at {path}", file=sys.stderr)
        return {"files_scanned": 0, "findings": [], "score": 100}

    all_findings = []
    files_scanned = 0

    patterns = [os.path.join(workflow_dir, "*.yml"), os.path.join(workflow_dir, "*.yaml")]
    workflow_files = sorted(set(
        f for pattern in patterns for f in glob_mod.glob(pattern)
    ))

    for filepath in workflow_files:
        files_scanned += 1
        try:
            with open(filepath, "r") as f:
                content = f.read()
        except (IOError, OSError) as e:
            print(f"Warning: Could not read {filepath}: {e}", file=sys.stderr)
            continue

        rel_path = os.path.relpath(filepath, path)
        all_findings.extend(scan_file(content, rel_path))

    # Calculate security score
    score = 100
    for f in all_findings:
        if f["severity"] == "critical":
            score -= 15
        elif f["severity"] == "high":
            score -= 10
        elif f["severity"] == "medium":
            score -= 5
        else:
            score -= 2
    score = max(0, score)

    return {
        "files_scanned": files_scanned,
        "findings": all_findings,
        "score": score,
    }


# ============================================================
# SHA Resolution (for --fix mode)
# ============================================================

_sha_cache = {}


def resolve_sha(action, ref, token=None):
    """Resolve an action reference to a commit SHA via GitHub API."""
    cache_key = f"{action}@{ref}"
    if cache_key in _sha_cache:
        return _sha_cache[cache_key]

    # Handle path-based actions (owner/repo/path → owner/repo)
    parts = action.split("/")
    if len(parts) >= 2:
        owner_repo = f"{parts[0]}/{parts[1]}"
    else:
        return None

    url = f"https://api.github.com/repos/{owner_repo}/commits/{ref}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "gh-workflow-hardener",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            sha = data["sha"]
            _sha_cache[cache_key] = sha
            return sha
    except (urllib.error.HTTPError, urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
        print(f"Warning: Could not resolve {cache_key}: {e}", file=sys.stderr)
        return None


def fix_unpinned_actions(path, findings, token=None):
    """Auto-fix unpinned actions by resolving and pinning to SHAs."""
    # Group findings by file
    by_file = {}
    for f in findings:
        if f["check"] != "unpinned-action":
            continue
        by_file.setdefault(f["file"], []).append(f)

    fixed_count = 0
    for rel_path, file_findings in by_file.items():
        filepath = os.path.join(path, rel_path)
        with open(filepath, "r") as fh:
            lines = fh.readlines()

        changed = False
        for finding in file_findings:
            line_idx = finding["line"] - 1
            action = finding["action"]
            ref = finding["ref"]

            sha = resolve_sha(action, ref, token)
            if not sha:
                continue

            old_line = lines[line_idx]
            # Replace @ref with @sha # ref
            new_line = re.sub(
                rf'(@){re.escape(ref)}(\s*(?:#.*)?)$',
                f'@{sha}  # {ref}',
                old_line.rstrip(),
            ) + "\n"

            if new_line != old_line:
                lines[line_idx] = new_line
                changed = True
                fixed_count += 1

        if changed:
            with open(filepath, "w") as fh:
                fh.writelines(lines)

    return fixed_count


# ============================================================
# Output formatters
# ============================================================

SEVERITY_ICONS = {
    "critical": "\u2622\ufe0f",  # radioactive
    "high": "\U0001f534",       # red circle
    "medium": "\U0001f7e0",     # orange circle
    "low": "\U0001f7e1",        # yellow circle
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def format_text(result):
    """Plain text output for terminals."""
    lines = []
    lines.append(f"gh-workflow-hardener v{__version__}")
    lines.append(f"Security Score: {result['score']}/100")
    lines.append(f"Files scanned: {result['files_scanned']}")
    lines.append(f"Issues found: {len(result['findings'])}")
    lines.append("")

    if not result["findings"]:
        lines.append("No security issues found. Your workflows look good!")
        return "\n".join(lines)

    # Sort by severity
    sorted_findings = sorted(result["findings"], key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    for f in sorted_findings:
        sev = f["severity"].upper()
        lines.append(f"[{sev}] {f['file']}:{f['line']}")
        lines.append(f"  Check: {f['check']}")
        lines.append(f"  {f['message']}")
        if f.get("fix"):
            lines.append(f"  Fix: {f['fix']}")
        lines.append("")

    return "\n".join(lines)


def format_json(result):
    """JSON output."""
    # Remove internal fields
    clean = {
        "version": __version__,
        "score": result["score"],
        "files_scanned": result["files_scanned"],
        "findings": [
            {k: v for k, v in f.items() if k not in ("action", "ref")}
            for f in result["findings"]
        ],
    }
    return json.dumps(clean, indent=2)


def format_markdown(result):
    """Markdown output for GitHub step summaries."""
    lines = []
    score = result["score"]
    count = len(result["findings"])

    # Score badge
    if score >= 80:
        grade = "A"
    elif score >= 60:
        grade = "B"
    elif score >= 40:
        grade = "C"
    elif score >= 20:
        grade = "D"
    else:
        grade = "F"

    lines.append(f"## Workflow Security Report")
    lines.append("")
    lines.append(f"**Score: {score}/100 (Grade: {grade})**")
    lines.append(f"**Files scanned:** {result['files_scanned']} | **Issues found:** {count}")
    lines.append("")

    if not result["findings"]:
        lines.append("No security issues found. Your workflows are hardened!")
        return "\n".join(lines)

    # Group by severity
    by_severity = {}
    for f in result["findings"]:
        by_severity.setdefault(f["severity"], []).append(f)

    for sev in ["critical", "high", "medium", "low"]:
        if sev not in by_severity:
            continue
        icon = SEVERITY_ICONS.get(sev, "")
        lines.append(f"### {icon} {sev.title()} ({len(by_severity[sev])})")
        lines.append("")

        for f in by_severity[sev]:
            lines.append(f"**{f['file']}:{f['line']}** - `{f['check']}`")
            lines.append(f"> {f['message']}")
            if f.get("fix"):
                lines.append(f"")
                lines.append(f"<details><summary>Suggested fix</summary>")
                lines.append(f"")
                lines.append(f"```yaml")
                lines.append(f"{f['fix']}")
                lines.append(f"```")
                lines.append(f"</details>")
            lines.append("")

    lines.append("---")
    lines.append(f"*Generated by [gh-workflow-hardener](https://github.com/indoor47/gh-workflow-hardener) v{__version__}*")

    return "\n".join(lines)


def format_sarif(result):
    """SARIF 2.1.0 output for GitHub Code Scanning integration."""
    rules = {}
    results = []

    for f in result["findings"]:
        rule_id = f["check"]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": rule_id.replace("-", " ").title()},
                "defaultConfiguration": {
                    "level": "error" if f["severity"] in ("critical", "high") else "warning"
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": "error" if f["severity"] in ("critical", "high") else "warning",
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": f["line"]},
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "gh-workflow-hardener",
                    "version": __version__,
                    "informationUri": "https://github.com/indoor47/gh-workflow-hardener",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    return json.dumps(sarif, indent=2)


# ============================================================
# GitHub Action integration
# ============================================================

def set_output(name, value):
    """Set a GitHub Actions output variable."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            # Handle multiline values
            if "\n" in str(value):
                import uuid
                delimiter = uuid.uuid4().hex
                f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
            else:
                f.write(f"{name}={value}\n")


def write_step_summary(content):
    """Write to GitHub Actions step summary."""
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write(content + "\n")


def run_action():
    """Run as a GitHub Action."""
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    fail_on = os.environ.get("INPUT_FAIL_ON", "critical").lower()
    output_format = os.environ.get("INPUT_FORMAT", "text").lower()
    do_fix = os.environ.get("INPUT_FIX", "false").lower() == "true"
    token = os.environ.get("INPUT_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")

    result = scan_directory(workspace)

    # Write step summary (always markdown)
    write_step_summary(format_markdown(result))

    # Set outputs
    set_output("score", result["score"])
    set_output("findings-count", len(result["findings"]))
    set_output("findings", format_json(result))

    # Write SARIF if requested
    if output_format == "sarif":
        sarif_path = os.path.join(workspace, "workflow-hardener.sarif")
        with open(sarif_path, "w") as f:
            f.write(format_sarif(result))
        set_output("sarif-file", sarif_path)
        print(f"SARIF report written to {sarif_path}")

    # Auto-fix if requested
    if do_fix:
        fixed = fix_unpinned_actions(workspace, result["findings"], token)
        if fixed:
            print(f"Fixed {fixed} unpinned action reference(s)")
            set_output("fixed-count", fixed)

    # Print text report
    print(format_text(result))

    # Determine exit code
    if fail_on == "none":
        return 0

    severity_threshold = SEVERITY_ORDER.get(fail_on, 0)
    for f in result["findings"]:
        if SEVERITY_ORDER.get(f["severity"], 99) <= severity_threshold:
            return 1

    return 0


# ============================================================
# CLI
# ============================================================

def print_usage():
    print(f"gh-workflow-hardener v{__version__}")
    print()
    print("Usage: hardener.py [OPTIONS] [PATH]")
    print()
    print("Scan GitHub Actions workflows for security issues.")
    print()
    print("Arguments:")
    print("  PATH                Repository root (default: current directory)")
    print()
    print("Options:")
    print("  --format FORMAT     Output format: text, json, markdown, sarif (default: text)")
    print("  --fix               Auto-fix unpinned actions by pinning to commit SHAs")
    print("  --fail-on SEVERITY  Exit 1 if findings at this severity or above")
    print("                      Options: critical, high, medium, low, none (default: critical)")
    print("  --token TOKEN       GitHub token for SHA resolution (or set GITHUB_TOKEN)")
    print("  --version           Show version")
    print("  --help              Show this help")


def run_cli(args):
    """Run as a CLI tool."""
    # Parse args
    path = "."
    output_format = "text"
    do_fix = False
    fail_on = "critical"
    token = os.environ.get("GITHUB_TOKEN")

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--format" and i + 1 < len(args):
            output_format = args[i + 1].lower()
            i += 2
        elif arg == "--fix":
            do_fix = True
            i += 1
        elif arg == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1].lower()
            i += 2
        elif arg == "--token" and i + 1 < len(args):
            token = args[i + 1]
            i += 2
        elif arg == "--version":
            print(f"gh-workflow-hardener v{__version__}")
            return 0
        elif arg in ("--help", "-h"):
            print_usage()
            return 0
        elif not arg.startswith("-"):
            path = arg
            i += 1
        else:
            print(f"Unknown option: {arg}", file=sys.stderr)
            print_usage()
            return 2

    result = scan_directory(path)

    # Auto-fix
    if do_fix:
        fixed = fix_unpinned_actions(path, result["findings"], token)
        if fixed:
            print(f"Fixed {fixed} unpinned action reference(s)", file=sys.stderr)
            # Re-scan after fix
            result = scan_directory(path)

    # Output
    formatters = {
        "text": format_text,
        "json": format_json,
        "markdown": format_markdown,
        "sarif": format_sarif,
    }
    formatter = formatters.get(output_format)
    if not formatter:
        print(f"Unknown format: {output_format}. Use: text, json, markdown, sarif", file=sys.stderr)
        return 2

    print(formatter(result))

    # Exit code
    if fail_on == "none":
        return 0

    severity_threshold = SEVERITY_ORDER.get(fail_on, 0)
    for f in result["findings"]:
        if SEVERITY_ORDER.get(f["severity"], 99) <= severity_threshold:
            return 1

    return 0


# ============================================================
# Entry point
# ============================================================

def main():
    if os.environ.get("GITHUB_ACTIONS") == "true":
        sys.exit(run_action())
    else:
        sys.exit(run_cli(sys.argv[1:]))


if __name__ == "__main__":
    main()
