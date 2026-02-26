"""GitHub Actions workflow validator module.

Core validation logic extracted from hardener.py into a reusable class.
Handles YAML parsing, issue detection, and reporting.
"""

import re
import yaml
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any


@dataclass
class Issue:
    """Represents a single security issue found in a workflow."""
    check: str
    severity: str  # "critical", "high", "medium", "low"
    line: int
    description: str
    location: Optional[str] = None  # action name, permission, etc
    fix: Optional[str] = None


class WorkflowValidator:
    """Validates GitHub Actions workflows for security issues.
    
    Detects:
    - Unpinned action references (supply chain risk)
    - Dangerous permissions (write access)
    - Script injection via untrusted GitHub context
    """

    # Regex patterns
    USES_RE = re.compile(
        r'^(\s*-?\s*uses:\s*)'
        r'([a-zA-Z0-9_.\-/]+(?:/[a-zA-Z0-9_.\-/]+)*)'
        r'@(\S+)',
    )
    SHA_RE = re.compile(r'^[0-9a-f]{40}$')
    EXPR_RE = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')

    # GitHub context values controlled by attackers
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

    UNTRUSTED_RE = re.compile(
        '|'.join(
            c.replace('.', r'\.').replace('[*]', r'\[\d+\]')
            for c in UNTRUSTED_CONTEXTS
        )
    )

    def __init__(self):
        """Initialize validator."""
        self.issues: List[Issue] = []
        self.lines: List[str] = []
        self.filepath: str = ""

    def load_workflow(self, path: str) -> bool:
        """Load and parse workflow YAML file.
        
        Args:
            path: Path to .yml or .yaml workflow file
            
        Returns:
            True if successfully loaded, False on parse error
        """
        self.filepath = path
        self.issues = []

        try:
            with open(path, 'r') as f:
                self.lines = f.read().splitlines()
                # Validate YAML structure (but keep lines for line-based checks)
                f.seek(0)
                yaml.safe_load(f)
            return True
        except (IOError, OSError) as e:
            self._add_issue(
                check="load-error",
                severity="critical",
                line=1,
                description=f"Could not read file: {e}",
            )
            return False
        except yaml.YAMLError as e:
            self._add_issue(
                check="yaml-parse-error",
                severity="critical",
                line=1,
                description=f"Invalid YAML: {e}",
            )
            return False

    def check_unpinned_actions(self) -> None:
        """Detect actions NOT pinned to a commit SHA (supply chain risk)."""
        for line_num, line in enumerate(self.lines, 1):
            m = self.USES_RE.match(line)
            if not m:
                continue

            action = m.group(2)
            ref = m.group(3)

            # Strip inline comments
            if " #" in ref:
                ref = ref.split(" #")[0].strip()

            # Skip local actions and Docker images
            if action.startswith(".") or action.startswith("docker://"):
                continue

            # Check if ref is a full SHA
            if not self.SHA_RE.match(ref):
                self._add_issue(
                    check="unpinned-action",
                    severity="critical",
                    line=line_num,
                    location=action,
                    description=(
                        f"Action `{action}@{ref}` is not pinned to a commit SHA. "
                        f"Tags and branches can be moved to point to malicious code. "
                        f"See: tj-actions/changed-files supply chain attack (March 2025)."
                    ),
                    fix=f"Pin to SHA: `uses: {action}@<commit-sha>  # {ref}`",
                )

    def check_dangerous_permissions(self) -> None:
        """Flag workflows with overly broad write permissions."""
        has_top_level_perms = False

        for line_num, line in enumerate(self.lines, 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            # Detect top-level permissions block
            if indent == 0 and stripped.startswith("permissions:"):
                has_top_level_perms = True

                # Check for write-all
                if "write-all" in stripped:
                    self._add_issue(
                        check="broad-permissions",
                        severity="high",
                        line=line_num,
                        location="permissions",
                        description=(
                            "Workflow uses `permissions: write-all`. "
                            "This grants the GITHUB_TOKEN full read-write access to all scopes. "
                            "Use least-privilege permissions instead."
                        ),
                        fix=(
                            "Replace with specific permissions:\n"
                            "permissions:\n"
                            "  contents: read\n"
                            "  pull-requests: write"
                        ),
                    )

            # Check for dangerous individual permissions
            if "contents: write" in stripped or "packages: write" in stripped:
                self._add_issue(
                    check="broad-permissions",
                    severity="high",
                    line=line_num,
                    location="permissions",
                    description=(
                        f"Permission `{stripped.strip()}` grants write access. "
                        f"This could allow a compromised step to modify your repository. "
                        f"Only grant write permissions when necessary."
                    ),
                )

        # No permissions block at all
        if not has_top_level_perms:
            self._add_issue(
                check="missing-permissions",
                severity="high",
                line=1,
                location="workflow root",
                description=(
                    "No top-level `permissions` block defined. "
                    "Without explicit permissions, the GITHUB_TOKEN gets the repository's default permissions "
                    "(often read-write). Add a top-level permissions block."
                ),
                fix=(
                    "Add at the top level:\n"
                    "permissions:\n"
                    "  contents: read"
                ),
            )

    def check_script_injection(self) -> None:
        """Detect run: commands with unescaped untrusted GitHub context."""
        in_run = False
        run_indent = 0
        run_start_line = 0

        for line_num, line in enumerate(self.lines, 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            # Detect start of run: block
            run_match = re.match(r'^(\s*(?:-\s+)?)run\s*:\s*(.*)', line)
            if run_match:
                run_start_line = line_num
                run_indent = indent
                inline_content = run_match.group(2).strip()

                # Single-line run
                if inline_content and inline_content not in ("|", "|+", "|-", ">", ">-", ">+"):
                    self._check_line_for_injection(inline_content, line_num)
                    in_run = False
                else:
                    in_run = bool(inline_content)
                continue

            # Inside multiline run block
            if in_run:
                if stripped == "" or indent > run_indent:
                    self._check_line_for_injection(line, line_num)
                else:
                    in_run = False

    def _check_line_for_injection(self, line: str, line_num: int) -> None:
        """Check a single line for untrusted GitHub expression usage."""
        for expr_match in self.EXPR_RE.finditer(line):
            expr = expr_match.group(1).strip()
            if self.UNTRUSTED_RE.search(expr):
                self._add_issue(
                    check="script-injection",
                    severity="critical",
                    line=line_num,
                    location=expr,
                    description=(
                        f"Untrusted input `${{{{ {expr} }}}}` used in a `run:` block. "
                        f"An attacker can inject arbitrary shell commands through this value. "
                        f"Assign to an environment variable and reference it as `$ENV_VAR` instead."
                    ),
                    fix=(
                        f"Move to env block:\n"
                        f"  env:\n"
                        f"    UNTRUSTED_INPUT: ${{{{ {expr} }}}}\n"
                        f"  run: echo \"$UNTRUSTED_INPUT\""
                    ),
                )

    def validate(self) -> List[Issue]:
        """Run all checks and return list of issues found.
        
        Returns:
            List of Issue objects representing security problems
        """
        if not self.lines:
            return self.issues

        self.check_unpinned_actions()
        self.check_dangerous_permissions()
        self.check_script_injection()

        return self.issues

    def _add_issue(
        self,
        check: str,
        severity: str,
        line: int,
        description: str,
        location: Optional[str] = None,
        fix: Optional[str] = None,
    ) -> None:
        """Add an issue to the issues list."""
        self.issues.append(Issue(
            check=check,
            severity=severity,
            line=line,
            location=location,
            description=description,
            fix=fix,
        ))

    def to_dict_list(self) -> List[Dict[str, Any]]:
        """Convert issues to list of dictionaries for serialization."""
        return [asdict(issue) for issue in self.issues]
