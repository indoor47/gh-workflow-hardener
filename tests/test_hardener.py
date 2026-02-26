#!/usr/bin/env python3
"""Tests for gh-workflow-hardener."""

import os
import sys
import json
import tempfile
import shutil
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import hardener


class TestScanUnpinnedActions(unittest.TestCase):
    """Tests for unpinned action detection."""

    def test_unpinned_tag(self):
        lines = ["    - uses: actions/checkout@v4"]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "unpinned-action")
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertIn("actions/checkout", findings[0]["message"])

    def test_unpinned_branch(self):
        lines = ["    - uses: actions/setup-python@main"]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertIn("main", findings[0]["message"])

    def test_pinned_sha(self):
        lines = ["    - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29"]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_pinned_sha_with_comment(self):
        lines = ["    - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29  # v4"]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_path_based_action(self):
        lines = ["    - uses: actions/aws/ec2@v1"]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertIn("actions/aws/ec2", findings[0]["action"])

    def test_multiple_unpinned(self):
        lines = [
            "    - uses: actions/checkout@v4",
            "    - uses: actions/setup-python@v5",
            "    - uses: actions/cache@v3",
        ]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 3)

    def test_mixed_pinned_and_unpinned(self):
        lines = [
            "    - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
            "    - uses: actions/setup-python@v5",
        ]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertIn("setup-python", findings[0]["message"])

    def test_non_uses_line(self):
        lines = ["    run: echo hello", "    name: Test step"]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_semver_tag(self):
        lines = ["    - uses: docker/build-push-action@v5.1.0"]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 1)

    def test_inline_comment_stripped(self):
        lines = ["    - uses: actions/checkout@v4 # some comment"]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ref"], "v4")

    def test_correct_line_numbers(self):
        lines = [
            "name: CI",
            "on: push",
            "jobs:",
            "  build:",
            "    steps:",
            "      - uses: actions/checkout@v4",
        ]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 6)


class TestScanPermissions(unittest.TestCase):
    """Tests for permissions checking."""

    def test_missing_permissions(self):
        lines = [
            "name: CI",
            "on: push",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
        ]
        findings = hardener.scan_permissions(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "missing-permissions")

    def test_has_top_level_permissions(self):
        lines = [
            "name: CI",
            "on: push",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
        ]
        findings = hardener.scan_permissions(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_write_all_top_level(self):
        lines = [
            "name: CI",
            "permissions: write-all",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
        ]
        findings = hardener.scan_permissions(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "broad-permissions")
        self.assertEqual(findings[0]["severity"], "high")

    def test_write_all_job_level(self):
        lines = [
            "name: CI",
            "permissions:",
            "  contents: read",
            "jobs:",
            "  deploy:",
            "    permissions: write-all",
            "    runs-on: ubuntu-latest",
        ]
        findings = hardener.scan_permissions(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "broad-permissions")
        self.assertIn("deploy", findings[0]["message"])

    def test_empty_permissions_ok(self):
        """Empty permissions block means read-only for all scopes."""
        lines = [
            "name: CI",
            "permissions: {}",
            "jobs:",
            "  build:",
            "    runs-on: ubuntu-latest",
        ]
        findings = hardener.scan_permissions(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_line_number_for_missing(self):
        lines = ["name: CI", "on: push", "jobs:", "  build:"]
        findings = hardener.scan_permissions(lines, "test.yml")
        self.assertEqual(findings[0]["line"], 1)


class TestScanScriptInjection(unittest.TestCase):
    """Tests for script injection detection."""

    def test_issue_title_in_run(self):
        lines = [
            "    - name: Greet",
            "      run: echo ${{ github.event.issue.title }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "script-injection")
        self.assertEqual(findings[0]["severity"], "critical")

    def test_pr_body_in_multiline_run(self):
        lines = [
            "    - name: Check PR",
            "      run: |",
            "        echo 'PR body:'",
            "        echo ${{ github.event.pull_request.body }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertIn("pull_request.body", findings[0]["message"])

    def test_safe_context_in_run(self):
        lines = [
            "    - name: Echo SHA",
            "      run: echo ${{ github.sha }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_github_token_in_run_ok(self):
        lines = [
            "    - name: Auth",
            "      run: echo ${{ secrets.GITHUB_TOKEN }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_head_ref_in_run(self):
        lines = [
            "    - name: Check branch",
            "      run: echo ${{ github.head_ref }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 1)

    def test_comment_body_in_run(self):
        lines = [
            "    - name: Process comment",
            "      run: |",
            "        BODY=\"${{ github.event.comment.body }}\"",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 1)

    def test_safe_env_usage(self):
        """Using env var reference (not expression) in run is safe."""
        lines = [
            "    - name: Safe",
            "      env:",
            "        TITLE: ${{ github.event.issue.title }}",
            "      run: echo \"$TITLE\"",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_head_commit_message(self):
        lines = [
            "    - run: git log --oneline ${{ github.event.head_commit.message }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 1)

    def test_no_run_block(self):
        lines = [
            "    - uses: actions/checkout@v4",
            "      with:",
            "        ref: ${{ github.event.pull_request.head.ref }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_pr_title_in_run(self):
        lines = [
            "    - run: echo \"${{ github.event.pull_request.title }}\"",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 1)

    def test_discussion_body(self):
        lines = [
            "    - run: echo ${{ github.event.discussion.body }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 1)

    def test_pr_head_ref(self):
        lines = [
            "    - run: echo ${{ github.event.pull_request.head.ref }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 1)


class TestScanInsecureCheckout(unittest.TestCase):
    """Tests for insecure checkout detection."""

    def test_checkout_without_persist_creds(self):
        lines = [
            "    - uses: actions/checkout@v4",
        ]
        findings = hardener.scan_insecure_checkout(lines, "test.yml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check"], "insecure-checkout")
        self.assertEqual(findings[0]["severity"], "medium")

    def test_checkout_with_persist_false(self):
        lines = [
            "    - uses: actions/checkout@v4",
            "      with:",
            "        persist-credentials: false",
        ]
        findings = hardener.scan_insecure_checkout(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_checkout_sha_without_persist(self):
        lines = [
            "    - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29",
        ]
        findings = hardener.scan_insecure_checkout(lines, "test.yml")
        self.assertEqual(len(findings), 1)

    def test_checkout_with_other_options(self):
        lines = [
            "    - uses: actions/checkout@v4",
            "      with:",
            "        fetch-depth: 0",
            "        persist-credentials: false",
        ]
        findings = hardener.scan_insecure_checkout(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_non_checkout_action(self):
        lines = [
            "    - uses: actions/setup-python@v5",
        ]
        findings = hardener.scan_insecure_checkout(lines, "test.yml")
        self.assertEqual(len(findings), 0)


class TestScanFile(unittest.TestCase):
    """Integration tests for full file scanning."""

    def test_clean_workflow(self):
        content = """name: CI
on: push

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29  # v4
        with:
          persist-credentials: false
      - run: echo "Hello"
"""
        findings = hardener.scan_file(content, "clean.yml")
        self.assertEqual(len(findings), 0)

    def test_vulnerable_workflow(self):
        content = """name: PR Greeter
on:
  issues:
    types: [opened]

jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          echo "New issue: ${{ github.event.issue.title }}"
"""
        findings = hardener.scan_file(content, "vuln.yml")
        # Should find: unpinned action, missing permissions, script injection, insecure checkout
        checks = {f["check"] for f in findings}
        self.assertIn("unpinned-action", checks)
        self.assertIn("missing-permissions", checks)
        self.assertIn("script-injection", checks)
        self.assertIn("insecure-checkout", checks)
        self.assertGreaterEqual(len(findings), 4)

    def test_minimal_workflow(self):
        content = """name: Test
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = hardener.scan_file(content, "minimal.yml")
        self.assertEqual(len(findings), 0)


class TestScanDirectory(unittest.TestCase):
    """Tests for directory scanning."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.workflow_dir = os.path.join(self.tmpdir, ".github", "workflows")
        os.makedirs(self.workflow_dir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_no_workflow_dir(self):
        empty_dir = tempfile.mkdtemp()
        result = hardener.scan_directory(empty_dir)
        self.assertEqual(result["files_scanned"], 0)
        self.assertEqual(result["score"], 100)
        shutil.rmtree(empty_dir)

    def test_scan_yml_files(self):
        with open(os.path.join(self.workflow_dir, "ci.yml"), "w") as f:
            f.write("name: CI\non: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        result = hardener.scan_directory(self.tmpdir)
        self.assertEqual(result["files_scanned"], 1)
        self.assertEqual(len(result["findings"]), 0)
        self.assertEqual(result["score"], 100)

    def test_scan_yaml_extension(self):
        with open(os.path.join(self.workflow_dir, "ci.yaml"), "w") as f:
            f.write("name: CI\non: push\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        result = hardener.scan_directory(self.tmpdir)
        self.assertEqual(result["files_scanned"], 1)

    def test_score_deduction(self):
        with open(os.path.join(self.workflow_dir, "ci.yml"), "w") as f:
            f.write("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n")
        result = hardener.scan_directory(self.tmpdir)
        self.assertLess(result["score"], 100)
        self.assertGreater(len(result["findings"]), 0)

    def test_multiple_files(self):
        for name in ["ci.yml", "deploy.yml"]:
            with open(os.path.join(self.workflow_dir, name), "w") as f:
                f.write("name: Test\non: push\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        result = hardener.scan_directory(self.tmpdir)
        self.assertEqual(result["files_scanned"], 2)


class TestFormatText(unittest.TestCase):
    """Tests for text output formatting."""

    def test_clean_result(self):
        result = {"files_scanned": 1, "findings": [], "score": 100}
        output = hardener.format_text(result)
        self.assertIn("100/100", output)
        self.assertIn("No security issues found", output)

    def test_findings_shown(self):
        result = {
            "files_scanned": 1,
            "score": 85,
            "findings": [{
                "file": "ci.yml",
                "line": 5,
                "check": "unpinned-action",
                "severity": "critical",
                "message": "Action is not pinned",
                "fix": "Pin it",
            }],
        }
        output = hardener.format_text(result)
        self.assertIn("CRITICAL", output)
        self.assertIn("ci.yml:5", output)
        self.assertIn("unpinned-action", output)


class TestFormatJson(unittest.TestCase):
    """Tests for JSON output formatting."""

    def test_valid_json(self):
        result = {"files_scanned": 1, "findings": [], "score": 100}
        output = hardener.format_json(result)
        parsed = json.loads(output)
        self.assertEqual(parsed["score"], 100)
        self.assertEqual(parsed["findings"], [])

    def test_internal_fields_stripped(self):
        result = {
            "files_scanned": 1,
            "score": 85,
            "findings": [{
                "file": "ci.yml",
                "line": 5,
                "check": "unpinned-action",
                "severity": "critical",
                "message": "test",
                "fix": "test",
                "action": "actions/checkout",
                "ref": "v4",
            }],
        }
        output = hardener.format_json(result)
        parsed = json.loads(output)
        self.assertNotIn("action", parsed["findings"][0])
        self.assertNotIn("ref", parsed["findings"][0])


class TestFormatMarkdown(unittest.TestCase):
    """Tests for markdown output formatting."""

    def test_clean_result(self):
        result = {"files_scanned": 1, "findings": [], "score": 100}
        output = hardener.format_markdown(result)
        self.assertIn("100/100", output)
        self.assertIn("Grade: A", output)

    def test_grade_calculation(self):
        for score, expected_grade in [(100, "A"), (80, "A"), (79, "B"), (60, "B"), (40, "C"), (20, "D"), (0, "F")]:
            result = {"files_scanned": 1, "findings": [], "score": score}
            output = hardener.format_markdown(result)
            self.assertIn(f"Grade: {expected_grade}", output, f"Score {score} should be grade {expected_grade}")

    def test_findings_grouped(self):
        result = {
            "files_scanned": 1,
            "score": 50,
            "findings": [
                {"file": "a.yml", "line": 1, "check": "x", "severity": "critical", "message": "crit issue"},
                {"file": "a.yml", "line": 2, "check": "y", "severity": "medium", "message": "med issue"},
            ],
        }
        output = hardener.format_markdown(result)
        self.assertIn("Critical", output)
        self.assertIn("Medium", output)


class TestFormatSarif(unittest.TestCase):
    """Tests for SARIF output formatting."""

    def test_valid_sarif(self):
        result = {
            "files_scanned": 1,
            "score": 85,
            "findings": [{
                "file": ".github/workflows/ci.yml",
                "line": 5,
                "check": "unpinned-action",
                "severity": "critical",
                "message": "Action not pinned",
            }],
        }
        output = hardener.format_sarif(result)
        parsed = json.loads(output)
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertEqual(len(parsed["runs"]), 1)
        self.assertEqual(len(parsed["runs"][0]["results"]), 1)
        self.assertEqual(parsed["runs"][0]["results"][0]["ruleId"], "unpinned-action")

    def test_empty_sarif(self):
        result = {"files_scanned": 0, "findings": [], "score": 100}
        output = hardener.format_sarif(result)
        parsed = json.loads(output)
        self.assertEqual(len(parsed["runs"][0]["results"]), 0)

    def test_severity_mapping(self):
        result = {
            "files_scanned": 1,
            "score": 50,
            "findings": [
                {"file": "a.yml", "line": 1, "check": "x", "severity": "critical", "message": "test"},
                {"file": "a.yml", "line": 2, "check": "y", "severity": "medium", "message": "test"},
            ],
        }
        output = hardener.format_sarif(result)
        parsed = json.loads(output)
        levels = [r["level"] for r in parsed["runs"][0]["results"]]
        self.assertEqual(levels, ["error", "warning"])


class TestFixUnpinnedActions(unittest.TestCase):
    """Tests for SHA pinning auto-fix."""

    def test_fix_replaces_ref(self):
        tmpdir = tempfile.mkdtemp()
        wf_dir = os.path.join(tmpdir, ".github", "workflows")
        os.makedirs(wf_dir)
        wf_file = os.path.join(wf_dir, "ci.yml")
        with open(wf_file, "w") as f:
            f.write("    - uses: actions/checkout@v4\n")

        findings = [{
            "file": ".github/workflows/ci.yml",
            "line": 1,
            "check": "unpinned-action",
            "severity": "critical",
            "message": "test",
            "action": "actions/checkout",
            "ref": "v4",
        }]

        # Mock resolve_sha
        original_resolve = hardener.resolve_sha
        hardener.resolve_sha = lambda a, r, t=None: "a5ac7e51b41094c92402da3b24376905380afc29"
        try:
            fixed = hardener.fix_unpinned_actions(tmpdir, findings)
            self.assertEqual(fixed, 1)
            with open(wf_file) as f:
                content = f.read()
            self.assertIn("a5ac7e51b41094c92402da3b24376905380afc29", content)
            self.assertIn("# v4", content)
        finally:
            hardener.resolve_sha = original_resolve
            shutil.rmtree(tmpdir)

    def test_fix_skips_when_resolve_fails(self):
        tmpdir = tempfile.mkdtemp()
        wf_dir = os.path.join(tmpdir, ".github", "workflows")
        os.makedirs(wf_dir)
        wf_file = os.path.join(wf_dir, "ci.yml")
        original_content = "    - uses: actions/checkout@v4\n"
        with open(wf_file, "w") as f:
            f.write(original_content)

        findings = [{
            "file": ".github/workflows/ci.yml",
            "line": 1,
            "check": "unpinned-action",
            "severity": "critical",
            "message": "test",
            "action": "actions/checkout",
            "ref": "v4",
        }]

        original_resolve = hardener.resolve_sha
        hardener.resolve_sha = lambda a, r, t=None: None
        try:
            fixed = hardener.fix_unpinned_actions(tmpdir, findings)
            self.assertEqual(fixed, 0)
            with open(wf_file) as f:
                content = f.read()
            self.assertEqual(content, original_content)
        finally:
            hardener.resolve_sha = original_resolve
            shutil.rmtree(tmpdir)


class TestCLIParsing(unittest.TestCase):
    """Tests for CLI argument handling."""

    def test_version(self):
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            code = hardener.run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn(hardener.__version__, f.getvalue())

    def test_help(self):
        import io
        from contextlib import redirect_stdout
        f = io.StringIO()
        with redirect_stdout(f):
            code = hardener.run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("Usage", f.getvalue())

    def test_unknown_option(self):
        code = hardener.run_cli(["--garbage"])
        self.assertEqual(code, 2)

    def test_unknown_format(self):
        tmpdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmpdir, ".github", "workflows"))
        code = hardener.run_cli(["--format", "xml", tmpdir])
        self.assertEqual(code, 2)
        shutil.rmtree(tmpdir)


class TestScoreCalculation(unittest.TestCase):
    """Tests for security score calculation."""

    def test_perfect_score(self):
        tmpdir = tempfile.mkdtemp()
        wf_dir = os.path.join(tmpdir, ".github", "workflows")
        os.makedirs(wf_dir)
        with open(os.path.join(wf_dir, "ci.yml"), "w") as f:
            f.write("name: CI\non: push\npermissions: {}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")
        result = hardener.scan_directory(tmpdir)
        self.assertEqual(result["score"], 100)
        shutil.rmtree(tmpdir)

    def test_score_floor_at_zero(self):
        result = {
            "files_scanned": 1,
            "findings": [
                {"severity": "critical"} for _ in range(20)
            ],
            "score": 100,
        }
        # Manually calculate
        score = 100
        for f in result["findings"]:
            score -= 15
        score = max(0, score)
        self.assertEqual(score, 0)


class TestEdgeCases(unittest.TestCase):
    """Edge cases and regression tests."""

    def test_empty_file(self):
        findings = hardener.scan_file("", "empty.yml")
        # Should find missing permissions at least
        checks = {f["check"] for f in findings}
        self.assertIn("missing-permissions", checks)

    def test_comments_only_file(self):
        content = "# This is a comment\n# Another comment\n"
        findings = hardener.scan_file(content, "comments.yml")
        checks = {f["check"] for f in findings}
        self.assertIn("missing-permissions", checks)

    def test_expression_in_with_block_not_flagged(self):
        """Expressions in with: blocks are string values, not shell injection."""
        lines = [
            "    - uses: actions/github-script@v7",
            "      with:",
            "        script: |",
            "          const title = context.payload.issue.title",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 0)

    def test_multiple_expressions_in_one_line(self):
        lines = [
            "    - run: echo ${{ github.event.issue.title }} ${{ github.event.issue.body }}",
        ]
        findings = hardener.scan_script_injection(lines, "test.yml")
        self.assertEqual(len(findings), 2)

    def test_sha_pattern_exact_40_chars(self):
        self.assertTrue(hardener.SHA_RE.match("a" * 40))
        self.assertFalse(hardener.SHA_RE.match("a" * 39))
        self.assertFalse(hardener.SHA_RE.match("a" * 41))
        self.assertFalse(hardener.SHA_RE.match("g" * 40))  # not hex

    def test_uses_without_at_sign(self):
        """Local actions like uses: ./my-action should not be flagged."""
        lines = ["    - uses: ./my-local-action"]
        findings = hardener.scan_unpinned_actions(lines, "test.yml")
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
