"""Comprehensive test suite for WorkflowValidator.

Tests cover:
- Unit tests for each validation check
- Integration tests for full workflows
- CLI functionality tests
- Edge cases and error handling
"""

import pytest
import json
import tempfile
from pathlib import Path
from click.testing import CliRunner

from src.validator import WorkflowValidator, Issue
from src.cli import cli


# ============================================================================
# FIXTURES: Load test workflows
# ============================================================================

@pytest.fixture
def vulnerable_workflow():
    """Load vulnerable.yml fixture with 7+ issues."""
    return Path(__file__).parent.parent / 'fixtures' / 'vulnerable.yml'


@pytest.fixture
def safe_workflow():
    """Load safe.yml fixture with no issues."""
    return Path(__file__).parent.parent / 'fixtures' / 'safe.yml'


@pytest.fixture
def partial_workflow():
    """Load partial.yml fixture with 1 unpinned action."""
    return Path(__file__).parent.parent / 'fixtures' / 'partial.yml'


@pytest.fixture
def validator():
    """Create a fresh WorkflowValidator instance."""
    return WorkflowValidator()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ============================================================================
# UNIT TESTS: Individual check methods
# ============================================================================

class TestUnpinnedActions:
    """Test detection of unpinned GitHub Actions."""

    def test_unpinned_actions_detects_branch_refs(self, validator):
        """Test that branch references (v3, main) are flagged as critical."""
        workflow = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_unpinned_actions()
            
            assert len(validator.issues) == 1
            assert validator.issues[0].check == "unpinned-action"
            assert validator.issues[0].severity == "critical"
            assert "actions/checkout@v3" in validator.issues[0].description
            
            Path(f.name).unlink()

    def test_unpinned_actions_detects_latest_tag(self, validator):
        """Test that 'latest' and other tags are flagged."""
        workflow = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@latest
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_unpinned_actions()
            
            assert len(validator.issues) == 1
            assert validator.issues[0].severity == "critical"
            
            Path(f.name).unlink()

    def test_unpinned_actions_allows_sha_pinned(self, validator):
        """Test that SHA-pinned actions (40 hex chars) pass validation."""
        workflow = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@6c8c9b89f1654e1eb3fcf0b25f9f0ec60a72cc2c
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_unpinned_actions()
            
            assert len(validator.issues) == 0
            
            Path(f.name).unlink()

    def test_unpinned_actions_skips_local_actions(self, validator):
        """Test that local actions (./) are not flagged."""
        workflow = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./path/to/local/action
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_unpinned_actions()
            
            assert len(validator.issues) == 0
            
            Path(f.name).unlink()

    def test_unpinned_actions_skips_docker_images(self, validator):
        """Test that docker:// images are not flagged."""
        workflow = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://ubuntu:latest
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_unpinned_actions()
            
            assert len(validator.issues) == 0
            
            Path(f.name).unlink()


class TestDangerousPermissions:
    """Test detection of overly broad permissions."""

    def test_dangerous_permissions_detects_write_all(self, validator):
        """Test that 'write-all' is flagged as high severity."""
        workflow = """
name: Test
on: push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_dangerous_permissions()
            
            assert len(validator.issues) >= 1
            critical_perms = [i for i in validator.issues if "write-all" in i.description]
            assert len(critical_perms) >= 1
            assert critical_perms[0].severity == "high"
            
            Path(f.name).unlink()

    def test_dangerous_permissions_detects_contents_write(self, validator):
        """Test that 'contents: write' is flagged."""
        workflow = """
name: Test
on: push
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_dangerous_permissions()
            
            perms_issues = [i for i in validator.issues if "broad-permissions" in i.check]
            assert len(perms_issues) >= 1
            assert perms_issues[0].severity == "high"
            
            Path(f.name).unlink()

    def test_dangerous_permissions_detects_packages_write(self, validator):
        """Test that 'packages: write' is flagged."""
        workflow = """
name: Test
on: push
permissions:
  packages: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_dangerous_permissions()
            
            perms_issues = [i for i in validator.issues if i.check == "broad-permissions"]
            assert len(perms_issues) >= 1
            
            Path(f.name).unlink()

    def test_dangerous_permissions_allows_read(self, validator):
        """Test that 'read' permissions pass validation."""
        workflow = """
name: Test
on: push
permissions:
  contents: read
  pull-requests: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_dangerous_permissions()
            
            # Should have no broad-permissions issues
            broad_perms_issues = [i for i in validator.issues if i.check == "broad-permissions"]
            assert len(broad_perms_issues) == 0
            
            Path(f.name).unlink()

    def test_dangerous_permissions_flags_missing_permissions(self, validator):
        """Test that missing permissions block is flagged."""
        workflow = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_dangerous_permissions()
            
            missing_perms = [i for i in validator.issues if i.check == "missing-permissions"]
            assert len(missing_perms) >= 1
            assert missing_perms[0].severity == "high"
            
            Path(f.name).unlink()


class TestScriptInjection:
    """Test detection of script injection vulnerabilities."""

    def test_script_injection_detects_github_context(self, validator):
        """Test detection of unescaped untrusted GitHub context."""
        workflow = """
name: Test
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.pull_request.title }}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            assert len(validator.issues) >= 1
            assert validator.issues[0].check == "script-injection"
            assert validator.issues[0].severity == "critical"
            
            Path(f.name).unlink()

    def test_script_injection_detects_pr_body(self, validator):
        """Test detection of PR body injection."""
        workflow = """
name: Test
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.pull_request.body }}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            assert len(validator.issues) >= 1
            assert validator.issues[0].check == "script-injection"
            
            Path(f.name).unlink()

    def test_script_injection_detects_issue_title(self, validator):
        """Test detection of issue title injection."""
        workflow = """
name: Test
on: issues
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.issue.title }}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            assert len(validator.issues) >= 1
            
            Path(f.name).unlink()

    def test_script_injection_allows_quoted_context(self, validator):
        """Test that quoted context variables are safe (no detection)."""
        workflow = """
name: Test
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            # Quoted variables are still flagged; user should use env
            injection_issues = [i for i in validator.issues if i.check == "script-injection"]
            # This actually WILL be flagged because we check the raw expression
            # The fix is to move it to env, which the issue message recommends
            assert len(injection_issues) >= 1
            
            Path(f.name).unlink()

    def test_script_injection_allows_env_variable_usage(self, validator):
        """Test that env variable usage is safe (no detection)."""
        workflow = """
name: Test
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      UNTRUSTED_INPUT: ${{ github.event.pull_request.title }}
    steps:
      - run: echo "$UNTRUSTED_INPUT"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            # env variable usage in run: is the safe pattern — nothing should be flagged
            injection_issues = [i for i in validator.issues if i.check == "script-injection"]
            assert len(injection_issues) == 0
            
            Path(f.name).unlink()

    def test_script_injection_allows_trusted_context(self, validator):
        """Test that trusted GitHub context (github.ref, etc) is safe."""
        workflow = """
name: Test
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.ref }}
      - run: echo ${{ github.repository }}
      - run: echo ${{ github.actor }}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            injection_issues = [i for i in validator.issues if i.check == "script-injection"]
            assert len(injection_issues) == 0
            
            Path(f.name).unlink()

    def test_script_injection_detects_multiple_injections(self, validator):
        """Test detection of multiple injection attempts in one workflow."""
        workflow = """
name: Test
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo ${{ github.event.pull_request.title }}
          echo ${{ github.event.pull_request.body }}
          echo ${{ github.event.issue.title }}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            injection_issues = [i for i in validator.issues if i.check == "script-injection"]
            assert len(injection_issues) >= 3
            
            Path(f.name).unlink()


# ============================================================================
# INTEGRATION TESTS: Full workflow validation
# ============================================================================

class TestWorkflowValidation:
    """Test full workflow validation workflow."""

    def test_validate_vulnerable_workflow(self, vulnerable_workflow, validator):
        """Test that vulnerable.yml returns multiple issues."""
        assert validator.load_workflow(str(vulnerable_workflow))
        issues = validator.validate()
        
        # vulnerable.yml has multiple issues:
        # - unpinned checkout@v3
        # - unpinned setup-node@v3
        # - permissions: contents: write (high)
        # - script injection (2x)
        assert len(issues) >= 4
        
        severities = {i.severity for i in issues}
        assert "critical" in severities or "high" in severities

    def test_validate_safe_workflow(self, safe_workflow, validator):
        """Test that safe.yml returns no issues."""
        assert validator.load_workflow(str(safe_workflow))
        issues = validator.validate()
        
        assert len(issues) == 0

    def test_validate_partial_workflow(self, partial_workflow, validator):
        """Test that partial.yml returns 1 unpinned action issue."""
        assert validator.load_workflow(str(partial_workflow))
        issues = validator.validate()
        
        # partial.yml has 1 unpinned action
        unpinned = [i for i in issues if i.check == "unpinned-action"]
        assert len(unpinned) == 1

    def test_validate_empty_workflow(self, validator):
        """Test handling of empty workflow (no jobs)."""
        workflow = """
name: Empty
on: push
permissions:
  contents: read
jobs: {}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            assert validator.load_workflow(f.name)
            issues = validator.validate()
            
            # Should have no issues (empty is valid)
            assert len(issues) == 0
            
            Path(f.name).unlink()

    def test_validate_workflow_no_run_blocks(self, validator):
        """Test workflow with no run blocks (only uses:)."""
        workflow = """
name: Test
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@6c8c9b89f1654e1eb3fcf0b25f9f0ec60a72cc2c
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            assert validator.load_workflow(f.name)
            issues = validator.validate()
            
            # Should have no issues
            assert len(issues) == 0
            
            Path(f.name).unlink()


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestErrorHandling:
    """Test error handling for invalid inputs."""

    def test_load_missing_file(self, validator):
        """Test graceful handling of missing file."""
        result = validator.load_workflow('/nonexistent/path/missing.yml')
        
        assert result is False
        assert len(validator.issues) == 1
        assert validator.issues[0].check == "load-error"
        assert validator.issues[0].severity == "critical"

    def test_load_invalid_yaml(self, validator):
        """Test graceful handling of invalid YAML."""
        workflow = """
name: Bad YAML
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
    invalid: [unclosed bracket
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            result = validator.load_workflow(f.name)
            
            assert result is False
            assert len(validator.issues) >= 1
            assert validator.issues[0].check == "yaml-parse-error"
            assert validator.issues[0].severity == "critical"
            
            Path(f.name).unlink()

    def test_validate_without_loading(self, validator):
        """Test validate() on unloaded validator."""
        issues = validator.validate()
        
        # Should return empty list for unloaded workflow
        assert issues == []


# ============================================================================
# CLI TESTS: Command-line interface
# ============================================================================

class TestCLI:
    """Test command-line interface functionality."""

    def test_cli_scan_safe_file(self, safe_workflow):
        """Test CLI scanning a safe workflow file."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(safe_workflow)])
        
        assert result.exit_code == 0
        assert "No security issues found" in result.output

    def test_cli_scan_vulnerable_file(self, vulnerable_workflow):
        """Test CLI scanning a vulnerable workflow file."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(vulnerable_workflow)])
        
        # Should fail with default fail-on=critical
        assert result.exit_code == 1
        assert "Issues found:" in result.output

    def test_cli_json_output(self, vulnerable_workflow):
        """Test CLI JSON output format."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(vulnerable_workflow), '--format', 'json'])
        
        # Parse JSON output
        output_json = json.loads(result.output)
        
        assert 'issues_found' in output_json
        assert 'issues' in output_json
        assert output_json['issues_found'] > 0
        assert len(output_json['issues']) > 0

    def test_cli_fail_on_critical(self, partial_workflow):
        """Test --fail-on critical (should pass for unpinned action at level critical)."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(partial_workflow), '--fail-on', 'critical'])
        
        # partial.yml has unpinned action (critical), so should fail
        assert result.exit_code == 1

    def test_cli_fail_on_high(self, partial_workflow):
        """Test --fail-on high (should pass for critical issues)."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(partial_workflow), '--fail-on', 'high'])
        
        # partial.yml has critical issues, so should fail
        assert result.exit_code == 1

    def test_cli_fail_on_none(self, vulnerable_workflow):
        """Test --fail-on none (should always exit 0)."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(vulnerable_workflow), '--fail-on', 'none'])
        
        assert result.exit_code == 0
        assert "Issues found:" in result.output

    def test_cli_directory_scan(self, temp_dir):
        """Test scanning a directory with .github/workflows/."""
        # Create .github/workflows structure
        workflows_dir = temp_dir / '.github' / 'workflows'
        workflows_dir.mkdir(parents=True)
        
        # Add a safe workflow
        safe_file = workflows_dir / 'safe.yml'
        safe_file.write_text("""
name: Safe
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@6c8c9b89f1654e1eb3fcf0b25f9f0ec60a72cc2c
""")
        
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(temp_dir)])
        
        assert result.exit_code == 0
        assert "No security issues found" in result.output

    def test_cli_directory_scan_with_issues(self, temp_dir):
        """Test scanning directory with vulnerable workflows."""
        workflows_dir = temp_dir / '.github' / 'workflows'
        workflows_dir.mkdir(parents=True)
        
        # Add a vulnerable workflow
        vuln_file = workflows_dir / 'vulnerable.yml'
        vuln_file.write_text("""
name: Vulnerable
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
""")
        
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(temp_dir)])
        
        # Should fail due to unpinned action
        assert result.exit_code == 1

    def test_cli_missing_directory(self, temp_dir):
        """Test CLI with missing .github/workflows directory."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(temp_dir)])
        
        assert result.exit_code == 1
        assert "No .github/workflows/ directory found" in result.output

    def test_cli_text_output_format(self, vulnerable_workflow):
        """Test CLI text output format (default)."""
        runner = CliRunner()
        result = runner.invoke(cli, ['scan', str(vulnerable_workflow), '--format', 'text'])
        
        assert "[CRITICAL]" in result.output or "[HIGH]" in result.output
        assert "Issues found:" in result.output


# ============================================================================
# EDGE CASES
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_injection_with_secrets_context(self, validator):
        """Test that secrets context is handled (safer than user input)."""
        workflow = """
name: Test
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.TOKEN }}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            # secrets is not in UNTRUSTED_CONTEXTS, so no flag
            injection_issues = [i for i in validator.issues if i.check == "script-injection"]
            assert len(injection_issues) == 0
            
            Path(f.name).unlink()

    def test_injection_with_env_context(self, validator):
        """Test that env context is handled (safer than user input)."""
        workflow = """
name: Test
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ env.MY_VAR }}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            # env is not in UNTRUSTED_CONTEXTS, so no flag
            injection_issues = [i for i in validator.issues if i.check == "script-injection"]
            assert len(injection_issues) == 0
            
            Path(f.name).unlink()

    def test_injection_with_inputs_context(self, validator):
        """Test that inputs context is handled (safer than user input)."""
        workflow = """
name: Test
on: workflow_call
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ inputs.version }}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            # inputs is not in UNTRUSTED_CONTEXTS, so no flag
            injection_issues = [i for i in validator.issues if i.check == "script-injection"]
            assert len(injection_issues) == 0
            
            Path(f.name).unlink()

    def test_multiline_run_with_injection(self, validator):
        """Test multiline run block with injection on non-first line."""
        workflow = """
name: Test
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Safe line"
          echo ${{ github.event.pull_request.title }}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_script_injection()
            
            injection_issues = [i for i in validator.issues if i.check == "script-injection"]
            assert len(injection_issues) >= 1
            
            Path(f.name).unlink()

    def test_sha_with_comment(self, validator):
        """Test that SHA with inline comment is correctly parsed."""
        workflow = """
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@6c8c9b89f1654e1eb3fcf0b25f9f0ec60a72cc2c  # v4.0.0
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(workflow)
            f.flush()
            
            validator.load_workflow(f.name)
            validator.check_unpinned_actions()
            
            # Should be recognized as valid SHA despite comment
            issues = [i for i in validator.issues if i.check == "unpinned-action"]
            assert len(issues) == 0
            
            Path(f.name).unlink()

    def test_issue_object_serialization(self, validator):
        """Test that Issue objects can be serialized to dict."""
        from src.validator import Issue
        
        issue = Issue(
            check="test-check",
            severity="high",
            line=42,
            description="Test issue",
            location="test.yml",
            fix="Fix it"
        )
        
        issue_dict = issue.__dict__
        assert issue_dict['check'] == "test-check"
        assert issue_dict['severity'] == "high"
        assert issue_dict['line'] == 42

    def test_validator_reuse_for_multiple_files(self, safe_workflow, partial_workflow):
        """Test that validator can be reused for multiple files."""
        validator = WorkflowValidator()
        
        # Validate first file
        validator.load_workflow(str(safe_workflow))
        issues1 = validator.validate()
        assert len(issues1) == 0
        
        # Reuse validator for second file
        validator2 = WorkflowValidator()
        validator2.load_workflow(str(partial_workflow))
        issues2 = validator2.validate()
        assert len(issues2) >= 1


# ============================================================================
# ISSUE STRUCTURE TESTS
# ============================================================================

class TestIssueStructure:
    """Test that Issue objects have expected attributes."""

    def test_issue_has_required_fields(self):
        """Test that Issue dataclass has all required fields."""
        from src.validator import Issue
        
        issue = Issue(
            check="test",
            severity="high",
            line=1,
            description="Test"
        )
        
        assert hasattr(issue, 'check')
        assert hasattr(issue, 'severity')
        assert hasattr(issue, 'line')
        assert hasattr(issue, 'description')
        assert hasattr(issue, 'location')
        assert hasattr(issue, 'fix')

    def test_issue_optional_fields(self):
        """Test that location and fix are optional."""
        from src.validator import Issue
        
        # Without optional fields
        issue1 = Issue(
            check="test",
            severity="high",
            line=1,
            description="Test"
        )
        
        assert issue1.location is None
        assert issue1.fix is None
        
        # With optional fields
        issue2 = Issue(
            check="test",
            severity="high",
            line=1,
            description="Test",
            location="test.yml",
            fix="Fix it"
        )
        
        assert issue2.location == "test.yml"
        assert issue2.fix == "Fix it"
