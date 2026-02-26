"""Command-line interface for gh-workflow-hardener.

Provides the `hardener scan` command for easy workflow validation.
"""

import click
import json
from pathlib import Path
from typing import List
from .validator import WorkflowValidator, Issue


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@click.group()
@click.version_option(version="1.0.0", prog_name="hardener")
def cli():
    """GitHub Actions Workflow Security Scanner.
    
    Find unpinned actions, dangerous permissions, and script injection vulnerabilities.
    """
    pass


@cli.command()
@click.argument('path', type=click.Path(exists=True, file_okay=True, dir_okay=True), default='.')
@click.option('--format', 'output_format', type=click.Choice(['text', 'json']), default='text',
              help='Output format')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low', 'none']),
              default='critical', help='Exit with error if findings at this severity or above')
def scan(path: str, output_format: str, fail_on: str):
    """Scan a workflow file or directory for security issues.
    
    PATH can be a single .yml/.yaml file or a directory containing .github/workflows/
    """
    validator = WorkflowValidator()
    issues = []

    path_obj = Path(path)

    # Handle single file
    if path_obj.is_file():
        if validator.load_workflow(str(path_obj)):
            issues = validator.validate()
    # Handle directory with .github/workflows
    elif path_obj.is_dir():
        workflows_dir = path_obj / '.github' / 'workflows'
        if workflows_dir.exists():
            for workflow_file in sorted(workflows_dir.glob('*.yml')) + sorted(workflows_dir.glob('*.yaml')):
                v = WorkflowValidator()
                if v.load_workflow(str(workflow_file)):
                    issues.extend(v.validate())
        else:
            click.echo(f"Error: No .github/workflows/ directory found at {path}", err=True)
            exit(1)
    else:
        click.echo(f"Error: Path does not exist: {path}", err=True)
        exit(1)

    # Sort by severity
    issues = sorted(issues, key=lambda i: SEVERITY_ORDER.get(i.severity, 99))

    # Output
    if output_format == 'json':
        output = {
            'issues_found': len(issues),
            'issues': [
                {
                    'check': i.check,
                    'severity': i.severity,
                    'line': i.line,
                    'location': i.location,
                    'description': i.description,
                    'fix': i.fix,
                }
                for i in issues
            ]
        }
        click.echo(json.dumps(output, indent=2))
    else:
        # Text output
        click.echo(f"gh-workflow-hardener v1.0.0")
        click.echo(f"Issues found: {len(issues)}")
        click.echo()

        if not issues:
            click.echo("No security issues found. Your workflows look good!")
        else:
            for issue in issues:
                severity_upper = issue.severity.upper()
                click.echo(f"[{severity_upper}] Line {issue.line}: {issue.check}")
                click.echo(f"  {issue.description}")
                if issue.fix:
                    click.echo(f"  Fix: {issue.fix}")
                click.echo()

    # Determine exit code
    if fail_on == 'none':
        exit(0)

    threshold = SEVERITY_ORDER.get(fail_on, 0)
    for issue in issues:
        if SEVERITY_ORDER.get(issue.severity, 99) <= threshold:
            exit(1)

    exit(0)


if __name__ == '__main__':
    cli()
