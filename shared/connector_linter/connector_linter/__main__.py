"""CLI entry point for the connector linter."""

import sys
from pathlib import Path

import click
from connector_linter import __version__
from connector_linter.formatters import format_github, format_json, format_text
from connector_linter.models import Severity
from connector_linter.registry import CheckRegistry
from connector_linter.runner import _discover_checks, run_checks


@click.group()
@click.version_option(version=__version__, prog_name="connector-linter")
def cli() -> None:
    """OpenCTI Connector Verified Linter.

    Validates whether an OpenCTI connector meets the "Verified" status criteria.
    Works like flake8/pylint with individual error codes per check.
    """


@cli.command()
@click.argument("connector_path", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "github"]),
    default="text",
    help="Output format.",
)
@click.option(
    "--select",
    multiple=True,
    help="Only run checks matching these codes/prefixes (e.g. VC101, VC1xx).",
)
@click.option(
    "--ignore",
    multiple=True,
    help="Skip checks matching these codes/prefixes.",
)
@click.option(
    "--severity",
    type=click.Choice(["error", "warning", "info"]),
    default=None,
    help="Minimum severity to report.",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    default=False,
    help="Only show failures and warnings (hide passed checks).",
)
@click.option(
    "--disable-noqa",
    is_flag=True,
    default=False,
    help="Ignore all # noqa inline suppressions.",
)
@click.option(
    "--abspath",
    is_flag=True,
    default=False,
    help="Show absolute file paths in text output (JSON always uses absolute paths).",
)
def check(
    connector_path: str,
    output_format: str,
    select: tuple[str, ...],
    ignore: tuple[str, ...],
    severity: str | None,
    quiet: bool,
    disable_noqa: bool,
    abspath: bool,
) -> None:
    r"""Check a connector against Verified criteria.

    \b
    Examples:
        python -m connector_linter check ./external-import/myconnector
        python -m connector_linter check ./external-import/myconnector --format json
        python -m connector_linter check ./external-import/myconnector --select VC1xx
        python -m connector_linter check ./external-import/myconnector --ignore VC101
        python -m connector_linter check ./external-import/myconnector -q
    """
    path = Path(connector_path)

    results = run_checks(
        connector_path=path,
        select=list(select) if select else None,
        ignore=list(ignore) if ignore else None,
        disable_noqa=disable_noqa,
    )

    # Filter by severity if requested
    if severity:
        severity_order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}
        min_sev = Severity(severity)
        results = [
            r for r in results if severity_order[r.severity] >= severity_order[min_sev]
        ]

    # Format output
    if output_format == "text":
        format_text(results, path, sys.stdout, quiet=quiet, abspath=abspath)
    else:
        formatter = {"json": format_json, "github": format_github}[output_format]
        formatter(results, path, sys.stdout)

    # Exit code: 1 if any errors failed, 0 otherwise
    has_errors = any(not r.passed and r.severity == Severity.ERROR for r in results)
    sys.exit(1 if has_errors else 0)


@cli.command(name="list")
def list_checks() -> None:
    """List all available checks."""
    _discover_checks()
    checks = CheckRegistry.get_all()

    if not checks:
        click.echo("No checks registered yet.")
        return

    click.echo(f"{'Code':<8} {'Sev':<5} {'Name':<30} Description")
    click.echo(f"{'─' * 8} {'─' * 5} {'─' * 30} {'─' * 40}")
    for code in sorted(checks.keys()):
        desc = checks[code]
        sev_color = {"E": "red", "W": "yellow", "I": "cyan"}[desc.severity.symbol()]
        click.echo(
            f"{code:<8} "
            f"{click.style(desc.severity.symbol(), fg=sev_color):<14} "
            f"{desc.name:<30} {desc.description}",
        )


if __name__ == "__main__":
    cli()
