"""CLI entry point for the connector linter."""

import sys
from pathlib import Path

import click
from connector_linter import __version__
from connector_linter._doc_generator import generate_rules_markdown
from connector_linter.formatters import (
    format_github,
    format_json,
    format_markdown,
    format_text,
)
from connector_linter.models import SEVERITY_COLOR, Severity
from connector_linter.registry import CheckRegistry
from connector_linter.runner import _import_checks_modules, run_checks


@click.group()
@click.version_option(version=__version__, prog_name="connector-linter")
def cli() -> None:
    """OpenCTI Connector Verified Linter.

    Validates whether an OpenCTI connector meets the "Verified" status criteria.
    Works like flake8/pylint with individual error codes per check.
    """


_CONNECTOR_ROOT_MARKERS = {"src", "__metadata__", "Dockerfile", "docker-compose.yml"}


def _resolve_connector_root(file_path: Path) -> Path | None:
    """Walk up from *file_path* to find the connector root directory.

    A connector root is identified by the presence of at least one marker:
    ``src/``, ``__metadata__/``, ``Dockerfile``, or ``docker-compose.yml``.
    """
    candidate = file_path.resolve().parent
    while candidate != candidate.parent:
        if any((candidate / m).exists() for m in _CONNECTOR_ROOT_MARKERS):
            return candidate
        candidate = candidate.parent
    return None


@cli.command()
@click.argument("connector_path", type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "github", "markdown"]),
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
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Show all checks including passed (default hides passed).",
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
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to pyproject.toml (auto-detected if not specified).",
)
def check(
    connector_path: str,
    output_format: str,
    select: tuple[str, ...],
    ignore: tuple[str, ...],
    severity: str | None,
    verbose: bool,
    disable_noqa: bool,
    abspath: bool,
    config_path: str | None,
) -> None:
    r"""Check a connector against Verified criteria.

    CONNECTOR_PATH can be a connector directory or a specific file within one.
    When a file is given, the connector root is resolved automatically and only
    findings for that file are shown.

    \b
    Examples:
        python -m connector_linter check ./external-import/myconnector
        python -m connector_linter check ./external-import/myconnector/src/main.py
        python -m connector_linter check ./external-import/myconnector --format json
        python -m connector_linter check ./external-import/myconnector --select VC1xx
        python -m connector_linter check ./external-import/myconnector --ignore VC101
        python -m connector_linter check ./external-import/myconnector -v
    """
    path = Path(connector_path)
    target_file: Path | None = None

    if path.is_file():
        target_file = path.resolve()
        connector_root = _resolve_connector_root(path)
        if connector_root is None:
            click.echo(
                f"Error: Could not determine connector root for {path}. "
                "Ensure the file is inside a connector directory (with src/, "
                "__metadata__/, Dockerfile, or docker-compose.yml).",
                err=True,
            )
            sys.exit(2)
        path = connector_root

    results = run_checks(
        connector_path=path,
        select=list(select) if select else None,
        ignore=list(ignore) if ignore else None,
        disable_noqa=disable_noqa,
        config_path=Path(config_path) if config_path else None,
    )

    # When a specific file was targeted, keep only findings for that file
    if target_file is not None:
        results = [
            r
            for r in results
            if r.file_path is not None and r.file_path.resolve() == target_file
        ]

    # Filter by severity if requested
    if severity:
        min_sev = Severity(severity)
        results = [r for r in results if r.severity.rank() >= min_sev.rank()]

    # Format output
    if output_format == "text":
        format_text(results, path, sys.stdout, verbose=verbose, abspath=abspath)
    elif output_format == "markdown":
        format_markdown(results, path, sys.stdout, verbose=verbose, abspath=abspath)
    else:
        formatter = {"json": format_json, "github": format_github}[output_format]
        formatter(results, path, sys.stdout)

    # Exit code: 1 if any errors failed, 0 otherwise
    has_errors = any(r.severity == Severity.ERROR for r in results)
    sys.exit(1 if has_errors else 0)


@cli.command(name="list")
def list_checks() -> None:
    """List all available checks."""
    _import_checks_modules()
    checks = CheckRegistry.get_all()

    if not checks:
        click.echo("No checks registered yet.")
        return

    click.echo(f"{'Code':<8} {'Sev':<5} {'Name':<30} {'Scope':<28} Description")
    click.echo(f"{'─' * 8} {'─' * 5} {'─' * 30} {'─' * 28} {'─' * 40}")
    for code in sorted(checks.keys()):
        desc = checks[code]
        sev_color = SEVERITY_COLOR[desc.severity]
        if desc.applicable_types:
            scope = ",".join(sorted(t.label for t in desc.applicable_types))
        else:
            scope = "All"
        click.echo(
            f"{code:<8} "
            f"{click.style(desc.severity.symbol(), fg=sev_color):<14} "
            f"{desc.name:<30} "
            f"{scope:<28} {desc.description}",
        )


@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Write output to a file instead of stdout.",
)
def docs(output: str | None) -> None:
    """Generate Markdown documentation for all implemented rules.

    Extracts code, title, severity, scope, and docstring from each check
    to produce a Markdown document suitable for import into Notion or wikis.
    """
    _import_checks_modules()
    checks = CheckRegistry.get_all()

    if not checks:
        click.echo("No checks registered yet.", err=True)
        return

    content = generate_rules_markdown(checks)

    if output:
        out_path = Path(output)
        out_path.write_text(content)
        click.echo(f"Documentation written to {out_path}", err=True)
    else:
        click.echo(content)


if __name__ == "__main__":
    cli()
