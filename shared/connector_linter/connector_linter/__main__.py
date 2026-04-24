"""CLI entry point for the connector linter."""

import ast
import inspect
import sys
from pathlib import Path

import click
from connector_linter import __version__
from connector_linter.formatters import (
    format_github,
    format_json,
    format_markdown,
    format_text,
)
from connector_linter.models import Severity
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
def check(
    connector_path: str,
    output_format: str,
    select: tuple[str, ...],
    ignore: tuple[str, ...],
    severity: str | None,
    verbose: bool,
    disable_noqa: bool,
    abspath: bool,
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
        severity_order = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}
        min_sev = Severity(severity)
        results = [
            r for r in results if severity_order[r.severity] >= severity_order[min_sev]
        ]

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


def _extract_check_docstring(func: object) -> str | None:
    """Extract the module-level docstring from the file defining *func*."""
    source_file = inspect.getfile(func)  # type: ignore[arg-type]
    with open(source_file) as f:
        tree = ast.parse(f.read())
    return ast.get_docstring(tree)


def _extract_applicable_types(func: object) -> list[str] | None:
    """Extract ``_APPLICABLE_TYPES`` set literal from the check's source file."""
    source_file = inspect.getfile(func)  # type: ignore[arg-type]
    with open(source_file) as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "_APPLICABLE_TYPES":
                    if isinstance(node.value, ast.Set):
                        return sorted(
                            elt.value
                            for elt in node.value.elts
                            if isinstance(elt, ast.Constant)
                        )
    return None


# Mapping from internal type constants to human-readable labels
_TYPE_LABELS = {
    "EXTERNAL_IMPORT": "External Import",
    "INTERNAL_ENRICHMENT": "Internal Enrichment",
    "INTERNAL_EXPORT_FILE": "Internal Export File",
    "INTERNAL_IMPORT_FILE": "Internal Import File",
    "STREAM": "Stream",
}


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

    # Group checks by category prefix
    categories: dict[str, list[str]] = {}
    for code in sorted(checks.keys()):
        prefix = code[:3]  # "VC1", "VC2", …
        categories.setdefault(prefix, []).append(code)

    category_titles = {
        "VC1": "VC1xx — Configuration",
        "VC2": "VC2xx — Metadata",
        "VC3": "VC3xx — Code Quality",
        "VC4": "VC4xx — Docker",
        "VC5": "VC5xx — Deprecation",
    }

    lines: list[str] = []
    lines.append("# Connector Linter — Rules Reference\n")
    lines.append(f"Total rules: **{len(checks)}**\n")

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Code | Severity | Name | Scope |")
    lines.append("|------|----------|------|-------|")
    for code in sorted(checks.keys()):
        desc = checks[code]
        sev_icon = {"E": "🔴", "W": "🟡", "I": "🔵"}[desc.severity.symbol()]
        applicable = _extract_applicable_types(desc.func)
        if applicable:
            scope = ", ".join(_TYPE_LABELS.get(t, t) for t in applicable)
        else:
            scope = "All"
        lines.append(
            f"| {code} | {sev_icon} {desc.severity.value.capitalize()} | {desc.name} | {scope} |"
        )

    lines.append("")

    # Detailed sections per category
    for prefix in sorted(categories.keys()):
        title = category_titles.get(prefix, f"{prefix}xx")
        lines.append(f"## {title}\n")

        for code in categories[prefix]:
            desc = checks[code]
            sev_icon = {"E": "🔴", "W": "🟡", "I": "🔵"}[desc.severity.symbol()]
            lines.append(f"### {code} — {desc.name}\n")
            lines.append(
                f"- **Severity:** {sev_icon} {desc.severity.value.capitalize()}"
            )

            applicable = _extract_applicable_types(desc.func)
            if applicable:
                scope = ", ".join(_TYPE_LABELS.get(t, t) for t in applicable)
            else:
                scope = "All connector types"
            lines.append(f"- **Scope:** {scope}")
            lines.append(f"- **Description:** {desc.description}\n")

            docstring = _extract_check_docstring(desc.func)
            if docstring:
                # Strip the first line (title, usually "VCxxx — ...")
                doc_lines = docstring.strip().split("\n")
                body = "\n".join(doc_lines[1:]).strip()
                if body:
                    lines.append(f"{body}\n")

    content = "\n".join(lines)

    if output:
        out_path = Path(output)
        out_path.write_text(content)
        click.echo(f"Documentation written to {out_path}", err=True)
    else:
        click.echo(content)


if __name__ == "__main__":
    cli()
