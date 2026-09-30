"""Documentation generator for connector-linter rules.

Extracts check metadata (code, severity, scope, description, docstring)
from the registry and renders a Markdown reference document suitable for
import into Notion, GitHub wikis, or any Markdown viewer.

Separated from ``__main__.py`` to keep the CLI entry-point focused on
argument parsing and output routing.
"""

import importlib
import pkgutil
from pathlib import Path

import connector_linter.checks as _checks_pkg
from connector_linter.models import SEVERITY_EMOJI
from connector_linter.registry import CheckDescriptor


def load_category_titles() -> dict[str, str]:
    """Build category title map from check sub-package docstrings.

    Reads the first docstring line of each ``vc<N>xx_*`` sub-package so the
    map is automatically up-to-date when new categories are added.

    Example output::

        {"VC1": "VC1xx — Configuration checks.",
         "VC2": "VC2xx — Metadata checks.", ...}
    """
    titles: dict[str, str] = {}
    pkg_path = Path(_checks_pkg.__file__).parent
    for _finder, name, is_pkg in pkgutil.iter_modules([str(pkg_path)]):
        if not is_pkg:
            continue
        prefix = name[:3].upper()  # "vc1" → "VC1"
        mod = importlib.import_module(f"connector_linter.checks.{name}")
        first_line = (mod.__doc__ or "").strip().splitlines()[0] if mod.__doc__ else ""
        if first_line:
            titles[prefix] = first_line.rstrip(".")
    return titles


def generate_rules_markdown(checks: dict[str, CheckDescriptor]) -> str:
    """Render a Markdown reference document for all provided checks.

    Args:
        checks: Mapping of code → CheckDescriptor (e.g. from CheckRegistry.get_all()).

    Returns:
        A Markdown string ready to write to a file or stdout.
    """
    # Group checks by category prefix ("VC1", "VC2", …)
    categories: dict[str, list[str]] = {}
    for code in sorted(checks.keys()):
        prefix = code[:3]
        categories.setdefault(prefix, []).append(code)

    category_titles = load_category_titles()

    lines: list[str] = []
    lines.append("# Connector Linter — Rules Reference\n")
    lines.append(f"Total rules: **{len(checks)}**\n")

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Code | Severity | Name | Scope |")
    lines.append("|------|----------|------|-------|")
    for code in sorted(checks.keys()):
        desc = checks[code]
        sev_icon = SEVERITY_EMOJI[desc.severity]
        if desc.applicable_types:
            scope = ", ".join(t.label for t in sorted(desc.applicable_types))
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
            sev_icon = SEVERITY_EMOJI[desc.severity]
            lines.append(f"### {code} — {desc.name}\n")
            lines.append(
                f"- **Severity:** {sev_icon} {desc.severity.value.capitalize()}"
            )

            if desc.applicable_types:
                scope = ", ".join(t.label for t in sorted(desc.applicable_types))
            else:
                scope = "All connector types"
            lines.append(f"- **Scope:** {scope}")
            lines.append(f"- **Description:** {desc.description}\n")

            docstring = desc.module_doc
            if docstring:
                # Strip the first line (title, usually "VCxxx — ...")
                doc_lines = docstring.strip().split("\n")
                body = "\n".join(doc_lines[1:]).strip()
                if body:
                    lines.append(f"{body}\n")

    return "\n".join(lines)
