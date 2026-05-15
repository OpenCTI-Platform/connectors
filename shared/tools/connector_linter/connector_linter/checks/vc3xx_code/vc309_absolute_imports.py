"""VC309 — Connector must use only absolute imports, no relative imports.

Severity: ERROR — Docker containers run connectors as installed packages.
Relative imports (from . import X) break when the package structure doesn't
match the development layout, causing ImportError at container startup.
"""

import ast
from typing import TYPE_CHECKING

from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

if TYPE_CHECKING:
    from pathlib import Path


@CheckRegistry.register(
    code="VC309",
    name="absolute-imports-only",
    description="Connector must use only absolute imports, no relative imports",
    severity=Severity.ERROR,
)
def check_absolute_imports_only(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector uses only absolute imports (no relative from . / from ..)."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees

    # ---------------------------------------------------------------------------
    # Detect relative imports via AST.
    #
    # In Python's AST, ImportFrom nodes have a `level` field:
    #   level=0 → absolute import  (from package import X)
    #   level=1 → relative import  (from . import X)
    #   level=2 → parent relative  (from .. import X)
    #   etc.
    # ---------------------------------------------------------------------------
    relative_imports: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level and node.level > 0:
                # Reconstruct the import statement for display in findings
                dots = "." * node.level
                module = node.module or ""
                names = ", ".join(alias.name for alias in node.names)
                stmt = f"from {dots}{module} import {names}"
                relative_imports.append((file_path, node.lineno, stmt))

    if not relative_imports:
        return [
            CheckFinding(
                message="All imports are absolute",
                severity=Severity.INFO,
            ),
        ]

    # Report all relative imports
    results: list[CheckFinding] = []
    for file_path, line_no, stmt in relative_imports:
        results.append(
            CheckFinding(
                message=f"Relative import: {stmt}",
                severity=Severity.ERROR,
                file_path=file_path,
                line=line_no,
                suggestion="Replace with an absolute import",
            ),
        )

    return results
