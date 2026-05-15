"""VC316 — Connector must close work with to_processed after processing.

Uses AST to verify:
- ``to_processed()`` is called somewhere.
- ``in_error=`` is used as a keyword argument specifically in a
  ``to_processed()`` call (not just any ``in_error=`` assignment).

Scope: EXTERNAL_IMPORT only — other connector types have their work
lifecycle managed by the platform or SDK.
"""

import ast
from pathlib import Path

from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    ConnectorType,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

# Only EXTERNAL_IMPORT connectors need to explicitly close work


def _find_to_processed_calls(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int, bool]]:
    """Find to_processed() calls. Returns (file, line, has_in_error_kwarg).

    Matches the Attribute pattern only (e.g. self.helper.api.work.to_processed(...))
    since to_processed is always called as a method. Also detects whether the
    in_error= keyword argument is used, which signals proper error handling
    during work closure.
    """
    hits: list[tuple[Path, int, bool]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Match *.to_processed(...) method calls
            if isinstance(func, ast.Attribute) and func.attr == "to_processed":
                # Check if in_error= keyword argument is present
                has_in_error = any(kw.arg == "in_error" for kw in node.keywords)
                hits.append((file_path, node.lineno, has_in_error))
    return hits


@CheckRegistry.register(
    code="VC316",
    name="work-closed",
    description="Connector must close work with to_processed after processing",
    severity=Severity.ERROR,
    applicable_types={ConnectorType.EXTERNAL_IMPORT},
)
def check_work_closed(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector calls to_processed to close work."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees
    calls = _find_to_processed_calls(trees)

    # ---------------------------------------------------------------------------
    # Two sub-checks:
    #   1. to_processed exists (ERROR if missing) — work must be closed
    #   2. in_error= is used (WARNING if missing) — proper error signaling
    # ---------------------------------------------------------------------------

    if not calls:
        return [
            CheckFinding(
                message="No to_processed call found — work is never closed",
                severity=Severity.ERROR,
                suggestion=(
                    "Add self.helper.api.work.to_processed(work_id, message) "
                    "to close work after processing. Use in_error=True on "
                    "exception or interruption."
                ),
            ),
        ]

    results: list[CheckFinding] = []
    first = calls[0]

    # Sub-check 1: to_processed exists → PASS
    results.append(
        CheckFinding(
            message="Connector closes work with to_processed",
            severity=Severity.INFO,
            file_path=first[0],
            line=first[1],
        ),
    )

    # Sub-check 2: check if any to_processed call uses in_error= kwarg
    # (WARNING severity — not blocking, but important for proper error reporting)
    has_error_handling = any(has_in_error for _, _, has_in_error in calls)
    if not has_error_handling:
        results.append(
            CheckFinding(
                message="to_processed never uses in_error=True for error handling",
                severity=Severity.WARNING,
                file_path=ctx.path / first[0],
                line=first[1],
                suggestion=(
                    "On exception or CTRL+C, close work with "
                    "to_processed(work_id, message, in_error=True) "
                    "to properly signal errors to the platform."
                ),
            ),
        )

    return results
