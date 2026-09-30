"""VC312 — send_stix2_bundle must use cleanup_inconsistent_bundle=True.

Since pycti >= 6.3.3, ``send_stix2_bundle`` accepts
``cleanup_inconsistent_bundle=True`` to avoid MISSING_REFERENCE_ERROR.
All connectors calling this method must pass this parameter.
"""

import ast
from pathlib import Path

from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry


def _find_send_bundle_calls(
    tree: ast.Module,
    file_path: Path,
) -> list[tuple[Path, int, bool]]:
    """Find all send_stix2_bundle calls and whether cleanup_inconsistent_bundle=True.

    Matches two call patterns:
      1. self.helper.send_stix2_bundle(...)  — Attribute node (method call)
      2. send_stix2_bundle(...)              — Name node (bare function call)

    For each call, checks if cleanup_inconsistent_bundle=True is passed as
    a keyword argument. Only checks for the literal True value (not variables
    or expressions).

    Returns list of (file_path, line_no, has_cleanup_true).
    """
    results: list[tuple[Path, int, bool]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Match *.send_stix2_bundle(...) or send_stix2_bundle(...)
        func_name = None
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "send_stix2_bundle"
        ) or (isinstance(node.func, ast.Name) and node.func.id == "send_stix2_bundle"):
            func_name = "send_stix2_bundle"

        if func_name is None:
            continue

        has_cleanup_true = False
        for kw in node.keywords:
            if kw.arg == "cleanup_inconsistent_bundle":
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_cleanup_true = True

        results.append((file_path, node.lineno, has_cleanup_true))

    return results


@CheckRegistry.register(
    code="VC312",
    name="cleanup-inconsistent-bundle",
    description="send_stix2_bundle must use cleanup_inconsistent_bundle=True",
    severity=Severity.ERROR,
)
def check_cleanup_inconsistent_bundle(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that all send_stix2_bundle calls pass cleanup_inconsistent_bundle=True."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees

    all_calls: list[tuple[Path, int, bool]] = []
    for file_path, tree in trees.items():
        all_calls.extend(_find_send_bundle_calls(tree, file_path))

    # No send_stix2_bundle calls found → return empty (check doesn't apply).
    # Returning [] instead of FAIL because not all connectors use send_stix2_bundle
    # (e.g. stream connectors, or SDK-based connectors that handle bundles internally).
    if not all_calls:
        return []

    results: list[CheckFinding] = []
    for file_path, line_no, has_cleanup_true in all_calls:
        if has_cleanup_true:
            results.append(
                CheckFinding(
                    message="send_stix2_bundle uses cleanup_inconsistent_bundle=True",
                    severity=Severity.INFO,
                    file_path=file_path,
                    line=line_no,
                ),
            )
        else:
            results.append(
                CheckFinding(
                    message="send_stix2_bundle missing cleanup_inconsistent_bundle=True",
                    severity=Severity.ERROR,
                    file_path=file_path,
                    line=line_no,
                    suggestion=(
                        "Add cleanup_inconsistent_bundle=True to send_stix2_bundle() "
                        "to avoid MISSING_REFERENCE_ERROR. Also ensure author and "
                        "markings, and any related objects are included in the bundle."
                    ),
                ),
            )

    return results
