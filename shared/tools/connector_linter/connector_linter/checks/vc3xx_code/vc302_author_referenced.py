"""VC302 — Author must be referenced on STIX entities (created_by_ref).

Uses AST to detect ``author=`` as a keyword argument in function calls
(avoids false positives from variable assignments like ``author = "John"``).
Also detects ``created_by_ref=`` and ``x_opencti_created_by_ref`` via AST.
"""

import ast
from pathlib import Path

from connector_linter.checks.vc3xx_code.vc301_author_defined import (
    find_author_definitions,
)
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    ConnectorType,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Keyword argument names that attach an author identity to STIX entities:
#
#   created_by_ref           — standard STIX 2.1 field (SDOs)
#   author                   — connectors-sdk model parameter
#   x_opencti_created_by_ref — OpenCTI custom property (used on observables/SCOs)
# ---------------------------------------------------------------------------
_AUTHOR_KWARGS = {"created_by_ref", "author", "x_opencti_created_by_ref"}


def _find_author_references(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int, str]]:
    """Find keyword arguments that reference an author on STIX entities.

    Detects ``created_by_ref=``, ``author=``, and ``x_opencti_created_by_ref``
    as keyword arguments in function/constructor calls — not plain assignments.
    """
    hits: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            # Only check Call nodes — we want keyword arguments in function/
            # constructor calls, not standalone assignments like `author = "John"`
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg in _AUTHOR_KWARGS:
                    # Use the keyword node's own lineno when available;
                    # fall back to the call node's lineno otherwise
                    hits.append(
                        (
                            file_path,
                            getattr(kw, "lineno", node.lineno) or node.lineno,
                            kw.arg,
                        ),
                    )
    return hits


@CheckRegistry.register(
    code="VC302",
    name="author-referenced-on-entities",
    description="Author must be referenced on STIX entities (created_by_ref)",
    severity=Severity.ERROR,
    applicable_types={
        ConnectorType.INTERNAL_ENRICHMENT,
        ConnectorType.EXTERNAL_IMPORT,
        ConnectorType.INTERNAL_IMPORT_FILE,
    },
)
def check_author_referenced(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that created_by_ref or author= is used to attach author to entities."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    # Dependency: an author must be defined first (VC301) before it can be referenced.
    # If no author definition exists, we fail with a clear message pointing to VC301.
    author_hits = find_author_definitions(sources, ctx.python_trees)
    if not author_hits:
        return [
            CheckFinding(
                message="No author defined — cannot reference author on entities",
                severity=Severity.ERROR,
                suggestion="Define an author first (see VC301), then use created_by_ref= on STIX objects",
            ),
        ]

    # Author exists — now check if it's actually referenced on STIX entities (AST-based)
    trees = ctx.python_trees
    ref_hits = _find_author_references(trees)

    if ref_hits:
        file_path, line, _kwarg = ref_hits[0]
        return [
            CheckFinding(
                message=f"Author referenced on entities ({len(ref_hits)} occurrence(s) found)",
                severity=Severity.INFO,
                file_path=file_path,
                line=line,
            ),
        ]

    return [
        CheckFinding(
            message="Author is defined but never referenced on STIX entities",
            severity=Severity.ERROR,
            suggestion=(
                "Use created_by_ref=self.author.id on SDOs, "
                "or x_opencti_created_by_ref in custom_properties for observables, "
                "or author= parameter when using connectors-sdk models"
            ),
        ),
    ]
