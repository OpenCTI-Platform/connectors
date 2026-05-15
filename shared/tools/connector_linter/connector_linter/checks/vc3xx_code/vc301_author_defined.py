"""VC301 — Connector must define an author identity.

Uses AST to detect author identity definitions by looking for constructor
calls (``Identity(...)``, ``OrganizationAuthor(...)``, ``stix2.Identity(...)``)
and API calls (``helper.api.identity.create(...)``).

Import validation for bare ``Identity(...)`` calls is also AST-based:
the call is only counted when ``Identity`` is imported from ``stix2``
or ``pycti`` (not some unrelated class).
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

# ---------------------------------------------------------------------------
# Author-definition patterns (AST-based)
# ---------------------------------------------------------------------------

# Function/constructor names that unambiguously define an author
_UNAMBIGUOUS_AUTHOR_CALLS = {"OrganizationAuthor"}

# Import modules that confirm bare Identity() comes from stix2/pycti
_IDENTITY_MODULES = {"stix2", "pycti"}


def _has_identity_import(trees: dict[Path, ast.Module]) -> bool:
    """Check if any source file imports Identity from stix2 or pycti."""
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                # from stix2[.xxx] import Identity / from pycti[.xxx] import Identity
                mod_root = node.module.split(".")[0]
                if mod_root in _IDENTITY_MODULES:
                    for alias in node.names:
                        if alias.name == "Identity":
                            return True
            elif isinstance(node, ast.Import):
                # import stix2  (Identity accessed as stix2.Identity)
                for alias in node.names:
                    if alias.name.split(".")[0] in _IDENTITY_MODULES:
                        return True
    return False


def _is_author_call(node: ast.Call, identity_imported: bool) -> bool:
    """Determine if an ast.Call node represents an author definition.

    Recognized patterns:
    1. OrganizationAuthor(...)          — connectors-sdk
    2. stix2.Identity(...)              — qualified stix2 constructor
    3. Identity(...)                    — bare, only if imported from stix2/pycti
    4. *.api.identity.create(...)       — legacy pycti API call
    """
    func = node.func

    # Pattern 1 & 3: bare function call — OrganizationAuthor(...) or Identity(...)
    if isinstance(func, ast.Name):
        if func.id in _UNAMBIGUOUS_AUTHOR_CALLS:
            return True
        if func.id == "Identity" and identity_imported:
            return True

    # Patterns 2 & 4: attribute-based calls
    if isinstance(func, ast.Attribute):
        # Pattern 2: stix2.Identity(...)
        if func.attr == "Identity" and isinstance(func.value, ast.Name):
            if func.value.id == "stix2":
                return True

        # Pattern 4: *.api.identity.create(...)
        if (
            func.attr == "create"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "identity"
            and isinstance(func.value.value, ast.Attribute)
            and func.value.value.attr == "api"
        ):
            return True

    return False


def find_author_definitions(
    sources: dict[Path, str],
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int, str]]:
    """Find author definition locations using AST analysis.

    Args:
        sources: Raw Python source content keyed by relative path (used for
            line-text extraction in findings).
        trees:   Pre-parsed AST modules (e.g. ``ctx.python_trees``).  Passing
            the cached property avoids redundant parsing across checks.

    Returns:
        List of (file_path, line_number, matched_line_text).
    """
    identity_imported = _has_identity_import(trees)

    hits: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        content_lines = sources[file_path].splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_author_call(node, identity_imported):
                line_text = (
                    content_lines[node.lineno - 1].strip()
                    if node.lineno <= len(content_lines)
                    else ""
                )
                hits.append((file_path, node.lineno, line_text))

    return hits


@CheckRegistry.register(
    code="VC301",
    name="author-defined",
    description="Connector must define an author identity",
    severity=Severity.ERROR,
    applicable_types={
        ConnectorType.INTERNAL_ENRICHMENT,
        ConnectorType.EXTERNAL_IMPORT,
        ConnectorType.INTERNAL_IMPORT_FILE,
    },
)
def check_author_defined(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector defines an author identity somewhere in its source."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    hits = find_author_definitions(sources, ctx.python_trees)

    if hits:
        file_path, line, _ = hits[0]
        return [
            CheckFinding(
                message="Author identity defined",
                severity=Severity.INFO,
                file_path=file_path,
                line=line,
            ),
        ]

    return [
        CheckFinding(
            message="No author identity definition found in connector source",
            severity=Severity.ERROR,
            suggestion=(
                "Define an author using one of: "
                "stix2.Identity(name=..., identity_class='organization'), "
                "OrganizationAuthor(name=...), "
                "or self.helper.api.identity.create(type='Organization', name=...)"
            ),
        ),
    ]
