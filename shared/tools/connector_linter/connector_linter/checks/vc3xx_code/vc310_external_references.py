"""VC310 — External references must not be added by default to all entities.

Adding default external references to all entities can trigger enrichment
connectors and create unnecessary ingestion, potentially causing platform
timeouts. External references using ``self.external_reference(s)`` should
only appear on Identity (Organization) objects. Dynamic per-entity external
references created as local variables are not flagged by this check.
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

# ---------------------------------------------------------------------------
# Identity type names are EXEMPT from this check.
#
# External references on Identity/Organization objects are expected (they
# describe the connector author). Only non-Identity types are flagged.
# Matching is case-insensitive.
# ---------------------------------------------------------------------------
_IDENTITY_NAMES = {"identity", "organizationauthor"}


def _get_call_type_name(call_node: ast.Call) -> str | None:
    """Extract the STIX type name from a Call node.

    Distinguishes two call patterns:
      - ast.Attribute: stix2.Identity(...)     → returns "Identity" (the attr)
      - ast.Name:      Identity(...)           → returns "Identity" (the id)
    Returns None for complex expressions (e.g. pycti.Identity.generate_id()).
    """
    func = call_node.func
    if isinstance(func, ast.Attribute):
        # stix2.Identity(...) → attr = "Identity"
        return func.attr
    if isinstance(func, ast.Name):
        # Identity(...)
        return func.id
    return None


def _references_self_ext_ref(node: ast.expr) -> bool:
    """Check if an AST expression references self.external_reference(s).

    Detects the pattern where a connector stores its external reference as
    an instance attribute and spreads it to all STIX objects. Handles:
      - self.external_reference       (singular)
      - self.external_references      (plural)
      - [self.external_reference]     (wrapped in a list literal)
      - [self.external_references]
    """
    if isinstance(node, ast.Attribute):
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "self"
            and node.attr in ("external_reference", "external_references")
        ):
            return True
    elif isinstance(node, ast.List):
        return any(_references_self_ext_ref(elt) for elt in node.elts)
    return False


def _check_custom_properties_dict(node: ast.expr) -> bool:
    """Check if a custom_properties dict contains x_opencti_external_references
    referencing self.external_reference(s).

    Detects the pattern where external references are smuggled through
    custom_properties instead of the standard external_references kwarg:
      custom_properties={"x_opencti_external_references": self.external_references}
    """
    if not isinstance(node, ast.Dict):
        return False
    for key, value in zip(node.keys, node.values, strict=False):
        if (
            key is not None
            and isinstance(key, ast.Constant)
            and key.value == "x_opencti_external_references"
            and value is not None
            and _references_self_ext_ref(value)
        ):
            return True
    return False


def _is_identity_type(type_name: str) -> bool:
    """Check if a STIX type name refers to an Identity object."""
    return type_name.lower() in _IDENTITY_NAMES


def _find_violations(tree: ast.Module, file_path: Path) -> list[tuple[Path, int, str]]:
    """Find all calls where self.external_reference(s) is used on non-Identity objects.

    Detection flow:
      1. Walk all Call nodes in the AST
      2. Skip calls to Identity-type constructors (exempt)
      3. Check keyword arguments for:
         a. external_references=self.external_reference(s)  (direct kwarg)
         b. custom_properties={...x_opencti_external_references: self.ext_ref...}

    Returns list of (file_path, line_no, description).
    """
    violations: list[tuple[Path, int, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        type_name = _get_call_type_name(node)
        if type_name and _is_identity_type(type_name):
            continue

        for kw in node.keywords:
            if kw.arg == "external_references" and _references_self_ext_ref(kw.value):
                context = f"on {type_name}()" if type_name else "in call"
                violations.append(
                    (
                        file_path,
                        kw.value.lineno,
                        f"Default external_references=self.external_reference(s) {context}",
                    ),
                )

            if kw.arg == "custom_properties" and _check_custom_properties_dict(
                kw.value,
            ):
                context = f"on {type_name}()" if type_name else "in call"
                violations.append(
                    (
                        file_path,
                        kw.value.lineno,
                        f"Default x_opencti_external_references via self.external_reference(s) {context}",
                    ),
                )

    return violations


@CheckRegistry.register(
    code="VC310",
    name="external-references-not-default",
    description=(
        "External references must not be added by default to all entities; "
        "only add on Identity (Organization)"
    ),
    severity=Severity.ERROR,
)
def check_external_references_not_default(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that self.external_reference(s) is not spread to non-Identity STIX objects."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees

    all_violations: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        all_violations.extend(_find_violations(tree, file_path))

    if not all_violations:
        return [
            CheckFinding(
                message="No default external references spread to non-Identity objects",
                severity=Severity.INFO,
            ),
        ]

    results: list[CheckFinding] = []
    for file_path, line_no, description in all_violations:
        results.append(
            CheckFinding(
                message=f"{description}",
                severity=Severity.ERROR,
                file_path=file_path,
                line=line_no,
                suggestion=(
                    "Remove default external_references from non-Identity objects. "
                    "Only add them on Identity (Organization). See issue #4210."
                ),
            ),
        )

    return results
