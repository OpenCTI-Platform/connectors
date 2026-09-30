"""VC320 — Enrichment connector must enforce TLP access control.

Before processing an entity, the connector must extract its TLP marking
from ``objectMarking``, validate it against the configured ``max_tlp``,
and reject processing if the TLP is too high.  This prevents data
leakage — e.g. sending TLP:RED data on a TLP:CLEAR platform.

Distinct from VC304 (which checks that ``check_max_tlp`` is called):
VC320 verifies the **complete access-control flow**:
  1. Extract TLP from ``objectMarking``
  2. Call ``check_max_tlp``
  3. Reject (raise) when invalid

Scope: INTERNAL_ENRICHMENT only.
Severity: ERROR.
"""

import ast
from typing import TYPE_CHECKING, cast

from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    ConnectorType,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

if TYPE_CHECKING:
    from pathlib import Path

# Only enrichment connectors need TLP access control — they receive
# individual entities from the platform and must not leak sensitive data.


# ---------------------------------------------------------------------------
# Step 1 helper: detect objectMarking access
#
# The TLP marking is stored in the entity's "objectMarking" field.
# Two AST patterns are matched:
#   - ast.Constant with value "objectMarking" → dict subscript access
#     e.g. entity["objectMarking"]
#   - ast.Attribute with attr "objectMarking"  → attribute access
#     e.g. entity.objectMarking
# ---------------------------------------------------------------------------
def _has_object_marking_access(tree: ast.Module) -> int | None:
    """Check if objectMarking is accessed (subscript or attribute)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "objectMarking":
            return node.lineno
        if isinstance(node, ast.Attribute) and node.attr == "objectMarking":
            return node.lineno
    return None


# ---------------------------------------------------------------------------
# Step 2 helper: detect check_max_tlp() call
#
# Two call patterns are matched:
#   - self.helper.check_max_tlp(...)  → Attribute node with attr "check_max_tlp"
#   - check_max_tlp(...)              → bare Name node (imported function)
# ---------------------------------------------------------------------------
def _has_check_max_tlp(tree: ast.Module) -> int | None:
    """Check if check_max_tlp() is called."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "check_max_tlp":
            return node.lineno
        if isinstance(func, ast.Name) and func.id == "check_max_tlp":
            return node.lineno
    return None


# ---------------------------------------------------------------------------
# Step 3 helper: detect raise after TLP check
#
# Scoped to FunctionDef/AsyncFunctionDef to ensure the raise and the
# check_max_tlp call are in the same function (not unrelated code).
# We walk children of each function looking for BOTH a check_max_tlp call
# AND a raise statement.  If the same function contains both, the connector
# is considered to reject invalid TLP.
# ---------------------------------------------------------------------------
def _has_raise_after_tlp_check(tree: ast.Module) -> int | None:
    """Check for a raise statement that could reject invalid TLP.

    Looks for raise inside an if block that follows or contains check_max_tlp.
    Also matches raise inside a function that contains check_max_tlp.
    """
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        has_tlp_check = False
        has_raise = False
        raise_line = None
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func = child.func
                if (
                    isinstance(func, ast.Attribute) and func.attr == "check_max_tlp"
                ) or (isinstance(func, ast.Name) and func.id == "check_max_tlp"):
                    has_tlp_check = True
            if isinstance(child, ast.Raise):
                has_raise = True
                raise_line = child.lineno
        if has_tlp_check and has_raise:
            return raise_line
    return None


@CheckRegistry.register(
    code="VC320",
    name="tlp-access-control",
    description=(
        "Enrichment connector must enforce TLP access control: "
        "extract objectMarking, check_max_tlp, reject if invalid"
    ),
    severity=Severity.ERROR,
    applicable_types={ConnectorType.INTERNAL_ENRICHMENT},
)
def check_tlp_access_control(ctx: ConnectorContext) -> list[CheckFinding]:
    """Verify the complete TLP access-control flow."""
    sources = ctx.python_sources
    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees

    # ---------------------------------------------------------------------------
    # 3-step TLP access control verification:
    #   Step 1: Extract — objectMarking is accessed to get the entity's TLP
    #   Step 2: Validate — check_max_tlp() is called to compare against max
    #   Step 3: Reject — a raise statement prevents processing if TLP too high
    #
    # Distinct from VC304 which only checks that check_max_tlp is called.
    # VC320 verifies the COMPLETE access-control flow end-to-end.
    # ---------------------------------------------------------------------------

    # Step 1: objectMarking access
    marking_line = None
    marking_file: Path | None = None
    for fp, tree in trees.items():
        line = _has_object_marking_access(tree)
        if line is not None:
            marking_line = line
            marking_file = fp
            break

    if marking_line is None:
        return [
            CheckFinding(
                message=(
                    "objectMarking is never accessed — TLP of incoming "
                    "entities is not extracted"
                ),
                severity=Severity.ERROR,
                suggestion=(
                    "Extract TLP from opencti_entity['objectMarking'], "
                    "call self.helper.check_max_tlp(tlp, max_tlp), "
                    "and raise if the TLP exceeds the configured maximum. "
                    "This prevents leaking paid TLP:RED data on a TLP:CLEAR platform."
                ),
            ),
        ]
    # cast() is needed for mypy: marking_file is Path at this point
    # (we returned [] above if None), but mypy can't infer that.
    marking_file = cast("Path", marking_file)  # for mypy

    # Step 2: check_max_tlp call
    check_line = None
    check_file = None
    for fp, tree in trees.items():
        line = _has_check_max_tlp(tree)
        if line is not None:
            check_line = line
            check_file = fp
            break

    if check_line is None:
        return [
            CheckFinding(
                message=(
                    "objectMarking is read but check_max_tlp is never "
                    "called — TLP is not enforced"
                ),
                severity=Severity.ERROR,
                file_path=marking_file,
                line=marking_line,
                suggestion=(
                    "After extracting TLP from objectMarking, call "
                    "self.helper.check_max_tlp(tlp, max_tlp) and raise "
                    "an error if the entity's TLP exceeds the maximum."
                ),
            ),
        ]

    # cast() for mypy: same pattern as marking_file above
    check_file = cast("Path", check_file)  # for mypy

    # Step 3: reject (raise) when invalid
    results: list[CheckFinding] = []
    reject_line = None
    for fp, tree in trees.items():
        line = _has_raise_after_tlp_check(tree)
        if line is not None:
            reject_line = line
            break

    if reject_line is None:
        results.append(
            CheckFinding(
                message=(
                    "check_max_tlp is called but no raise found — "
                    "invalid TLP may not be rejected"
                ),
                severity=Severity.WARNING,
                file_path=check_file,
                line=check_line,
                suggestion=(
                    "After check_max_tlp returns False, raise an error "
                    "to prevent processing entities with TLP exceeding max."
                ),
            ),
        )
    else:
        results.append(
            CheckFinding(
                message="TLP access control is enforced (objectMarking + check_max_tlp + reject)",
                severity=Severity.INFO,
                file_path=check_file,
                line=check_line,
            ),
        )

    return results
