"""VC304 — Ensure TLP markings are checked before processing entities.

Uses AST to detect ``check_max_tlp()`` calls (avoids false positives
from comments/docstrings mentioning check_max_tlp).

Scope: INTERNAL_ENRICHMENT only — enrichment connectors receive external
entities and must verify TLP markings before processing them. Other
connector types produce their own entities and set TLP themselves.
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


def _find_check_max_tlp_calls(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int]]:
    """Find check_max_tlp() calls via AST.

    Matches two call patterns:
      1. self.helper.check_max_tlp(...)  — Attribute node (method call)
      2. check_max_tlp(...)              — Name node (bare function call)
    """
    hits: list[tuple[Path, int]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (isinstance(func, ast.Attribute) and func.attr == "check_max_tlp") or (
                isinstance(func, ast.Name) and func.id == "check_max_tlp"
            ):
                hits.append((file_path, node.lineno))
    return hits


def _find_object_marking_access(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int]]:
    """Find objectMarking accesses via AST (string constants or attributes).

    Checks two AST node types because "objectMarking" can appear as:
      - Constant: entity["objectMarking"]  (dict key string literal)
      - Attribute: entity.objectMarking     (attribute access)
    """
    hits: list[tuple[Path, int]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and node.value == "objectMarking") or (
                isinstance(node, ast.Attribute) and node.attr == "objectMarking"
            ):
                hits.append((file_path, node.lineno))
    return hits


@CheckRegistry.register(
    code="VC304",
    name="markings-checked",
    description="Ensure TLP markings are checked before processing entities",
    severity=Severity.ERROR,
    applicable_types={ConnectorType.INTERNAL_ENRICHMENT},
)
def check_markings_checked(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector verifies TLP markings via check_max_tlp."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees

    # ---------------------------------------------------------------------------
    # 3-tier detection:
    #   1. check_max_tlp() call found → PASS (best: proper TLP validation)
    #   2. objectMarking access found → FAIL (TLP extracted but not validated)
    #   3. Nothing found              → FAIL (no TLP handling at all)
    # ---------------------------------------------------------------------------

    # Tier 1: check for check_max_tlp call (AST-based)
    tlp_check_hits = _find_check_max_tlp_calls(trees)

    if tlp_check_hits:
        file_path, line = tlp_check_hits[0]
        return [
            CheckFinding(
                message="check_max_tlp() found",
                severity=Severity.INFO,
                file_path=file_path,
                line=line,
            ),
        ]

    # Tier 2: check_max_tlp not found — check if there's at least TLP extraction
    extract_hits = _find_object_marking_access(trees)

    if extract_hits:
        file_path, line = extract_hits[0]
        return [
            CheckFinding(
                message=(
                    f"TLP extraction found in {file_path}:{line} "
                    "but check_max_tlp is not called"
                ),
                severity=Severity.ERROR,
                file_path=file_path,
                line=line,
                suggestion=(
                    "Add self.helper.check_max_tlp(self.tlp, self.config.max_tlp) "
                    "to validate TLP before processing the entity"
                ),
            ),
        ]

    return [
        CheckFinding(
            message="No TLP marking check found in connector source",
            severity=Severity.ERROR,
            suggestion=(
                'Implement TLP checking: extract TLP from opencti_entity["objectMarking"], '
                "then call self.helper.check_max_tlp(entity_tlp, max_tlp) "
                "and reject processing if it returns False"
            ),
        ),
    ]
