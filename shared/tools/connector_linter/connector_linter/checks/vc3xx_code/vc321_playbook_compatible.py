"""VC321 — Enrichment connector must be playbook-compatible.

Uses AST to verify ``playbook_compatible=True`` is a keyword argument
in a constructor call (avoids false positives from comments/docstrings).

Sub-check A: ``playbook_compatible=True`` is set (ERROR).
Sub-check B: ``send_stix2_bundle`` is called (WARNING — bundle-based flow).

Scope: INTERNAL_ENRICHMENT only.
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

# Only enrichment connectors participate in playbook automation.
# External-import connectors are scheduled, not triggered by playbooks.


# ---------------------------------------------------------------------------
# AST helper: find playbook_compatible= keyword argument
#
# Walks every Call node and inspects its keyword arguments.  When a keyword
# named "playbook_compatible" is found, we check whether its value is the
# literal True (ast.Constant with value True).
#
# Returns tuples of (file, line, is_true) — is_true distinguishes between
# playbook_compatible=True (correct) and playbook_compatible=False or
# playbook_compatible=some_var (incorrect / ambiguous).
# ---------------------------------------------------------------------------
def _find_playbook_compatible_kwarg(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int, bool]]:
    """Find playbook_compatible= keyword args. Returns (file, line, is_true)."""
    hits: list[tuple[Path, int, bool]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg == "playbook_compatible":
                    # Check if the value is literally True (ast.Constant)
                    is_true = (
                        isinstance(kw.value, ast.Constant) and kw.value.value is True
                    )
                    hits.append((file_path, node.lineno, is_true))
    return hits


# ---------------------------------------------------------------------------
# AST helper: find send_stix2_bundle() calls
#
# Playbook-compatible connectors must send bundles so the playbook pipeline
# can forward enriched data to the next step.  This detects *.send_stix2_bundle()
# method calls (Attribute node with attr "send_stix2_bundle").
# ---------------------------------------------------------------------------
def _find_send_bundle_calls(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int]]:
    """Find send_stix2_bundle() calls via AST."""
    hits: list[tuple[Path, int]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "send_stix2_bundle":
                hits.append((file_path, node.lineno))
    return hits


@CheckRegistry.register(
    code="VC321",
    name="playbook-compatible",
    description="Enrichment connector must be playbook-compatible",
    severity=Severity.ERROR,
    applicable_types={ConnectorType.INTERNAL_ENRICHMENT},
)
def check_playbook_compatible(ctx: ConnectorContext) -> list[CheckFinding]:
    """Verify playbook compatibility."""
    sources = ctx.python_sources
    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees
    results: list[CheckFinding] = []

    # ---------------------------------------------------------------------------
    # Sub-check A: playbook_compatible=True keyword argument
    #
    # Three outcomes:
    #   1. Found with value True  → PASS
    #   2. Found with value != True (False, variable, etc.) → FAIL
    #   3. Not found at all → FAIL (missing from OpenCTIConnectorHelper call)
    # ---------------------------------------------------------------------------
    pb_hits = _find_playbook_compatible_kwarg(trees)

    if pb_hits:
        first = pb_hits[0]
        if first[2]:  # is_true
            results.append(
                CheckFinding(
                    message="playbook_compatible=True is set",
                    severity=Severity.INFO,
                    file_path=first[0],
                    line=first[1],
                ),
            )
        else:
            results.append(
                CheckFinding(
                    message=(
                        "playbook_compatible is set but not to True — "
                        "playbook automation will not work"
                    ),
                    severity=Severity.ERROR,
                    file_path=first[0],
                    line=first[1],
                    suggestion="Set playbook_compatible=True in OpenCTIConnectorHelper().",
                ),
            )
    else:
        results.append(
            CheckFinding(
                message="playbook_compatible is not set in OpenCTIConnectorHelper()",
                severity=Severity.ERROR,
                suggestion=(
                    "Add playbook_compatible=True to your "
                    "OpenCTIConnectorHelper() call. Ensure the connector "
                    "sends a bundle back in all paths (success, not-in-scope, error)."
                ),
            ),
        )

    # ---------------------------------------------------------------------------
    # Sub-check B: send_stix2_bundle() is called
    #
    # Severity is WARNING (not ERROR) because the bundle-based flow is the
    # ideal pattern for playbook compatibility, but some connectors may use
    # alternative methods.  Missing send_stix2_bundle is a strong signal
    # the connector won't forward enriched data through playbooks.
    # ---------------------------------------------------------------------------
    bundle_hits = _find_send_bundle_calls(trees)
    if not bundle_hits:
        results.append(
            CheckFinding(
                message=(
                    "send_stix2_bundle is never called — playbook cannot "
                    "forward the enriched bundle"
                ),
                severity=Severity.WARNING,
                suggestion=(
                    "Use self.helper.send_stix2_bundle() to send enriched "
                    "data. The bundle must be sent in all paths: success, "
                    "not-in-scope (original bundle), and error (original bundle)."
                ),
            ),
        )

    return results
