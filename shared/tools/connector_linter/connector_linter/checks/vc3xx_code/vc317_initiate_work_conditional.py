"""VC317 — initiate_work should only be called when data is available.

Creating jobs with zero bundles clutters the UI and confuses users.
``initiate_work`` should be guarded by a condition that verifies data
availability *before* creating the work.

Scope: EXTERNAL_IMPORT, INTERNAL_ENRICHMENT
Severity: WARNING (heuristic — hard to prove statically)
"""

import ast
from typing import TYPE_CHECKING

from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    ConnectorType,
    Severity,
)
from connector_linter.registry import CheckRegistry

if TYPE_CHECKING:
    from pathlib import Path

# Only external-import and internal-enrichment connectors create "work" items.
# Stream connectors use a different event model and never call initiate_work.


# ---------------------------------------------------------------------------
# AST NodeVisitor: track initiate_work calls and whether they are guarded
#
# Uses a depth counter (_if_depth) to detect if the call site is nested
# inside at least one ``if`` block.  The visitor increments the counter on
# entering an ``if`` and decrements it on exit, so any Call node found
# with _if_depth > 0 is considered "conditional".
#
# This is a heuristic — it cannot prove the condition actually checks data
# availability — but it catches the most common anti-pattern of calling
# initiate_work at the top level with no guard at all.
# ---------------------------------------------------------------------------
class _InitiateWorkVisitor(ast.NodeVisitor):
    """Collect initiate_work calls and whether they are inside an ``if``."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, bool]] = []  # (lineno, is_conditional)
        # Depth counter: >0 means we are inside at least one ``if`` block
        self._if_depth = 0

    def visit_If(self, node: ast.If) -> None:
        # Increment depth before visiting children, decrement after.
        # This way any Call node encountered while depth > 0 is conditional.
        self._if_depth += 1
        self.generic_visit(node)
        self._if_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        # Record every initiate_work call with its conditionality status
        if self._is_initiate_work(node):
            self.calls.append((node.lineno, self._if_depth > 0))
        self.generic_visit(node)

    @staticmethod
    def _is_initiate_work(node: ast.Call) -> bool:
        """Match ``*.initiate_work(...)``."""
        # ---------------------------------------------------------------------------
        # AST pattern: *.initiate_work(...)
        #
        # Matches any method call where the attribute name is "initiate_work":
        #   self.helper.initiate_work(...)   — typical usage
        #   helper.initiate_work(...)        — also matched
        # We only check the Attribute node, not the receiver, to stay flexible.
        # ---------------------------------------------------------------------------
        func = node.func
        return bool(isinstance(func, ast.Attribute) and func.attr == "initiate_work")


@CheckRegistry.register(
    code="VC317",
    name="initiate-work-conditional",
    description=(
        "initiate_work should only be called when data is available "
        "(never create empty jobs)"
    ),
    severity=Severity.WARNING,
    applicable_types={ConnectorType.EXTERNAL_IMPORT, ConnectorType.INTERNAL_ENRICHMENT},
)
def check_initiate_work_conditional(ctx: ConnectorContext) -> list[CheckFinding]:
    """Warn if initiate_work is called unconditionally (outside any ``if``)."""
    sources = ctx.python_sources
    if not sources:
        return []

    trees = ctx.python_trees
    if not trees:
        return []

    # Partition all initiate_work calls into unconditional (top-level) and
    # conditional (inside at least one ``if`` block).
    unconditional: list[tuple[Path, int]] = []
    conditional: list[tuple[Path, int]] = []

    for filepath, tree in trees.items():
        visitor = _InitiateWorkVisitor()
        visitor.visit(tree)
        for lineno, is_cond in visitor.calls:
            if is_cond:
                conditional.append((filepath, lineno))
            else:
                unconditional.append((filepath, lineno))

    if not unconditional and not conditional:
        # No initiate_work found anywhere — VC315 already flags that case,
        # so we return an empty list to avoid duplicate findings.
        return []

    results: list[CheckFinding] = []

    # Unconditional initiate_work is the anti-pattern: if no data was fetched,
    # an empty work item clutters the OpenCTI jobs UI.  We report it as
    # passed=True with a WARNING because this is heuristic-based.
    if unconditional:
        first = unconditional[0]
        results.append(
            CheckFinding(
                message=(
                    "initiate_work is called unconditionally — "
                    "may create empty jobs when no data is available"
                ),
                severity=Severity.WARNING,
                file_path=first[0],
                line=first[1],
                suggestion=(
                    "Guard initiate_work with a condition that checks data "
                    "availability first. Only create a work when the bundle "
                    "will contain objects. Track "
                    "'last_run_end_datetime_with_ingested_data' in state."
                ),
            ),
        )
    else:
        first = conditional[0]
        results.append(
            CheckFinding(
                message="initiate_work is guarded by a condition",
                severity=Severity.INFO,
                file_path=first[0],
                line=first[1],
            ),
        )

    return results
