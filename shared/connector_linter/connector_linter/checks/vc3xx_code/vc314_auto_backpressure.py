"""VC314 — External-import connectors must use schedule_process or schedule_iso.

Uses AST to detect ``while True`` loops (avoids false positives from
comments like ``# migrated from while True``).

``self.helper.schedule_process(message_callback=..., duration_period=...)``
or ``self.helper.schedule_iso(message_callback=..., duration_period=...)``
provide automatic scheduling with backpressure. Manual ``while True`` /
``time.sleep`` loops should be migrated.

Scope: EXTERNAL_IMPORT only — other connector types are event-driven.
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


def _find_schedule_calls(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int, str]]:
    """Find schedule_process or schedule_iso calls via AST.

    These are the two valid scheduling methods from pycti:
      - schedule_process: legacy scheduler with polling interval
      - schedule_iso:     ISO 8601 duration-based scheduler (preferred)
    Both provide automatic backpressure management.
    """
    hits: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in (
                "schedule_process",
                "schedule_iso",
            ):
                hits.append((file_path, node.lineno, func.attr))
    return hits


def _find_while_true_loops(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int]]:
    """Find ``while True:`` loops via AST.

    The while True + time.sleep() pattern is an anti-pattern for connectors:
    it doesn't respect platform backpressure, can cause duplicate processing,
    and lacks proper state management. Should be replaced with schedule_iso.
    """
    hits: list[tuple[Path, int]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.While):
                continue
            if isinstance(node.test, ast.Constant) and node.test.value is True:
                hits.append((file_path, node.lineno))
    return hits


@CheckRegistry.register(
    code="VC314",
    name="auto-backpressure",
    description="External-import connectors must use schedule_process or schedule_iso",
    severity=Severity.ERROR,
    applicable_types={ConnectorType.EXTERNAL_IMPORT},
)
def check_auto_backpressure(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that external-import connectors use schedule_process/schedule_iso."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees

    # ---------------------------------------------------------------------------
    # Detection priority:
    #   1. schedule_process/schedule_iso found → PASS (proper scheduling)
    #   2. while True loop found → FAIL with specific detail
    #   3. Nothing found → FAIL with generic message
    # ---------------------------------------------------------------------------

    # Check for either valid scheduling method (AST)
    schedule_hits = _find_schedule_calls(trees)

    if schedule_hits:
        first = schedule_hits[0]
        return [
            CheckFinding(
                message=f"Connector uses {first[2]} for scheduling",
                severity=Severity.INFO,
                file_path=first[0],
                line=first[1],
            ),
        ]

    # No valid scheduling found — check for while True anti-pattern (AST)
    results: list[CheckFinding] = []
    while_loops = _find_while_true_loops(trees)
    for file_path, line_no in while_loops:
        results.append(
            CheckFinding(
                message="Uses while True loop instead of scheduler",
                severity=Severity.WARNING,
                file_path=file_path,
                line=line_no,
                suggestion=(
                    "Replace manual while True / time.sleep loop with "
                    "self.helper.schedule_iso(message_callback=..., "
                    "duration_period=...) or schedule_process(). See PR #4227."
                ),
            ),
        )

    if not results:
        results.append(
            CheckFinding(
                message="No schedule_process or schedule_iso call found",
                severity=Severity.ERROR,
                suggestion=(
                    "Use self.helper.schedule_iso(message_callback=self.process_message, "
                    "duration_period=self.config.connector.duration_period) for scheduling."
                ),
            ),
        )

    return results
