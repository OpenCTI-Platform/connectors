"""VC318 — Internal-enrichment connectors must use helper.listen().

Uses AST to verify the call is ``self.helper.listen()`` specifically,
avoiding false positives from other ``.listen()`` calls (e.g. sockets).

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

# ---------------------------------------------------------------------------
# Scope: INTERNAL_ENRICHMENT only.
#
# Enrichment connectors are event-driven — they react to platform events
# (e.g. "enrich this indicator") by registering a callback via
# self.helper.listen(message_callback=self.process_message).
#
# This is distinct from VC323 which checks helper.listen_stream() for
# STREAM connectors.  listen() and listen_stream() are different methods:
#   - listen()        → enrichment, receives entity-level events
#   - listen_stream() → stream, receives the full event stream
# ---------------------------------------------------------------------------


def _find_helper_listen_calls(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int]]:
    """Find ``*.helper.listen(...)`` calls using AST."""
    hits: list[tuple[Path, int]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # First level: the called method must be .listen()
            if not isinstance(func, ast.Attribute) or func.attr != "listen":
                continue
            # ---------------------------------------------------------------------------
            # Second level: verify the receiver is "helper" to avoid false positives
            #
            # Two patterns are accepted:
            #   1. self.helper.listen(...)  — Attribute chain: receiver is
            #      an ast.Attribute with attr == "helper"
            #   2. helper.listen(...)       — bare name: receiver is
            #      an ast.Name with id == "helper"
            #
            # This prevents matching unrelated .listen() calls (e.g. sockets).
            # ---------------------------------------------------------------------------
            receiver = func.value
            if (isinstance(receiver, ast.Attribute) and receiver.attr == "helper") or (
                isinstance(receiver, ast.Name) and receiver.id == "helper"
            ):
                hits.append((file_path, node.lineno))
    return hits


@CheckRegistry.register(
    code="VC318",
    name="helper-listen",
    description="Internal-enrichment connectors must use helper.listen()",
    severity=Severity.ERROR,
    applicable_types={ConnectorType.INTERNAL_ENRICHMENT},
)
def check_helper_listen(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector uses helper.listen()."""
    sources = ctx.python_sources
    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees
    locations = _find_helper_listen_calls(trees)

    if not locations:
        return [
            CheckFinding(
                message="helper.listen() not found — enrichment connector is not event-driven",
                severity=Severity.ERROR,
                suggestion=(
                    "Add self.helper.listen(message_callback=self.process_message) "
                    "in the run method to listen for platform events."
                ),
            ),
        ]

    first = locations[0]
    return [
        CheckFinding(
            message="Connector uses helper.listen() for event-driven processing",
            severity=Severity.INFO,
            file_path=first[0],
            line=first[1],
        ),
    ]
