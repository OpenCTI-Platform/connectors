"""VC327 — Internal hunt connectors must listen to hunt runs.

An ``INTERNAL_HUNT`` connector receives one message per hunt run. It must be
built on the connectors-sdk ``InternalHuntConnector`` base class (which
registers the hunt platform, listens to hunt runs, enforces the run limits,
redacts the evidence and reports every run), or call
``self.helper.listen_hunt()`` itself.

Scope: INTERNAL_HUNT only.
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

_HUNT_BASE_CLASS = "InternalHuntConnector"


def _base_name(base: ast.expr) -> str:
    """Return the unqualified name of a base class expression."""
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute):
        return base.attr
    return ""


def _is_helper_listen_hunt(node: ast.Call) -> bool:
    """Return whether a call is ``self.helper.listen_hunt(...)`` or ``helper.listen_hunt(...)``."""
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "listen_hunt":
        return False
    receiver = func.value
    return (isinstance(receiver, ast.Attribute) and receiver.attr == "helper") or (
        isinstance(receiver, ast.Name) and receiver.id == "helper"
    )


def _find_hunt_entrypoints(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int, str]]:
    """Find hunt connector classes and ``helper.listen_hunt()`` calls."""
    hits: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                _base_name(base) == _HUNT_BASE_CLASS for base in node.bases
            ):
                hits.append((file_path, node.lineno, "base class"))
            elif isinstance(node, ast.Call) and _is_helper_listen_hunt(node):
                hits.append((file_path, node.lineno, "listen_hunt"))
    return hits


@CheckRegistry.register(
    code="VC327",
    name="hunt-connector-base",
    description="Internal hunt connectors must use InternalHuntConnector or helper.listen_hunt()",
    severity=Severity.ERROR,
    applicable_types={ConnectorType.INTERNAL_HUNT},
)
def check_hunt_connector_base(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the hunt connector listens to hunt runs."""
    sources = ctx.python_sources
    if not sources:
        return [no_python_sources_finding()]

    hits = _find_hunt_entrypoints(ctx.python_trees)
    if not hits:
        return [
            CheckFinding(
                message="No InternalHuntConnector subclass nor helper.listen_hunt() call found",
                severity=Severity.ERROR,
                suggestion=(
                    "Subclass connectors_sdk InternalHuntConnector (preferred) or call "
                    "self.helper.listen_hunt(message_callback=self.process_message)."
                ),
            ),
        ]

    file_path, line, kind = hits[0]
    message = (
        "Connector is built on InternalHuntConnector"
        if kind == "base class"
        else "Connector uses helper.listen_hunt() to process hunt runs"
    )
    return [
        CheckFinding(
            message=message,
            severity=Severity.INFO,
            file_path=file_path,
            line=line,
        ),
    ]
