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
_SDK_PACKAGE = "connectors_sdk"


def _is_sdk_module(name: str) -> bool:
    """Return whether a module name is the connectors-sdk package or one of its modules."""
    return name == _SDK_PACKAGE or name.startswith(f"{_SDK_PACKAGE}.")


def _sdk_bindings(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Return the names a module binds to the SDK hunt base class and to SDK modules.

    A class of the module named like the base class shadows it, so it binds nothing.
    """
    base_names: set[str] = set()
    module_names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and _is_sdk_module(node.module)
        ):
            base_names.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == _HUNT_BASE_CLASS
            )
        elif isinstance(node, ast.Import):
            module_names.update(
                alias.asname or alias.name.split(".")[0]
                for alias in node.names
                if _is_sdk_module(alias.name)
            )
    if any(
        isinstance(node, ast.ClassDef) and node.name == _HUNT_BASE_CLASS
        for node in ast.walk(tree)
    ):
        base_names.discard(_HUNT_BASE_CLASS)
    return base_names, module_names


def _is_sdk_hunt_base(
    base: ast.expr, base_names: set[str], module_names: set[str]
) -> bool:
    """Return whether a base class expression is the SDK ``InternalHuntConnector``."""
    if isinstance(base, ast.Name):
        return base.id in base_names
    if isinstance(base, ast.Attribute) and base.attr == _HUNT_BASE_CLASS:
        root = base.value
        while isinstance(root, ast.Attribute):
            root = root.value
        return isinstance(root, ast.Name) and root.id in module_names
    return False


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
    """Find subclasses of the SDK hunt base class and ``helper.listen_hunt()`` calls."""
    hits: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        base_names, module_names = _sdk_bindings(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                _is_sdk_hunt_base(base, base_names, module_names) for base in node.bases
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
