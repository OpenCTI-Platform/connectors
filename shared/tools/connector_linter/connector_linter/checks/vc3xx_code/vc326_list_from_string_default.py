"""VC326 — ListFromString settings must define a default value.

``connectors_sdk.ListFromString`` fields that have no default (not even an
empty list) cannot be used from the OpenCTI Composer UI: a required
array-typed setting with no default blocks form submission, and it also
prevents the connector from starting when the corresponding environment
variable is left unset.

Two complementary detections are performed:

1. **Code** — any concrete/leaf class defines a field annotated
   ``ListFromString`` without a default (no bare value, no
   ``Field(default=...)``/positional default, no ``default_factory``).
   Classes prefixed with ``_`` (e.g. ``connectors_sdk``'s
   ``_BaseConnectorConfig``) or locally subclassed elsewhere in the same
   connector (e.g. an interface-style ``ConfigLoaderConnectorExtra``
   overridden by a concrete ``ConfigLoaderConnector``) follow the codebase's
   abstract/interface config convention and are expected to have their
   default supplied by the concrete subclass — these are skipped.
2. **Config schema** — ``__metadata__/connector_config_schema.json`` is the
   rendered, inheritance-resolved artifact actually consumed by the
   Composer UI. Any ``array`` property with ``string`` items but no
   ``default`` key is flagged, catching the case where a concrete settings
   class inherits a ``ListFromString`` field (e.g. ``scope``) from an SDK
   base class but forgets to override it with a default.

Scope: Common (all connector types).
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


def _annotation_references_list_from_string(annotation: ast.expr) -> bool:
    """Return True if the annotation node references ``ListFromString``.

    Handles direct usage (``scope: ListFromString``) as well as wrapped
    usages (``Optional[ListFromString]``, ``ListFromString | None``) by
    walking the whole annotation subtree.
    """
    for node in ast.walk(annotation):
        if isinstance(node, ast.Name) and node.id == "ListFromString":
            return True
    return False


def _field_call_has_default(call: ast.Call) -> bool:
    """Return True if a ``Field(...)`` call defines a default or a factory."""
    for kw in call.keywords:
        if kw.arg in ("default", "default_factory"):
            return True
    # Field("value", ...) — positional first argument is the default
    return bool(call.args)


def _local_base_class_names(trees: dict[Path, ast.Module]) -> set[str]:
    """Return the names of every locally-defined class used as a base class.

    Connectors in this codebase follow (with varying naming: ``_Foo``,
    ``FooExtra``, or a shared ``Config``/``ConnectorConfig`` module) the
    convention of an abstract/interface config class that a concrete
    subclass overrides with real defaults (see ``connectors_sdk``'s
    ``_BaseConnectorConfig``). A class subclassed elsewhere in the same
    connector is therefore not the final word on defaults — the subclass is.
    """
    base_names: set[str] = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for base in node.bases:
                if isinstance(base, ast.Name):
                    base_names.add(base.id)
                elif isinstance(base, ast.Attribute):
                    base_names.add(base.attr)
    return base_names


def _find_missing_defaults(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int, str, str]]:
    """Return (file, line, class_name, field_name) for fields missing a default.

    Only inspects concrete/leaf classes: names prefixed with ``_`` (abstract
    convention) and classes locally subclassed elsewhere (interface classes
    expected to be overridden) are skipped — the defaults they lack are
    expected to be supplied by whichever concrete class wins at runtime,
    which is verified separately via the rendered config schema.
    """
    abstract_names = _local_base_class_names(trees)
    hits: list[tuple[Path, int, str, str]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name.startswith("_") or node.name in abstract_names:
                continue
            for stmt in node.body:
                if not isinstance(stmt, ast.AnnAssign) or not isinstance(
                    stmt.target,
                    ast.Name,
                ):
                    continue
                if not _annotation_references_list_from_string(stmt.annotation):
                    continue

                if stmt.value is None:
                    # Bare annotation, e.g. `scope: ListFromString` — no default
                    hits.append(
                        (file_path, stmt.lineno, node.name, stmt.target.id),
                    )
                    continue

                if isinstance(stmt.value, ast.Call):
                    func = stmt.value.func
                    func_name = (
                        func.id
                        if isinstance(func, ast.Name)
                        else func.attr if isinstance(func, ast.Attribute) else ""
                    )
                    if func_name == "Field" and not _field_call_has_default(
                        stmt.value,
                    ):
                        hits.append(
                            (file_path, stmt.lineno, node.name, stmt.target.id),
                        )
                # Any other assigned value (e.g. a direct list literal) counts
                # as a default.
    return hits


def _find_schema_properties_missing_default(
    config_schema: dict,
) -> list[str]:
    """Return property names that look like ListFromString but lack a default.

    Detected via the rendered JSON schema shape produced for
    ``ListFromString`` fields: ``{"type": "array", "items": {"type": "string"}}``.
    """
    missing: list[str] = []
    properties = config_schema.get("properties", {})
    if not isinstance(properties, dict):
        return missing
    for name, prop in properties.items():
        if not isinstance(prop, dict):
            continue
        if prop.get("type") != "array":
            continue
        items = prop.get("items", {})
        if isinstance(items, dict) and items.get("type") == "string":
            if "default" not in prop:
                missing.append(name)
    return missing


@CheckRegistry.register(
    code="VC326",
    name="list-from-string-default",
    description="ListFromString settings must define a default value (even an empty list)",
    severity=Severity.ERROR,
)
def check_list_from_string_default(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that ListFromString fields always define a default value."""
    sources = ctx.python_sources
    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees
    results: list[CheckFinding] = []

    # 1. Code — concrete class fields with no default
    code_hits = _find_missing_defaults(trees)
    for file_path, line, class_name, field_name in code_hits:
        results.append(
            CheckFinding(
                message=(
                    f"{file_path}:{line}: {class_name}.{field_name} is a "
                    "ListFromString without a default value"
                ),
                severity=Severity.ERROR,
                file_path=ctx.path / file_path,
                line=line,
                suggestion=(
                    "Set a default (even an empty list, e.g. default=[]) on "
                    f"{class_name}.{field_name}. Without a default, this "
                    "setting cannot be used from the Composer UI and blocks "
                    "the connector if the env var is unset"
                ),
            ),
        )

    # 2. Config schema — rendered artifact actually consumed by Composer UI
    if ctx.config_schema:
        for prop_name in _find_schema_properties_missing_default(ctx.config_schema):
            results.append(
                CheckFinding(
                    message=(
                        f"Config schema property '{prop_name}' is an array of "
                        "strings with no default value"
                    ),
                    severity=Severity.ERROR,
                    file_path=ctx.path
                    / "__metadata__"
                    / "connector_config_schema.json",
                    suggestion=(
                        f"Give '{prop_name}' a default (even an empty list) in "
                        "its settings class. It is likely inherited from an SDK "
                        "base config class (e.g. 'scope') without being "
                        "overridden with a default in the connector's own "
                        "settings"
                    ),
                ),
            )

    if not results:
        return [
            CheckFinding(
                message="All ListFromString settings define a default value ✓",
                severity=Severity.INFO,
            ),
        ]
    return results
