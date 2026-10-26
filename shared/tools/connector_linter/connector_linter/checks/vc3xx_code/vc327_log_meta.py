"""VC327 — SDK log messages must be static, with variable data passed in ``meta``.

The connectors-sdk logger is structured: it accepts a ``meta`` dict whose
values are emitted as separate JSON fields. Interpolating values into the
message instead makes every log line unique, so they can no longer be
grouped, searched or filtered on the message::

    # Bad
    self.logger.info(f"Fetched {len(reports)} reports")
    self.logger.error(str(err))

    # Good
    self.logger.info("Reports fetched", meta={"count": len(reports)})
    self.logger.error("Import failed", meta={"error": str(err)})

Only calls on a connectors-sdk logger are checked. A receiver is resolved
as an SDK logger when it is:

- ``self.logger`` / ``cls.logger`` in a class inheriting, directly or
  through local classes, from ``BaseDataProcessor``,
  ``ExternalImportConnector`` or ``BaseClientApi``;
- a name or ``self`` attribute bound to ``get_logger(...)``;
- a parameter, variable or attribute annotated ``ConnectorLoggerAdapter``;
- a name or ``self`` attribute assigned from one of the above.

An untyped ``logger`` parameter is not followed: annotate it with
``ConnectorLoggerAdapter`` to have its calls checked. pycti's
``helper.connector_logger`` and stdlib loggers are out of scope.

Flagged message expressions: f-strings with placeholders, ``%`` formatting,
concatenation with a non-literal operand and any call (``str(err)``,
``"...".format(...)``). A message held in a variable is not flagged, since
its content cannot be known statically.

Scope: Common (all connector types).
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path

from connector_linter.checks.vc3xx_code._helpers import find_imports
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

_LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical"}

# SDK classes whose instances get a ``logger`` attribute (_ClassLoggerMixin)
_SDK_LOGGER_CLASSES = {"BaseDataProcessor", "ExternalImportConnector", "BaseClientApi"}
_GET_LOGGER = "get_logger"
_ADAPTER = "ConnectorLoggerAdapter"


@dataclass
class _SdkNames:
    """Local names bound to the connectors-sdk logger API in the connector."""

    get_logger: set[str] = field(default_factory=set)
    adapter: set[str] = field(default_factory=set)
    # SDK classes carrying a logger, plus local classes inheriting from them
    logger_classes: set[str] = field(default_factory=set)


@dataclass
class _ClassCtx:
    """The class enclosing the code being scanned."""

    has_sdk_logger: bool
    # Attributes of ``self``/``cls`` holding an SDK logger
    attrs: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# SDK logger resolution
# ---------------------------------------------------------------------------


def _collect_sdk_names(trees: dict[Path, ast.Module]) -> _SdkNames:
    """Collect the SDK logger names imported or derived in the connector."""
    sdk = _SdkNames()
    imports = find_imports(
        trees,
        module_pattern=r"^connectors_sdk(\.|$)",
        name_pattern=rf"^({_GET_LOGGER}|{_ADAPTER}|{'|'.join(_SDK_LOGGER_CLASSES)})$",
    )
    for imp in imports:
        local_name = imp.alias or imp.name
        if imp.name == _GET_LOGGER:
            sdk.get_logger.add(local_name)
        elif imp.name == _ADAPTER:
            sdk.adapter.add(local_name)
        else:
            sdk.logger_classes.add(local_name)

    # Local subclasses inherit the SDK logger, possibly over several levels
    classes = [
        node
        for tree in trees.values()
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    ]
    changed = bool(sdk.logger_classes)
    while changed:
        changed = False
        for cls in classes:
            if cls.name in sdk.logger_classes:
                continue
            if any(_base_name(base) in sdk.logger_classes for base in cls.bases):
                sdk.logger_classes.add(cls.name)
                changed = True
    return sdk


def _base_name(node: ast.expr) -> str | None:
    """Return the unqualified name of a base class expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_adapter_annotation(node: ast.expr | None, sdk: _SdkNames) -> bool:
    """Match ``ConnectorLoggerAdapter``, ``ConnectorLoggerAdapter | None``, etc."""
    if node is None:
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in sdk.adapter:
            return True
        if isinstance(sub, ast.Attribute) and sub.attr == _ADAPTER:
            return True
        # String annotation, e.g. "ConnectorLoggerAdapter | None"
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if _ADAPTER in sub.value and sdk.adapter:
                return True
    return False


def _is_sdk_logger(
    node: ast.expr,
    sdk: _SdkNames,
    names: set[str],
    cls: _ClassCtx | None,
) -> bool:
    """Return True if the expression evaluates to a connectors-sdk logger."""
    # get_logger(__name__)
    if isinstance(node, ast.Call):
        return isinstance(node.func, ast.Name) and node.func.id in sdk.get_logger
    # logger, _LOGGER...
    if isinstance(node, ast.Name):
        return node.id in names
    # self.logger, self._logger, cls.logger
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in ("self", "cls")
        and cls is not None
    ):
        return (node.attr == "logger" and cls.has_sdk_logger) or node.attr in cls.attrs
    # logger or get_logger(__name__): every operand must be an SDK logger
    if isinstance(node, ast.BoolOp):
        return all(_is_sdk_logger(value, sdk, names, cls) for value in node.values)
    return False


def _bound_names(
    stmts: list[ast.AST],
    sdk: _SdkNames,
    names: set[str],
    cls: _ClassCtx | None,
) -> set[str]:
    """Return ``names`` plus the plain names the statements bind to an SDK logger."""
    bound = set(names)
    changed = True
    while changed:
        changed = False
        for stmt in stmts:
            for node in ast.walk(stmt):
                for target in _sdk_logger_targets(node, sdk, bound, cls):
                    if isinstance(target, ast.Name) and target.id not in bound:
                        bound.add(target.id)
                        changed = True
    return bound


def _sdk_logger_targets(
    node: ast.AST,
    sdk: _SdkNames,
    names: set[str],
    cls: _ClassCtx | None,
) -> list[ast.expr]:
    """Return the assignment targets of ``node`` that receive an SDK logger."""
    if isinstance(node, ast.AnnAssign):
        if _is_adapter_annotation(node.annotation, sdk) or (
            node.value is not None and _is_sdk_logger(node.value, sdk, names, cls)
        ):
            return [node.target]
    elif isinstance(node, ast.Assign):
        if _is_sdk_logger(node.value, sdk, names, cls):
            return list(node.targets)
    return []


def _adapter_params(func: ast.FunctionDef | ast.AsyncFunctionDef, sdk: _SdkNames):
    """Return the parameters of ``func`` annotated ``ConnectorLoggerAdapter``."""
    args = func.args
    params = args.posonlyargs + args.args + args.kwonlyargs
    return {arg.arg for arg in params if _is_adapter_annotation(arg.annotation, sdk)}


def _function_names(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    sdk: _SdkNames,
    names: set[str],
    cls: _ClassCtx | None,
) -> set[str]:
    """Return the SDK logger names visible in the body of ``func``."""
    return _bound_names(func.body, sdk, names | _adapter_params(func, sdk), cls)


def _class_ctx(node: ast.ClassDef, sdk: _SdkNames, names: set[str]) -> _ClassCtx:
    """Build the context of a class: SDK base and ``self`` logger attributes."""
    ctx = _ClassCtx(
        has_sdk_logger=any(_base_name(b) in sdk.logger_classes for b in node.bases),
    )
    methods = [
        stmt
        for stmt in node.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    # Class-level attributes: _logger: ConnectorLoggerAdapter, _logger = get_logger()
    for stmt in node.body:
        if stmt in methods:
            continue
        for target in _sdk_logger_targets(stmt, sdk, names, ctx):
            if isinstance(target, ast.Name):
                ctx.attrs.add(target.id)
    # Attributes set in methods: self._logger = logger. They can be set from
    # each other (self.a = self.b) in any method order, hence the fixpoint.
    changed = True
    while changed:
        changed = False
        for method in methods:
            local = _function_names(method, sdk, names, ctx)
            for sub in ast.walk(method):
                for target in _sdk_logger_targets(sub, sdk, local, ctx):
                    attr = _self_attr(target)
                    if attr and attr not in ctx.attrs:
                        ctx.attrs.add(attr)
                        changed = True
    return ctx


def _self_attr(node: ast.expr) -> str | None:
    """Return ``x`` for ``self.x`` / ``cls.x``, else None."""
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in ("self", "cls")
    ):
        return node.attr
    return None


# ---------------------------------------------------------------------------
# Message analysis
# ---------------------------------------------------------------------------


def _is_literal(node: ast.expr) -> bool:
    """Return True for a string literal or a concatenation of literals."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        # f-string without any placeholder, e.g. f"Done"
        return not any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_literal(node.left) and _is_literal(node.right)
    return False


def _dynamic_message_kind(node: ast.expr) -> str | None:
    """Describe how a log message is built, or None if it is acceptable."""
    if _is_literal(node):
        return None
    if isinstance(node, ast.JoinedStr):
        return "an f-string"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return "% formatting"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return "string concatenation"
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return "str.format()"
        return "a function call"
    # Variables and attributes: content unknown statically
    return None


def _message_arg(node: ast.Call) -> ast.expr | None:
    """Return the message argument of a logging call (positional or keyword)."""
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg in ("message", "msg"):
            return kw.value
    return None


# ---------------------------------------------------------------------------
# Scope-aware scan
# ---------------------------------------------------------------------------


def _scan(
    node: ast.AST,
    sdk: _SdkNames,
    names: set[str],
    cls: _ClassCtx | None,
    hits: list[tuple[int, str, str]],
) -> None:
    """Collect (line, method, kind) for SDK logging calls with a dynamic message."""
    if isinstance(node, ast.ClassDef):
        ctx = _class_ctx(node, sdk, names)
        for stmt in node.body:
            _scan(stmt, sdk, names, ctx, hits)
        return
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        local = _function_names(node, sdk, names, cls)
        for stmt in node.body:
            _scan(stmt, sdk, local, cls, hits)
        return
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _LOG_METHODS
            and _is_sdk_logger(func.value, sdk, names, cls)
        ):
            message = _message_arg(node)
            kind = _dynamic_message_kind(message) if message is not None else None
            if kind:
                hits.append((node.lineno, func.attr, kind))
    for child in ast.iter_child_nodes(node):
        _scan(child, sdk, names, cls, hits)


@CheckRegistry.register(
    code="VC327",
    name="log-meta",
    description=(
        "connectors-sdk log messages must be static, with variable data passed in meta"
    ),
    severity=Severity.WARNING,
)
def check_log_meta(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that SDK logging calls use a static message and pass data in meta."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees
    sdk = _collect_sdk_names(trees)

    if not (sdk.get_logger or sdk.adapter or sdk.logger_classes):
        return [
            CheckFinding(
                message="Connector does not use the connectors-sdk logger — skipped",
                severity=Severity.INFO,
            ),
        ]

    results: list[CheckFinding] = []
    for file_path, tree in sorted(trees.items()):
        module_names = _bound_names(
            [
                stmt
                for stmt in tree.body
                if not isinstance(
                    stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                )
            ],
            sdk,
            set(),
            None,
        )
        hits: list[tuple[int, str, str]] = []
        _scan(tree, sdk, module_names, None, hits)
        results.extend(
            CheckFinding(
                message=f"Log message built with {kind} in {method}() call",
                severity=Severity.WARNING,
                file_path=file_path,
                line=line,
                suggestion=(
                    "Use a static message and pass the variable parts in meta, e.g. "
                    f'self.logger.{method}("Reports fetched", '
                    'meta={"count": len(reports)}).'
                ),
            )
            for line, method, kind in sorted(hits)
        )

    if not results:
        return [
            CheckFinding(
                message="All connectors-sdk log messages are static",
                severity=Severity.INFO,
            ),
        ]

    return results
