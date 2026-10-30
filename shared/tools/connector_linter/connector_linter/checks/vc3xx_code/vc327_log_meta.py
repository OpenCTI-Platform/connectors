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

Only calls on a connectors-sdk logger are checked, since a connector can
still mix it with pycti's ``helper.connector_logger`` or stdlib loggers. A
receiver is resolved as an SDK logger when it is:

- ``self.logger`` / ``cls.logger`` in a class inheriting, directly or
  through other connector classes, from ``BaseDataProcessor``,
  ``ExternalImportConnector`` or ``BaseClientApi``;
- a name or ``self`` attribute bound to ``get_logger(...)``;
- a parameter, variable or attribute annotated ``ConnectorLoggerAdapter``;
- a name or ``self`` attribute assigned from one of the above, including a
  logger imported from another connector module.

Resolution follows Python scoping: imports are resolved per module (through
the connector's own modules for re-exports and base classes), a parameter or
local assignment shadows an enclosing name, and nested functions and classes
are resolved on their own. A name or attribute is an SDK logger only if every
assignment to it is one. An untyped ``logger`` parameter is not followed:
annotate it with ``ConnectorLoggerAdapter`` to have its calls checked.

Flagged message expressions: f-strings with placeholders, ``%`` formatting,
concatenation with a non-literal operand and any call (``str(err)``,
``"...".format(...)``). A message held in a variable is not flagged, since
its content cannot be known statically.

Scope: Common (all connector types).
"""

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

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
_SDK_LOGGER_NAMES = _SDK_LOGGER_CLASSES | {_GET_LOGGER, _ADAPTER}
_SDK_MODULE = re.compile(r"^connectors_sdk(\.|$)")

# Guard against import cycles between connector modules
_MAX_DEPTH = 32

_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
# Nodes opening a new scope: their bodies are resolved separately
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


@dataclass(eq=False)
class _Module:
    """A connector source module and its top-level definitions and imports."""

    name: str
    # Package that relative imports resolve against
    package: str
    tree: ast.Module
    classes: dict[str, ast.ClassDef] = field(default_factory=dict)
    # Local name -> (module, name) for ``from module import name``
    imported_names: dict[str, tuple[str, str]] = field(default_factory=dict)
    # Local name -> module for ``import module``
    imported_modules: dict[str, str] = field(default_factory=dict)


@dataclass(eq=False)
class _Symbol:
    """What a module-level name refers to."""

    kind: Literal["sdk", "sdk_module", "class", "module", "logger"]
    # Original SDK name, for kind "sdk"
    name: str = ""
    # Defining module, for kinds "class" and "module"
    module: _Module | None = None
    node: ast.ClassDef | None = None


@dataclass(eq=False)
class _Site:
    """A place where a name or attribute is bound."""

    kind: Literal["param", "value", "annotated", "import", "other"]
    # ast.arg for "param", the assigned value for "value", the AnnAssign
    # for "annotated"
    node: ast.AST | None = None
    # (module, name) for "import"
    source: tuple[str, str] | None = None
    # Method binding a ``self`` attribute, None for a class body binding
    method: _FunctionNode | None = None


@dataclass
class _ClassCtx:
    """The class enclosing the code being resolved."""

    has_sdk_logger: bool
    # Attributes of ``self``/``cls`` holding an SDK logger
    attrs: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------


def _scope_nodes(stmts: list[ast.stmt]) -> Iterator[ast.AST]:
    """Yield the nodes of a scope without entering nested functions or classes."""
    stack: list[ast.AST] = list(stmts)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPE_NODES):
            stack.extend(ast.iter_child_nodes(node))


def _module_name(path: Path) -> str:
    """Return the importable name of a source file, e.g. ``connector.client``."""
    parts = list(path.with_suffix("").parts)
    if "src" in parts:
        parts = parts[parts.index("src") + 1 :]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _absolute_module(node: ast.ImportFrom, package: str) -> str:
    """Return the absolute module of a ``from ... import`` statement."""
    if not node.level:
        return node.module or ""
    parts = package.split(".") if package else []
    base = parts[: max(len(parts) - (node.level - 1), 0)]
    return ".".join([*base, node.module] if node.module else base)


def _load_module(path: Path, tree: ast.Module) -> _Module:
    """Index the top-level classes and imports of a source file."""
    name = _module_name(path)
    package = name if path.name == "__init__.py" else name.rpartition(".")[0]
    module = _Module(name=name, package=package, tree=tree)
    for node in _scope_nodes(tree.body):
        if isinstance(node, ast.ClassDef):
            module.classes[node.name] = node
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                module.imported_modules[local_name] = (
                    alias.name if alias.asname else local_name
                )
        elif isinstance(node, ast.ImportFrom):
            source = _absolute_module(node, package)
            for alias in node.names:
                module.imported_names[alias.asname or alias.name] = (
                    source,
                    alias.name,
                )
    return module


def _collect_sites(
    stmts: list[ast.stmt],
    args: ast.arguments | None,
    package: str,
) -> dict[str, list[_Site]]:
    """Return every binding of a plain name in a scope, keyed by name."""
    sites: dict[str, list[_Site]] = {}
    if args is not None:
        params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        params += [arg for arg in (args.vararg, args.kwarg) if arg is not None]
        for arg in params:
            sites.setdefault(arg.arg, []).append(_Site("param", node=arg))

    nodes = list(_scope_nodes(stmts))
    # Plain assignment targets get a precise site, every other store is opaque
    direct_targets: set[int] = set()
    for node in nodes:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    direct_targets.add(id(target))
                    sites.setdefault(target.id, []).append(
                        _Site("value", node=node.value)
                    )
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            direct_targets.add(id(node.target))
            sites.setdefault(node.target.id, []).append(_Site("annotated", node=node))

    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if id(node) not in direct_targets:
                sites.setdefault(node.id, []).append(_Site("other"))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                sites.setdefault(alias.asname or alias.name, []).append(
                    _Site(
                        "import", source=(_absolute_module(node, package), alias.name)
                    )
                )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                sites.setdefault(local_name, []).append(_Site("other"))
        elif isinstance(node, _FunctionNode | ast.ClassDef):
            sites.setdefault(node.name, []).append(_Site("other"))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            sites.setdefault(node.name, []).append(_Site("other"))
    return sites


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
# SDK logger resolution
# ---------------------------------------------------------------------------


class _Resolver:
    """Resolve expressions to connectors-sdk loggers across the connector modules."""

    def __init__(self, trees: dict[Path, ast.Module]) -> None:
        self.modules: dict[str, _Module] = {}
        self.by_path: dict[Path, _Module] = {}
        for path, tree in trees.items():
            module = _load_module(path, tree)
            self.modules[module.name] = module
            self.by_path[path] = module
        self._module_loggers: dict[str, set[str]] = {}
        self._sdk_classes: dict[int, bool] = {}
        self._class_ctxs: dict[int, _ClassCtx] = {}

    def uses_sdk_logger(self) -> bool:
        """Return True if any module imports a connectors-sdk logger API."""
        return any(
            _SDK_MODULE.match(source) and name in _SDK_LOGGER_NAMES
            for module in self.modules.values()
            for source, name in module.imported_names.values()
        ) or any(
            _SDK_MODULE.match(source)
            for module in self.modules.values()
            for source in module.imported_modules.values()
        )

    # --- Module-level names ------------------------------------------------

    def symbol(self, module: _Module, name: str, depth: int = 0) -> _Symbol | None:
        """Resolve a module-level name, following the connector's own imports."""
        if depth > _MAX_DEPTH:
            return None
        if name in module.classes:
            return _Symbol("class", module=module, node=module.classes[name])
        if name in module.imported_names:
            source, original = module.imported_names[name]
            if _SDK_MODULE.match(source):
                return _Symbol("sdk", name=original)
            submodule = self.modules.get(f"{source}.{original}")
            if submodule is not None:
                return _Symbol("module", module=submodule)
            target = self.modules.get(source)
            return self.symbol(target, original, depth + 1) if target else None
        if name in module.imported_modules:
            source = module.imported_modules[name]
            if _SDK_MODULE.match(source):
                return _Symbol("sdk_module", name=source)
            target = self.modules.get(source)
            return _Symbol("module", module=target) if target else None
        if name in self.module_loggers(module):
            return _Symbol("logger")
        return None

    def resolve(
        self, module: _Module, node: ast.expr, depth: int = 0
    ) -> _Symbol | None:
        """Resolve a module-level ``name`` or dotted ``module.name`` expression."""
        if isinstance(node, ast.Name):
            return self.symbol(module, node.id, depth)
        if isinstance(node, ast.Attribute):
            base = self.resolve(module, node.value, depth)
            if base is None:
                return None
            if base.kind == "sdk_module":
                return _Symbol("sdk", name=node.attr)
            if base.kind == "module" and base.module is not None:
                return self.symbol(base.module, node.attr, depth + 1)
        return None

    def module_loggers(self, module: _Module) -> set[str]:
        """Return the module-level names bound to an SDK logger."""
        if module.name not in self._module_loggers:
            # Placeholder: a cyclic import resolves to "no logger"
            self._module_loggers[module.name] = set()
            self._module_loggers[module.name] = self.scope_loggers(
                module, module.tree.body, set(), None, None
            )
        return self._module_loggers[module.name]

    # --- SDK API detection -------------------------------------------------

    def _is_sdk(self, module: _Module, node: ast.expr, name: str) -> bool:
        """Return True if the expression refers to the SDK object ``name``."""
        symbol = self.resolve(module, node)
        return symbol is not None and symbol.kind == "sdk" and symbol.name == name

    def is_adapter_annotation(self, module: _Module, node: ast.expr | None) -> bool:
        """Match ``ConnectorLoggerAdapter``, ``ConnectorLoggerAdapter | None``, etc."""
        if node is None:
            return False
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name | ast.Attribute) and self._is_sdk(
                module, sub, _ADAPTER
            ):
                return True
            # String annotation, e.g. "ConnectorLoggerAdapter | None"
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                try:
                    parsed = ast.parse(sub.value, mode="eval").body
                except SyntaxError:
                    continue
                if self.is_adapter_annotation(module, parsed):
                    return True
        return False

    def is_sdk_class(self, module: _Module, node: ast.ClassDef) -> bool:
        """Return True if the class inherits the SDK ``logger`` attribute."""
        key = id(node)
        if key not in self._sdk_classes:
            self._sdk_classes[key] = False  # guard against inheritance cycles
            self._sdk_classes[key] = any(
                self._base_is_sdk(module, base) for base in node.bases
            )
        return self._sdk_classes[key]

    def _base_is_sdk(self, module: _Module, base: ast.expr) -> bool:
        symbol = self.resolve(module, base)
        if symbol is None:
            return False
        if symbol.kind == "sdk":
            return symbol.name in _SDK_LOGGER_CLASSES
        if symbol.kind == "class" and symbol.module and symbol.node:
            return self.is_sdk_class(symbol.module, symbol.node)
        return False

    # --- Scopes ------------------------------------------------------------

    def is_sdk_logger(
        self,
        module: _Module,
        node: ast.expr,
        names: set[str],
        cls: _ClassCtx | None,
    ) -> bool:
        """Return True if the expression evaluates to a connectors-sdk logger."""
        # get_logger(__name__)
        if isinstance(node, ast.Call):
            return self._is_sdk(module, node.func, _GET_LOGGER)
        # logger, _LOGGER...
        if isinstance(node, ast.Name):
            return node.id in names
        if isinstance(node, ast.Attribute):
            # self.logger, self._logger, cls.logger
            attr = _self_attr(node)
            if attr is not None:
                return cls is not None and (
                    (attr == "logger" and cls.has_sdk_logger) or attr in cls.attrs
                )
            # utils.LOGGER, with ``from connector import utils``
            symbol = self.resolve(module, node)
            return symbol is not None and symbol.kind == "logger"
        # logger or get_logger(__name__): every operand must be an SDK logger
        if isinstance(node, ast.BoolOp):
            return all(self.is_sdk_logger(module, v, names, cls) for v in node.values)
        return False

    def _site_is_sdk(
        self,
        module: _Module,
        site: _Site,
        names: set[str],
        cls: _ClassCtx | None,
    ) -> bool:
        """Return True if the binding site assigns an SDK logger."""
        if site.kind == "param" and isinstance(site.node, ast.arg):
            return self.is_adapter_annotation(module, site.node.annotation)
        if site.kind == "value" and isinstance(site.node, ast.expr):
            return self.is_sdk_logger(module, site.node, names, cls)
        if site.kind == "annotated" and isinstance(site.node, ast.AnnAssign):
            value = site.node.value
            return self.is_adapter_annotation(module, site.node.annotation) or (
                value is not None and self.is_sdk_logger(module, value, names, cls)
            )
        if site.kind == "import" and site.source is not None:
            source, original = site.source
            target = self.modules.get(source)
            if target is None:
                return False
            symbol = self.symbol(target, original)
            return symbol is not None and symbol.kind == "logger"
        return False

    def scope_loggers(
        self,
        module: _Module,
        stmts: list[ast.stmt],
        outer: set[str],
        cls: _ClassCtx | None,
        args: ast.arguments | None,
    ) -> set[str]:
        """Return the names bound to an SDK logger visible in a scope.

        A name bound in the scope (parameter, assignment, import...) shadows the
        enclosing one, and is an SDK logger only if every binding is one.
        """
        sites = _collect_sites(stmts, args, module.package)
        inherited = outer - sites.keys()
        local: set[str] = set()
        # Names can be assigned from each other (log = logger) in any order
        changed = True
        while changed:
            changed = False
            visible = inherited | local
            for name, name_sites in sites.items():
                if name not in local and all(
                    self._site_is_sdk(module, site, visible, cls) for site in name_sites
                ):
                    local.add(name)
                    changed = True
        return inherited | local

    def class_ctx(
        self,
        module: _Module,
        node: ast.ClassDef,
        outer: set[str],
    ) -> _ClassCtx:
        """Build the context of a class: SDK base and ``self`` logger attributes."""
        key = id(node)
        if key in self._class_ctxs:
            return self._class_ctxs[key]
        ctx = _ClassCtx(has_sdk_logger=self.is_sdk_class(module, node))
        self._class_ctxs[key] = ctx  # guard against inheritance cycles

        # Class-level bindings (``_logger: ConnectorLoggerAdapter``) and
        # ``self.x = ...`` in methods
        sites = _collect_sites(node.body, None, module.package)
        methods = [stmt for stmt in node.body if isinstance(stmt, _FunctionNode)]
        for method in methods:
            for sub in _scope_nodes(method.body):
                if isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        attr = _self_attr(target)
                        if attr:
                            sites.setdefault(attr, []).append(
                                _Site("value", node=sub.value, method=method)
                            )
                elif isinstance(sub, ast.AnnAssign):
                    attr = _self_attr(sub.target)
                    if attr:
                        sites.setdefault(attr, []).append(
                            _Site("annotated", node=sub, method=method)
                        )

        # Attributes set by connector base classes and not rebound here
        for base in node.bases:
            symbol = self.resolve(module, base)
            if symbol and symbol.kind == "class" and symbol.module and symbol.node:
                base_ctx = self.class_ctx(
                    symbol.module, symbol.node, self.module_loggers(symbol.module)
                )
                ctx.attrs |= base_ctx.attrs - sites.keys()

        # Attributes can be set from each other (self.a = self.b) in any order
        changed = True
        while changed:
            changed = False
            method_names = {
                id(method): self.scope_loggers(
                    module, method.body, outer, ctx, method.args
                )
                for method in methods
            }
            for attr, attr_sites in sites.items():
                if attr not in ctx.attrs and all(
                    self._site_is_sdk(
                        module,
                        site,
                        method_names[id(site.method)] if site.method else outer,
                        ctx,
                    )
                    for site in attr_sites
                ):
                    ctx.attrs.add(attr)
                    changed = True
        return ctx


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
    resolver: _Resolver,
    module: _Module,
    node: ast.AST,
    names: set[str],
    cls: _ClassCtx | None,
    hits: list[tuple[int, str, str]],
) -> None:
    """Collect (line, method, kind) for SDK logging calls with a dynamic message."""
    if isinstance(node, ast.ClassDef):
        ctx = resolver.class_ctx(module, node, names)
        for stmt in node.body:
            _scan(resolver, module, stmt, names, ctx, hits)
        return
    if isinstance(node, _FunctionNode):
        local = resolver.scope_loggers(module, node.body, names, cls, node.args)
        for stmt in node.body:
            _scan(resolver, module, stmt, local, cls, hits)
        return
    if isinstance(node, ast.Call):
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _LOG_METHODS
            and resolver.is_sdk_logger(module, func.value, names, cls)
        ):
            message = _message_arg(node)
            kind = _dynamic_message_kind(message) if message is not None else None
            if kind:
                hits.append((node.lineno, func.attr, kind))
    for child in ast.iter_child_nodes(node):
        _scan(resolver, module, child, names, cls, hits)


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
    resolver = _Resolver(trees)

    if not resolver.uses_sdk_logger():
        return [
            CheckFinding(
                message="Connector does not use the connectors-sdk logger — skipped",
                severity=Severity.INFO,
            ),
        ]

    results: list[CheckFinding] = []
    for file_path, tree in sorted(trees.items()):
        module = resolver.by_path[file_path]
        hits: list[tuple[int, str, str]] = []
        _scan(resolver, module, tree, resolver.module_loggers(module), None, hits)
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
