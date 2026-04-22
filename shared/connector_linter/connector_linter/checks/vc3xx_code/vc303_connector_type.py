"""VC303 — CONNECTOR_TYPE must be defined in application code, not read from env."""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    ConnectorType,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Valid connector type strings — derived from ConnectorType enum so this set
# stays automatically in sync when new types are added.
# ---------------------------------------------------------------------------
_CONNECTOR_TYPES = frozenset(t.value for t in ConnectorType)

# ---------------------------------------------------------------------------
# connectors-sdk base config classes — each one hardcodes a connector type,
# so inheriting from one is the preferred way to set the type.
# ---------------------------------------------------------------------------
_SDK_BASE_CONFIG_CLASSES = {
    "BaseExternalImportConnectorConfig",
    "BaseInternalEnrichmentConnectorConfig",
    "BaseStreamConnectorConfig",
    "BaseInternalExportFileConnectorConfig",
    "BaseInternalImportFileConnectorConfig",
}


@dataclass
class _Hit:
    file_path: Path
    line: int


@CheckRegistry.register(
    code="VC303",
    name="connector-type-hardcoded",
    description="CONNECTOR_TYPE must be defined in application code, not read from env",
    severity=Severity.ERROR,
)
def check_connector_type_hardcoded(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector type is hardcoded in the application, not read from env."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees
    if not trees:
        return [
            CheckFinding(
                message="No parseable Python source files found in src/",
                severity=Severity.ERROR,
                suggestion="Fix syntax errors in source files under src/",
            ),
        ]

    # ---------------------------------------------------------------------------
    # 4-way detection: scan AST for each pattern in priority order.
    #
    #   env_hit      — ANTI-PATTERN: reading CONNECTOR_TYPE from env/config
    #   sdk_hit      — PREFERRED: inheriting from SDK Base*ConnectorConfig
    #   hardcoded_hit — LEGACY OK: config["connector"]["type"] = "EXTERNAL_IMPORT"
    #   pydantic_hit — CUSTOM OK: type: Literal["EXTERNAL_IMPORT"] or Field(...)
    # ---------------------------------------------------------------------------
    env_hit: _Hit | None = None
    sdk_hit: _Hit | None = None
    hardcoded_hit: _Hit | None = None
    pydantic_hit: _Hit | None = None

    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            # Anti-pattern: reading CONNECTOR_TYPE from environment
            # (e.g. os.environ["CONNECTOR_TYPE"], get_config_variable(...))
            if env_hit is None and _reads_connector_type_from_env(node):
                node = cast("ast.Call | ast.Subscript", node)
                env_hit = _Hit(file_path=file_path, line=node.lineno)

            # Preferred: SDK base config class (inherits type automatically)
            if (
                sdk_hit is None
                and isinstance(node, ast.ClassDef)
                and any(
                    _base_name(base) in _SDK_BASE_CONFIG_CLASSES for base in node.bases
                )
            ):
                sdk_hit = _Hit(file_path=file_path, line=node.lineno)

            # Legacy pycti-style: config["connector"]["type"] = "EXTERNAL_IMPORT"
            # or dict literal: {"connector": {"type": "EXTERNAL_IMPORT"}}
            if hardcoded_hit is None and isinstance(node, ast.Assign):
                if any(_is_connector_type_target(t) for t in node.targets):
                    if _is_connector_type_value(node.value):
                        hardcoded_hit = _Hit(file_path=file_path, line=node.lineno)

            if hardcoded_hit is None and isinstance(node, ast.Dict):
                hit_line = _find_type_in_connector_dict(node)
                if hit_line is not None:
                    hardcoded_hit = _Hit(file_path=file_path, line=hit_line)

            # Custom Pydantic: type: Literal["EXTERNAL_IMPORT"] or Field(default=...)
            if pydantic_hit is None and isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.target.id == "type":
                    if _is_literal_type_annotation(
                        node.annotation,
                    ) or _is_field_default(
                        node.value,
                    ):
                        pydantic_hit = _Hit(file_path=file_path, line=node.lineno)

    # ---------------------------------------------------------------------------
    # Priority order for results:
    #   1. env_hit → FAIL (anti-pattern, checked first because it overrides all)
    #   2. sdk_hit → PASS (best practice)
    #   3. hardcoded_hit → PASS (legacy but acceptable)
    #   4. pydantic_hit → PASS (custom but acceptable)
    #   5. nothing → FAIL
    # ---------------------------------------------------------------------------
    if env_hit:
        file_path, line = env_hit.file_path, env_hit.line
        return [
            CheckFinding(
                message="CONNECTOR_TYPE is read from environment",
                severity=Severity.ERROR,
                file_path=file_path,
                line=line,
                suggestion=(
                    "Hardcode the connector type instead of reading from env. "
                    "Use connectors-sdk (e.g. BaseExternalImportConnectorConfig) "
                    'or set config["connector"]["type"] = "EXTERNAL_IMPORT" directly'
                ),
            ),
        ]

    # SDK-based approach (inherits from Base*ConnectorConfig)
    if sdk_hit:
        file_path, line = sdk_hit.file_path, sdk_hit.line
        return [
            CheckFinding(
                message="Connector type defined via connectors-sdk",
                severity=Severity.INFO,
                file_path=file_path,
                line=line,
            ),
        ]

    # pycti-style hardcoded assignment
    if hardcoded_hit:
        file_path, line = hardcoded_hit.file_path, hardcoded_hit.line
        return [
            CheckFinding(
                message="Connector type hardcoded",
                severity=Severity.WARNING,
                file_path=file_path,
                line=line,
            ),
        ]

    # Custom Pydantic Literal or Field default
    if pydantic_hit:
        file_path, line = pydantic_hit.file_path, pydantic_hit.line
        return [
            CheckFinding(
                message="Connector type hardcoded via Pydantic field",
                severity=Severity.WARNING,
                file_path=file_path,
                line=line,
            ),
        ]

    # No type definition found at all
    return [
        CheckFinding(
            message="No CONNECTOR_TYPE definition found in application code",
            severity=Severity.ERROR,
            suggestion=(
                "Hardcode the connector type in code. "
                "Best: use connectors-sdk (e.g. BaseExternalImportConnectorConfig). "
                'Or: set config["connector"]["type"] = "EXTERNAL_IMPORT" in main.py'
            ),
        ),
    ]


def _base_name(base: ast.expr) -> str:
    """Extract the unqualified class name from a base class expression.

    Handles both direct references (Name) and qualified (Attribute):
      BaseSettings            → "BaseSettings"
      connectors_sdk.BaseXxx  → "BaseXxx"
    """
    if isinstance(base, ast.Name):
        return base.id
    if isinstance(base, ast.Attribute):
        return base.attr
    return ""


def _constant_str(node: ast.expr | None) -> str | None:
    """Extract a string constant from an AST node, or None if not a string literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _subscript_key(node: ast.Subscript) -> str | None:
    """Extract the string key from a subscript expression like d["key"]."""
    slice_node = node.slice
    if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
        return slice_node.value
    return None


def _is_connector_type_target(node: ast.expr) -> bool:
    """Check if node is the assignment target config["connector"]["type"].

    Matches the nested subscript pattern: outer["type"] on inner["connector"].
    """
    if not isinstance(node, ast.Subscript):
        return False
    if _subscript_key(node) != "type":
        return False
    inner = node.value
    return isinstance(inner, ast.Subscript) and _subscript_key(inner) == "connector"


def _is_connector_type_value(node: ast.expr) -> bool:
    """Check if node is a string literal matching a valid connector type."""
    value = _constant_str(node)
    return value in _CONNECTOR_TYPES if value else False


def _find_type_in_connector_dict(node: ast.Dict) -> int | None:
    """Find ``"type": "EXTERNAL_IMPORT"`` inside a ``"connector"`` dict literal.

    Matches the pattern::

        {
            "connector": {
                "type": "EXTERNAL_IMPORT",  # ← returns this line
            }
        }

    Returns the line number of the ``"type"`` key, or None if not found.
    """
    for key, value in zip(node.keys, node.values):
        if _constant_str(key) == "connector" and isinstance(value, ast.Dict):
            for inner_key, inner_value in zip(value.keys, value.values):
                if _constant_str(inner_key) == "type" and _is_connector_type_value(
                    inner_value
                ):
                    return getattr(inner_key, "lineno", node.lineno)
    return None


def _is_literal_type_annotation(node: ast.expr) -> bool:
    """Check if node is a Literal type annotation containing a valid connector type.

    Matches:
      Literal["EXTERNAL_IMPORT"]       → single-value Literal
      Literal["EXTERNAL_IMPORT", ...]  → multi-value Literal (tuple slice)
    """
    if not isinstance(node, ast.Subscript):
        return False
    if not isinstance(node.value, ast.Name) or node.value.id != "Literal":
        return False

    slice_node = node.slice
    # Single-value Literal: Literal["EXTERNAL_IMPORT"]
    if isinstance(slice_node, ast.Constant):
        return (
            isinstance(slice_node.value, str) and slice_node.value in _CONNECTOR_TYPES
        )
    # Multi-value Literal: Literal["EXTERNAL_IMPORT", "STREAM"]
    if isinstance(slice_node, ast.Tuple):
        for elt in slice_node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                if elt.value in _CONNECTOR_TYPES:
                    return True
    return False


def _is_field_default(node: ast.expr | None) -> bool:
    """Check if node is a Pydantic Field() with a valid connector type as default.

    Matches:
      Field(default="EXTERNAL_IMPORT")  → keyword default
      Field("EXTERNAL_IMPORT")          → positional default
    """
    if not isinstance(node, ast.Call):
        return False
    func_name = ""
    if isinstance(node.func, ast.Name):
        func_name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        func_name = node.func.attr
    if func_name != "Field":
        return False

    # Check keyword: Field(default="EXTERNAL_IMPORT")
    for kw in node.keywords:
        if kw.arg == "default" and _is_connector_type_value(kw.value):
            return True
    # Check positional: Field("EXTERNAL_IMPORT")
    return bool(node.args) and _is_connector_type_value(node.args[0])


def _is_call_with_connector_type_arg(node: ast.Call, names: set[str]) -> bool:
    """Check if a function call (by name) has "CONNECTOR_TYPE" as first argument.

    Matches both bare calls (``getenv(...)``) and qualified calls
    (``self.helper.get_config_variable(...)``).
    """
    func_name = ""
    if isinstance(node.func, ast.Name):
        func_name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        func_name = node.func.attr
    if func_name not in names or not node.args:
        return False
    return _constant_str(node.args[0]) == "CONNECTOR_TYPE"


def _reads_connector_type_from_env(node: ast.AST) -> bool:
    """Detect if an AST node reads CONNECTOR_TYPE from the environment.

    Covers multiple patterns:
      - os.environ["CONNECTOR_TYPE"]        (Subscript on Attribute)
      - environ["CONNECTOR_TYPE"]           (Subscript on Name)
      - get_config_variable("CONNECTOR_TYPE")  (pycti helper)
      - getenv("CONNECTOR_TYPE")            (bare or os.getenv)
      - os.environ.get("CONNECTOR_TYPE")    (dict .get() method)
    """
    # --- Subscript patterns: environ["CONNECTOR_TYPE"] ---
    if isinstance(node, ast.Subscript):
        key = _subscript_key(node)
        if key != "CONNECTOR_TYPE":
            return False
        # os.environ["CONNECTOR_TYPE"]
        if isinstance(node.value, ast.Attribute):
            return (
                isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "environ"
            )
        # environ["CONNECTOR_TYPE"]
        return isinstance(node.value, ast.Name) and node.value.id == "environ"

    # --- Call patterns: function calls that read from env ---
    if isinstance(node, ast.Call):
        # Bare function calls: get_config_variable("CONNECTOR_TYPE")
        # or getenv("CONNECTOR_TYPE") (from os import getenv)
        if isinstance(node.func, ast.Name) and _is_call_with_connector_type_arg(
            node, {"get_config_variable", "getenv"}
        ):
            return True
        # Qualified method calls: self.helper.get_config_variable("CONNECTOR_TYPE")
        # (but NOT arbitrary .getenv — that's handled separately for os.getenv only)
        if isinstance(node.func, ast.Attribute) and _is_call_with_connector_type_arg(
            node, {"get_config_variable"}
        ):
            return True
        if isinstance(node.func, ast.Attribute):
            # os.getenv("CONNECTOR_TYPE") — verify receiver is `os`
            if (
                node.func.attr == "getenv"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.args
            ):
                if _constant_str(node.args[0]) == "CONNECTOR_TYPE":
                    return True
            # os.environ.get("CONNECTOR_TYPE")
            if node.func.attr == "get" and node.args:
                if _constant_str(node.args[0]) != "CONNECTOR_TYPE":
                    return False
                receiver = node.func.value
                if isinstance(receiver, ast.Attribute):
                    return (
                        isinstance(receiver.value, ast.Name)
                        and receiver.value.id == "os"
                        and receiver.attr == "environ"
                    )
                return isinstance(receiver, ast.Name) and receiver.id == "environ"
    return False
