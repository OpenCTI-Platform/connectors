"""Shared helpers for VC3xx code quality checks."""

import ast
import re
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Regex helpers (for simple text-pattern checks)
# ---------------------------------------------------------------------------


def find_pattern_locations(
    sources: dict[Path, str],
    patterns: list[re.Pattern],
) -> list[tuple[Path, int, str]]:
    """Find all occurrences of any pattern in sources.

    Returns list of (file_path, line_number, matched_line).
    """
    hits: list[tuple[Path, int, str]] = []
    for file_path, content in sources.items():
        # Scan line-by-line so we can report exact line numbers
        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            for pattern in patterns:
                if pattern.search(line):
                    hits.append((file_path, line_no, line.strip()))
                    # One match per line is enough — avoids duplicate reports
                    # when multiple patterns match the same line
                    break
    return hits


# ---------------------------------------------------------------------------
# AST helpers — structural analysis of Python source
# ---------------------------------------------------------------------------


@dataclass
class ImportInfo:
    """Represents a single imported name from a source file."""

    module: str  # The source module, e.g. "connectors_sdk" or "pydantic_settings"
    name: str  # The imported symbol, e.g. "BaseConnectorSettings"
    alias: str | None  # The 'as' alias if present, e.g. "BCS" for `import ... as BCS`
    file_path: Path  # Which file contains this import
    line: int  # Line number for reporting


def find_imports(
    trees: dict[Path, ast.Module],
    module_pattern: str | None = None,
    name_pattern: str | None = None,
) -> list[ImportInfo]:
    """Find imports matching optional module and/or name patterns.

    Args:
        trees: Parsed AST modules keyed by file path.
        module_pattern: Regex to match the module (e.g. r"connectors_sdk").
        name_pattern: Regex to match the imported name (e.g. r"BaseConnectorSettings").

    Returns:
        List of ImportInfo for matching imports.

    """
    results: list[ImportInfo] = []
    # Pre-compile patterns for efficient repeated matching
    mod_re = re.compile(module_pattern) if module_pattern else None
    name_re = re.compile(name_pattern) if name_pattern else None

    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            # ---------------------------------------------------------------------------
            # Handle `from <module> import <name>` (ImportFrom)
            #
            # module_pattern filters the source module (e.g. "connectors_sdk")
            # name_pattern filters the imported symbol (e.g. "BaseConnectorSettings")
            # ---------------------------------------------------------------------------
            if isinstance(node, ast.ImportFrom) and node.module:
                if mod_re and not mod_re.search(node.module):
                    continue
                for alias in node.names:
                    if name_re and not name_re.search(alias.name):
                        continue
                    results.append(
                        ImportInfo(
                            module=node.module,
                            name=alias.name,
                            alias=alias.asname,
                            file_path=file_path,
                            line=node.lineno,
                        ),
                    )
            # ---------------------------------------------------------------------------
            # Handle `import <module>` (Import)
            #
            # For bare imports, both module and name are the full module name
            # (e.g. `import stix2` → module="stix2", name="stix2").
            # Both module_pattern and name_pattern are checked against this name.
            # ---------------------------------------------------------------------------
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name
                    if mod_re and not mod_re.search(module_name):
                        continue
                    if name_re and not name_re.search(module_name):
                        continue
                    results.append(
                        ImportInfo(
                            module=module_name,
                            name=module_name,
                            alias=alias.asname,
                            file_path=file_path,
                            line=node.lineno,
                        ),
                    )
    return results


@dataclass
class ClassInfo:
    """Represents a class definition found in source."""

    name: str
    # Base class names are stored unqualified (just the final name):
    #   class Foo(mod.BaseSettings) → bases = ["BaseSettings"]
    #   class Foo(BaseSettings)     → bases = ["BaseSettings"]
    bases: list[str]
    file_path: Path
    line: int


def find_classes(
    trees: dict[Path, ast.Module],
    base_name: str | None = None,
) -> list[ClassInfo]:
    """Find class definitions, optionally filtering by base class name.

    Args:
        trees: Parsed AST modules keyed by file path.
        base_name: If provided, only return classes inheriting from this name.

    """
    results: list[ClassInfo] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases: list[str] = []
            for base in node.bases:
                # ast.Name → direct reference: class Foo(BaseSettings)
                if isinstance(base, ast.Name):
                    bases.append(base.id)
                # ast.Attribute → qualified reference: class Foo(mod.BaseSettings)
                # We only keep the final attr name for matching simplicity
                elif isinstance(base, ast.Attribute):
                    bases.append(base.attr)
            if base_name and base_name not in bases:
                continue
            results.append(
                ClassInfo(
                    name=node.name,
                    bases=bases,
                    file_path=file_path,
                    line=node.lineno,
                ),
            )
    return results


@dataclass
class ExceptBlockInfo:
    """Represents an except handler block found in source."""

    exception_types: list[str]  # e.g. ["ValueError", "TypeError"]
    # The body (list of statements) is stored so downstream checks can
    # analyze what happens inside the except block (e.g. logging calls)
    body: list[ast.stmt]
    file_path: Path
    line: int


def find_except_blocks(
    trees: dict[Path, ast.Module],
) -> list[ExceptBlockInfo]:
    """Find all except handler blocks across source files."""
    results: list[ExceptBlockInfo] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue

            exc_types: list[str] = []
            if node.type is not None:
                # Single exception: except ValueError:
                if isinstance(node.type, ast.Name):
                    exc_types.append(node.type.id)
                # Tuple of exceptions: except (ValueError, TypeError):
                elif isinstance(node.type, ast.Tuple):
                    for elt in node.type.elts:
                        if isinstance(elt, ast.Name):
                            exc_types.append(elt.id)

            results.append(
                ExceptBlockInfo(
                    exception_types=exc_types,
                    body=node.body,
                    file_path=file_path,
                    line=node.lineno,
                ),
            )
    return results


@dataclass
class CallInfo:
    """Represents a function/method call found in source."""

    func_name: str  # The method/function name, e.g. "error" or "check_max_tlp"
    # The receiver (object the method is called on), reconstructed as a dotted
    # string, e.g. "self.helper.connector_logger" for
    # self.helper.connector_logger.error(). None for bare function calls.
    receiver: str | None
    file_path: Path
    line: int


def find_calls_in_stmts(
    stmts: list[ast.stmt],
    file_path: Path,
    func_names: set[str] | None = None,
) -> list[CallInfo]:
    """Find function/method calls within a list of AST statements.

    Operates on a list of statements (not the whole tree) to support
    scoped analysis — e.g. searching only inside an except block body.

    Args:
        stmts: AST statement nodes to search.
        func_names: If provided, only return calls matching these function names.
        file_path: File path for reporting.

    """
    results: list[CallInfo] = []
    for stmt in stmts:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue

            func_name: str | None = None
            receiver: str | None = None

            # Bare function call: print_exc()
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            # Method call: self.logger.error() → func_name="error"
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                receiver = _unparse_receiver(node.func.value)

            if func_name is None:
                continue
            if func_names and func_name not in func_names:
                continue

            results.append(
                CallInfo(
                    func_name=func_name,
                    receiver=receiver,
                    file_path=file_path,
                    line=node.lineno,
                ),
            )
    return results


def _unparse_receiver(node: ast.expr) -> str:
    """Unparse the receiver of a method call (e.g. self.helper.connector_logger).

    Recursively walks the dotted attribute chain:
      self.helper.connector_logger  →  Name("self") . Attr("helper") . Attr("connector_logger")
    producing the string "self.helper.connector_logger".
    """
    # Base case: simple name like "self" or "logger"
    if isinstance(node, ast.Name):
        return node.id
    # Recursive case: dotted attribute access (a.b.c → recurse on a.b, append .c)
    if isinstance(node, ast.Attribute):
        parent = _unparse_receiver(node.value)
        return f"{parent}.{node.attr}"
    # Fallback for complex expressions (e.g. function calls as receivers)
    return "<unknown>"


@dataclass
class FieldDefaultInfo:
    """Represents a class field with a default value."""

    class_name: str  # The class containing this field (e.g. "ConnectorSettings")
    field_name: str  # The field name (e.g. "log_level")
    default_value: str | None  # Lowercased string of the default (e.g. "error")
    file_path: Path
    line: int


def find_field_defaults(
    trees: dict[Path, ast.Module],
    field_name: str,
    class_base: str | None = None,
) -> list[FieldDefaultInfo]:
    """Find class field assignments with defaults, optionally filtered by base class.

    Detects patterns like:
        log_level: str = "error"
        log_level: str = Field(default="error")
        log_level: LogLevelType = LogLevelType.ERROR
        log_level: ... = Field(default=LogLevelType.ERROR)
    """
    results: list[FieldDefaultInfo] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            # If class_base is specified, only match classes inheriting from it
            if class_base:
                base_names = [
                    (
                        b.id
                        if isinstance(b, ast.Name)
                        else b.attr if isinstance(b, ast.Attribute) else ""
                    )
                    for b in node.bases
                ]
                if class_base not in base_names:
                    continue

            # Only look at annotated assignments in the class body (not nested)
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(
                    stmt.target,
                    ast.Name,
                ):
                    if stmt.target.id != field_name:
                        continue
                    # Extract the default from the 4 recognized patterns:
                    #   1. field: str = "error"                (Constant)
                    #   2. field: X = LogLevelType.ERROR        (Attribute/enum)
                    #   3. field: str = Field(default="error")  (Call with kwarg)
                    #   4. field: str = Field("error")          (Call with positional)
                    default_val = _extract_default_value(stmt.value)
                    results.append(
                        FieldDefaultInfo(
                            class_name=node.name,
                            field_name=field_name,
                            default_value=default_val,
                            file_path=file_path,
                            line=stmt.lineno,
                        ),
                    )
    return results


def _extract_default_value(node: ast.expr | None) -> str | None:
    """Extract the default value from a field assignment or Field() call.

    Handles each AST node type that can represent a default value:
      - ast.Constant  → direct string literal (e.g. "error")
      - ast.Attribute → enum member access (e.g. LogLevelType.ERROR)
      - ast.Call      → Pydantic Field() with default= kwarg or positional arg
    """
    if node is None:
        return None

    # Pattern 1 — Direct constant: log_level = "error"
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower()

    # Pattern 2 — Enum access: log_level = LogLevelType.ERROR → "error"
    if isinstance(node, ast.Attribute):
        return node.attr.lower()

    # Pattern 3 & 4 — Pydantic Field() call
    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name == "Field":
            # Pattern 3: Field(default="error") — keyword argument
            for kw in node.keywords:
                if kw.arg == "default":
                    # Recurse: the default value itself may be a Constant or Attribute
                    return _extract_default_value(kw.value)
            # Pattern 4: Field("error") — positional first argument
            if node.args:
                return _extract_default_value(node.args[0])

    return None
