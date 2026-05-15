"""VC325 — Connector must have minimal settings tests.

Verified connectors must include at minimum a settings test that:

1.  Exercises ``ConnectorSettings`` with **valid** input (all required fields
    present) and asserts the object is created successfully.
2.  Exercises ``ConnectorSettings`` with **invalid** input (missing a required
    field) and asserts ``ConfigValidationError`` is raised.

This baseline matches the pattern established in the connector templates
(``templates/<type>/tests/tests_connector/test_settings.py``).

Detection is AST-based:
- A settings test file is one whose name contains "settings" or that
  contains an ``ImportFrom`` of ``ConnectorSettings``.
- Valid-input coverage is detected by finding an ``Assign`` or ``AnnAssign``
  whose right-hand side is a ``Call`` to a class whose name ends in
  ``"Settings"`` — i.e., ``settings = FakeConnectorSettings()``.
- Error-input coverage is detected by finding a ``pytest.raises(...)`` call.

Missing a settings test file is a WARNING (tests exist, just not for
settings). Missing valid-input or error-input coverage inside an existing
settings test is an ERROR.

Scope: Common (all connector types).
"""

import ast
from pathlib import Path

from connector_linter.models import CheckFinding, ConnectorContext, Severity
from connector_linter.registry import CheckRegistry


def _read_test_files(ctx: ConnectorContext) -> dict[Path, str]:
    """Read all ``test_*.py`` files from the connector's ``tests/`` directory."""
    sources: dict[Path, str] = {}
    tests_dir = ctx.path / "tests"
    if not tests_dir.exists():
        return sources
    for py_file in tests_dir.rglob("test_*.py"):
        rel_path = py_file.relative_to(ctx.path)
        try:
            sources[rel_path] = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return sources


def _parse_test_files(sources: dict[Path, str]) -> dict[Path, ast.Module]:
    """Parse test source files into AST modules, skipping files with syntax errors."""
    trees: dict[Path, ast.Module] = {}
    for file_path, content in sources.items():
        try:
            trees[file_path] = ast.parse(content, filename=str(file_path))
        except SyntaxError:
            continue
    return trees


def _imports_connector_settings(tree: ast.Module) -> bool:
    """Return ``True`` if the module imports ``ConnectorSettings``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "ConnectorSettings":
                    return True
    return False


class _SettingsCallFinder(ast.NodeVisitor):
    """Locate ``*Settings()`` or ``*Loader()`` calls that are **not** inside
    a ``pytest.raises(...)`` block.

    Handles all forms observed in the connector codebase:

    * Direct assignment:  ``settings = FakeConnectorSettings()``
    * Method chaining:    ``config = ConnectorSettings().model_dump()``
    * Bare expression:    ``ConnectorSettings()``  (mokn-style smoke test)
    * Config-loader name: ``settings = FakeConfigLoader(**d)``
    """

    def __init__(self) -> None:
        self._inside_raises_depth: int = 0
        self.found: bool = False

    def visit_With(self, node: ast.With) -> None:
        is_raises = any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Attribute)
            and item.context_expr.func.attr == "raises"
            and isinstance(item.context_expr.func.value, ast.Name)
            and item.context_expr.func.value.id == "pytest"
            for item in node.items
        )
        if is_raises:
            self._inside_raises_depth += 1
        self.generic_visit(node)
        if is_raises:
            self._inside_raises_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if (
            self._inside_raises_depth == 0
            and isinstance(node.func, ast.Name)
            and (node.func.id.endswith("Settings") or node.func.id.endswith("Loader"))
        ):
            self.found = True
        self.generic_visit(node)


def _has_settings_valid_call(tree: ast.Module) -> bool:
    """Return ``True`` if the module calls a ``*Settings()`` or ``*Loader()``
    class outside of a ``pytest.raises(...)`` block."""
    finder = _SettingsCallFinder()
    finder.visit(tree)
    return finder.found


def _has_pytest_raises(tree: ast.Module) -> bool:
    """Return ``True`` if the module calls ``pytest.raises(...)``."""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "raises"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pytest"
        ):
            return True
    return False


@CheckRegistry.register(
    code="VC325",
    name="minimal-settings-tests",
    description="Connector must have minimal settings tests covering valid and invalid inputs",
    severity=Severity.ERROR,
)
def check_minimal_settings_tests(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector has minimal settings tests."""
    if not ctx.has_tests:
        return [
            CheckFinding(
                message="No tests/ directory found",
                severity=Severity.ERROR,
                suggestion=(
                    "Create a tests/ directory with at minimum a "
                    "tests_connector/test_settings.py that verifies ConnectorSettings "
                    "accepts valid input and raises ConfigValidationError for missing "
                    "required fields (see templates/<type>/tests/ for the expected pattern)"
                ),
            )
        ]

    test_sources = _read_test_files(ctx)
    if not test_sources:
        return [
            CheckFinding(
                message="No test files (test_*.py) found in tests/",
                severity=Severity.ERROR,
                suggestion=(
                    "Add tests/tests_connector/test_settings.py that verifies "
                    "ConnectorSettings accepts valid input and raises "
                    "ConfigValidationError for missing required fields"
                ),
            )
        ]

    trees = _parse_test_files(test_sources)

    # A settings test file is identified by filename or by importing ConnectorSettings.
    settings_test_trees = {
        path: tree
        for path, tree in trees.items()
        if "settings" in path.name.lower() or _imports_connector_settings(tree)
    }

    if not settings_test_trees:
        return [
            CheckFinding(
                message=(
                    "No settings test file found in tests/ "
                    "(expected a file named test_settings*.py or one that imports ConnectorSettings)"
                ),
                # Advisory: the connector has other tests, but settings are not covered yet.
                severity=Severity.WARNING,
                suggestion=(
                    "Create tests/tests_connector/test_settings.py that imports "
                    "ConnectorSettings and tests both valid input and "
                    "missing required fields (raises ConfigValidationError)"
                ),
            )
        ]

    has_valid_test = any(
        _has_settings_valid_call(tree) for tree in settings_test_trees.values()
    )
    has_error_test = any(
        _has_pytest_raises(tree) for tree in settings_test_trees.values()
    )

    results: list[CheckFinding] = []
    settings_paths = ", ".join(str(p) for p in settings_test_trees)

    if not has_valid_test:
        results.append(
            CheckFinding(
                message=(
                    f"Settings test(s) ({settings_paths}) do not cover valid input "
                    "(no *Settings() or *Loader() call found outside pytest.raises)"
                ),
                severity=Severity.ERROR,
                suggestion=(
                    "Add a parametrized test that instantiates ConnectorSettings (or a "
                    "fake subclass) with a valid config dict and asserts the settings "
                    "object loads correctly "
                    "(see templates/<type>/tests/tests_connector/test_settings.py)"
                ),
            )
        )

    if not has_error_test:
        results.append(
            CheckFinding(
                message=(
                    f"Settings test(s) ({settings_paths}) do not cover missing required fields "
                    "(no pytest.raises(...) call found)"
                ),
                severity=Severity.WARNING,
                suggestion=(
                    "Add a test using pytest.raises(ConfigValidationError) that verifies "
                    "required settings raise an error when missing "
                    "(see templates/<type>/tests/tests_connector/test_settings.py)"
                ),
            )
        )

    if results:
        return results

    return [
        CheckFinding(
            message=f"Settings tests cover both valid and invalid inputs ✓ ({settings_paths})",
            severity=Severity.INFO,
        )
    ]
