"""VC308 — Use a traceback in the main entry point."""

import ast
from pathlib import Path

from connector_linter.checks.vc3xx_code._helpers import (
    find_calls_in_stmts,
)
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry


def _check_main_structure(
    source: str,
    file_path: Path,
) -> tuple[bool, bool, bool, int | None]:
    """Analyze the main.py structure.

    Returns a 4-value tuple:
      has_traceback_import  — `import traceback` or `from traceback import ...` found
      has_main_guard        — `if __name__ == "__main__":` guard found
      has_try_traceback     — try/except with traceback.print_exc() inside main guard
      main_guard_line       — line number of the main guard (for reporting)
    """
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return False, False, False, None

    has_traceback_import = False
    has_main_guard = False
    has_try_traceback = False
    main_guard_line: int | None = None

    for node in ast.walk(tree):
        # Check for `import traceback`
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "traceback":
                    has_traceback_import = True

        # Check for `from traceback import ...`
        if isinstance(node, ast.ImportFrom) and node.module == "traceback":
            has_traceback_import = True

    # Find `if __name__ == "__main__":` at module level
    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        if _is_main_guard(node):
            has_main_guard = True
            main_guard_line = node.lineno
            # Check body for try/except with traceback.print_exc()
            has_try_traceback = _has_try_with_traceback(node.body, file_path)
            break

    return has_traceback_import, has_main_guard, has_try_traceback, main_guard_line


def _is_main_guard(node: ast.If) -> bool:
    """Check if an If node is `if __name__ == "__main__":`.

    Handles both comparison orders:
      __name__ == "__main__"   (standard)
      "__main__" == __name__   (reversed, less common but valid)
    """
    test = node.test
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        if isinstance(test.ops[0], ast.Eq):
            left = test.left
            comparator = test.comparators[0]
            # __name__ == "__main__" or "__main__" == __name__
            if (
                isinstance(left, ast.Name)
                and left.id == "__name__"
                and isinstance(comparator, ast.Constant)
                and comparator.value == "__main__"
            ):
                return True
            if (
                isinstance(left, ast.Constant)
                and left.value == "__main__"
                and isinstance(comparator, ast.Name)
                and comparator.id == "__name__"
            ):
                return True
    return False


def _has_try_with_traceback(stmts: list[ast.stmt], file_path: Path) -> bool:
    """Check if statements contain a try/except with traceback.print_exc().

    Uses a recursive search strategy to handle multiple code patterns:
      1. Direct try/except in the main guard body
      2. Try/except inside a function defined in the main guard
         (e.g. some connectors wrap logic in a main() function)
      3. Fallback: ast.walk over all nested nodes to catch any other nesting
    """
    for stmt in stmts:
        # Pattern 1: direct try in the main guard body
        if isinstance(stmt, ast.Try):
            if _except_has_traceback(stmt.handlers, file_path):
                return True
        # Pattern 2: function def called from main guard (e.g. def main(): try: ...)
        if isinstance(stmt, ast.FunctionDef):
            for inner in stmt.body:
                if isinstance(inner, ast.Try):
                    if _except_has_traceback(inner.handlers, file_path):
                        return True
        # Pattern 3: walk all nested nodes as fallback
        for node in ast.walk(stmt):
            if isinstance(node, ast.Try):
                if _except_has_traceback(node.handlers, file_path):
                    return True
    return False


def _except_has_traceback(handlers: list[ast.ExceptHandler], file_path: Path) -> bool:
    """Check if any except handler calls traceback.print_exc().

    Verifies the receiver contains "traceback" to distinguish from unrelated
    print_exc-like functions. Also accepts bare print_exc() calls (valid when
    `from traceback import print_exc` is used).
    """
    for handler in handlers:
        calls = find_calls_in_stmts(
            handler.body,
            func_names={"print_exc"},
            file_path=file_path,
        )
        for call in calls:
            # Check receiver for "traceback" module (e.g. traceback.print_exc())
            if call.receiver and "traceback" in call.receiver:
                return True
            # Bare print_exc() — valid if `from traceback import print_exc`
            if call.receiver is None:
                return True
    return False


@CheckRegistry.register(
    code="VC308",
    name="main-traceback",
    description="Main entry point must use traceback for error handling",
    severity=Severity.ERROR,
)
def check_main_traceback(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that main.py uses if __name__ guard with try/except and traceback."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    # Find main.py
    main_file = None
    main_content = None
    for file_path, content in sources.items():
        if file_path.name == "main.py":
            main_file = file_path
            main_content = content
            break

    if main_file is None or main_content is None:
        return [
            CheckFinding(
                message="No main.py found in src/",
                severity=Severity.ERROR,
                suggestion="Connector must have a main.py entry point under src/",
            ),
        ]

    has_import, has_guard, has_try_tb, guard_line = _check_main_structure(
        main_content,
        main_file,
    )

    # Accumulate all issues found — multiple problems may coexist
    issues: list[str] = []
    if not has_import:
        issues.append("missing `import traceback`")
    if not has_guard:
        issues.append('missing `if __name__ == "__main__":` guard')
    if has_guard and not has_try_tb:
        issues.append("missing `try/except` with `traceback.print_exc()` in main guard")

    if not issues:
        return [
            CheckFinding(
                message=f"Main entry point has proper error handling in {main_file}",
                severity=Severity.INFO,
                file_path=main_file,
                line=guard_line,
            ),
        ]

    return [
        CheckFinding(
            message=f"Main entry point issues in {main_file}: {'; '.join(issues)}",
            severity=Severity.ERROR,
            file_path=main_file,
            line=guard_line or 1,
            suggestion=(
                "Use this pattern in main.py:\n"
                "    import traceback\n"
                '    if __name__ == "__main__":\n'
                "        try:\n"
                "            connector = MyConnector()\n"
                "            connector.run()\n"
                "        except Exception:\n"
                "            traceback.print_exc()\n"
                "            exit(1)"
            ),
        ),
    ]
