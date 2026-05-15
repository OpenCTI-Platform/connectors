"""VC503 — No use of deprecated helper logger ``helper.log_{level}()``.

The legacy logging methods on ``OpenCTIConnectorHelper``:

- ``helper.log_debug()``
- ``helper.log_info()``
- ``helper.log_warning()`` / ``helper.log_warn()``
- ``helper.log_error()``

are deprecated. Connectors must use the structured ``connector_logger``
instead::

    self.helper.connector_logger.debug("message", {"key": "value"})
    self.helper.connector_logger.info("message")
    self.helper.connector_logger.warning("message")
    self.helper.connector_logger.error("message", {"error": str(e)})

Matched patterns:

- ``self.helper.log_*()`` — qualified attribute
- ``self._helper.log_*()`` — private helper attribute
- ``helper.log_*()`` — bare helper name (common in utility functions)

Reference: https://github.com/OpenCTI-Platform/connectors/pull/3948

Scope: Common (all connector types).
"""

import ast
from pathlib import Path

from connector_linter.checks.vc5xx_deprecation._helpers import is_helper_node
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Full list of deprecated helper logging methods.
#
# These methods were the original logging API on OpenCTIConnectorHelper:
#   log_debug   → replaced by connector_logger.debug()
#   log_info    → replaced by connector_logger.info()
#   log_warning → replaced by connector_logger.warning()
#   log_warn    → alias for log_warning, also deprecated
#   log_error   → replaced by connector_logger.error()
#
# The new connector_logger supports structured metadata as a second arg:
#   self.helper.connector_logger.info("msg", {"key": "value"})
# ---------------------------------------------------------------------------
_DEPRECATED_LOG_METHODS = frozenset(
    {
        "log_debug",
        "log_info",
        "log_warning",
        "log_warn",
        "log_error",
    },
)


# ---------------------------------------------------------------------------
# AST detection: find deprecated helper.log_*() calls
#
# Matches three patterns (all ending in .log_*(...)):
#
#   Pattern 1 — qualified attribute:
#     X.helper.log_debug(...)    (e.g. self.helper.log_info())
#     X._helper.log_info(...)   (e.g. self._helper.log_error())
#
#   Pattern 2 — bare name:
#     helper.log_debug(...)     (e.g. helper.log_info())
#     _helper.log_info(...)     (e.g. _helper.log_error())
#
# The chain is: Call → Attribute(attr=log_*) → <helper_node>
# Only methods in _DEPRECATED_LOG_METHODS are flagged.
# ---------------------------------------------------------------------------
def _find_deprecated_log_calls(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int, str]]:
    """Return (file, line, method_name) for deprecated helper.log_*() calls."""
    hits: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Match: <helper>.log_debug(), <helper>.log_info(), etc.
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _DEPRECATED_LOG_METHODS
                and is_helper_node(func.value)
            ):
                hits.append((file_path, node.lineno, func.attr))
    return hits


@CheckRegistry.register(
    code="VC503",
    name="no-deprecated-helper-logger",
    description="Must use connector_logger instead of deprecated helper.log_{level}()",
    severity=Severity.ERROR,
)
def check_no_deprecated_helper_logger(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect deprecated helper.log_*() calls."""
    sources = ctx.python_sources
    if not sources:
        return [
            CheckFinding(
                message="No Python sources found — skipped",
                severity=Severity.ERROR,
            ),
        ]

    trees = ctx.python_trees
    hits = _find_deprecated_log_calls(trees)

    if not hits:
        return [
            CheckFinding(
                message="No deprecated helper.log_*() calls found ✓",
                severity=Severity.INFO,
            ),
        ]

    results: list[CheckFinding] = []
    for file_path, line, method in hits:
        # Map deprecated method name to the new connector_logger equivalent.
        # Strip the "log_" prefix: log_debug → debug, log_info → info, etc.
        # Special case: log_warn → "warning" (Python logging uses "warning",
        # not "warn").
        level = method.replace("log_", "")
        if level == "warn":
            level = "warning"
        results.append(
            CheckFinding(
                message=f"uses deprecated helper.{method}()",
                severity=Severity.ERROR,
                file_path=file_path,
                line=line,
                suggestion=(
                    f"Replace with self.helper.connector_logger.{level}(). "
                    f"The connector_logger supports structured metadata as "
                    f'a second argument: .{level}("message", {{"key": val}})'
                ),
            ),
        )

    return results
