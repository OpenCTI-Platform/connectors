"""VC502 — No use of deprecated ``x_opencti_report_status``.

The custom STIX property ``x_opencti_report_status`` is deprecated and
no longer functional.  Connectors must not set it on any STIX object.

Note: ``x_opencti_workflow_id`` *works* but is fragile because the UUID
is unique per installation; it is flagged as a WARNING.

Reference: https://github.com/OpenCTI-Platform/connectors/issues/1830
"""

import ast
from pathlib import Path

from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
)
from connector_linter.registry import CheckRegistry

# Fully deprecated — this property is non-functional in current OpenCTI.
# Using it has no effect; the platform ignores it entirely.
_DEPRECATED_PROP = "x_opencti_report_status"

# Fragile but functional — x_opencti_workflow_id works but the UUID
# is unique per OpenCTI installation.  A hardcoded UUID will break when
# the connector is deployed on a different platform instance.
_FRAGILE_PROP = "x_opencti_workflow_id"


def _scan_with_lines(
    trees: dict[Path, ast.Module],
    prop_name: str,
) -> list[tuple[Path, int]]:
    """Return (file, line) pairs for all keyword-arg or string-literal uses.

    Two detection patterns (both via AST):
      1. ast.keyword with arg == prop_name
         Catches: SomeObject(x_opencti_report_status=value)
      2. ast.Constant with value == prop_name
         Catches: string literals like "x_opencti_report_status" used as
         dict keys, get_config_variable args, etc.
    """
    hits: list[tuple[Path, int]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == prop_name:
                # ast.keyword may not have lineno in all Python versions,
                # so we use getattr with a fallback to 0 for safety.
                line = getattr(node, "lineno", 0) or 0
                hits.append((file_path, line))
            elif isinstance(node, ast.Constant) and node.value == prop_name:
                hits.append((file_path, node.lineno))
    return hits


@CheckRegistry.register(
    code="VC502",
    name="no-deprecated-report-status",
    description="Must not use deprecated x_opencti_report_status custom property",
    severity=Severity.ERROR,
)
def check_no_deprecated_report_status(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect usage of x_opencti_report_status (ERROR) and warn about
    x_opencti_workflow_id (WARNING).
    """
    sources = ctx.python_sources
    if not sources:
        return [
            CheckFinding(
                message="No Python sources found — skipped",
                severity=Severity.ERROR,
            ),
        ]

    trees = ctx.python_trees
    results: list[CheckFinding] = []

    # ERROR: x_opencti_report_status is fully deprecated and non-functional.
    # Any usage is dead code that should be removed.
    for file_path, line in _scan_with_lines(trees, _DEPRECATED_PROP):
        results.append(
            CheckFinding(
                message="uses deprecated x_opencti_report_status",
                severity=Severity.ERROR,
                file_path=file_path,
                line=line,
                suggestion=(
                    "Remove x_opencti_report_status — it is deprecated and "
                    "non-functional. Use workflow status changes via the "
                    "platform UI or API instead."
                ),
            ),
        )

    # WARNING (not ERROR): x_opencti_workflow_id works but the UUID is
    # install-specific.  Hardcoding it makes the connector non-portable.
    for file_path, line in _scan_with_lines(trees, _FRAGILE_PROP):
        results.append(
            CheckFinding(
                message=("uses x_opencti_workflow_id — UUID is install-specific"),
                severity=Severity.WARNING,
                file_path=file_path,
                line=line,
                suggestion=(
                    "x_opencti_workflow_id works but the UUID is unique per "
                    "installation. Consider managing workflow status via the "
                    "platform instead of hardcoding in the connector."
                ),
            ),
        )

    if not results:
        return [
            CheckFinding(
                message="No deprecated report status properties found ✓",
                severity=Severity.INFO,
            ),
        ]

    return results
