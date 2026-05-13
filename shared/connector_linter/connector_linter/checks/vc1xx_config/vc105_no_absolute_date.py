"""VC105 — Import start dates must use ISO duration, not absolute dates.

When a connector supports configuring the historical import window
(``start_date``, ``import_start_date``, etc.), it must accept ISO 8601
**duration** strings (e.g. ``P30D``, ``P6M``) rather than hardcoded
absolute dates like ``2020-05-01T00:00:00``.

The connectors-sdk provides ``DatetimeFromIsoString`` which automatically
handles both absolute ISO dates and relative durations.

Scope: Common (all connector types).
"""

import ast
import re
from datetime import date, datetime

from connector_linter.checks.vc1xx_config._helpers import extract_all_env_vars
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Regex: env var names that indicate a start/import date setting.
#
# Matches substrings like START_DATE, START_TIMESTAMP, IMPORT_DATE,
# IMPORT_START inside variable names.  Case-insensitive to catch both
# env var names (uppercase) and Python field names (snake_case).
#
# Examples that match:
#   CONNECTOR_START_DATE, import_start_date, MY_IMPORT_DATE
# ---------------------------------------------------------------------------
_DATE_VAR_NAMES = re.compile(
    r"(?:START_DATE|START_TIMESTAMP|IMPORT_DATE|IMPORT_START|SINCE)",
    re.IGNORECASE,
)


def _is_absolute_iso_datetime(value: str) -> bool:
    """Return True when value is an absolute ISO date/datetime string.

    Accepts quoted and unquoted values. Durations (e.g. P30D), env var
    placeholders (e.g. ${START_DATE}), and invalid date strings return False.
    """
    normalized = value.strip().strip("\"'")
    if not normalized:
        return False

    # Python's fromisoformat accepts +00:00 but not every trailing "Z" form.
    normalized = normalized.replace("Z", "+00:00")

    for parser in (datetime.fromisoformat, date.fromisoformat):
        try:
            parser(normalized)
            return True
        except ValueError:
            continue
    return False


def _check_config_files(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check config files for absolute dates in start_date-like variables.

    Detection flow:
      1. Extract all env vars from docker-compose.yml / .env.sample.
      2. Skip commented-out lines (inactive config).
      3. Keep only variables whose name contains a date-like keyword.
      4. Flag any whose value looks like an absolute ISO date (20xx-…).
    """
    results: list[CheckFinding] = []
    env_vars = extract_all_env_vars(ctx)

    for var in env_vars:
        # Commented-out vars are informational — skip them
        if var.is_commented:
            continue
        # Only inspect variables with date-related names
        if not _DATE_VAR_NAMES.search(var.name):
            continue
        # Flag values that look like absolute dates (e.g. "2020-05-01")
        if _is_absolute_iso_datetime(var.value):
            rel = var.file_path.relative_to(ctx.path)
            results.append(
                CheckFinding(
                    message=(
                        f"{rel}:{var.line}: {var.name}={var.value} uses absolute date"
                    ),
                    severity=Severity.WARNING,
                    file_path=var.file_path,
                    line=var.line,
                    suggestion=(
                        "Use an ISO 8601 duration (e.g. P30D for 30 days ago) "
                        "instead of a fixed date. The SDK's DatetimeFromIsoString "
                        "type accepts both formats."
                    ),
                ),
            )

    return results


def _check_code_defaults(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check Python code for hardcoded date defaults in Field() or assignments.

    Looks for AST patterns like:
        Field(default="2020-05-01T00:00:00Z")

    where a keyword argument ``default`` is set to a string constant
    matching an absolute date.  This catches Pydantic settings fields
    that should use ISO durations instead.
    """
    sources = ctx.python_sources
    if not sources:
        return []

    trees = ctx.python_trees
    results: list[CheckFinding] = []

    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            # Check Field(default="2020-...") or direct assignment
            if (
                isinstance(node, ast.keyword)
                and node.arg == "default"
                and (
                    isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                    and _is_absolute_iso_datetime(node.value.value)
                )
            ):
                # Walk up to find the field name context
                results.append(
                    CheckFinding(
                        message=(
                            f'Field default="{node.value.value}" '
                            f"is a hardcoded absolute date"
                        ),
                        severity=Severity.WARNING,
                        file_path=file_path,
                        line=node.value.lineno,
                        suggestion=(
                            'Use an ISO duration default (e.g. "P30D") '
                            "and type the field as DatetimeFromIsoString "
                            "from connectors-sdk."
                        ),
                    ),
                )

    return results


@CheckRegistry.register(
    code="VC105",
    name="no-absolute-import-date",
    description="Import start dates should use ISO duration, not absolute dates",
    severity=Severity.WARNING,
)
def check_no_absolute_import_date(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that no absolute dates are used for import start configuration."""
    config_results = _check_config_files(ctx)
    code_results = _check_code_defaults(ctx)

    all_results = config_results + code_results

    if not all_results:
        return [
            CheckFinding(
                message="No hardcoded absolute import dates found ✓",
                severity=Severity.INFO,
            ),
        ]

    return all_results
