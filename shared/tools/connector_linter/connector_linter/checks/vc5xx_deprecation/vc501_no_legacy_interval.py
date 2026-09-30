"""VC501 — Connectors must use ``duration_period`` (ISO 8601), not legacy interval.

The legacy ``*_INTERVAL`` configuration pattern (minutes, hours, days as
plain integers) and ``schedule_unit()`` are deprecated. Connectors must
migrate to:

- ``CONNECTOR_DURATION_PERIOD`` (ISO 8601 format, e.g. ``PT30M``, ``P7D``)
- ``self.helper.schedule_iso()`` or ``schedule_process()`` for scheduling

The SDK's deprecation mechanism (``DeprecatedField``) should be used to
provide backwards compatibility during the migration window.

Scope: EXTERNAL_IMPORT (scheduling is only relevant for importers).
"""

import ast
import re

from connector_linter.checks.vc1xx_config._helpers import extract_all_env_vars
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    ConnectorType,
    Severity,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Regex: detect legacy interval configuration variable names
#
# Two patterns are flagged:
#   1. *_INTERVAL$        — any env var ending in _INTERVAL
#      e.g. CONNECTOR_INTERVAL, DOPPEL_INTERVAL, IMPORT_INTERVAL
#   2. ^CONNECTOR_RUN_EVERY$ — another legacy naming convention
#
# The modern replacement is CONNECTOR_DURATION_PERIOD using ISO 8601
# duration format (e.g. PT30M = 30 minutes, PT2H = 2 hours, P7D = 7 days).
# The numeric interval approach (minutes/hours/days as plain integers) is
# error-prone and does not encode the time unit in the value itself.
# ---------------------------------------------------------------------------
_INTERVAL_VAR_RE = re.compile(r"_INTERVAL$|^CONNECTOR_RUN_EVERY$")


def _check_interval_config(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect legacy _INTERVAL config variables.

    Scans all env vars extracted from docker-compose.yml and .env files
    for variable names that match the legacy interval naming pattern.
    """
    results: list[CheckFinding] = []
    env_vars = extract_all_env_vars(ctx)

    for var in env_vars:
        if var.is_commented:
            continue
        if _INTERVAL_VAR_RE.search(var.name):
            results.append(
                CheckFinding(
                    message=(f"{var.name}={var.value} — legacy interval variable"),
                    severity=Severity.ERROR,
                    file_path=var.file_path,
                    line=var.line,
                    suggestion=(
                        "Replace with CONNECTOR_DURATION_PERIOD using ISO 8601 "
                        "format (e.g. PT30M, PT2H, P7D). Use SDK DeprecatedField "
                        "for backwards compatibility."
                    ),
                ),
            )

    return results


def _check_schedule_unit(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect schedule_unit() calls (deprecated).

    Uses AST analysis to find *.schedule_unit() method calls.  The
    schedule_unit() method was used with the legacy interval pattern
    to convert numeric intervals with a unit (minutes, hours, days)
    into seconds.  It is replaced by schedule_iso() or schedule_process()
    which work directly with ISO 8601 duration strings.
    """
    sources = ctx.python_sources
    if not sources:
        return []

    trees = ctx.python_trees
    results: list[CheckFinding] = []

    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "schedule_unit":
                results.append(
                    CheckFinding(
                        message="uses deprecated schedule_unit()",
                        severity=Severity.ERROR,
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=(
                            "Replace schedule_unit() with schedule_iso() or "
                            "schedule_process(). Use duration_period (ISO 8601) "
                            "instead of numeric intervals with time units."
                        ),
                    ),
                )

    return results


@CheckRegistry.register(
    code="VC501",
    name="no-legacy-interval",
    description="Must use duration_period (ISO 8601), not legacy interval config",
    severity=Severity.ERROR,
    applicable_types={ConnectorType.EXTERNAL_IMPORT},
)
def check_no_legacy_interval(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check for deprecated interval patterns."""
    # Two detection strategies: config files (env vars) and code (AST)
    config_results = _check_interval_config(ctx)
    code_results = _check_schedule_unit(ctx)

    all_results = config_results + code_results

    if not all_results:
        return [
            CheckFinding(
                message="No legacy interval patterns found ✓",
                severity=Severity.INFO,
            ),
        ]

    return all_results
