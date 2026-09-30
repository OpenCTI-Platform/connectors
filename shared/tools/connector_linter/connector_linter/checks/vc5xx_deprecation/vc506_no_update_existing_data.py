"""VC506 — No use of deprecated ``UPDATE_EXISTING_DATA``.

The ``update_existing_data`` setting no longer exists in the connector
helper and must be removed from configuration files and code.

Detection:
1. Config: ``*UPDATE_EXISTING_DATA*`` env vars in docker-compose / .env
2. Code: ``update_existing_data`` attribute access and string literals

**Exception**: The ``opencti`` datasets connector (external-import/opencti)
is explicitly exempt from this check.

Reference:
- https://github.com/OpenCTI-Platform/connectors/commit/efb345a5

Scope: Common (all connector types).
"""

import ast
import re

from connector_linter.checks.vc1xx_config._helpers import extract_all_env_vars
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
)
from connector_linter.registry import CheckRegistry

_UPDATE_VAR_RE = re.compile(r"UPDATE_EXISTING_DATA", re.IGNORECASE)

# The opencti datasets connector (external-import/opencti) is explicitly
# exempt because it is a special-purpose connector that manages platform
# reference data and legitimately needs update_existing_data for its
# dataset seeding workflow.
_EXEMPT_DIRNAMES = {"opencti"}


def _is_exempt(ctx: ConnectorContext) -> bool:
    dirname = ctx.path.name
    return dirname in _EXEMPT_DIRNAMES


def _check_config_vars(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect UPDATE_EXISTING_DATA in config files.

    Scans env vars from docker-compose.yml and .env files for variable
    names containing UPDATE_EXISTING_DATA (case-insensitive).
    """
    results: list[CheckFinding] = []
    env_vars = extract_all_env_vars(ctx)

    for var in env_vars:
        if var.is_commented:
            continue
        if _UPDATE_VAR_RE.search(var.name):
            results.append(
                CheckFinding(
                    message=(f"{var.name}={var.value} — deprecated setting"),
                    severity=Severity.ERROR,
                    file_path=var.file_path,
                    line=var.line,
                    suggestion=(
                        "Remove UPDATE_EXISTING_DATA from configuration. "
                        "This setting no longer exists in the connector helper."
                    ),
                ),
            )

    return results


def _check_code_usage(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect update_existing_data usage in Python code.

    Two detection patterns via AST:
      1. Attribute access: ``*.update_existing_data``
         Catches: ``self.update_existing_data``, ``config.update_existing_data``
      2. String literal containing ``"UPDATE_EXISTING_DATA"``
         Catches: ``get_config_variable("CONNECTOR_UPDATE_EXISTING_DATA")``,
         ``os.environ["UPDATE_EXISTING_DATA"]``, etc.

    Limitations:
      - Plain variable names (``ast.Name``) like ``update_existing_data = ...``
        are not detected. This is intentional to avoid false positives on
        function parameters or local variables that happen to share the name.

    The setting no longer exists in the connector helper — it was removed
    and any reference to it is dead code.
    """
    sources = ctx.python_sources
    if not sources:
        return []

    trees = ctx.python_trees
    results: list[CheckFinding] = []

    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            # Attribute access: self.update_existing_data, *.update_existing_data
            if isinstance(node, ast.Attribute) and node.attr == "update_existing_data":
                results.append(
                    CheckFinding(
                        message=("uses deprecated update_existing_data"),
                        severity=Severity.ERROR,
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=(
                            "Remove update_existing_data — this setting no "
                            "longer exists in the connector helper."
                        ),
                    ),
                )

            # String literal: "UPDATE_EXISTING_DATA" / "update_existing_data"
            # This includes docstrings — if a docstring mentions this setting,
            # the docstring itself is outdated and should be updated.
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and _UPDATE_VAR_RE.search(node.value)
            ):
                results.append(
                    CheckFinding(
                        message=(f'references deprecated "{node.value}"'),
                        severity=Severity.ERROR,
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=(
                            "Remove UPDATE_EXISTING_DATA references — this "
                            "setting no longer exists in the connector helper."
                        ),
                    ),
                )

    return results


@CheckRegistry.register(
    code="VC506",
    name="no-update-existing-data",
    description="Must not use deprecated UPDATE_EXISTING_DATA setting",
    severity=Severity.ERROR,
)
def check_no_update_existing_data(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect deprecated UPDATE_EXISTING_DATA patterns."""
    if _is_exempt(ctx):
        return [
            CheckFinding(
                message="Exempt — opencti datasets connector may use this ✓",
                severity=Severity.INFO,
            ),
        ]

    config_results = _check_config_vars(ctx)
    code_results = _check_code_usage(ctx)

    all_results = config_results + code_results

    if not all_results:
        return [
            CheckFinding(
                message="No deprecated UPDATE_EXISTING_DATA usage found ✓",
                severity=Severity.INFO,
            ),
        ]

    return all_results
