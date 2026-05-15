"""VC504 — No use of deprecated ``CONFIDENCE_LEVEL`` configuration.

Since OpenCTI 6.0, the confidence level is managed via user/group
confidence policies on the platform. It must **not** be set:

1. In configuration files (``CONNECTOR_CONFIDENCE_LEVEL``, ``*_CONFIDENCE*``
   env vars in docker-compose.yml / .env.sample)
2. In code via ``self.helper.connect_confidence_level``
3. As ``confidence=`` keyword argument on STIX objects

Passing ``confidence`` on STIX objects prevents the platform from managing
it correctly through confidence policies.

References:
- https://github.com/OpenCTI-Platform/connectors/pull/3316
- https://github.com/OpenCTI-Platform/connectors/issues/1816
- https://docs.opencti.io/latest/usage/reliability-confidence/

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

# ---------------------------------------------------------------------------
# Regex: targeted match for CONFIDENCE_LEVEL or CONFIDENCE_SCORE env var names
#
# Matches env vars whose name contains "CONFIDENCE_LEVEL" or
# "CONFIDENCE_SCORE" (case-insensitive), e.g.:
#   CONNECTOR_CONFIDENCE_LEVEL
#   CONNECTOR_CONFIDENCE_SCORE
#
# Deliberately excludes bare "CONFIDENCE" to avoid false positives on
# unrelated env vars (e.g. SELF_CONFIDENCE, CONFIDENCE_THRESHOLD).
#
# Since OpenCTI 6.0, the platform manages confidence via user/group
# confidence policies.  Connectors must not set it because:
#   1. Config var is ignored by the new connector helper
#   2. Setting confidence= on STIX objects prevents the platform from
#      applying its own confidence policies correctly
# ---------------------------------------------------------------------------
_CONFIDENCE_VAR_RE = re.compile(r"CONFIDENCE_(LEVEL|SCORE)", re.IGNORECASE)


def _check_config_vars(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect CONFIDENCE-related env vars in config files.

    Scans all env vars from docker-compose.yml and .env files for names
    containing "CONFIDENCE" (case-insensitive).
    """
    results: list[CheckFinding] = []
    env_vars = extract_all_env_vars(ctx)

    for var in env_vars:
        if var.is_commented:
            continue
        if _CONFIDENCE_VAR_RE.search(var.name):
            results.append(
                CheckFinding(
                    message=(
                        f"{var.name}={var.value} — confidence level in config is deprecated"
                    ),
                    severity=Severity.ERROR,
                    file_path=var.file_path,
                    line=var.line,
                    suggestion=(
                        "Remove confidence level from configuration. Since "
                        "OpenCTI 6.0, confidence is managed via user/group "
                        "confidence policies on the platform."
                    ),
                ),
            )

    return results


def _check_code_usage(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect connect_confidence_level and confidence= kwarg in code.

    Two detection patterns via AST:
      1. Attribute access: *.connect_confidence_level
         Catches: self.helper.connect_confidence_level
      2. Keyword argument: confidence=<value>
         Catches: SomeSTIXObject(confidence=80) in STIX object constructors
    """
    sources = ctx.python_sources
    if not sources:
        return []

    trees = ctx.python_trees
    results: list[CheckFinding] = []

    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            # Pattern 1: *.connect_confidence_level attribute access
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "connect_confidence_level"
            ):
                results.append(
                    CheckFinding(
                        message="uses deprecated connect_confidence_level",
                        severity=Severity.ERROR,
                        file_path=file_path,
                        line=node.lineno,
                        suggestion=(
                            "Remove connect_confidence_level usage. Confidence "
                            "is now managed by user/group policies on the "
                            "platform, not by the connector."
                        ),
                    ),
                )

            # Pattern 2: confidence= keyword arg in STIX object construction.
            # ast.keyword may lack lineno in some Python versions — use
            # getattr with fallback to 0 for safety.
            if isinstance(node, ast.keyword) and node.arg == "confidence":
                line = getattr(node, "lineno", 0) or 0
                results.append(
                    CheckFinding(
                        message=(
                            "sets confidence= on STIX object — deprecated since 6.0"
                        ),
                        severity=Severity.ERROR,
                        file_path=file_path,
                        line=line,
                        suggestion=(
                            "Remove the confidence= argument. Let the platform "
                            "manage confidence via user/group confidence "
                            "policies instead of setting it on STIX objects."
                        ),
                    ),
                )

    return results


@CheckRegistry.register(
    code="VC504",
    name="no-deprecated-confidence",
    description="Must not use deprecated confidence level (removed since OpenCTI 6.0)",
    severity=Severity.ERROR,
)
def check_no_deprecated_confidence(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect deprecated confidence level patterns."""
    config_results = _check_config_vars(ctx)
    code_results = _check_code_usage(ctx)

    all_results = config_results + code_results

    if not all_results:
        return [
            CheckFinding(
                message="No deprecated confidence level usage found ✓",
                severity=Severity.INFO,
            ),
        ]

    return all_results
