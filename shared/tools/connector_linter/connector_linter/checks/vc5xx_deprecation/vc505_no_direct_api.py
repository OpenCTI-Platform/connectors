"""VC505 — No direct GraphQL API calls via ``helper.api.*``.

Connectors should send STIX bundles to OpenCTI workers rather than
making direct GraphQL API calls (e.g. ``self.helper.api.campaign.read``).

Matched patterns:

- ``self.helper.api.<submodule>`` — qualified attribute
- ``self._helper.api.<submodule>`` — private helper attribute
- ``helper.api.<submodule>`` — bare helper name (common in utility functions)

**Allowed exceptions** (not flagged):

- ``self.helper.api.work.*`` — required for work lifecycle management
- ``self.helper.api.vocabulary.*`` — needed for vocabulary management
- ``self.helper.api.label.*`` — needed for label/tag color management
- ``self.helper.api.marking_definition.*`` — needed for marking lookups
- ``self.helper.api.fetch_opencti_file`` — needed for file retrieval
- ``self.helper.api.stix2.*`` — STIX2 utility methods

This check emits WARNINGs since some edge cases legitimately need
direct API access.

Scope: Common (all connector types).
"""

import ast
from pathlib import Path

from connector_linter.checks.vc5xx_deprecation._helpers import is_helper_node
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# API submodules that are allowed (not flagged)
#
# These submodules have legitimate use cases that cannot be replaced by
# sending STIX bundles:
#   - work          — work lifecycle management (initiate, close, report)
#   - vocabulary    — vocabulary/dropdown management, no STIX equivalent
#   - label         — label/tag color management, STIX labels lack colors
#   - marking_definition — TLP marking lookups for access control
#   - fetch_opencti_file — file retrieval, no bundle equivalent
#   - stix2         — STIX2 utility methods (conversion helpers)
#
# The architectural principle: connectors should send STIX bundles to
# OpenCTI workers for ingestion rather than making direct GraphQL API
# calls.  Direct API calls bypass the worker pipeline (deduplication,
# dependency resolution, etc.) and create tight coupling to the API schema.
# ---------------------------------------------------------------------------
_ALLOWED_API_SUBMODULES = frozenset(
    {
        "work",
        "vocabulary",
        "label",
        "marking_definition",
        "fetch_opencti_file",
        "stix2",
    },
)


# ---------------------------------------------------------------------------
# AST detection: find direct helper.api.* attribute access
#
# Matches three patterns (all ending in .api.<submodule>):
#
#   Pattern 1 — qualified attribute:
#     X.helper.api.<submodule>   (e.g. self.helper.api.campaign)
#     X._helper.api.<submodule>  (e.g. self._helper.api.work)
#
#   Pattern 2 — bare name:
#     helper.api.<submodule>     (e.g. helper.api.work)
#     _helper.api.<submodule>    (e.g. _helper.api.identity)
#
# Only submodules NOT in _ALLOWED_API_SUBMODULES are flagged.
# ---------------------------------------------------------------------------
def _find_direct_api_calls(
    trees: dict[Path, ast.Module],
) -> list[tuple[Path, int, str]]:
    """Return (file, line, submodule) for helper.api.* attribute access."""
    hits: list[tuple[Path, int, str]] = []
    for file_path, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            # Match: <helper>.api.<submodule>
            parent = node.value
            if (
                isinstance(parent, ast.Attribute)
                and parent.attr == "api"
                and is_helper_node(parent.value)
            ):
                submodule = node.attr
                if submodule not in _ALLOWED_API_SUBMODULES:
                    hits.append((file_path, node.lineno, submodule))
    return hits


@CheckRegistry.register(
    code="VC505",
    name="no-direct-api-calls",
    description="Connector should not use direct GraphQL API calls (helper.api.*)",
    severity=Severity.WARNING,
)
def check_no_direct_api_calls(ctx: ConnectorContext) -> list[CheckFinding]:
    """Detect direct API calls via helper.api.* (WARNING).

    Severity is WARNING (not ERROR) because some edge cases legitimately
    need direct API access — e.g. reading entity relationships that cannot
    be expressed in a STIX bundle query.
    """
    sources = ctx.python_sources
    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees
    hits = _find_direct_api_calls(trees)

    if not hits:
        return [
            CheckFinding(
                message="No direct API calls found ✓",
                severity=Severity.INFO,
            ),
        ]

    results: list[CheckFinding] = []
    for file_path, line, submodule in hits:
        results.append(
            CheckFinding(
                message=(f"direct API call helper.api.{submodule}"),
                severity=Severity.WARNING,
                file_path=file_path,
                line=line,
                suggestion=(
                    "Avoid direct GraphQL API calls. Send STIX bundles to "
                    "OpenCTI workers instead. helper.api.work is allowed "
                    "for work lifecycle management."
                ),
            ),
        )

    return results
