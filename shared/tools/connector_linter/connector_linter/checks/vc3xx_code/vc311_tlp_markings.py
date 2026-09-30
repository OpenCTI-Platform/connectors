"""VC311 — Connector should use TLP markings on entities.

- Paid source (Commercial Threat Intel): should use TLP:AMBER or TLP:RED
- Free source (Open Source Threat Intel): should use TLP:CLEAR (or TLP:WHITE)

The source type is inferred from ``connector_manifest.json`` ``use_cases``
field, but it is not 100% reliable — hence this check is WARNING only.
"""

import re
from pathlib import Path

from connector_linter.checks.vc3xx_code._helpers import (
    find_pattern_locations,
)
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    ConnectorType,
    Severity,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Pattern list 1: General TLP usage patterns.
#
# Detects ANY TLP-related code — constants, marking definition refs, etc.
# Used for sub-check A (basic TLP usage detection).
# ---------------------------------------------------------------------------
_TLP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bTLP_WHITE\b"),
    re.compile(r"\bTLP_GREEN\b"),
    re.compile(r"\bTLP_AMBER\b"),
    re.compile(r"\bTLP_RED\b"),
    re.compile(r"\bTLP_CLEAR\b"),
    re.compile(r"\bTLPMarking\b"),
    re.compile(r"\bobject_marking_refs\b"),
    re.compile(r"\bTLP_MARKING_DEFINITION_MAPPING\b"),
    re.compile(r"marking-definition--"),
    re.compile(r"TLP:(?:WHITE|CLEAR|GREEN|AMBER|RED|AMBER\+STRICT)", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Pattern list 2: Paid/commercial TLP levels (TLP:AMBER, TLP:RED).
#
# These are the restrictive TLP levels appropriate for commercial threat
# intelligence sources (data that shouldn't be freely shared).
# ---------------------------------------------------------------------------
_PAID_TLP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bTLP_AMBER\b"),
    re.compile(r"\bTLP_RED\b"),
    re.compile(r"TLP:AMBER", re.IGNORECASE),
    re.compile(r"TLP:RED", re.IGNORECASE),
    re.compile(r"AMBER\+STRICT", re.IGNORECASE),
    re.compile(r"""['"]amber['"]""", re.IGNORECASE),
    re.compile(r"""['"]red['"]""", re.IGNORECASE),
    re.compile(r"""['"]amber\+strict['"]""", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Pattern list 3: Free/open-source TLP levels (TLP:CLEAR, TLP:WHITE).
#
# These are the permissive TLP levels appropriate for open-source threat
# intelligence sources (freely shareable data).
# ---------------------------------------------------------------------------
_FREE_TLP_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bTLP_WHITE\b"),
    re.compile(r"\bTLP_CLEAR\b"),
    re.compile(r"TLP:WHITE", re.IGNORECASE),
    re.compile(r"TLP:CLEAR", re.IGNORECASE),
    re.compile(r"""['"]white['"]""", re.IGNORECASE),
    re.compile(r"""['"]clear['"]""", re.IGNORECASE),
]


def _has_tlp_usage(sources: dict[Path, str]) -> bool:
    """Check if any TLP-related pattern exists in the source files.

    Uses an any-match approach: returns True as soon as any pattern matches
    in any source file. Doesn't need to find all matches.
    """
    for content in sources.values():
        for pattern in _TLP_PATTERNS:
            if pattern.search(content):
                return True
    return False


def _detect_tlp_levels(sources: dict[Path, str]) -> tuple[bool, bool]:
    """Detect which TLP levels are used in source files.

    Distinguishes paid (AMBER/RED) from free (CLEAR/WHITE) TLP levels
    to determine if the level matches the connector's source type.
    Both can be True if the connector uses multiple TLP levels.

    Returns (has_paid_level, has_free_level).
    """
    has_paid = False
    has_free = False
    for content in sources.values():
        for pattern in _PAID_TLP_PATTERNS:
            if pattern.search(content):
                has_paid = True
        for pattern in _FREE_TLP_PATTERNS:
            if pattern.search(content):
                has_free = True
    return has_paid, has_free


def _get_source_type(ctx: ConnectorContext) -> str | None:
    """Infer source type from connector_manifest.json use_cases.

    Uses a manifest-based heuristic: scans the use_cases list for keywords
    like "commercial", "paid", "open source", "free". This is not 100%
    reliable — connectors may not declare use_cases, or the wording may
    not match. Returns None when undetermined.

    Returns "commercial", "open_source", or None if undetermined.
    """
    manifest = ctx.manifest
    if not manifest:
        return None

    use_cases = manifest.get("use_cases", [])
    if not isinstance(use_cases, list):
        return None

    for uc in use_cases:
        if not isinstance(uc, str):
            continue
        lower = uc.lower()
        if "commercial" in lower or "paid" in lower:
            return "commercial"
        if "open source" in lower or "free" in lower:
            return "open_source"

    return None


@CheckRegistry.register(
    code="VC311",
    name="tlp-markings-on-entities",
    description="Connector should use TLP markings on entities with appropriate level",
    severity=Severity.WARNING,
    applicable_types={
        ConnectorType.INTERNAL_ENRICHMENT,
        ConnectorType.EXTERNAL_IMPORT,
    },
)
def check_tlp_markings(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector uses TLP markings and that the level is appropriate."""
    sources = ctx.python_sources

    if not sources:
        return [
            CheckFinding(
                message="No Python source files found in src/",
                severity=Severity.ERROR,
            ),
        ]

    results: list[CheckFinding] = []

    # Sub-check A: Are TLP markings used at all?
    if not _has_tlp_usage(sources):
        results.append(
            CheckFinding(
                message="No TLP marking usage detected in source code",
                severity=Severity.WARNING,
                suggestion=(
                    "Use TLP markings on STIX entities via object_marking_refs. "
                    "Paid sources should use TLP:AMBER or TLP:RED, "
                    "free sources should use TLP:CLEAR."
                ),
            ),
        )
        return results

    # TLP is used — report PASS for basic usage
    results.append(
        CheckFinding(
            message="TLP markings are used on entities",
            severity=Severity.INFO,
        ),
    )

    # Sub-check B: Is the TLP level appropriate for the source type?
    source_type = _get_source_type(ctx)
    if source_type is None:
        return results

    has_paid_level, has_free_level = _detect_tlp_levels(sources)

    if source_type == "commercial" and has_free_level and not has_paid_level:
        locations = find_pattern_locations(sources, _FREE_TLP_PATTERNS)
        first_loc = locations[0] if locations else None

        results.append(
            CheckFinding(
                message=(
                    "Commercial Threat Intel source uses TLP:CLEAR/WHITE "
                    "— expected TLP:AMBER or TLP:RED"
                ),
                severity=Severity.WARNING,
                file_path=(first_loc[0]) if first_loc else None,
                line=first_loc[1] if first_loc else None,
                suggestion=(
                    "Paid/commercial sources should typically use TLP:AMBER "
                    "or TLP:RED markings, not TLP:CLEAR/WHITE."
                ),
            ),
        )

    elif source_type == "open_source" and has_paid_level and not has_free_level:
        locations = find_pattern_locations(sources, _PAID_TLP_PATTERNS)
        first_loc = locations[0] if locations else None

        results.append(
            CheckFinding(
                message=(
                    "Open Source Threat Intel source uses TLP:AMBER/RED "
                    "— expected TLP:CLEAR"
                ),
                severity=Severity.WARNING,
                file_path=(first_loc[0]) if first_loc else None,
                line=first_loc[1] if first_loc else None,
                suggestion=(
                    "Open source/free sources should typically use TLP:CLEAR "
                    "(TLP:WHITE) markings, not TLP:AMBER/RED."
                ),
            ),
        )

    return results
