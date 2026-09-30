"""VC322 — Enrichment connector must read the former bundle from data.

For playbook compatibility the connector must read ``data["stix_objects"]``
(the original bundle) early in ``process_message`` so it can be returned
in **every** code path: success, not-in-scope, and error.

Scope: INTERNAL_ENRICHMENT only.
Severity: ERROR.
"""

import re

from connector_linter.checks.vc3xx_code._helpers import (
    find_pattern_locations,
)
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    ConnectorType,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Regex: detect access to data['stix_objects'] or data["stix_objects"]
#
# Matches patterns like:
#   data['stix_objects']
#   data["stix_objects"]
#   data [ 'stix_objects' ]   (with optional whitespace)
#
# The stix_objects field in the incoming data dict contains the original
# STIX bundle that the platform sent to the enrichment connector.
# Reading it early in process_message is essential so it can be returned
# unchanged in all 3 code paths:
#   1. Success — enriched objects appended to original bundle
#   2. Not-in-scope — original bundle returned as-is for playbook continuity
#   3. Error — original bundle returned so the playbook is not broken
# ---------------------------------------------------------------------------
_STIX_OBJECTS_DATA = re.compile(r"""data\s*\[\s*['"]stix_objects['"]\s*\]""")

# Only enrichment connectors receive data['stix_objects'] from the platform.
# External-import connectors fetch data themselves and don't receive bundles.


@CheckRegistry.register(
    code="VC322",
    name="former-bundle-read",
    description=(
        "Enrichment connector must read data['stix_objects'] "
        "(former bundle) for playbook compatibility"
    ),
    severity=Severity.ERROR,
    applicable_types={ConnectorType.INTERNAL_ENRICHMENT},
)
def check_former_bundle(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that data['stix_objects'] is read."""
    sources = ctx.python_sources
    if not sources:
        return [no_python_sources_finding()]

    locations = find_pattern_locations(sources, [_STIX_OBJECTS_DATA])

    if not locations:
        return [
            CheckFinding(
                message=(
                    "data['stix_objects'] is never read — the original "
                    "bundle cannot be returned on error or not-in-scope"
                ),
                severity=Severity.ERROR,
                suggestion=(
                    "Read the former bundle with "
                    "stix_objects = data['stix_objects'] early in "
                    "process_message. Send it back unchanged on error "
                    "or when entity is not in scope (playbook compatibility)."
                ),
            ),
        ]

    first = locations[0]
    return [
        CheckFinding(
            message="Former bundle is read from data['stix_objects']",
            severity=Severity.INFO,
            file_path=first[0],
            line=first[1],
        ),
    ]
