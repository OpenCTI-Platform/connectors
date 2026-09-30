"""VC319 — Enrichment connector must return original bundle when not in scope.

When an enrichment connector is triggered by a playbook for an entity type
outside its scope, it **must** send the original bundle back unchanged so the
playbook can continue.  Detection relies on the ``event_type`` field in data:
if absent, the trigger came from a playbook.

Scope: INTERNAL_ENRICHMENT only.
Severity: WARNING (best practice, not yet universally adopted).
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
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Regex: detect access to the "event_type" key in source code.
#
# Matches string literals 'event_type' or "event_type".  When an enrichment
# connector is triggered by a playbook, the data dict does NOT contain an
# event_type field.  Checking for its presence lets the connector
# distinguish between "manual enrichment" (has event_type) and "playbook
# trigger" (no event_type).
# ---------------------------------------------------------------------------
_EVENT_TYPE_PATTERN = re.compile(r"""['"](event_type)['"]""")

# ---------------------------------------------------------------------------
# Regex: detect access to data['stix_objects'] or data["stix_objects"].
#
# The stix_objects field contains the original STIX bundle that was passed
# to the enrichment connector.  Reading it is a prerequisite for returning
# the bundle unchanged when the entity is out of scope.
# ---------------------------------------------------------------------------
_STIX_OBJECTS_DATA = re.compile(r"""data\s*\[\s*['"]stix_objects['"]\s*\]""")

# Only enrichment connectors receive playbook triggers with scope concerns


@CheckRegistry.register(
    code="VC319",
    name="scope-fallback-bundle",
    description=(
        "Enrichment connector must return original bundle when entity is "
        "not in scope (playbook compatibility)"
    ),
    severity=Severity.WARNING,
    applicable_types={ConnectorType.INTERNAL_ENRICHMENT},
)
def check_scope_fallback(ctx: ConnectorContext) -> list[CheckFinding]:
    """Warn if the connector does not handle out-of-scope playbook triggers.

    Severity is WARNING because this is a best practice that is not yet
    universally adopted across the connector ecosystem.  When an enrichment
    connector receives a playbook trigger for an entity type it does not
    handle (e.g. a "Domain Name" enricher gets an "IPv4"), it should send
    the original bundle back unchanged so the playbook pipeline can continue.
    """
    sources = ctx.python_sources
    if not sources:
        return []

    # Detection flow:
    # 1. First check stix_objects — reading it is required to be able to
    #    return the original bundle.  If missing, we fail early.
    # 2. Then check event_type — its absence in the data dict signals a
    #    playbook trigger vs. a manual enrichment request.
    event_type_locs = find_pattern_locations(sources, [_EVENT_TYPE_PATTERN])
    stix_objects_locs = find_pattern_locations(sources, [_STIX_OBJECTS_DATA])

    results: list[CheckFinding] = []

    # If stix_objects is never read, the connector cannot return the original
    # bundle — flag this first (more fundamental issue than missing event_type).
    if not stix_objects_locs:
        results.append(
            CheckFinding(
                message=(
                    "data['stix_objects'] is never read — original bundle "
                    "cannot be returned for out-of-scope playbook triggers"
                ),
                severity=Severity.WARNING,
                suggestion=(
                    "Read data['stix_objects'] and send the original bundle "
                    "back unchanged when the entity is not in scope. "
                    "Check data.get('event_type') to detect playbook triggers."
                ),
            ),
        )
        return results

    if not event_type_locs:
        results.append(
            CheckFinding(
                message=(
                    "No event_type check found — out-of-scope playbook "
                    "triggers may not return the original bundle"
                ),
                severity=Severity.WARNING,
                suggestion=(
                    "Use data.get('event_type') to detect playbook triggers. "
                    "When not in scope and no event_type, send back the "
                    "original stix_objects bundle unchanged."
                ),
            ),
        )
    else:
        first = event_type_locs[0]
        results.append(
            CheckFinding(
                message="Connector handles event_type for playbook compatibility",
                severity=Severity.INFO,
                file_path=first[0],
                line=first[1],
            ),
        )

    return results
