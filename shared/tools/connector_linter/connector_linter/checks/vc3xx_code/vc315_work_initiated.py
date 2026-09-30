"""VC315 — Connector must initiate work before processing.

External-import connectors must call
``self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)``
to properly track work lifecycle in the OpenCTI platform.

Scope: EXTERNAL_IMPORT only.
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
# Regex to detect .initiate_work( calls.
#
# Matches any method call ending in .initiate_work(, which is the pycti API
# for creating a new work tracking record. The leading dot ensures we match
# method calls (e.g. self.helper.api.work.initiate_work) and not unrelated
# functions that happen to contain "initiate_work" in their name.
# ---------------------------------------------------------------------------
_INITIATE_WORK = re.compile(r"\.initiate_work\s*\(")


# ---------------------------------------------------------------------------
# Applicable connector types.
#
# Only EXTERNAL_IMPORT connectors need to initiate work explicitly —
# other types have their work lifecycle managed by the platform or SDK.
# ---------------------------------------------------------------------------
@CheckRegistry.register(
    code="VC315",
    name="work-initiated",
    description="Connector must call initiate_work before processing",
    severity=Severity.ERROR,
    applicable_types={ConnectorType.EXTERNAL_IMPORT},
)
def check_work_initiated(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector calls initiate_work."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    # Simple presence check: scan all source files for .initiate_work( calls
    locations = find_pattern_locations(sources, [_INITIATE_WORK])

    if locations:
        first = locations[0]
        return [
            CheckFinding(
                message="Connector calls initiate_work to track work lifecycle",
                severity=Severity.INFO,
                file_path=first[0],
                line=first[1],
            ),
        ]

    return [
        CheckFinding(
            message="No initiate_work call found",
            severity=Severity.ERROR,
            suggestion=(
                "Add self.helper.api.work.initiate_work("
                "self.helper.connect_id, friendly_name) "
                "before processing to track work lifecycle."
            ),
        ),
    ]
