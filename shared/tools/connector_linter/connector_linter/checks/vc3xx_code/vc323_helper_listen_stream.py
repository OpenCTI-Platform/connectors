"""VC323 — Stream connectors must use helper.listen_stream().

Stream connectors receive live events from the platform via
``self.helper.listen_stream(message_callback=self.process_message)``.

Scope: STREAM only.
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
# Regex: detect .listen_stream( calls in source code
#
# Matches the method call pattern:
#   .listen_stream(          — with optional whitespace before the paren
#
# This is the stream-specific counterpart to VC318's helper.listen():
#   - VC318 checks helper.listen()        → enrichment connectors (event-driven)
#   - VC323 checks helper.listen_stream() → stream connectors (live event stream)
#
# Stream connectors receive the full event stream from the OpenCTI platform
# (create, update, delete events) via listen_stream, whereas enrichment
# connectors receive individual entity enrichment requests via listen.
# ---------------------------------------------------------------------------
_LISTEN_STREAM = re.compile(r"""\.listen_stream\s*\(""")

# Only STREAM type connectors use listen_stream.
# Enrichment connectors use helper.listen() (checked by VC318).


@CheckRegistry.register(
    code="VC323",
    name="helper-listen-stream",
    description="Stream connectors must use helper.listen_stream()",
    severity=Severity.ERROR,
    applicable_types={ConnectorType.STREAM},
)
def check_helper_listen_stream(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that the connector uses helper.listen_stream()."""
    sources = ctx.python_sources
    if not sources:
        return [no_python_sources_finding()]

    locations = find_pattern_locations(sources, [_LISTEN_STREAM])

    if not locations:
        return [
            CheckFinding(
                message="helper.listen_stream() not found — stream connector is not receiving events",
                severity=Severity.ERROR,
                suggestion=(
                    "Add self.helper.listen_stream(message_callback=self.process_message) "
                    "in the run method to receive live events from the platform."
                ),
            ),
        ]

    first = locations[0]
    return [
        CheckFinding(
            message="Connector uses helper.listen_stream() for event processing",
            severity=Severity.INFO,
            file_path=first[0],
            line=first[1],
        ),
    ]
