"""Connector persisted state.

OpenCTI stores this state between runs. It lets the connector forward only
the objects Dark Web Informer changed since the previous run, instead of
re-importing the whole snapshot every time.
"""

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState
from pydantic import Field


class ConnectorState(ExternalImportConnectorState):
    """Checkpoints used to resume imports across connector runs.

    Inherits the generic ``last_run`` timestamp from ``connectors-sdk``.
    """

    cursors: dict[str, datetime] | None = Field(
        default=None,
        description=(
            "Per source, the most recent `modified`/`created` timestamp seen in "
            "the Dark Web Informer bundle during the last successful ingestion."
        ),
    )
