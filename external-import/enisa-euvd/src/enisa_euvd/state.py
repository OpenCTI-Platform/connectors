"""Connector persisted state.

`last_euvd_updated` is the single watermark this connector relies on: it is
the `dateUpdated` of the most recently updated vulnerability successfully
processed on the last fully-successful run (see
`processors/vulnerability_processor.py` for how it is produced and consumed).
"""

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    """Checkpoints used to resume imports across connector runs."""

    last_euvd_updated: datetime | None = None
