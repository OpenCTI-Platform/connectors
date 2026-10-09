"""Connector persisted state.

The state is a small piece of data OpenCTI stores for the connector between
runs. It is used to remember progress so each run only imports campaigns that
are new since the previous run.
"""

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    """Checkpoints used to resume imports across connector runs.

    Extends ``ExternalImportConnectorState`` (from ``connectors-sdk``), which
    already provides a generic ``last_run`` timestamp, with the date of the most
    recent Darkmoon campaign successfully imported. On the next run only
    campaigns dated strictly after this checkpoint are imported.
    """

    # Date of the most recent campaign processed, used to only import newer
    # campaigns on the next run.
    last_campaign_date: datetime | None = None
