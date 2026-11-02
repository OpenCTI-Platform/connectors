"""Connector persisted state (stored by OpenCTI between runs)."""

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    """Checkpoint of the reports import.

    Attributes:
        last_report_updated: ``last_updated`` timestamp of the most recent
            report that was fully sent to OpenCTI.
        last_report_ids: IDs of the reports sent with exactly that
            timestamp. Rösti timestamps have one-second resolution, so the
            next run asks for reports updated one second earlier and skips
            these IDs instead of risking to miss a report with the same
            timestamp.
    """

    last_report_updated: datetime | None = None
    last_report_ids: list[str] | None = None
