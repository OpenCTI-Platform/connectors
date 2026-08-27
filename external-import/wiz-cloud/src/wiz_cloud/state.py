"""Connector state.

The SDK's ExternalImportConnectorState carries only last_run, and every data
processor shares the same instance. Per-collection cursors are therefore
declared here rather than relying on extra="allow".

Processors read and write these fields but never call state.load() or
state.save(); the connector owns persistence.
"""

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState


class WizConnectorState(ExternalImportConnectorState):
    # Highest createdAt seen across all successfully processed issues.
    # createdAt is the cursor, not statusChangedAt: each run imports issues
    # created since the last run, ordered CREATED_AT DESC. Safe because
    # createdAt is append-only: an issue created while a run is walking pages
    # sorts above the pages already read and is picked up by the next run.
    issues_last_created_at: datetime | None = None

    # Reserved for vulnerability collection, declared now so the field exists
    # in stored state.
    vulnerabilities_last_created_at: datetime | None = None
