"""Persisted checkpoints between connector runs.

``last_run`` is inherited and owned by the SDK. We add one extra field:
a per-service high-water mark on ``created_at``. Services fail independently,
so one 403 must not rewind or skip the others.
"""

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    """Resume markers for Cyble Vision imports."""

    # service name -> ISO-8601 created_at of the last successfully converted alert
    last_alert_created_at: dict[str, str] | None = None
    last_advisory_publish_date: str | None = None
    last_newsfeed_post_date: str | None = None
    last_newsflash_published_date: str | None = None
