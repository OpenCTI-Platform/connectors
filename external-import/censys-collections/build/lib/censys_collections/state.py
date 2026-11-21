"""Connector state for Censys Collections."""

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState
from pydantic import Field


class CensysCollectionsState(ExternalImportConnectorState):
    """External import state with a per-collection ingestion checkpoint.

    ``collection_checkpoints`` maps a Censys collection ID to the time its
    assets were last fetched and sent successfully. It is compared against the
    collection's asset-added events to skip collections that have not changed.
    """

    collection_checkpoints: dict[str, datetime] = Field(default_factory=dict)
