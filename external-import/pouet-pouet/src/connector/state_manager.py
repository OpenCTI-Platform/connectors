"""
This module contains the implementation of the `StateManager` class for the `PouetPouetConnector`.
"""

from datetime import datetime

from connectors_sdk import BaseConnectorStateManager
from pydantic import Field


class ConnectorStateManager(BaseConnectorStateManager):
    """
    State manager implementation for the `PouetPouetConnector`.
    This class inherits from `BaseConnectorStateManager`, defines the state attributes that are relevant
    for the connector and validates the state data before saving it on OpenCTI.
    """

    last_pouet_id: str | None = Field(
        default=None,
        description="The ID of the last ingested Pouet.",
    )
    last_ingested_at: datetime | None = Field(
        default=None,
        description="The datetime of the last ingested Pouet.",
    )
