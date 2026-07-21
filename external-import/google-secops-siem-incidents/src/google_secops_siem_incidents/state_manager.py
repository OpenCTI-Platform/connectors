"""Typed state manager for the Google SecOps SIEM Incidents connector."""

from datetime import datetime
from typing import Any

from connectors_sdk import ExternalImportConnectorState
from pydantic import Field


class GoogleSecOpsSIEMState(ExternalImportConnectorState):
    """Typed state manager for the Google SecOps SIEM Incidents connector with alert timestamp and pagination checkpoint fields.

    Attributes:
        last_alert_timestamp: Timestamp of the most recently processed alert.
        pagination_checkpoint: Saved pagination window for mid-run resume.
    """

    last_alert_timestamp: datetime | None = Field(default=None)
    pagination_checkpoint: dict[str, Any] | None = Field(default=None)
