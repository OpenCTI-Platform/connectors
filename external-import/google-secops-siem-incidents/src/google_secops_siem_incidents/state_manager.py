"""Typed state manager for the Google SecOps SIEM Incidents connector."""

from datetime import datetime
from typing import Any

from connectors_sdk.state_manager.state_manager import ConnectorStateManager
from pydantic import Field


class GoogleSecOpsSIEMState(ConnectorStateManager):
    """Typed state manager for the Google SecOps SIEM Incidents connector with alert timestamp and pagination checkpoint fields.

    Attributes:
        last_alert_timestamp: Timestamp of the most recently processed alert.
        pagination_checkpoint: Saved pagination window for mid-run resume.
    """

    last_alert_timestamp: datetime | None = Field(default=None)
    pagination_checkpoint: dict[str, Any] | None = Field(default=None)

    def save(self) -> None:
        """Persist declared fields to OpenCTI, omitting None values, then call force_ping."""
        declared_fields = set(type(self).model_fields)
        state_dump = self.model_dump(
            mode="json",
            include=declared_fields,
            exclude_none=True,
        )
        if self.model_extra:
            state_dump.update(self.model_extra)

        self._helper.set_state(state_dump)
        self._helper.force_ping()
        self._can_be_loaded = True
