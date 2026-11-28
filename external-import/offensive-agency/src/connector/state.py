"""Connector persisted state: where the last run left off in the feed."""

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState
from pydantic import Field


class ConnectorState(ExternalImportConnectorState):
    """Checkpoint used to only send the feed entries that changed."""

    last_modified: datetime | None = Field(
        default=None,
        description="Most recent `modified` date of an indicator sent to OpenCTI. "
        "The next run sends the indicators modified on or after it. "
        "None means the whole feed is sent.",
    )

    def load(self, force: bool = False) -> None:
        """Reload from OpenCTI, resetting our checkpoint first.

        `BaseConnectorState.load()` only overwrites the keys present in the
        stored state, so a state reset from the OpenCTI UI would otherwise keep
        the in-memory checkpoint and save it back on the next run.

        Args:
            force: Load even if the instance has unsaved changes.
        """
        if self._client and (force or self._can_be_loaded):
            # Only when the base class will actually load; otherwise it returns
            # early precisely to keep unsaved changes.
            self.last_modified = None
        super().load(force=force)
