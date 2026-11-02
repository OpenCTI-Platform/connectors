"""Connector state: where the ORKL sync left off.

ORKL rewrites ``updated_at`` on every library entry during its nightly rebuild,
so a timestamp cursor cannot tell new entries from untouched ones. The sync is
driven by ORKL's own library version counter instead (``/library/version``):
each nightly version lists the entries created that day.
"""

from __future__ import annotations

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState
from pydantic import Field


class OrklState(ExternalImportConnectorState):
    """State persisted in OpenCTI between two runs."""

    last_library_version: int | None = Field(
        default=None,
        description=(
            "ORKL library version reached by the last successful run. Entries "
            "created in later versions are imported on the next run. None means "
            "the whole library has never been imported."
        ),
    )
    last_full_sync: datetime | None = Field(
        default=None,
        description="When the whole library was last imported.",
    )

    def load(self, force: bool = False) -> None:
        """Reload from OpenCTI, resetting our fields first.

        ``BaseConnectorState.load()`` only overwrites the keys present in the
        stored state, so a state reset from the OpenCTI UI would otherwise keep
        the in-memory cursor and save it back on the next run.
        """
        if self._client and (force or self._can_be_loaded):
            # Only when the base class will actually load; otherwise it returns
            # early precisely to keep unsaved changes.
            self.last_library_version = None
            self.last_full_sync = None
        super().load(force=force)
