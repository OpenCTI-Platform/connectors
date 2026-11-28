"""Connector persisted state.

Stored by OpenCTI between runs, as JSON:

    {
        "last_run": "2026-11-10T15:00:00+00:00",
        "collections": {
            "trustgroup": {
                "added_after": "2026-11-10T14:53:00.403510Z",
                "next_token": null
            }
        },
        "hunting": {...}
    }

`collections` holds one cursor per TAXII API root. `added_after` is the
`X-TAXII-Date-Added-Last` value of the last page sent (or the backfill start
before the first page), so a fresh query resumes right after it.
`next_token` is only set when a run stopped while the server still had more
pages (the per-run object limit was reached); the next run continues with it.

`hunting` is owned by the live hunting source and stored as it returns it.
"""

from typing import Any

from connectors_sdk import ExternalImportConnectorState
from pydantic import BaseModel


class CollectionCursor(BaseModel):
    """Where to resume one TAXII collection."""

    added_after: str | None = None
    next_token: str | None = None


class ConnectorState(ExternalImportConnectorState):
    """Checkpoints used to resume imports across connector runs."""

    collections: dict[str, CollectionCursor] | None = None
    hunting: dict[str, Any] | None = None

    def get_cursor(self, collection: str) -> CollectionCursor:
        """Return a copy of a collection's cursor (empty if never run)."""
        cursor = (self.collections or {}).get(collection)
        return cursor.model_copy() if cursor else CollectionCursor()

    def set_cursor(self, collection: str, cursor: CollectionCursor) -> None:
        """Replace a collection's cursor (stores a copy)."""
        self.collections = {
            **(self.collections or {}),
            collection: cursor.model_copy(),
        }
