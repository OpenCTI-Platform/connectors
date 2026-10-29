from __future__ import annotations

from datetime import datetime

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    """Checkpoints for the MalEval import window.

    `watermark` is the committed lower bound of the next window: every object
    first seen before it has been imported. While one window takes several
    runs to drain (each run stops at `STAIRWELL_IMPORT_MAX_INDICATORS`), the `pending_*`
    fields hold that window and the page token to resume from; the watermark
    advances to `pending_window_end` only once the window's last page has been
    sent. The SDK saves state only after a successful run, so a failed run
    never moves either.
    """

    watermark: datetime | None = None
    pending_cutoff: datetime | None = None
    pending_window_end: datetime | None = None
    pending_page_token: str | None = None

    def migrate_legacy(self) -> None:
        """Adopt checkpoints saved before this connector used the SDK.

        That state held the watermark in `last_run` and the cursor in a nested
        `pending` dict ({cutoff, window_end, page_token}). Current state always
        has a `watermark` key once saved (even when None), so its absence after
        `load()` marks the old format; dropping the old cursor would restart
        from the first-run window and skip the rest of a backlog.
        """
        if "watermark" in self.model_fields_set:
            return
        pending = (self.model_extra or {}).pop("pending", None)
        if isinstance(pending, dict) and pending.get("cutoff"):
            self.pending_cutoff = pending["cutoff"]
            self.pending_window_end = pending.get("window_end")
            self.pending_page_token = pending.get("page_token")
        if self.last_run is not None:
            self.watermark = self.last_run
