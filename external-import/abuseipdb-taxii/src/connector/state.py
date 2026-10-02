"""Connector persisted state: TAXII high-water mark and resume cursor."""

from connectors_sdk import ExternalImportConnectorState


class ConnectorState(ExternalImportConnectorState):
    """Checkpoints used to resume the TAXII pull across connector runs.

    ``added_after`` is kept as a string rather than a ``datetime``: the server
    only accepts ``Z``-suffixed timestamps for ``added_after``, and the stored
    value is sent back to it as is.

    Attributes:
        added_after: The high-water mark, a ``Z``-suffixed UTC timestamp taken
            from the server's ``X-TAXII-Date-Added-Last`` header of the last
            completed pull.
        next_cursor: The cursor of the first page not yet handed to OpenCTI, or
            ``None`` when the last pull reached the end of the feed.
        collection_id: The ID of the feed ``added_after`` and ``next_cursor``
            belong to, or ``None`` when it is not known yet.
    """

    added_after: str | None = None
    next_cursor: str | None = None
    collection_id: str | None = None
