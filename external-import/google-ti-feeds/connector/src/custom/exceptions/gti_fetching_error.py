"""Exception raised for errors in the Fetching."""

from typing import Any

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIFetchingError(GTIBaseError):
    """Exception raised during GTI data fetching operations."""

    def __init__(
        self,
        message: str,
        entity_type: str | None = None,
        entity_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Initialize a GTIFetchingError instance."""
        super().__init__(message, details)
        self.entity_type = entity_type
        self.entity_id = entity_id
