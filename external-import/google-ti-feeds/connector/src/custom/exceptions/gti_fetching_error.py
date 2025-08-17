"""Exception raised for errors in the Fetching."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIFetchingError(GTIBaseError):
    """Exception raised during GTI data fetching operations."""

    def __init__(
        self,
        message: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize a GTIFetchingError instance."""
        super().__init__(message, details)
        self.entity_type = entity_type
        self.entity_id = entity_id
