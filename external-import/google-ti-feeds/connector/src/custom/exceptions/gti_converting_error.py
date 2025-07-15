"""Exception raised for errors in the Converting."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIConvertingError(GTIBaseError):
    """Exception raised during GTI data conversion to STIX."""

    def __init__(
        self,
        message: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        stix_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize a GTIConvertingError instance."""
        super().__init__(message, details)
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.stix_type = stix_type
