"""Exception for errors when fetching relationships from Google Threat Intelligence API."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIRelationshipFetchError(GTIApiError):
    """Exception raised when there's an error fetching relationships from GTI API."""

    def __init__(
        self,
        message: str,
        source_id: Optional[str] = None,
        relationship_type: Optional[str] = None,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            source_id: ID of the source entity for the relationships
            relationship_type: Type of relationship that failed to fetch
            endpoint: API endpoint where the error occurred
            status_code: HTTP status code, if available
            details: Additional details about the error

        """
        if source_id and relationship_type:
            error_msg = f"Error fetching {relationship_type} relationships for {source_id}: {message}"
        elif source_id:
            error_msg = f"Error fetching relationships for {source_id}: {message}"
        elif relationship_type:
            error_msg = f"Error fetching {relationship_type} relationships: {message}"
        else:
            error_msg = f"Error fetching relationships: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
        self.source_id = source_id
        self.relationship_type = relationship_type
