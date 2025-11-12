"""Exception for errors when fetching relationships from Google Threat Intelligence API."""

from typing import Any

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIRelationshipFetchError(GTIApiError):
    """Exception raised when there's an error fetching relationships from GTI API."""

    def __init__(
        self,
        message: str,
        source_id: str | None = None,
        relationship_type: str | None = None,
        endpoint: str | None = None,
        status_code: str | None = None,
        details: dict[str, Any] | None = None,
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
            error_msg = "Error fetching relationships for source: {message}"
        elif source_id:
            error_msg = "Error fetching relationships for source: {message}"
        elif relationship_type:
            error_msg = "Error fetching relationships: {message}"
        else:
            error_msg = "Error fetching relationships: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
        self.source_id = source_id
        self.relationship_type = relationship_type

        # Add structured data for logging
        if hasattr(self, "structured_data"):
            if source_id:
                self.structured_data["source_id"] = source_id
            if relationship_type:
                self.structured_data["relationship_type"] = relationship_type
        else:
            self.structured_data = {}
            if source_id:
                self.structured_data["source_id"] = source_id
            if relationship_type:
                self.structured_data["relationship_type"] = relationship_type
