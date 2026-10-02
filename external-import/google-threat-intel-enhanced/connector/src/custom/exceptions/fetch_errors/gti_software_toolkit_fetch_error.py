"""Exception for errors when fetching software toolkits from Google Threat Intelligence API."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTISoftwareToolkitFetchError(GTIApiError):
    """Exception raised when there's an error fetching software toolkits from GTI API."""

    def __init__(
        self,
        message: str,
        software_toolkit_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Human-readable error message
            software_toolkit_id: ID of the software toolkit being fetched
            endpoint: API endpoint that was called
            status_code: HTTP status code if applicable
            details: Additional error details

        """
        super().__init__(
            message=message, endpoint=endpoint, status_code=status_code, details=details
        )
        self.software_toolkit_id = software_toolkit_id

    def __str__(self) -> str:
        """Return string representation of error."""
        base = super().__str__()
        if self.software_toolkit_id:
            return f"{base} (software_toolkit_id={self.software_toolkit_id})"
        return base
