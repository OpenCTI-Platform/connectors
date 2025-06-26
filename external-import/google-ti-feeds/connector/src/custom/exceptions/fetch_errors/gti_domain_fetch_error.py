"""Exception for errors when fetching domains from Google Threat Intelligence API."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIDomainFetchError(GTIApiError):
    """Exception raised when there's an error fetching domains from GTI API."""

    def __init__(
        self,
        message: str,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            endpoint: API endpoint where the error occurred
            status_code: HTTP status code, if available
            details: Additional details about the error

        """
        error_msg = f"Error fetching domains: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
