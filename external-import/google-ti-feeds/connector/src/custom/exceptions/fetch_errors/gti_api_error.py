"""Exception for API-related errors when fetching data from Google Threat Intelligence."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.gti_fetching_error import GTIFetchingError


class GTIApiError(GTIFetchingError):
    """Exception raised when there's an error with the Google Threat Intelligence API."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        endpoint: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            status_code: HTTP status code, if available
            endpoint: API endpoint where the error occurred
            details: Additional details about the error

        """
        error_msg = message
        if endpoint and status_code:
            error_msg = f"API error at {endpoint} (status {status_code}): {message}"
        elif endpoint:
            error_msg = f"API error at {endpoint}: {message}"
        elif status_code:
            error_msg = f"API error (status {status_code}): {message}"

        super().__init__(error_msg)
        self.status_code = status_code
        self.endpoint = endpoint
        self.details = details or {}
