"""Exception for errors when fetching files from Google Threat Intelligence API."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIFileFetchError(GTIApiError):
    """Exception raised when there's an error fetching files from GTI API."""

    def __init__(
        self,
        message: str,
        endpoint: Optional[str] = None,
        status_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            endpoint: API endpoint where the error occurred
            status_code: HTTP status code, if available
            details: Additional details about the error

        """
        error_msg = "Error fetching files: {message}"
        super().__init__(error_msg, status_code, endpoint, details)

        # Add structured data for logging
        if hasattr(self, "structured_data"):
            pass  # structured_data will be inherited from parent GTIApiError
        else:
            self.structured_data = {
                "original_message": message,
            }
