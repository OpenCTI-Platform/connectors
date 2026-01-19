"""Exception for API-related errors when fetching data from Google Threat Intelligence."""

from typing import Any

from connector.src.custom.exceptions.gti_fetching_error import GTIFetchingError


class GTIApiError(GTIFetchingError):
    """Exception raised when there's an error with the Google Threat Intelligence API."""

    def __init__(
        self,
        message: str,
        status_code: str | None = None,
        endpoint: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            status_code: HTTP status code, if available
            endpoint: API endpoint where the error occurred
            details: Additional details about the error

        """
        if endpoint and status_code:
            error_msg = "API error at endpoint: {message}"
        elif endpoint:
            error_msg = "API error at endpoint: {message}"
        elif status_code:
            error_msg = "API error: {message}"
        else:
            error_msg = message

        super().__init__(error_msg)
        self.status_code = status_code
        self.endpoint = endpoint
        self.details = details or {}

        # Add structured data for logging
        self.structured_data = {
            "original_message": message,
        }
        if endpoint:
            self.structured_data["endpoint"] = endpoint
        if status_code:
            self.structured_data["status_code"] = status_code
        if self.details:
            self.structured_data.update(self.details)
