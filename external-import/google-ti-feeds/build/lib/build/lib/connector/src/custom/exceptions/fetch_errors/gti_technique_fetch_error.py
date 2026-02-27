"""Exception for errors when fetching attack techniques from Google Threat Intelligence API."""

from typing import Any

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTITechniqueFetchError(GTIApiError):
    """Exception raised when there's an error fetching attack techniques from GTI API."""

    def __init__(
        self,
        message: str,
        technique_id: str | None = None,
        endpoint: str | None = None,
        status_code: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            technique_id: ID of the attack technique that failed to fetch, if applicable
            endpoint: API endpoint where the error occurred
            status_code: HTTP status code, if available
            details: Additional details about the error

        """
        if technique_id:
            error_msg = "Error fetching attack technique: {message}"
        else:
            error_msg = "Error fetching attack techniques: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
        self.technique_id = technique_id

        # Add structured data for logging
        if hasattr(self, "structured_data"):
            if technique_id:
                self.structured_data["technique_id"] = technique_id
        else:
            self.structured_data = {}
            if technique_id:
                self.structured_data["technique_id"] = technique_id
