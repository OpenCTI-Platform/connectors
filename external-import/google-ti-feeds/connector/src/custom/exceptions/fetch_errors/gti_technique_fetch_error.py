"""Exception for errors when fetching attack techniques from Google Threat Intelligence API."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTITechniqueFetchError(GTIApiError):
    """Exception raised when there's an error fetching attack techniques from GTI API."""

    def __init__(
        self,
        message: str,
        technique_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
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
            error_msg = f"Error fetching attack technique {technique_id}: {message}"
        else:
            error_msg = f"Error fetching attack techniques: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
        self.technique_id = technique_id
