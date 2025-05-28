"""Exception for errors when fetching threat actors from Google Threat Intelligence API."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIActorFetchError(GTIApiError):
    """Exception raised when there's an error fetching threat actors from GTI API."""

    def __init__(
        self,
        message: str,
        actor_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            actor_id: ID of the threat actor that failed to fetch, if applicable
            endpoint: API endpoint where the error occurred
            status_code: HTTP status code, if available
            details: Additional details about the error

        """
        if actor_id:
            error_msg = f"Error fetching threat actor {actor_id}: {message}"
        else:
            error_msg = f"Error fetching threat actors: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
        self.actor_id = actor_id
