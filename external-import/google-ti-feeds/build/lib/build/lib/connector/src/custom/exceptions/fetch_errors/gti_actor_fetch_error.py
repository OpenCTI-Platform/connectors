"""Exception for errors when fetching threat actors from Google Threat Intelligence API."""

from typing import Any

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIActorFetchError(GTIApiError):
    """Exception raised when there's an error fetching threat actors from GTI API."""

    def __init__(
        self,
        message: str,
        actor_id: str | None = None,
        endpoint: str | None = None,
        status_code: str | None = None,
        details: dict[str, Any] | None = None,
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
            error_msg = "Error fetching threat actor: {message}"
        else:
            error_msg = "Error fetching threat actors: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
        self.actor_id = actor_id

        # Add structured data for logging
        if hasattr(self, "structured_data"):
            if actor_id:
                self.structured_data["actor_id"] = actor_id
        else:
            self.structured_data = {}
            if actor_id:
                self.structured_data["actor_id"] = actor_id
