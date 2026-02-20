"""Exception for errors related to API client setup and configuration."""

from typing import Any

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIApiClientError(GTIBaseError):
    """Exception raised when there's an error setting up or using the API client."""

    def __init__(
        self,
        message: str,
        client_component: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            client_component: Component of the API client that failed (e.g., "retry_strategy", "http_client")
            details: Additional details about the error

        """
        if client_component:
            error_msg = "API client error in component: {message}"
        else:
            error_msg = message

        super().__init__(error_msg)
        self.client_component = client_component
        self.details = details or {}

        # Add structured data for logging
        if client_component:
            self.details.update(
                {
                    "client_component": client_component,
                    "original_message": message,
                }
            )
