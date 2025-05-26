"""Exception for errors related to API client setup and configuration."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIApiClientError(GTIBaseError):
    """Exception raised when there's an error setting up or using the API client."""

    def __init__(
        self,
        message: str,
        client_component: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            client_component: Component of the API client that failed (e.g., "retry_strategy", "http_client")
            details: Additional details about the error

        """
        error_msg = message
        if client_component:
            error_msg = f"API client error in {client_component}: {message}"

        super().__init__(error_msg)
        self.client_component = client_component
        self.details = details or {}
