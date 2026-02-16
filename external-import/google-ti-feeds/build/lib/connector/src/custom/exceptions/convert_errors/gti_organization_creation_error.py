"""Exception for errors when creating organization Identity objects."""

from typing import Any

from connector.src.custom.exceptions.gti_converting_error import GTIConvertingError


class GTIOrganizationCreationError(GTIConvertingError):
    """Exception raised when there's an error creating the organization Identity object."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        """Initialize the exception.

        Args:
            message: Error message
            details: Additional details about the error

        """
        error_msg = "Failed to create organization Identity: {message}"
        super().__init__(error_msg)
        self.details = details or {}

        # Add structured data for logging
        self.structured_data = {
            "original_message": message,
        }
        if details:
            self.structured_data.update(details)
