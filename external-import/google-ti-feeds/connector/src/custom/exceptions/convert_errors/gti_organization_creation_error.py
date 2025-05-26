"""Exception for errors when creating organization Identity objects."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.gti_converting_error import GTIConvertingError


class GTIOrganizationCreationError(GTIConvertingError):
    """Exception raised when there's an error creating the organization Identity object."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Initialize the exception.

        Args:
            message: Error message
            details: Additional details about the error

        """
        super().__init__(f"Failed to create organization Identity: {message}")
        self.details = details or {}
