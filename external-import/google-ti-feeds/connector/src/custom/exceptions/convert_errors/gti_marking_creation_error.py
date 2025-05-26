"""Exception for errors when creating TLP marking definitions."""

from typing import Optional

from connector.src.custom.exceptions.gti_converting_error import GTIConvertingError


class GTIMarkingCreationError(GTIConvertingError):
    """Exception raised when there's an error creating the TLP marking definition."""

    def __init__(self, message: str, tlp_level: Optional[str] = None):
        """Initialize the exception.

        Args:
            message: Error message
            tlp_level: The TLP level that failed to be created

        """
        error_msg = f"Failed to create TLP marking: {message}"
        if tlp_level:
            error_msg = f"Failed to create TLP '{tlp_level}' marking: {message}"

        super().__init__(error_msg)
        self.tlp_level = tlp_level
