"""Exception for errors when creating TLP marking definitions."""

from connector.src.custom.exceptions.gti_converting_error import GTIConvertingError


class GTIMarkingCreationError(GTIConvertingError):
    """Exception raised when there's an error creating the TLP marking definition."""

    def __init__(self, message: str, tlp_level: str | None = None):
        """Initialize the exception.

        Args:
            message: Error message
            tlp_level: The TLP level that failed to be created

        """
        if tlp_level:
            error_msg = "Failed to create TLP marking: {message}"
        else:
            error_msg = f"Failed to create TLP marking: {message}"

        super().__init__(error_msg)
        self.tlp_level = tlp_level

        # Add structured data for logging
        self.structured_data = {
            "original_message": message,
        }
        if tlp_level:
            self.structured_data["tlp_level"] = tlp_level
