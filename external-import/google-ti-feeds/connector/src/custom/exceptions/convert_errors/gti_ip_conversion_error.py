"""Exception for errors when converting GTI IP addresses to STIX IP observable and indicator objects."""

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTIIPConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI IP address to STIX format."""

    def __init__(self, message: str):
        """Initialize the exception.

        Args:
            message: Error message

        """
        super().__init__(message, "IP Addresses")
