"""Exception for errors when converting GTI files to STIX file observable and indicator objects."""

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTIFileConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI file to STIX format."""

    def __init__(self, message: str):
        """Initialize the exception.

        Args:
            message: Error message

        """
        super().__init__(message, "Files")
