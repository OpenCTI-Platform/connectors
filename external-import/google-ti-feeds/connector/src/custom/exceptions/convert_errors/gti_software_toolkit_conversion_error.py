"""Exception for errors when converting GTI software toolkits to STIX tool objects."""

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTISoftwareToolkitConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI software toolkit to STIX format."""

    def __init__(
        self,
        message: str,
        toolkit_id: str | None = None,
        toolkit_name: str | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            toolkit_id: ID of the software toolkit that failed to convert
            toolkit_name: Name of the software toolkit, if available

        """
        super().__init__(message, toolkit_id, "SoftwareToolkit")
        self.toolkit_name = toolkit_name

        if hasattr(self, "structured_data"):
            if toolkit_name:
                self.structured_data["toolkit_name"] = toolkit_name
        else:
            self.structured_data = {}
            if toolkit_name:
                self.structured_data["toolkit_name"] = toolkit_name
