"""Exception for errors when converting GTI software toolkits to STIX Tool objects."""

from typing import Optional

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTISoftwareToolkitConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI software toolkit to STIX format."""

    def __init__(
        self,
        message: str,
        software_toolkit_id: Optional[str] = None,
        software_toolkit_name: Optional[str] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            software_toolkit_id: ID of the software toolkit that failed to convert
            software_toolkit_name: Name of the software toolkit, if available

        """
        super().__init__(message, software_toolkit_id, "Software Toolkit")
        self.software_toolkit_name = software_toolkit_name

        if software_toolkit_name and not self.args[0].endswith(f"(name: {software_toolkit_name})"):
            self.args = (f"{self.args[0]} (name: {software_toolkit_name})",)
