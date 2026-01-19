"""Base class for entity conversion errors."""

from connector.src.custom.exceptions.gti_converting_error import GTIConvertingError


class GTIEntityConversionError(GTIConvertingError):
    """Exception raised for errors in converting entities to STIX format.

    This serves as a base class for more specific entity conversion errors.
    """

    def __init__(
        self,
        message: str,
        entity_id: str | None = None,
        entity_type: str | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            entity_id: ID of the entity that failed to convert
            entity_type: Type of the entity that failed to convert

        """
        if entity_id and entity_type:
            error_msg = "Error converting entity: {message}"
        elif entity_id:
            error_msg = "Error converting entity: {message}"
        elif entity_type:
            error_msg = "Error converting entity: {message}"
        else:
            error_msg = message

        super().__init__(error_msg)
        self.entity_id = entity_id
        self.entity_type = entity_type

        # Add structured data for logging
        self.structured_data = {
            "original_message": message,
        }
        if entity_id:
            self.structured_data["entity_id"] = entity_id
        if entity_type:
            self.structured_data["entity_type"] = entity_type
