"""Base class for entity conversion errors."""

from typing import Optional

from connector.src.custom.exceptions.gti_converting_error import GTIConvertingError


class GTIEntityConversionError(GTIConvertingError):
    """Exception raised for errors in converting entities to STIX format.

    This serves as a base class for more specific entity conversion errors.
    """

    def __init__(
        self,
        message: str,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            entity_id: ID of the entity that failed to convert
            entity_type: Type of the entity that failed to convert

        """
        error_msg = message
        if entity_id and entity_type:
            error_msg = (
                f"Error converting {entity_type} entity (ID: {entity_id}): {message}"
            )
        elif entity_id:
            error_msg = f"Error converting entity (ID: {entity_id}): {message}"
        elif entity_type:
            error_msg = f"Error converting {entity_type} entity: {message}"

        super().__init__(error_msg)
        self.entity_id = entity_id
        self.entity_type = entity_type
