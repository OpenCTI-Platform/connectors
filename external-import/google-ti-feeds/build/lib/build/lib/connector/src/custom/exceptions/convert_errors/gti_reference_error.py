"""Exception for errors related to adding references between STIX objects."""

from connector.src.custom.exceptions.gti_converting_error import GTIConvertingError


class GTIReferenceError(GTIConvertingError):
    """Exception raised when there's an error adding a reference between STIX objects."""

    def __init__(
        self,
        message: str,
        source_id: str | None = None,
        target_id: str | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            source_id: ID of the source object where the reference should be added
            target_id: ID of the target object being referenced

        """
        if source_id and target_id:
            error_msg = "Failed to add reference: {message}"
        elif source_id:
            error_msg = "Failed to add reference: {message}"
        elif target_id:
            error_msg = "Failed to add reference: {message}"
        else:
            error_msg = f"Failed to add reference: {message}"

        super().__init__(error_msg)
        self.source_id = source_id
        self.target_id = target_id

        # Add structured data for logging
        self.structured_data = {
            "original_message": message,
        }
        if source_id:
            self.structured_data["source_id"] = source_id
        if target_id:
            self.structured_data["target_id"] = target_id
