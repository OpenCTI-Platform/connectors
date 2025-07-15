"""Exception for errors related to adding references between STIX objects."""

from typing import Optional

from connector.src.custom.exceptions.gti_converting_error import GTIConvertingError


class GTIReferenceError(GTIConvertingError):
    """Exception raised when there's an error adding a reference between STIX objects."""

    def __init__(
        self,
        message: str,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            source_id: ID of the source object where the reference should be added
            target_id: ID of the target object being referenced

        """
        error_msg = f"Failed to add reference: {message}"
        if source_id and target_id:
            error_msg = (
                f"Failed to add reference from {source_id} to {target_id}: {message}"
            )
        elif source_id:
            error_msg = f"Failed to add reference from {source_id}: {message}"
        elif target_id:
            error_msg = f"Failed to add reference to {target_id}: {message}"

        super().__init__(error_msg)
        self.source_id = source_id
        self.target_id = target_id
