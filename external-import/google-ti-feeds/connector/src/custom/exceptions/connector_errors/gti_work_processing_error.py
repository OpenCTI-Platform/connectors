"""Exception for errors when processing work in the connector."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIWorkProcessingError(GTIBaseError):
    """Exception raised when there's an error processing work in the connector."""

    def __init__(
        self,
        message: str,
        work_id: Optional[str] = None,
        batch_number: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            work_id: ID of the work that failed to process
            batch_number: Batch number that failed to process
            details: Additional details about the error

        """
        error_msg = message
        if work_id:
            error_msg = f"Error processing work {work_id}: {message}"

        super().__init__(error_msg, details)
        self.work_id = work_id
        self.batch_number = batch_number
