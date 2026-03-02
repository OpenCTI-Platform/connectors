"""Exception for errors when processing work in the connector."""

from typing import Any

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIWorkProcessingError(GTIBaseError):
    """Exception raised when there's an error processing work in the connector."""

    def __init__(
        self,
        message: str,
        work_id: str | None = None,
        batch_number: int | None = None,
        details: dict[str, Any] | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            work_id: ID of the work that failed to process
            batch_number: Batch number that failed to process
            details: Additional details about the error

        """
        if work_id:
            error_msg = "Error processing work: {message}"
        else:
            error_msg = message

        super().__init__(error_msg, details)
        self.work_id = work_id
        self.batch_number = batch_number

        # Add structured data for logging
        structured_details = details or {}
        if work_id:
            structured_details.update(
                {
                    "work_id": work_id,
                    "original_message": message,
                }
            )
        if batch_number is not None:
            structured_details.update(
                {
                    "batch_number": batch_number,
                }
            )
        self.details = structured_details
