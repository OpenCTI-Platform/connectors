"""Exception for errors when processing work in the connector."""

from typing import Any


class WorkProcessingError(Exception):
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
        self.message = message
        self.details = details or {}

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

    def get_logging_data(self) -> dict[str, Any]:
        """Get structured data for logging this exception.

        Returns:
            dict containing structured data for logging, including error type,
            message, and any additional details stored in the exception.

        """
        logging_data = {
            "error_type": self.__class__.__name__,
            "error_message": self.message,
        }

        # Add structured data if available
        if hasattr(self, "structured_data"):
            logging_data.update(self.structured_data)

        # Add details
        if self.details:
            logging_data.update(self.details)

        return logging_data

    def log_error(
        self,
        logger: Any,
        log_message: str,
        additional_context: dict[str, Any] | None = None,
    ) -> None:
        """Log this exception with structured data.

        Args:
            logger: Logger instance to use
            log_message: Human-readable log message
            additional_context: Additional context to include in the log

        """
        logging_data = self.get_logging_data()
        if additional_context:
            logging_data.update(additional_context)

        logger.error(log_message, logging_data)
