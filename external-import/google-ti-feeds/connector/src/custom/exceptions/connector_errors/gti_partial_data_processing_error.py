"""Exception for errors when processing partial data after interruption."""

from typing import Any

from connector.src.custom.exceptions.connector_errors.gti_work_processing_error import (
    GTIWorkProcessingError,
)


class GTIPartialDataProcessingError(GTIWorkProcessingError):
    """Exception raised when there's an error processing partial data after interruption."""

    def __init__(
        self,
        message: str,
        work_id: str | None = None,
        interruption_type: str | None = None,
        reports_count: int | None = None,
        details: dict[str, Any] | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            work_id: ID of the work that was interrupted
            interruption_type: Type of interruption (e.g., "cancellation", "exception")
            reports_count: Number of reports that were fetched before interruption
            details: Additional details about the error

        """
        if interruption_type:
            error_msg = "Error processing partial data after interruption: {message}"
        else:
            error_msg = f"Error processing partial data: {message}"

        super().__init__(error_msg, work_id, reports_count, details)
        self.interruption_type = interruption_type
        self.reports_count = reports_count

        # Add structured data for logging
        structured_details = details or {}
        if interruption_type:
            structured_details.update(
                {
                    "interruption_type": interruption_type,
                    "original_message": message,
                }
            )
        if reports_count is not None:
            structured_details.update(
                {
                    "reports_count": reports_count,
                }
            )
        self.details = structured_details
