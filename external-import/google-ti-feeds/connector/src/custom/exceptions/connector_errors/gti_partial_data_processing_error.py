"""Exception for errors when processing partial data after interruption."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.connector_errors.gti_work_processing_error import (
    GTIWorkProcessingError,
)


class GTIPartialDataProcessingError(GTIWorkProcessingError):
    """Exception raised when there's an error processing partial data after interruption."""

    def __init__(
        self,
        message: str,
        work_id: Optional[str] = None,
        interruption_type: Optional[str] = None,
        reports_count: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            work_id: ID of the work that was interrupted
            interruption_type: Type of interruption (e.g., "cancellation", "exception")
            reports_count: Number of reports that were fetched before interruption
            details: Additional details about the error

        """
        error_msg = f"Error processing partial data: {message}"
        if interruption_type:
            error_msg = (
                f"Error processing partial data after {interruption_type}: {message}"
            )

        if reports_count is not None:
            error_msg += f" ({reports_count} reports were fetched)"

        super().__init__(error_msg, work_id, reports_count, details)
        self.interruption_type = interruption_type
        self.reports_count = reports_count
