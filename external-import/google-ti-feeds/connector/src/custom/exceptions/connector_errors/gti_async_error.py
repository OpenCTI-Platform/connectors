"""Exception for asynchronous processing errors in the connector."""

from typing import Any

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIAsyncError(GTIBaseError):
    """Exception raised when there's an error in asynchronous processing."""

    def __init__(
        self,
        message: str,
        operation: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            operation: Name of the async operation that failed
            details: Additional details about the error

        """
        if operation:
            error_msg = "Async error during operation: {message}"
        else:
            error_msg = message

        super().__init__(error_msg)
        self.operation = operation
        self.details = details or {}

        # Add structured data for logging
        if operation:
            self.details.update(
                {
                    "operation": operation,
                    "original_message": message,
                }
            )
