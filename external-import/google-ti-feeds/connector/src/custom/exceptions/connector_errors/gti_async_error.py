"""Exception for asynchronous processing errors in the connector."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIAsyncError(GTIBaseError):
    """Exception raised when there's an error in asynchronous processing."""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            operation: Name of the async operation that failed
            details: Additional details about the error

        """
        error_msg = message
        if operation:
            error_msg = f"Async error during '{operation}' operation: {message}"

        super().__init__(error_msg)
        self.operation = operation
        self.details = details or {}
