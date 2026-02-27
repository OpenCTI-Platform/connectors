"""Base class for GTI exceptions."""

from typing import Any


class GTIBaseError(Exception):
    """Base exception for all GTI-related errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        """Initialize a GTIBaseError instance."""
        super().__init__(message)
        self.message = message
        self.details = details or {}

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
