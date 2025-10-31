"""Custom exceptions for the Hunt.IO connector."""

from typing import Optional


class HuntIOConnectorError(Exception):
    """Base exception for Hunt.IO connector errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class APIError(HuntIOConnectorError):
    """Raised when API operations fail."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        details: Optional[dict] = None,
    ):
        super().__init__(message, details)
        self.status_code = status_code


class DataProcessingError(HuntIOConnectorError):
    """Raised when data processing fails."""


class QueueHealthError(HuntIOConnectorError):
    """Raised when queue health checks fail or thresholds are exceeded."""

    def __init__(
        self,
        message: str,
        queue_size: Optional[int] = None,
        queue_size_mb: Optional[float] = None,
    ):
        super().__init__(message)
        self.queue_size = queue_size
        self.queue_size_mb = queue_size_mb


class ConfigurationError(HuntIOConnectorError):
    """Raised when configuration is invalid or missing."""


class STIXConversionError(HuntIOConnectorError):
    """Raised when STIX object conversion fails."""


class BatchProcessingError(HuntIOConnectorError):
    """Raised when batch processing fails."""

    def __init__(
        self,
        message: str,
        batch_number: Optional[int] = None,
        entity_count: Optional[int] = None,
    ):
        super().__init__(message)
        self.batch_number = batch_number
        self.entity_count = entity_count


class RetryableError(HuntIOConnectorError):
    """Raised for errors that should be retried."""

    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.retry_after = retry_after


class NonRetryableError(HuntIOConnectorError):
    """Raised for errors that should not be retried."""


class InvalidTlpLevelError(HuntIOConnectorError):
    """Custom error for invalid TLP levels."""
