"""Timeout error."""

from .api_error import ApiError


class ApiTimeoutError(ApiError):
    """Raised when a request exceeds its configured timeout."""
