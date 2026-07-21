"""Validation error."""

from .api_error import ApiError


class ApiValidationError(ApiError):
    """Raised when response parsing or model validation fails."""
