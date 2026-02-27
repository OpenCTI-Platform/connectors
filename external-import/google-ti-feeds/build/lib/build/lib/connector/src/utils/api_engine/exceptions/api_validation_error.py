"""Base class for validation errors."""

from .api_error import ApiError


class ApiValidationError(ApiError):
    """Raised when the response cannot be validated or parsed."""

    pass
