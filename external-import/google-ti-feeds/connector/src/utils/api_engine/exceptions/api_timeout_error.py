"""Base class for timeout errors."""

from .api_error import ApiError


class ApiTimeoutError(ApiError):
    """Raises when request times out."""

    pass
