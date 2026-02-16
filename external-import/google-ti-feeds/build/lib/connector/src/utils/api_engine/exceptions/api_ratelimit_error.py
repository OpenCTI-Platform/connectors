"""Base class for rate limit errors."""

from .api_error import ApiError


class ApiRateLimitError(ApiError):
    """Raises when rate limit is exceeded."""

    pass
