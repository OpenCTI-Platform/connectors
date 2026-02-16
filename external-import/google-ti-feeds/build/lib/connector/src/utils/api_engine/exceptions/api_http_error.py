"""Base class for HTTP API errors."""

from .api_error import ApiError


class ApiHttpError(ApiError):
    """Base class for HTTP API errors in status code >= 400."""

    def __init__(self, status_code: int, message: str):
        """Initialize the error with status code and message."""
        self.status_code = status_code
        super().__init__(f"HTTP {status_code}: {message}")
